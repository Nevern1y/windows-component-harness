//! PE version-resource and Authenticode inspection.
//!
//! The implementation reads candidate files and passes their paths to
//! WinTrust; it never maps or executes a candidate image.

use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    mem,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr, slice,
};

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode, redact_text};
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, HWND},
        Security::{
            Cryptography::{
                CERT_CONTEXT, CERT_HASH_PROP_ID, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_SHA256_HASH_PROP_ID, CertGetCertificateContextProperty, CertGetNameStringW,
            },
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
                WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
                WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
                WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
                WTHelperProvDataFromStateData, WinVerifyTrust,
            },
        },
        Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
        },
    },
    core::{GUID, PCWSTR},
};

const MAX_VERSION_RESOURCE_BYTES: u32 = 16 * 1024 * 1024;
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF04BD;
const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B0003;

/// Result of the WinTrust trust-provider decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerStatus {
    Trusted,
    Unsigned,
    Untrusted,
}

impl SignerStatus {
    /// Map a raw WinTrust return value; only exactly zero is trusted.
    pub fn from_wintrust_status(status: i32) -> Self {
        if status == 0 {
            Self::Trusted
        } else if matches!(
            status as u32,
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN
        ) {
            Self::Unsigned
        } else {
            Self::Untrusted
        }
    }
}

/// Signer evidence returned by WinTrust while its verification state is alive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureInfo {
    pub status: SignerStatus,
    pub wintrust_status: i32,
    pub signer_subject: Option<String>,
    pub certificate_fingerprint: Option<String>,
}

/// Four-part file/product version from the PE version resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl FileVersion {
    pub fn as_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// Read-only executable metadata used by generic discovery and trust UX.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeMetadata {
    pub file_version: Option<FileVersion>,
    pub product_version: Option<FileVersion>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub original_filename: Option<String>,
    pub publisher: Option<String>,
    pub executable_hash: String,
    pub signature: SignatureInfo,
}

/// Inspect a PE file's version resource, BLAKE3 content hash, and signer state.
///
/// The input path is used only for read-only inspection. Missing, unreadable,
/// and malformed PE files return coded errors; an unsigned but structurally
/// valid PE returns metadata with `SignerStatus::Unsigned`.
pub fn inspect_pe(path: impl AsRef<Path>) -> Result<PeMetadata, Box<ErrorEnvelope>> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|error| io_error("open executable", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect executable metadata", &error))?;
    if !metadata.is_file() {
        return Err(version_error("candidate executable is not a regular file"));
    }
    validate_pe_header(&mut file, metadata.len())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind executable", &error))?;
    let executable_hash = hash_reader(&mut file)?;
    let version = read_version_resource(path)?;
    let signature = verify_signature(path);
    let publisher = version
        .as_ref()
        .and_then(|info| info.company_name.clone())
        .or_else(|| signature.signer_subject.clone());

    Ok(PeMetadata {
        file_version: version.as_ref().and_then(|info| info.file_version.clone()),
        product_version: version
            .as_ref()
            .and_then(|info| info.product_version.clone()),
        product_name: version.as_ref().and_then(|info| info.product_name.clone()),
        company_name: version.as_ref().and_then(|info| info.company_name.clone()),
        original_filename: version
            .as_ref()
            .and_then(|info| info.original_filename.clone()),
        publisher,
        executable_hash,
        signature,
    })
}

struct VersionResource {
    file_version: Option<FileVersion>,
    product_version: Option<FileVersion>,
    product_name: Option<String>,
    company_name: Option<String>,
    original_filename: Option<String>,
}

fn validate_pe_header(file: &mut File, file_len: u64) -> Result<(), Box<ErrorEnvelope>> {
    let mut dos_signature = [0u8; 2];
    file.read_exact(&mut dos_signature)
        .map_err(|error| io_error("read PE DOS header", &error))?;
    if dos_signature != *b"MZ" {
        return Err(version_error("candidate is not a PE image"));
    }

    file.seek(SeekFrom::Start(0x3c))
        .map_err(|error| io_error("seek PE header pointer", &error))?;
    let mut offset_bytes = [0u8; 4];
    file.read_exact(&mut offset_bytes)
        .map_err(|error| io_error("read PE header pointer", &error))?;
    let pe_offset = u32::from_le_bytes(offset_bytes) as u64;
    if pe_offset
        .checked_add(24)
        .is_none_or(|required_len| required_len > file_len)
    {
        return Err(version_error("PE header is truncated"));
    }

    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|error| io_error("seek PE signature", &error))?;
    let mut pe_signature = [0u8; 4];
    file.read_exact(&mut pe_signature)
        .map_err(|error| io_error("read PE signature", &error))?;
    if pe_signature != *b"PE\0\0" {
        return Err(version_error("candidate has an invalid PE signature"));
    }
    Ok(())
}

fn hash_reader(reader: &mut File) -> Result<String, Box<ErrorEnvelope>> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("hash executable", &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

fn read_version_resource(path: &Path) -> Result<Option<VersionResource>, Box<ErrorEnvelope>> {
    let wide_path = wide_path(path);
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide_path.as_ptr()), None) };
    if size == 0 {
        let _last_error = unsafe { GetLastError() };
        return Ok(None);
    }
    if size > MAX_VERSION_RESOURCE_BYTES {
        return Err(version_error(
            "version resource exceeds the inspection limit",
        ));
    }

    let mut block = vec![0u8; size as usize];
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide_path.as_ptr()),
            None,
            size,
            block.as_mut_ptr().cast(),
        )
    }
    .map_err(|error| windows_error("GetFileVersionInfoW", error.code().0))?;

    let fixed = query_fixed_file_info(&block)
        .ok_or_else(|| version_error("version resource has no valid fixed file information"))?;
    let translation = query_translation(&block).unwrap_or((0x0409, 0x04B0));
    let language_codepage = format!("{:04x}{:04x}", translation.0, translation.1);

    Ok(Some(VersionResource {
        file_version: Some(file_version(fixed.dwFileVersionMS, fixed.dwFileVersionLS)),
        product_version: Some(file_version(
            fixed.dwProductVersionMS,
            fixed.dwProductVersionLS,
        )),
        product_name: query_version_string(&block, &language_codepage, "ProductName"),
        company_name: query_version_string(&block, &language_codepage, "CompanyName"),
        original_filename: query_version_string(&block, &language_codepage, "OriginalFilename"),
    }))
}

fn query_fixed_file_info(block: &[u8]) -> Option<VS_FIXEDFILEINFO> {
    let bytes = query_block(block, "\\")?;
    if bytes.len() < mem::size_of::<VS_FIXEDFILEINFO>() {
        return None;
    }
    let fixed = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<VS_FIXEDFILEINFO>()) };
    (fixed.dwSignature == VS_FIXEDFILEINFO_SIGNATURE).then_some(fixed)
}

fn query_translation(block: &[u8]) -> Option<(u16, u16)> {
    let bytes = query_block(block, r"\VarFileInfo\Translation")?;
    if bytes.len() < 4 {
        return None;
    }
    Some((
        u16::from_le_bytes([bytes[0], bytes[1]]),
        u16::from_le_bytes([bytes[2], bytes[3]]),
    ))
}

fn query_version_string(block: &[u8], language_codepage: &str, name: &str) -> Option<String> {
    let path = format!(r"\StringFileInfo\{language_codepage}\{name}");
    let bytes = query_block(block, &path)?;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let units = pairs
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    let value = String::from_utf16(&units)
        .ok()?
        .trim_end_matches('\0')
        .to_owned();
    redact_text(&value)
}

fn query_block<'a>(block: &'a [u8], sub_block: &str) -> Option<&'a [u8]> {
    let wide_sub_block = wide_null(sub_block);
    let mut pointer = ptr::null_mut::<c_void>();
    let mut length = 0u32;
    let found = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR(wide_sub_block.as_ptr()),
            &mut pointer,
            &mut length,
        )
        .as_bool()
    };
    if !found || pointer.is_null() {
        return None;
    }
    let byte_len = (length as usize).checked_mul(mem::size_of::<u16>())?;
    bounded_slice(block, pointer, byte_len)
}

fn bounded_slice(block: &[u8], pointer: *mut c_void, byte_len: usize) -> Option<&[u8]> {
    let block_start = block.as_ptr() as usize;
    let block_end = block_start.checked_add(block.len())?;
    let start = pointer as usize;
    let end = start.checked_add(byte_len)?;
    if start < block_start || end > block_end {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(pointer.cast::<u8>(), byte_len) })
}

fn file_version(most_significant: u32, least_significant: u32) -> FileVersion {
    FileVersion {
        major: (most_significant >> 16) as u16,
        minor: most_significant as u16,
        build: (least_significant >> 16) as u16,
        revision: least_significant as u16,
    }
}

fn verify_signature(path: &Path) -> SignatureInfo {
    let wide_path = wide_path(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: ptr::null_mut::<GUID>(),
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };
    let signer = extract_signer(&trust_data);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        )
    };

    SignatureInfo {
        status: SignerStatus::from_wintrust_status(status),
        wintrust_status: status,
        signer_subject: signer.as_ref().and_then(|info| info.0.clone()),
        certificate_fingerprint: signer.and_then(|info| info.1),
    }
}

fn extract_signer(trust_data: &WINTRUST_DATA) -> Option<(Option<String>, Option<String>)> {
    unsafe {
        if trust_data.hWVTStateData.is_invalid() {
            return None;
        }
        let provider_data = WTHelperProvDataFromStateData(trust_data.hWVTStateData);
        if provider_data.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(provider_data, 0, false, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return None;
        }
        let certificate = WTHelperGetProvCertFromChain(signer, 0);
        if certificate.is_null() || (*certificate).pCert.is_null() {
            return None;
        }
        let certificate = (*certificate).pCert;
        Some((
            certificate_subject(certificate),
            certificate_fingerprint(certificate),
        ))
    }
}

fn certificate_subject(certificate: *const CERT_CONTEXT) -> Option<String> {
    let required =
        unsafe { CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if required <= 1 {
        return None;
    }
    let mut buffer = vec![0u16; required as usize];
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        )
    };
    if written <= 1 || written as usize > buffer.len() {
        return None;
    }
    redact_text(&String::from_utf16(&buffer[..written as usize - 1]).ok()?)
}

fn certificate_fingerprint(certificate: *const CERT_CONTEXT) -> Option<String> {
    certificate_hash(certificate, CERT_SHA256_HASH_PROP_ID)
        .map(|hash| format!("sha256:{hash}"))
        .or_else(|| {
            certificate_hash(certificate, CERT_HASH_PROP_ID).map(|hash| format!("sha1:{hash}"))
        })
}

fn certificate_hash(certificate: *const CERT_CONTEXT, property: u32) -> Option<String> {
    let mut size = 0u32;
    if unsafe { CertGetCertificateContextProperty(certificate, property, None, &mut size) }.is_err()
    {
        return None;
    }
    if size == 0 || size > 4096 {
        return None;
    }
    let mut bytes = vec![0u8; size as usize];
    if unsafe {
        CertGetCertificateContextProperty(
            certificate,
            property,
            Some(bytes.as_mut_ptr().cast()),
            &mut size,
        )
    }
    .is_err()
    {
        return None;
    }
    bytes.truncate(size as usize);
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn version_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::VersionUnavailable,
            "Executable metadata could not be read",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, operation))
}

fn windows_error(operation: &str, status: i32) -> Box<ErrorEnvelope> {
    let code = status as u32;
    let reforge_code = if code == ERROR_FILE_NOT_FOUND.0 {
        ReforgeErrorCode::PathNotFound
    } else {
        ReforgeErrorCode::VersionUnavailable
    };
    Box::new(
        ErrorEnvelope::new(reforge_code, format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT 0x{code:08X}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_zero_wintrust_status_is_trusted() {
        assert_eq!(SignerStatus::from_wintrust_status(0), SignerStatus::Trusted);
        assert_eq!(
            SignerStatus::from_wintrust_status(1),
            SignerStatus::Untrusted
        );
        assert_eq!(
            SignerStatus::from_wintrust_status(TRUST_E_NOSIGNATURE as i32),
            SignerStatus::Unsigned
        );
    }

    #[test]
    fn fixed_file_version_is_split_into_four_parts() {
        let version = file_version(0x0001_0002, 0x0003_0004);
        assert_eq!(version.as_string(), "1.2.3.4");
    }

    #[test]
    fn malformed_version_resource_pointer_is_rejected() {
        assert!(query_fixed_file_info(&[0u8; 16]).is_none());
    }
}
