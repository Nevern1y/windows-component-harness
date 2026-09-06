//! Windows host facts and current-user known-folder resolution.
//!
//! Absolute paths stay inside this process-local platform boundary. Callers
//! pass [`PathToken`] values across domain boundaries and resolve them only at
//! the current target.

use std::{
    collections::BTreeMap,
    fs,
    mem::{self, MaybeUninit},
    path::{Component, Path, PathBuf},
};

use reforge_domain::{
    AccountScope, Architecture, DriveFact, DriveFreeSpace, ErrorEnvelope, HostFacts,
    KnownFolderToken, PathToken, ReforgeErrorCode,
};
use windows::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            GetLengthSid, GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
            TokenElevation, TokenUser,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives,
            GetVolumeInformationW,
        },
        System::{
            Com::CoTaskMemFree,
            SystemInformation::{
                GetNativeSystemInfo, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
                PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64, PROCESSOR_ARCHITECTURE_ARM64,
                PROCESSOR_ARCHITECTURE_IA32_ON_WIN64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{
            FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Profile,
            FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
            FOLDERID_RoamingAppData, FOLDERID_StartMenu, FOLDERID_Startup, KNOWN_FOLDER_FLAG,
            SHGetKnownFolderPath,
        },
    },
    core::{GUID, PCWSTR},
};

/// Local-only map from an allowlisted token to an absolute target path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KnownFolderMap {
    /// Resolved paths. These values MUST remain inside the platform boundary.
    pub entries: BTreeMap<KnownFolderToken, PathBuf>,
    /// Folder/API failures retained as typed, redacted diagnostics.
    pub access_errors: Vec<KnownFolderAccessError>,
}

/// A known-folder resolution failure without an absolute path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownFolderAccessError {
    pub token: KnownFolderToken,
    pub error: ErrorEnvelope,
}

/// Host preflight output consumed by discovery and target analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPreflight {
    pub facts: HostFacts,
    pub known_folders: KnownFolderMap,
    /// Non-fatal host-query failures that callers should preserve as evidence.
    pub warnings: Vec<ErrorEnvelope>,
}

impl KnownFolderMap {
    /// Resolve all allowlisted current-user known folders through Shell32.
    ///
    /// Individual folder failures are retained in `access_errors`; the map is
    /// usable when at least one folder resolves. A completely unavailable map
    /// is a typed preflight failure.
    pub fn current_user() -> Result<Self, Box<ErrorEnvelope>> {
        let mut map = Self::default();
        for (token, folder_id) in known_folder_specs() {
            match resolve_known_folder(folder_id) {
                Ok(path) => match validate_known_folder_root(&path) {
                    Ok(()) => {
                        map.entries.insert(token, path);
                    }
                    Err(error) => map.access_errors.push(KnownFolderAccessError {
                        token,
                        error: *error,
                    }),
                },
                Err(error) => map.access_errors.push(KnownFolderAccessError {
                    token,
                    error: *error,
                }),
            }
        }

        if map.entries.is_empty() {
            return Err(Box::new(
                map.access_errors
                    .first()
                    .map(|failure| failure.error.clone())
                    .unwrap_or_else(|| {
                        ErrorEnvelope::new(
                            ReforgeErrorCode::PathNotFound,
                            "No current-user known folders could be resolved",
                        )
                    }),
            ));
        }
        Ok(map)
    }

    /// Construct a map for deterministic tests or an explicitly supplied target.
    pub fn from_entries(entries: BTreeMap<KnownFolderToken, PathBuf>) -> Self {
        Self {
            entries,
            access_errors: Vec::new(),
        }
    }

    /// Add an explicit user-selected root after validating its directory and identity.
    pub fn insert_user_selected(
        &mut self,
        id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let id = id.into();
        validate_user_selected_id(&id)?;
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid_path_error("user-selected root must be absolute"));
        }
        validate_known_folder_root(path)?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| io_error("canonicalize user-selected root", &error))?;
        self.entries
            .insert(KnownFolderToken::UserSelected { id }, canonical);
        Ok(())
    }

    /// Return normalized tokenized roots for all successfully resolved entries.
    pub fn tokenized_roots(&self) -> Vec<PathToken> {
        self.entries
            .keys()
            .filter_map(|root| PathToken::new(root.clone(), "").ok())
            .collect()
    }

    /// Resolve a token against the current target and reject unsafe components.
    pub fn resolve(&self, token: &PathToken) -> Result<PathBuf, Box<ErrorEnvelope>> {
        token
            .validate()
            .map_err(|_| invalid_path_error("path token failed validation"))?;
        let Some(root) = self.entries.get(&token.root) else {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::PathNotFound,
                "The requested known-folder root is unavailable on this target",
            )));
        };
        validate_known_folder_root(root)?;

        let mut current = root.clone();
        for component in Path::new(&token.relative).components() {
            let Component::Normal(segment) = component else {
                return Err(invalid_path_error(
                    "path token contains a non-relative component",
                ));
            };
            current.push(segment);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if is_reparse_point(&metadata) => {
                    return Err(Box::new(ErrorEnvelope::new(
                        ReforgeErrorCode::ReparsePoint,
                        "The target path contains a reparse point",
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(io_error("inspect target path", &error)),
            }
        }
        Ok(root.join(&token.relative))
    }
}

/// Run the complete host preflight and retain non-fatal observations.
pub fn host_preflight() -> Result<HostPreflight, Box<ErrorEnvelope>> {
    let known_folders = KnownFolderMap::current_user()?;
    let (os_version, os_build) = os_version()?;
    let architecture = native_architecture();
    let (elevated, sid_fingerprint) = token_facts()?;

    let mut warnings = Vec::new();
    let (drives, free_bytes) = drives_and_free_space(&mut warnings);
    let facts = HostFacts {
        os_version,
        os_build,
        architecture,
        elevated,
        account_scope: AccountScope::User,
        sid_fingerprint,
        known_folders: known_folders.tokenized_roots(),
        drives,
        free_bytes,
    };
    Ok(HostPreflight {
        facts,
        known_folders,
        warnings,
    })
}

/// Convenience wrapper returning only the typed host facts.
pub fn collect_host_facts() -> Result<HostFacts, Box<ErrorEnvelope>> {
    Ok(host_preflight()?.facts)
}

fn known_folder_specs() -> [(KnownFolderToken, GUID); 10] {
    [
        (KnownFolderToken::UserProfile, FOLDERID_Profile),
        (KnownFolderToken::RoamingAppData, FOLDERID_RoamingAppData),
        (KnownFolderToken::LocalAppData, FOLDERID_LocalAppData),
        (KnownFolderToken::ProgramData, FOLDERID_ProgramData),
        (KnownFolderToken::ProgramFiles, FOLDERID_ProgramFiles),
        (KnownFolderToken::ProgramFilesX86, FOLDERID_ProgramFilesX86),
        (KnownFolderToken::StartMenu, FOLDERID_StartMenu),
        (KnownFolderToken::Startup, FOLDERID_Startup),
        (KnownFolderToken::Desktop, FOLDERID_Desktop),
        (KnownFolderToken::Documents, FOLDERID_Documents),
    ]
}

fn resolve_known_folder(folder_id: GUID) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let pointer = unsafe { SHGetKnownFolderPath(&folder_id, KNOWN_FOLDER_FLAG(0), None) }
        .map_err(|error| windows_error("SHGetKnownFolderPath", &error))?;
    if pointer.is_null() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::PathNotFound,
            "Windows returned an empty known-folder path",
        )));
    }

    let converted = unsafe { pointer.to_string() };
    unsafe { CoTaskMemFree(Some(pointer.as_ptr().cast())) };
    let path = converted.map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Known-folder path was not valid UTF-16",
        ))
    })?;
    if path.is_empty() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::PathNotFound,
            "Windows returned an empty known-folder path",
        )));
    }
    Ok(PathBuf::from(path))
}

fn validate_known_folder_root(path: &Path) -> Result<(), Box<ErrorEnvelope>> {
    if !path.is_absolute() {
        return Err(invalid_path_error("known-folder root is not absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect known-folder root", &error))?;
    if !metadata.is_dir() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::PathNotFound,
            "known-folder root is not a directory",
        )));
    }
    if is_reparse_point(&metadata) {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ReparsePoint,
            "known-folder root is a reparse point",
        )));
    }
    Ok(())
}

fn validate_user_selected_id(id: &str) -> Result<(), Box<ErrorEnvelope>> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.contains(['/', '\\', ':'])
        || id.chars().any(char::is_control)
    {
        return Err(invalid_path_error(
            "user-selected root identifier is invalid",
        ));
    }
    Ok(())
}

fn os_version() -> Result<(String, String), Box<ErrorEnvelope>> {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // GetVersionExW reports Windows 8 for an unmanifested CLI, even on Windows 11.
    unsafe { RtlGetVersion(&mut info) }
        .ok()
        .map_err(|error| windows_error("RtlGetVersion", &error))?;
    Ok((
        format!("{}.{}", info.dwMajorVersion, info.dwMinorVersion),
        info.dwBuildNumber.to_string(),
    ))
}

fn native_architecture() -> Architecture {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    let processor_architecture = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture };
    match processor_architecture {
        PROCESSOR_ARCHITECTURE_AMD64 => Architecture::X64,
        PROCESSOR_ARCHITECTURE_ARM64 | PROCESSOR_ARCHITECTURE_ARM32_ON_WIN64 => Architecture::Arm64,
        PROCESSOR_ARCHITECTURE_INTEL | PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 => Architecture::X86,
        _ => Architecture::Unknown,
    }
}

fn token_facts() -> Result<(bool, Option<String>), Box<ErrorEnvelope>> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| windows_error("OpenProcessToken", &error))?;
    let token = OwnedHandle(token);

    let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::zeroed();
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(elevation.as_mut_ptr().cast()),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .map_err(|error| windows_error("GetTokenInformation(TokenElevation)", &error))?;
    let elevation = unsafe { elevation.assume_init() };

    let mut required = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required == 0 {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows did not report the current SID buffer size",
        )));
    }
    let word_count = (required as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * mem::size_of::<usize>()) as u32,
            &mut required,
        )
    }
    .map_err(|error| windows_error("GetTokenInformation(TokenUser)", &error))?;

    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid = token_user.User.Sid;
    if sid.0.is_null() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows returned an empty current SID",
        )));
    }
    let sid_length = unsafe { GetLengthSid(sid) } as usize;
    let start = sid.0 as usize;
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start + buffer.len() * mem::size_of::<usize>();
    let sid_end = start.checked_add(sid_length).ok_or_else(|| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Current SID length overflowed",
        ))
    })?;
    if sid_length == 0 || start < buffer_start || sid_end > buffer_end {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows returned an invalid current SID buffer",
        )));
    }
    let sid_bytes = unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), sid_length) };
    let sid_fingerprint = Some(format!("blake3:{}", blake3::hash(sid_bytes).to_hex()));
    Ok((elevation.TokenIsElevated != 0, sid_fingerprint))
}

fn drives_and_free_space(
    warnings: &mut Vec<ErrorEnvelope>,
) -> (Vec<DriveFact>, Vec<DriveFreeSpace>) {
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        warnings.push(*boxed_error(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows did not return a logical-drive mask",
        )));
        return (Vec::new(), Vec::new());
    }

    let mut drives = Vec::new();
    let mut free_bytes = Vec::new();
    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = char::from(b'A' + index as u8);
        let root = format!("{letter}:\\");
        let wide_root = wide_null(&root);
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide_root.as_ptr())) };
        if drive_type == 0 || drive_type == 1 {
            continue;
        }

        let filesystem = filesystem_name(PCWSTR(wide_root.as_ptr()));
        drives.push(DriveFact {
            token: format!("{letter}:"),
            filesystem,
        });

        let mut available = 0u64;
        match unsafe {
            GetDiskFreeSpaceExW(PCWSTR(wide_root.as_ptr()), Some(&mut available), None, None)
        } {
            Ok(()) => free_bytes.push(DriveFreeSpace {
                token: format!("{letter}:"),
                bytes: available,
            }),
            Err(error) => warnings.push(*windows_error("GetDiskFreeSpaceExW", &error)),
        }
    }
    (drives, free_bytes)
}

fn filesystem_name(root: PCWSTR) -> Option<String> {
    let mut name = [0u16; 64];
    unsafe { GetVolumeInformationW(root, None, None, None, None, Some(&mut name)) }
        .ok()
        .and_then(|()| utf16_string(&name))
}

fn utf16_string(buffer: &[u16]) -> Option<String> {
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).ok()
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

fn boxed_error(error: ErrorEnvelope) -> Box<ErrorEnvelope> {
    Box::new(error)
}

fn invalid_path_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::InvalidPath,
            "A path failed target validation",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &std::io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, operation))
}

fn windows_error(operation: &str, error: &windows::core::Error) -> Box<ErrorEnvelope> {
    let code = error.code().0 as u32;
    let reforge_code = match code {
        0x8007_0005 => ReforgeErrorCode::AccessDenied,
        0x8007_0002 => ReforgeErrorCode::PathNotFound,
        _ => ReforgeErrorCode::OperationFailed,
    };
    Box::new(
        ErrorEnvelope::new(reforge_code, format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT 0x{code:08X}")),
    )
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn current_user_known_folders_are_tokenized_without_trailing_separator_assumptions() {
        let preflight = host_preflight().expect("Windows host preflight should be available");
        assert!(
            preflight
                .known_folders
                .entries
                .contains_key(&KnownFolderToken::UserProfile)
        );
        assert!(
            preflight
                .facts
                .known_folders
                .iter()
                .all(|token| token.relative.is_empty())
        );
        assert!(
            preflight
                .known_folders
                .entries
                .contains_key(&KnownFolderToken::Startup)
        );

        let token = PathToken::new(KnownFolderToken::UserProfile, "Reforge\\probe").unwrap();
        let resolved = preflight.known_folders.resolve(&token).unwrap();
        assert!(resolved.ends_with(Path::new("Reforge/probe")));
    }

    #[test]
    fn unsafe_tokens_are_rejected_before_resolution() {
        let root = std::env::temp_dir();
        let mut entries = BTreeMap::new();
        entries.insert(KnownFolderToken::UserProfile, root);
        let map = KnownFolderMap::from_entries(entries);
        assert!(PathToken::new(KnownFolderToken::UserProfile, "../outside").is_err());
        assert!(
            map.resolve(&PathToken {
                root: KnownFolderToken::UserProfile,
                relative: "../outside".to_owned(),
            })
            .is_err()
        );
    }

    #[test]
    fn sid_is_fingerprinted_not_returned_as_plain_identity() {
        let facts = collect_host_facts().expect("Windows host facts should be available");
        let fingerprint = facts.sid_fingerprint.expect("current SID fingerprint");
        assert!(fingerprint.starts_with("blake3:"));
        assert!(!fingerprint.contains("S-1-"));
    }
}
