//! Read-only Windows Shell registration observations.
//!
//! Shortcut files are inspected through the Shell Link COM interface. Default
//! application associations are queried through the supported read-only Shell
//! API. Shortcut sources and any targets that live below a known folder cross
//! the platform boundary only as [`PathToken`] values; arbitrary command text
//! and absolute paths are deliberately not retained.

use std::{
    fs, iter,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use reforge_domain::{ErrorEnvelope, KnownFolderToken, PathToken, ReforgeErrorCode, redact_text};
use windows::{
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK},
        Storage::FileSystem::WIN32_FIND_DATAW,
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoTaskMemFree, CoUninitialize, IPersistFile, STGM_READ,
        },
        UI::Shell::{
            AL_EFFECTIVE, AT_FILEEXTENSION, AT_URLPROTOCOL, ApplicationAssociationRegistration,
            IApplicationAssociationRegistration, IShellLinkW, SLGP_RAWPATH,
        },
    },
    core::{GUID, Interface, PCWSTR},
};

use crate::{fs::FileObservationKind, known_folders::KnownFolderMap};

const MAX_SHORTCUT_ENTRIES: usize = 20_000;
const MAX_SHORTCUT_DEPTH: usize = 16;
const MAX_SHORTCUT_TEXT_CHARS: usize = 32 * 1024;
const MAX_DESCRIPTION_CHARS: usize = 4 * 1024;
const MAX_TARGET_NAME_CHARS: usize = 512;

const MAX_DEFAULT_ASSOCIATION_ID_CHARS: usize = 256;
const DEFAULT_ASSOCIATIONS: [(&str, DefaultAssociationKind); 3] = [
    ("http", DefaultAssociationKind::UrlProtocol),
    ("https", DefaultAssociationKind::UrlProtocol),
    (".html", DefaultAssociationKind::FileExtension),
];

// The Shell Link class is not emitted by the windows metadata in this crate.
const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);

/// A shortcut source and its safely reduced target metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellLinkObservation {
    /// Tokenized path to the `.lnk` file itself.
    pub source: PathToken,
    /// Tokenized target when the target is below a known folder.
    pub target: Option<PathToken>,
    /// Basename retained for targets outside known folders or missing targets.
    pub target_name: Option<String>,
    /// Whether the target path resolved to an existing filesystem entry.
    pub target_exists: bool,
    /// Optional user-visible description, after the standard redaction policy.
    pub description: Option<String>,
}

/// Operation associated with a shortcut access failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ShellLinkOperation {
    EnumerateRoot,
    CreateComObject,
    Load,
    ReadTarget,
    ReadDescription,
}

/// A non-fatal shortcut access failure without an absolute path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellLinkAccessError {
    pub root: KnownFolderToken,
    pub source: Option<PathToken>,
    pub operation: ShellLinkOperation,
    pub error: ErrorEnvelope,
}

/// Complete bounded shortcut enumeration result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShellLinkSnapshot {
    pub observations: Vec<ShellLinkObservation>,
    pub errors: Vec<ShellLinkAccessError>,
}

/// Association type for a supported default application query.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DefaultAssociationKind {
    UrlProtocol,
    FileExtension,
}

/// Safe, effective default application association metadata.
///
/// `prog_id` is retained only when it is a bounded ProgID-shaped identifier;
/// legacy machine-default command text is rejected rather than exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultAssociationObservation {
    pub association: String,
    pub kind: DefaultAssociationKind,
    pub prog_id: String,
}

/// Operation associated with a default-association access failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DefaultAssociationOperation {
    InitializeCom,
    CreateRegistration,
    QueryCurrentDefault,
    ReadProgId,
}

/// A non-fatal default-association query failure without command text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultAssociationAccessError {
    pub association: String,
    pub kind: DefaultAssociationKind,
    pub operation: DefaultAssociationOperation,
    pub hresult: u32,
    pub error: ErrorEnvelope,
}

/// Complete, bounded default-association query result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DefaultAssociationSnapshot {
    pub observations: Vec<DefaultAssociationObservation>,
    pub errors: Vec<DefaultAssociationAccessError>,
}

/// Inspect user Start Menu, Desktop, and Startup shortcut roots without
/// following reparse points or executing a shortcut target.
pub fn enumerate_shell_links(known_folders: &KnownFolderMap) -> ShellLinkSnapshot {
    let mut snapshot = ShellLinkSnapshot::default();
    let roots = [
        KnownFolderToken::StartMenu,
        KnownFolderToken::Desktop,
        KnownFolderToken::Startup,
    ];
    let mut candidates = Vec::new();

    for root_token in roots {
        let Some(root) = known_folders.entries.get(&root_token) else {
            snapshot.errors.push(ShellLinkAccessError {
                root: root_token,
                source: None,
                operation: ShellLinkOperation::EnumerateRoot,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::PathNotFound,
                    "The shortcut known-folder root is unavailable",
                ),
            });
            continue;
        };

        let walked = match crate::walk_reparse_safe(
            root,
            crate::WalkLimits {
                max_entries: MAX_SHORTCUT_ENTRIES,
                max_depth: MAX_SHORTCUT_DEPTH,
            },
        ) {
            Ok(walked) => walked,
            Err(error) => {
                snapshot.errors.push(ShellLinkAccessError {
                    root: root_token,
                    source: None,
                    operation: ShellLinkOperation::EnumerateRoot,
                    error: *error,
                });
                continue;
            }
        };

        for entry in walked {
            if entry.kind != FileObservationKind::File || !is_shortcut_path(entry.path.as_str()) {
                continue;
            }
            let source = match PathToken::new(root_token.clone(), entry.path.as_str()) {
                Ok(source) => source,
                Err(_) => {
                    snapshot.errors.push(ShellLinkAccessError {
                        root: root_token.clone(),
                        source: None,
                        operation: ShellLinkOperation::EnumerateRoot,
                        error: ErrorEnvelope::new(
                            ReforgeErrorCode::InvalidPath,
                            "A shortcut path could not be represented safely",
                        ),
                    });
                    continue;
                }
            };
            candidates.push((
                root_token.clone(),
                root.join(entry.path.to_path_buf()),
                source,
            ));
        }
    }

    if candidates.is_empty() {
        return snapshot;
    }

    let apartment = match ComApartment::initialize() {
        Ok(apartment) => apartment,
        Err(error) => {
            for (root, _, source) in candidates {
                snapshot.errors.push(ShellLinkAccessError {
                    root,
                    source: Some(source),
                    operation: ShellLinkOperation::CreateComObject,
                    error: (*error).clone(),
                });
            }
            return snapshot;
        }
    };

    for (root, absolute_source, source) in candidates {
        match inspect_shortcut(&absolute_source, &source, known_folders) {
            Ok(observation) => snapshot.observations.push(observation),
            Err((operation, error)) => snapshot.errors.push(ShellLinkAccessError {
                root,
                source: Some(source),
                operation,
                error: *error,
            }),
        }
    }
    drop(apartment);

    snapshot.observations.sort_by(|left, right| {
        left.source
            .root
            .cmp(&right.source.root)
            .then_with(|| left.source.relative.cmp(&right.source.relative))
    });
    snapshot.errors.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| match (&left.source, &right.source) {
                (Some(left), Some(right)) => left
                    .root
                    .cmp(&right.root)
                    .then_with(|| left.relative.cmp(&right.relative)),
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
            })
            .then_with(|| left.operation.cmp(&right.operation))
    });
    snapshot
}

/// Query the effective current-user defaults for HTTP, HTTPS, and HTML using
/// `IApplicationAssociationRegistration::QueryCurrentDefault`.
///
/// This function never reads or writes `UserChoice`, and never retains legacy
/// machine-default command text returned in place of a ProgID.
pub fn enumerate_default_associations() -> DefaultAssociationSnapshot {
    let mut snapshot = DefaultAssociationSnapshot::default();
    let apartment = match ComApartment::initialize() {
        Ok(apartment) => apartment,
        Err(error) => {
            for (association, kind) in DEFAULT_ASSOCIATIONS {
                snapshot.errors.push(DefaultAssociationAccessError {
                    association: association.to_owned(),
                    kind,
                    operation: DefaultAssociationOperation::InitializeCom,
                    hresult: 0,
                    error: (*error).clone(),
                });
            }
            return snapshot;
        }
    };

    let registration: IApplicationAssociationRegistration = match unsafe {
        CoCreateInstance(
            &ApplicationAssociationRegistration,
            None,
            CLSCTX_INPROC_SERVER,
        )
    } {
        Ok(registration) => registration,
        Err(error) => {
            for (association, kind) in DEFAULT_ASSOCIATIONS {
                snapshot.errors.push(DefaultAssociationAccessError {
                    association: association.to_owned(),
                    kind,
                    operation: DefaultAssociationOperation::CreateRegistration,
                    hresult: error.code().0 as u32,
                    error: *association_error(
                        "create application association registration",
                        &error,
                    ),
                });
            }
            drop(apartment);
            return snapshot;
        }
    };

    for (association, kind) in DEFAULT_ASSOCIATIONS {
        match query_default_association(&registration, association, kind) {
            Ok(observation) => snapshot.observations.push(observation),
            Err((operation, hresult, error)) => {
                snapshot.errors.push(DefaultAssociationAccessError {
                    association: association.to_owned(),
                    kind,
                    operation,
                    hresult,
                    error: *error,
                });
            }
        }
    }
    drop(registration);
    drop(apartment);

    snapshot.observations.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.association.cmp(&right.association))
    });
    snapshot.errors.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.association.cmp(&right.association))
            .then_with(|| left.operation.cmp(&right.operation))
            .then_with(|| left.hresult.cmp(&right.hresult))
    });
    snapshot
}

/// Return whether a root-relative entry has the `.lnk` extension.
pub fn is_shortcut_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"))
}

fn query_default_association(
    registration: &IApplicationAssociationRegistration,
    association: &str,
    kind: DefaultAssociationKind,
) -> Result<DefaultAssociationObservation, (DefaultAssociationOperation, u32, Box<ErrorEnvelope>)> {
    let query: Vec<u16> = association.encode_utf16().chain(iter::once(0)).collect();
    let association_type = match kind {
        DefaultAssociationKind::UrlProtocol => AT_URLPROTOCOL,
        DefaultAssociationKind::FileExtension => AT_FILEEXTENSION,
    };
    let value = unsafe {
        registration.QueryCurrentDefault(PCWSTR(query.as_ptr()), association_type, AL_EFFECTIVE)
    }
    .map_err(|error| {
        (
            DefaultAssociationOperation::QueryCurrentDefault,
            error.code().0 as u32,
            association_error("query current default association", &error),
        )
    })?;
    if value.is_null() {
        return Err((
            DefaultAssociationOperation::ReadProgId,
            0,
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "Windows returned an empty default association",
            )),
        ));
    }
    let decoded = unsafe { value.to_string() };
    unsafe { CoTaskMemFree(Some(value.as_ptr().cast())) };
    let value = decoded.map_err(|_| {
        (
            DefaultAssociationOperation::ReadProgId,
            0,
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "Windows returned invalid UTF-16 default association metadata",
            )),
        )
    })?;
    let prog_id = safe_default_association_id(&value).ok_or_else(|| {
        (
            DefaultAssociationOperation::ReadProgId,
            0,
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "Windows returned unsafe default association metadata",
            )),
        )
    })?;
    Ok(DefaultAssociationObservation {
        association: association.to_owned(),
        kind,
        prog_id,
    })
}

fn safe_default_association_id(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_DEFAULT_ASSOCIATION_ID_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(value.to_owned())
}

fn inspect_shortcut(
    absolute_source: &Path,
    source: &PathToken,
    known_folders: &KnownFolderMap,
) -> Result<ShellLinkObservation, (ShellLinkOperation, Box<ErrorEnvelope>)> {
    let link: IShellLinkW = unsafe {
        CoCreateInstance(&CLSID_SHELL_LINK, None, CLSCTX_INPROC_SERVER).map_err(|error| {
            (
                ShellLinkOperation::CreateComObject,
                com_error("create Shell Link", error),
            )
        })?
    };
    let persist: IPersistFile = link.cast().map_err(|error| {
        (
            ShellLinkOperation::CreateComObject,
            com_error("cast Shell Link", error),
        )
    })?;
    let wide_source: Vec<u16> = absolute_source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    unsafe { persist.Load(PCWSTR(wide_source.as_ptr()), STGM_READ) }.map_err(|error| {
        (
            ShellLinkOperation::Load,
            com_error("load Shell Link", error),
        )
    })?;

    let mut target_buffer = vec![0u16; MAX_SHORTCUT_TEXT_CHARS];
    let mut find_data = WIN32_FIND_DATAW::default();
    let target_result =
        unsafe { link.GetPath(&mut target_buffer, &mut find_data, SLGP_RAWPATH.0 as u32) };
    let target_text = match target_result {
        Ok(()) => bounded_utf16(&target_buffer)
            .map_err(|error| (ShellLinkOperation::ReadTarget, error))?,
        Err(_) => None,
    };

    let (target, target_name, target_exists) = target_text
        .as_deref()
        .map(|target| {
            let target_path = PathBuf::from(target);
            let exists = target_path.is_absolute() && fs::metadata(&target_path).is_ok();
            let token = token_for_absolute_path(known_folders, &target_path);
            let name = target_name(&target_path);
            (token, name, exists)
        })
        .unwrap_or((None, None, false));

    let mut description_buffer = vec![0u16; MAX_DESCRIPTION_CHARS];
    let description = match unsafe { link.GetDescription(&mut description_buffer) } {
        Ok(()) => bounded_utf16(&description_buffer)
            .ok()
            .flatten()
            .and_then(|value| redact_text(value.trim()))
            .filter(|value| !value.is_empty()),
        Err(_) => None,
    };

    Ok(ShellLinkObservation {
        source: source.clone(),
        target,
        target_name,
        target_exists,
        description,
    })
}

fn bounded_utf16(buffer: &[u16]) -> Result<Option<String>, Box<ErrorEnvelope>> {
    let Some(end) = buffer.iter().position(|value| *value == 0) else {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Windows returned an unterminated shortcut string",
        )));
    };
    if end == 0 {
        return Ok(None);
    }
    String::from_utf16(&buffer[..end]).map(Some).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows returned invalid UTF-16 shortcut metadata",
        ))
    })
}

fn target_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_TARGET_NAME_CHARS {
        return None;
    }
    if name.chars().any(|character| character.is_control()) {
        return None;
    }
    Some(name.to_owned())
}

/// Tokenize an absolute path only when it is below one of the known roots.
fn token_for_absolute_path(known_folders: &KnownFolderMap, path: &Path) -> Option<PathToken> {
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    known_folders.entries.iter().find_map(|(token, root)| {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        let relative = relative_path_case_insensitive(&root, &candidate)?;
        PathToken::new(token.clone(), relative).ok()
    })
}

fn relative_path_case_insensitive(root: &Path, candidate: &Path) -> Option<String> {
    let root_text = path_text(root)?;
    let candidate_text = path_text(candidate)?;
    let root_key = root_text.trim_end_matches('/').to_ascii_lowercase();
    let candidate_key = candidate_text.trim_end_matches('/').to_ascii_lowercase();
    if candidate_key == root_key {
        return Some(String::new());
    }
    let prefix = format!("{root_key}/");
    if !candidate_key.starts_with(&prefix) {
        return None;
    }
    let offset = root_text.trim_end_matches('/').len() + 1;
    Some(candidate_text[offset..].replace('\\', "/"))
}

fn path_text(path: &Path) -> Option<String> {
    let value = path.to_str()?.replace('\\', "/");
    (!value.is_empty()).then_some(value)
}

fn com_error(operation: &str, error: windows::core::Error) -> Box<ErrorEnvelope> {
    let code = error.code().0 as u32;
    let reforge_code = if code & 0xffff == 5 {
        ReforgeErrorCode::AccessDenied
    } else {
        ReforgeErrorCode::OperationFailed
    };
    Box::new(
        ErrorEnvelope::new(reforge_code, format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT=0x{code:08x}")),
    )
}

fn association_error(operation: &str, error: &windows::core::Error) -> Box<ErrorEnvelope> {
    let code = error.code().0 as u32;
    let reforge_code = if code & 0xffff == 5 {
        ReforgeErrorCode::AccessDenied
    } else {
        ReforgeErrorCode::OperationFailed
    };
    Box::new(
        ErrorEnvelope::new(reforge_code, format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT=0x{code:08x}")),
    )
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn initialize() -> Result<Self, Box<ErrorEnvelope>> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result == S_OK || result == S_FALSE {
            return Ok(Self { uninitialize: true });
        }
        if result == RPC_E_CHANGED_MODE {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::AccessDenied,
                "The current thread uses an incompatible COM apartment",
            )));
        }
        Err(Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "Windows COM initialization failed",
            )
            .with_technical_detail(format!("HRESULT=0x{:08x}", result.0 as u32)),
        ))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn shortcut_extension_matching_is_case_insensitive() {
        assert!(is_shortcut_path("Programs/Tool.LNK"));
        assert!(!is_shortcut_path("Programs/Tool.exe"));
    }

    #[test]
    fn absolute_target_is_tokenized_only_below_known_root() {
        let root = std::env::temp_dir().join("reforge-shell-link-root");
        let mut entries = BTreeMap::new();
        entries.insert(KnownFolderToken::Desktop, root.clone());
        let map = KnownFolderMap::from_entries(entries);

        assert_eq!(
            token_for_absolute_path(&map, &root.join("nested/tool.exe")),
            PathToken::new(KnownFolderToken::Desktop, "nested/tool.exe").ok()
        );
        assert!(token_for_absolute_path(&map, &root.join(r"..\other.exe")).is_none());
    }

    #[test]
    fn missing_target_is_explicitly_reported_by_metadata_shape() {
        let observation = ShellLinkObservation {
            source: PathToken::new(KnownFolderToken::Desktop, "missing.lnk").unwrap(),
            target: None,
            target_name: Some("missing.exe".to_owned()),
            target_exists: false,
            description: None,
        };
        assert!(!observation.target_exists);
        assert_eq!(observation.target_name.as_deref(), Some("missing.exe"));
    }
    #[test]
    fn default_association_rejects_legacy_command_text() {
        assert_eq!(
            safe_default_association_id("MSEdgeHTM"),
            Some("MSEdgeHTM".to_owned())
        );
        assert_eq!(
            safe_default_association_id("AppX1234567890_abc"),
            Some("AppX1234567890_abc".to_owned())
        );
        assert!(safe_default_association_id(r#"C:\Program Files\Browser\browser.exe"#).is_none());
        assert!(safe_default_association_id("browser.exe --open").is_none());
    }
}
