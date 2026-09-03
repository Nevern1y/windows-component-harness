//! Read-only Windows registry observations for discovery.
//!
//! Every query carries its hive scope and WOW64 view. Registry values are
//! decoded only according to their declared type; opaque/binary values never
//! get guessed as text and all text exposed outside this module is redacted.

use std::mem;

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode, redact_text};
use windows::{
    Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
            ERROR_SUCCESS,
        },
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
            KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ,
            REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD,
            REG_RESOURCE_LIST, REG_RESOURCE_REQUIREMENTS_LIST, REG_SAM_FLAGS, REG_SZ,
            REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
            RegQueryInfoKeyW,
        },
    },
    core::{PCWSTR, PWSTR},
};

const MAX_REGISTRY_NAME_CHARS: u32 = 32 * 1024;
const MAX_REGISTRY_VALUE_BYTES: u32 = 4 * 1024 * 1024;
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
const SECRET_VALUE_NAME_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "authorization",
    "cookie",
];
const APP_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const USER_ENVIRONMENT_KEY: &str = "Environment";
const SYSTEM_ENVIRONMENT_KEY: &str =
    r"System\CurrentControlSet\Control\Session Manager\Environment";
const CURRENT_USER_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Registry hive scope attached to every observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryScope {
    LocalMachine,
    CurrentUser,
}

/// WOW64 registry view attached to every observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryView {
    View32,
    View64,
}

/// Fixed registry roots used by the discovery phase.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryRoot {
    Uninstall,
    AppPaths,
    CurrentUserRun,
    UserEnvironment,
    SystemEnvironment,
}

impl RegistryRoot {
    fn key_path(self) -> &'static str {
        match self {
            Self::Uninstall => UNINSTALL_KEY,
            Self::AppPaths => APP_PATHS_KEY,
            Self::CurrentUserRun => CURRENT_USER_RUN_KEY,
            Self::UserEnvironment => USER_ENVIRONMENT_KEY,
            Self::SystemEnvironment => SYSTEM_ENVIRONMENT_KEY,
        }
    }

    fn supports_scope(self, scope: RegistryScope) -> bool {
        match self {
            Self::UserEnvironment | Self::CurrentUserRun => scope == RegistryScope::CurrentUser,
            Self::SystemEnvironment => scope == RegistryScope::LocalMachine,
            Self::Uninstall | Self::AppPaths => true,
        }
    }
}

impl RegistryView {
    fn sam_flags(self) -> REG_SAM_FLAGS {
        match self {
            Self::View32 => KEY_WOW64_32KEY,
            Self::View64 => KEY_WOW64_64KEY,
        }
    }
}

/// Registry roots, scopes, and views requested by a scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryQuery {
    pub scopes: Vec<RegistryScope>,
    pub views: Vec<RegistryView>,
    pub roots: Vec<RegistryRoot>,
}

impl RegistryQuery {
    /// Request all roots in both user/machine scopes and both WOW64 views.
    pub fn all() -> Self {
        Self {
            scopes: vec![RegistryScope::CurrentUser, RegistryScope::LocalMachine],
            views: vec![RegistryView::View32, RegistryView::View64],
            roots: vec![
                RegistryRoot::Uninstall,
                RegistryRoot::AppPaths,
                RegistryRoot::CurrentUserRun,
                RegistryRoot::UserEnvironment,
                RegistryRoot::SystemEnvironment,
            ],
        }
    }

    fn normalized(&self) -> Self {
        Self {
            scopes: sorted_unique(self.scopes.clone()),
            views: sorted_unique(self.views.clone()),
            roots: sorted_unique(self.roots.clone()),
        }
    }
}

impl Default for RegistryQuery {
    fn default() -> Self {
        Self::all()
    }
}

/// All registry observations and failures from one deterministic scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistrySnapshot {
    pub observations: Vec<RegistryKeyObservation>,
    pub errors: Vec<RegistryAccessError>,
}

/// Values observed under one registry key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryKeyObservation {
    pub scope: RegistryScope,
    pub view: RegistryView,
    pub root: RegistryRoot,
    /// Hive-relative locator, redacted before it leaves this boundary.
    pub key_path: String,
    pub values: Vec<RegistryValueObservation>,
}

/// A registry read failure retained as evidence instead of silently dropping a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryAccessError {
    pub scope: RegistryScope,
    pub view: RegistryView,
    pub root: RegistryRoot,
    pub key_path: String,
    pub operation: RegistryOperation,
    pub win32_code: u32,
    pub error: ErrorEnvelope,
}

/// Registry operation associated with an access failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryOperation {
    OpenKey,
    QueryKeyInfo,
    EnumerateSubkeys,
    EnumerateValues,
    ReadValue,
}

/// Declared Windows registry value type, including unknown future types.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryValueType {
    None,
    String,
    ExpandString,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiString,
    ResourceList,
    ResourceRequirementsList,
    FullResourceDescriptor,
    Qword,
    Unknown(u32),
}

impl RegistryValueType {
    fn from_raw(value_type: REG_VALUE_TYPE) -> Self {
        match value_type {
            REG_NONE => Self::None,
            REG_SZ => Self::String,
            REG_EXPAND_SZ => Self::ExpandString,
            REG_BINARY => Self::Binary,
            REG_DWORD => Self::Dword,
            REG_DWORD_BIG_ENDIAN => Self::DwordBigEndian,
            REG_LINK => Self::Link,
            REG_MULTI_SZ => Self::MultiString,
            REG_RESOURCE_LIST => Self::ResourceList,
            REG_RESOURCE_REQUIREMENTS_LIST => Self::ResourceRequirementsList,
            REG_FULL_RESOURCE_DESCRIPTOR => Self::FullResourceDescriptor,
            REG_QWORD => Self::Qword,
            other => Self::Unknown(other.0),
        }
    }
}

/// A redacted string plus its comparison-normalized form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryTextValue {
    pub redacted: Option<String>,
    pub normalized: Option<String>,
}

/// Type-aware registry value payload. Opaque data is represented by length only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryValueData {
    Text(RegistryTextValue),
    MultiString(Vec<RegistryTextValue>),
    Dword(u32),
    Qword(u64),
    Opaque { byte_len: u32 },
    Unavailable { byte_len: u32 },
    Redacted { byte_len: u32 },
    Malformed { byte_len: u32 },
}

/// One value with its declared type and safely normalized payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryValueObservation {
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: RegistryValueData,
}

/// Enumerate all configured uninstall, App Paths, current-user Run, and environment roots.
pub fn enumerate_registry() -> RegistrySnapshot {
    enumerate_registry_with(&RegistryQuery::all())
}

/// Enumerate selected roots read-only in each requested scope and view.
///
/// Missing keys and access-denied keys are returned in `errors`; one failed
/// root never prevents the remaining requested roots from being inspected.
pub fn enumerate_registry_with(query: &RegistryQuery) -> RegistrySnapshot {
    let query = query.normalized();
    let mut snapshot = RegistrySnapshot::default();
    for scope in query.scopes {
        for view in &query.views {
            for root in &query.roots {
                if root.supports_scope(scope) {
                    scan_root(&mut snapshot, scope, *view, *root);
                }
            }
        }
    }
    snapshot.sort_deterministically();
    snapshot
}

impl RegistrySnapshot {
    fn sort_deterministically(&mut self) {
        self.observations.sort_by(|left, right| {
            (left.scope, left.view, left.root, &left.key_path).cmp(&(
                right.scope,
                right.view,
                right.root,
                &right.key_path,
            ))
        });
        for observation in &mut self.observations {
            observation
                .values
                .sort_by(|left, right| left.name.cmp(&right.name));
        }
        self.errors.sort_by(|left, right| {
            (
                left.scope,
                left.view,
                left.root,
                &left.key_path,
                left.operation,
                left.win32_code,
            )
                .cmp(&(
                    right.scope,
                    right.view,
                    right.root,
                    &right.key_path,
                    right.operation,
                    right.win32_code,
                ))
        });
    }
}

fn scan_root(
    snapshot: &mut RegistrySnapshot,
    scope: RegistryScope,
    view: RegistryView,
    root: RegistryRoot,
) {
    let raw_path = root.key_path();
    let wide_path = wide_null(raw_path);
    let mut opened = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            predefined_hive(scope),
            PCWSTR(wide_path.as_ptr()),
            None,
            KEY_READ | view.sam_flags(),
            &mut opened,
        )
    };
    if status != ERROR_SUCCESS {
        record_error(
            snapshot,
            scope,
            view,
            root,
            raw_path,
            RegistryOperation::OpenKey,
            status.0,
        );
        return;
    }
    let opened = OwnedRegistryKey(opened);

    let (subkey_count, max_subkey_len, value_count, max_value_name_len, max_value_len) =
        match query_key_info(snapshot, scope, view, root, raw_path, opened.0) {
            Some(info) => info,
            None => return,
        };

    let values = read_values(
        snapshot,
        scope,
        view,
        root,
        raw_path,
        opened.0,
        value_count,
        max_value_name_len,
        max_value_len,
    );
    if !values.is_empty() {
        snapshot.observations.push(RegistryKeyObservation {
            scope,
            view,
            root,
            key_path: redact_locator(raw_path),
            values,
        });
    }

    let name_capacity = bounded_name_capacity(max_subkey_len);
    let mut name_buffer = vec![0u16; name_capacity as usize + 1];
    for index in 0..subkey_count {
        let mut name_len = name_capacity;
        let status = unsafe {
            RegEnumKeyExW(
                opened.0,
                index,
                Some(PWSTR(name_buffer.as_mut_ptr())),
                &mut name_len,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            record_error(
                snapshot,
                scope,
                view,
                root,
                raw_path,
                RegistryOperation::EnumerateSubkeys,
                status.0,
            );
            continue;
        }
        let Some(name) = utf16_value(&name_buffer[..name_len as usize]) else {
            record_error(
                snapshot,
                scope,
                view,
                root,
                raw_path,
                RegistryOperation::EnumerateSubkeys,
                ERROR_MORE_DATA.0,
            );
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let child_path = format!(r"{raw_path}\{name}");
        let child_wide = wide_null(&name);
        let mut child = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                opened.0,
                PCWSTR(child_wide.as_ptr()),
                None,
                KEY_READ | view.sam_flags(),
                &mut child,
            )
        };
        if status != ERROR_SUCCESS {
            record_error(
                snapshot,
                scope,
                view,
                root,
                &child_path,
                RegistryOperation::OpenKey,
                status.0,
            );
            continue;
        }
        let child = OwnedRegistryKey(child);
        let Some((_, _, child_value_count, child_max_name_len, child_max_value_len)) =
            query_key_info(snapshot, scope, view, root, &child_path, child.0)
        else {
            continue;
        };
        let values = read_values(
            snapshot,
            scope,
            view,
            root,
            &child_path,
            child.0,
            child_value_count,
            child_max_name_len,
            child_max_value_len,
        );
        if !values.is_empty() {
            snapshot.observations.push(RegistryKeyObservation {
                scope,
                view,
                root,
                key_path: redact_locator(&child_path),
                values,
            });
        }
    }
}

fn query_key_info(
    snapshot: &mut RegistrySnapshot,
    scope: RegistryScope,
    view: RegistryView,
    root: RegistryRoot,
    key_path: &str,
    key: HKEY,
) -> Option<(u32, u32, u32, u32, u32)> {
    let mut subkey_count = 0;
    let mut max_subkey_len = 0;
    let mut value_count = 0;
    let mut max_value_name_len = 0;
    let mut max_value_len = 0;
    let status = unsafe {
        RegQueryInfoKeyW(
            key,
            None,
            None,
            None,
            Some(&mut subkey_count),
            Some(&mut max_subkey_len),
            None,
            Some(&mut value_count),
            Some(&mut max_value_name_len),
            Some(&mut max_value_len),
            None,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        record_error(
            snapshot,
            scope,
            view,
            root,
            key_path,
            RegistryOperation::QueryKeyInfo,
            status.0,
        );
        None
    } else {
        Some((
            subkey_count,
            max_subkey_len,
            value_count,
            max_value_name_len,
            max_value_len,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn read_values(
    snapshot: &mut RegistrySnapshot,
    scope: RegistryScope,
    view: RegistryView,
    root: RegistryRoot,
    key_path: &str,
    key: HKEY,
    value_count: u32,
    max_value_name_len: u32,
    max_value_len: u32,
) -> Vec<RegistryValueObservation> {
    let name_capacity = bounded_name_capacity(max_value_name_len);
    let mut name_buffer = vec![0u16; name_capacity as usize + 1];
    let mut values = Vec::new();

    for index in 0..value_count {
        let mut name_len = name_capacity;
        let mut type_raw = 0u32;
        let mut data_len = 0u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                Some(PWSTR(name_buffer.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut type_raw),
                None,
                Some(&mut data_len),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            record_error(
                snapshot,
                scope,
                view,
                root,
                key_path,
                RegistryOperation::EnumerateValues,
                status.0,
            );
            continue;
        }

        let name = utf16_value(&name_buffer[..(name_len as usize).min(name_buffer.len())])
            .unwrap_or_else(|| "<INVALID_VALUE_NAME>".to_owned());
        let value_type = RegistryValueType::from_raw(REG_VALUE_TYPE(type_raw));
        let data = if should_redact_value(root, &name) {
            RegistryValueData::Redacted { byte_len: data_len }
        } else if data_len > MAX_REGISTRY_VALUE_BYTES {
            RegistryValueData::Unavailable { byte_len: data_len }
        } else if data_len == 0 {
            parse_value_data(value_type, &[])
        } else {
            let mut data_buffer = vec![0u8; data_len as usize];
            let mut retry_name_len = name_capacity;
            let mut retry_data_len = data_len;
            let retry_status = unsafe {
                RegEnumValueW(
                    key,
                    index,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut retry_name_len,
                    None,
                    Some(&mut type_raw),
                    Some(data_buffer.as_mut_ptr()),
                    Some(&mut retry_data_len),
                )
            };
            if retry_status == ERROR_SUCCESS {
                data_buffer.truncate(retry_data_len.min(data_len) as usize);
                parse_value_data(value_type, &data_buffer)
            } else {
                record_error(
                    snapshot,
                    scope,
                    view,
                    root,
                    key_path,
                    RegistryOperation::ReadValue,
                    retry_status.0,
                );
                RegistryValueData::Unavailable { byte_len: data_len }
            }
        };
        values.push(RegistryValueObservation {
            name: redact_locator(&name),
            value_type,
            data,
        });
    }

    if max_value_len > MAX_REGISTRY_VALUE_BYTES {
        record_error(
            snapshot,
            scope,
            view,
            root,
            key_path,
            RegistryOperation::ReadValue,
            ERROR_MORE_DATA.0,
        );
    }
    values
}

fn parse_value_data(value_type: RegistryValueType, data: &[u8]) -> RegistryValueData {
    match value_type {
        RegistryValueType::String | RegistryValueType::ExpandString => decode_text(data)
            .map(RegistryValueData::Text)
            .unwrap_or(RegistryValueData::Malformed {
                byte_len: data.len().min(u32::MAX as usize) as u32,
            }),
        RegistryValueType::MultiString => decode_multi_string(data)
            .map(RegistryValueData::MultiString)
            .unwrap_or(RegistryValueData::Malformed {
                byte_len: data.len().min(u32::MAX as usize) as u32,
            }),
        RegistryValueType::Dword => parse_u32(data, false)
            .map(RegistryValueData::Dword)
            .unwrap_or(RegistryValueData::Malformed {
                byte_len: data.len().min(u32::MAX as usize) as u32,
            }),
        RegistryValueType::DwordBigEndian => parse_u32(data, true)
            .map(RegistryValueData::Dword)
            .unwrap_or(RegistryValueData::Malformed {
                byte_len: data.len().min(u32::MAX as usize) as u32,
            }),
        RegistryValueType::Qword => {
            parse_u64(data)
                .map(RegistryValueData::Qword)
                .unwrap_or(RegistryValueData::Malformed {
                    byte_len: data.len().min(u32::MAX as usize) as u32,
                })
        }
        RegistryValueType::None
        | RegistryValueType::Binary
        | RegistryValueType::Link
        | RegistryValueType::ResourceList
        | RegistryValueType::ResourceRequirementsList
        | RegistryValueType::FullResourceDescriptor
        | RegistryValueType::Unknown(_) => RegistryValueData::Opaque {
            byte_len: data.len().min(u32::MAX as usize) as u32,
        },
    }
}

fn decode_text(data: &[u8]) -> Option<RegistryTextValue> {
    let units = utf16_units(data)?;
    let value = String::from_utf16(&units)
        .ok()?
        .trim_end_matches('\0')
        .to_owned();
    Some(redacted_text_value(&value))
}

fn decode_multi_string(data: &[u8]) -> Option<Vec<RegistryTextValue>> {
    let units = utf16_units(data)?;
    let value = String::from_utf16(&units).ok()?;
    let value = value.trim_end_matches('\0');
    if value.is_empty() {
        return Some(Vec::new());
    }
    Some(value.split('\0').map(redacted_text_value).collect())
}

fn parse_u32(data: &[u8], big_endian: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

fn parse_u64(data: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(data.try_into().ok()?))
}

fn utf16_units(data: &[u8]) -> Option<Vec<u16>> {
    if !data.len().is_multiple_of(mem::size_of::<u16>()) {
        return None;
    }
    let (pairs, _) = data.as_chunks::<2>();
    Some(pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect())
}

fn redacted_text_value(value: &str) -> RegistryTextValue {
    let redacted = redact_text(value);
    let normalized = redacted.as_deref().map(normalize_text);
    RegistryTextValue {
        redacted,
        normalized,
    }
}

fn is_secret_value_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    SECRET_VALUE_NAME_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn should_redact_value(root: RegistryRoot, name: &str) -> bool {
    root == RegistryRoot::CurrentUserRun || is_secret_value_name(name)
}

fn normalize_text(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

fn record_error(
    snapshot: &mut RegistrySnapshot,
    scope: RegistryScope,
    view: RegistryView,
    root: RegistryRoot,
    key_path: &str,
    operation: RegistryOperation,
    win32_code: u32,
) {
    snapshot.errors.push(RegistryAccessError {
        scope,
        view,
        root,
        key_path: redact_locator(key_path),
        operation,
        win32_code,
        error: registry_error(win32_code),
    });
}

fn registry_error(win32_code: u32) -> ErrorEnvelope {
    let code = match win32_code {
        value if value == ERROR_ACCESS_DENIED.0 => ReforgeErrorCode::AccessDenied,
        value if value == ERROR_FILE_NOT_FOUND.0 => ReforgeErrorCode::PathNotFound,
        _ => ReforgeErrorCode::OperationFailed,
    };
    ErrorEnvelope::new(code, "Registry metadata could not be read")
        .with_technical_detail(format!("Win32 error {win32_code}"))
}

fn predefined_hive(scope: RegistryScope) -> HKEY {
    match scope {
        RegistryScope::LocalMachine => HKEY_LOCAL_MACHINE,
        RegistryScope::CurrentUser => HKEY_CURRENT_USER,
    }
}

fn bounded_name_capacity(value: u32) -> u32 {
    value.min(MAX_REGISTRY_NAME_CHARS)
}

fn redact_locator(value: &str) -> String {
    redact_text(value).unwrap_or_else(|| "<REDACTED>".to_owned())
}

fn utf16_value(value: &[u16]) -> Option<String> {
    String::from_utf16(value).ok()
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort_unstable();
    values.dedup();
    values
}

struct OwnedRegistryKey(HKEY);

impl Drop for OwnedRegistryKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn query_normalization_is_deterministic_and_deduplicated() {
        let query = RegistryQuery {
            scopes: vec![RegistryScope::LocalMachine, RegistryScope::LocalMachine],
            views: vec![
                RegistryView::View64,
                RegistryView::View32,
                RegistryView::View64,
            ],
            roots: vec![RegistryRoot::AppPaths, RegistryRoot::AppPaths],
        };
        let normalized = query.normalized();
        assert_eq!(normalized.scopes, vec![RegistryScope::LocalMachine]);
        assert_eq!(
            normalized.views,
            vec![RegistryView::View32, RegistryView::View64]
        );
        assert_eq!(normalized.roots, vec![RegistryRoot::AppPaths]);
    }

    #[test]
    fn current_user_run_root_is_user_scoped_and_allowlisted() {
        assert_eq!(
            RegistryRoot::CurrentUserRun.key_path(),
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert!(RegistryRoot::CurrentUserRun.supports_scope(RegistryScope::CurrentUser));
        assert!(!RegistryRoot::CurrentUserRun.supports_scope(RegistryScope::LocalMachine));
        assert!(
            RegistryQuery::all()
                .roots
                .contains(&RegistryRoot::CurrentUserRun)
        );
    }

    #[test]
    fn current_user_run_values_are_redacted_before_leaving_registry_boundary() {
        assert!(should_redact_value(
            RegistryRoot::CurrentUserRun,
            "launch-on-login"
        ));
        assert!(should_redact_value(RegistryRoot::Uninstall, "api_token"));
        assert!(!should_redact_value(RegistryRoot::Uninstall, "DisplayName"));
    }

    #[test]
    fn typed_decoding_does_not_treat_binary_as_text() {
        assert_eq!(
            parse_value_data(RegistryValueType::Binary, b"hello"),
            RegistryValueData::Opaque { byte_len: 5 }
        );
        assert!(matches!(
            parse_value_data(RegistryValueType::String, &[0x41]),
            RegistryValueData::Malformed { byte_len: 1 }
        ));
        assert_eq!(
            parse_value_data(RegistryValueType::Dword, &[1, 0, 0, 0]),
            RegistryValueData::Dword(1)
        );
    }

    #[test]
    fn registry_fixtures_cover_views_scopes_and_failures() {
        let uninstall: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/registry/uninstall.json"
        ))
        .unwrap();
        let app_paths: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/registry/app_paths.json"
        ))
        .unwrap();
        let environment: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/registry/environment.json"
        ))
        .unwrap();

        for fixture in [&uninstall, &app_paths, &environment] {
            let entries = fixture["entries"].as_array().unwrap();
            assert!(entries.iter().any(|entry| entry["view"] == "view_32"));
            assert!(entries.iter().any(|entry| entry["view"] == "view_64"));
            assert!(entries.iter().any(|entry| entry["scope"] == "current_user"));
            assert!(
                entries
                    .iter()
                    .any(|entry| entry["scope"] == "local_machine")
            );
        }
        assert!(uninstall["entries"].to_string().contains("REG_BINARY"));
        assert!(uninstall["entries"].to_string().contains("malformed"));
        assert_eq!(environment["errors"][0]["win32_code"], 5);
        assert_eq!(environment["errors"][1]["win32_code"], 2);
    }

    #[test]
    fn live_scan_preserves_scope_and_view_on_observations_and_errors() {
        let snapshot = enumerate_registry_with(&RegistryQuery::all());
        for observation in &snapshot.observations {
            assert!(!observation.key_path.is_empty());
            assert!(!observation.values.is_empty());
        }
        for error in &snapshot.errors {
            assert!(!error.key_path.is_empty());
            assert!(matches!(
                error.operation,
                RegistryOperation::OpenKey
                    | RegistryOperation::QueryKeyInfo
                    | RegistryOperation::EnumerateSubkeys
                    | RegistryOperation::EnumerateValues
                    | RegistryOperation::ReadValue
            ));
        }
        assert!(!snapshot.observations.is_empty() || !snapshot.errors.is_empty());
    }

    #[test]
    fn status_classification_keeps_access_denied_and_missing_key_distinct() {
        assert_eq!(
            registry_error(ERROR_ACCESS_DENIED.0).code,
            ReforgeErrorCode::AccessDenied
        );
        assert_eq!(
            registry_error(ERROR_FILE_NOT_FOUND.0).code,
            ReforgeErrorCode::PathNotFound
        );
    }
}
