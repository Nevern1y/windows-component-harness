//! Current-user, non-secret environment restore handlers.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use reforge_domain::{Operation, OperationKind, ReforgeErrorCode, SafeValueRef};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use serde_json::json;
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, LPARAM, WPARAM},
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ,
            REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
            RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
        },
        UI::WindowsAndMessaging::{
            HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
        },
    },
    core::PCWSTR,
};

use super::operation_error;
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
    restore_error,
};

const ENVIRONMENT_KEY: &str = "Environment";
const MAX_ENV_NAME_BYTES: usize = 256;
const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;
const MAX_PATH_ENTRIES: usize = 4096;

/// Narrow persistence boundary for current-user environment values.
///
/// The handler never accepts a hive, registry path, or system scope from an
/// operation.  The production implementation is fixed to HKCU\Environment;
/// tests can use the in-memory implementation below.
pub trait UserEnvironmentBackend: Send + Sync {
    fn read(&self, name: &str) -> RestoreResult<Option<String>>;
    fn write(&self, name: &str, value: &str) -> RestoreResult<()>;
    fn broadcast(&self) -> RestoreResult<()>;
}

/// Current-user environment registry backend.  It writes values only beneath
/// HKCU\Environment and broadcasts `WM_SETTINGCHANGE` after a successful write.
#[derive(Clone, Copy, Debug, Default)]
pub struct RegistryUserEnvironment;

impl UserEnvironmentBackend for RegistryUserEnvironment {
    fn read(&self, name: &str) -> RestoreResult<Option<String>> {
        let Some(key) = open_environment_key(EnvironmentKeyAccess::Read)? else {
            return Ok(None);
        };
        let value_name = wide_null(name);
        let mut value_type = REG_VALUE_TYPE(0);
        let mut byte_len = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut byte_len),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            close_key(key);
            return Ok(None);
        }
        if status.0 != 0 {
            close_key(key);
            return Err(registry_error(
                ReforgeErrorCode::OperationFailed,
                "read current-user environment value",
                status.0,
            ));
        }
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            close_key(key);
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "current-user environment value is not a string",
            ));
        }
        if byte_len as usize > MAX_ENV_VALUE_BYTES {
            close_key(key);
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "current-user environment value exceeds the reviewed limit",
            ));
        }
        let mut bytes = vec![0u8; byte_len as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(bytes.as_mut_ptr()),
                Some(&mut byte_len),
            )
        };
        close_key(key);
        if status.0 != 0 {
            return Err(registry_error(
                ReforgeErrorCode::OperationFailed,
                "read current-user environment value",
                status.0,
            ));
        }
        decode_registry_string(&bytes[..byte_len as usize])
    }

    fn write(&self, name: &str, value: &str) -> RestoreResult<()> {
        validate_environment_name(name)?;
        validate_environment_value(value)?;
        let key = open_environment_key(EnvironmentKeyAccess::Write)?.ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::OperationFailed,
                "current-user environment key could not be created",
            )
        })?;
        let value_name = wide_null(name);
        let value_data = wide_null(value);
        let bytes = utf16_bytes(&value_data);
        let status =
            unsafe { RegSetValueExW(key, PCWSTR(value_name.as_ptr()), None, REG_SZ, Some(&bytes)) };
        close_key(key);
        if status.0 != 0 {
            return Err(registry_error(
                ReforgeErrorCode::OperationFailed,
                "write current-user environment value",
                status.0,
            ));
        }
        Ok(())
    }

    fn broadcast(&self) -> RestoreResult<()> {
        let setting = wide_null(ENVIRONMENT_KEY);
        let mut result = 0usize;
        let sent = unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(setting.as_ptr() as isize),
                SMTO_ABORTIFHUNG,
                5_000,
                Some(&mut result),
            )
        };
        if sent.0 == 0 {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "Windows rejected the user-environment change broadcast",
            ));
        }
        Ok(())
    }
}

/// Deterministic backend for handler tests and offline callers.
#[derive(Clone, Debug, Default)]
pub struct MemoryUserEnvironment {
    values: Arc<Mutex<BTreeMap<String, String>>>,
    broadcasts: Arc<AtomicUsize>,
}

impl MemoryUserEnvironment {
    pub fn with_values(values: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            values: Arc::new(Mutex::new(values.into_iter().collect())),
            broadcasts: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn value(&self, name: &str) -> Option<String> {
        self.values
            .lock()
            .expect("environment fixture lock")
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    pub fn broadcast_count(&self) -> usize {
        self.broadcasts.load(Ordering::Acquire)
    }
}

impl UserEnvironmentBackend for MemoryUserEnvironment {
    fn read(&self, name: &str) -> RestoreResult<Option<String>> {
        Ok(self.value(name))
    }
    fn write(&self, name: &str, value: &str) -> RestoreResult<()> {
        let mut values = self.values.lock().expect("environment fixture lock");
        if let Some((_key, existing)) = values
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            *existing = value.to_owned();
        } else {
            values.insert(name.to_owned(), value.to_owned());
        }
        Ok(())
    }

    fn broadcast(&self) -> RestoreResult<()> {
        self.broadcasts.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// Handler for `SetUserEnvironment` and `AppendUserPath`.
#[derive(Clone)]
pub struct EnvironmentRestoreHandler {
    roots: KnownFolderMap,
    backend: Arc<dyn UserEnvironmentBackend>,
}

impl std::fmt::Debug for EnvironmentRestoreHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentRestoreHandler")
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

impl EnvironmentRestoreHandler {
    pub fn new(roots: KnownFolderMap) -> Self {
        Self {
            roots,
            backend: Arc::new(RegistryUserEnvironment),
        }
    }

    pub fn with_backend<B>(mut self, backend: Arc<B>) -> Self
    where
        B: UserEnvironmentBackend + 'static,
    {
        self.backend = backend;
        self
    }

    pub fn roots(&self) -> &KnownFolderMap {
        &self.roots
    }

    fn desired(&self, operation: &Operation) -> RestoreResult<DesiredEnvironment> {
        match &operation.kind {
            OperationKind::SetUserEnvironment { name, value } => {
                validate_environment_name(name)?;
                match value {
                    SafeValueRef::LiteralNonSecret(value) => {
                        validate_environment_value(value)?;
                        if looks_secret(name, value) {
                            return Ok(DesiredEnvironment::Manual {
                                reason: "environment value appears secret-bearing",
                            });
                        }
                        Ok(DesiredEnvironment::Value {
                            name: name.clone(),
                            value: value.clone(),
                        })
                    }
                    SafeValueRef::EnvironmentReference { name: source_name } => {
                        validate_environment_name(source_name)?;
                        if looks_secret_name(name) || looks_secret_name(source_name) {
                            return Ok(DesiredEnvironment::Manual {
                                reason: "environment reference may contain a secret",
                            });
                        }
                        let Some(value) = self.backend.read(source_name)? else {
                            return Ok(DesiredEnvironment::Manual {
                                reason: "environment reference is unavailable",
                            });
                        };
                        validate_environment_value(&value)?;
                        if looks_secret(name, &value) {
                            return Ok(DesiredEnvironment::Manual {
                                reason: "environment reference resolved to a secret-like value",
                            });
                        }
                        Ok(DesiredEnvironment::Value {
                            name: name.clone(),
                            value,
                        })
                    }
                    SafeValueRef::SecretReference { .. } | SafeValueRef::RedactedUnknown => {
                        Ok(DesiredEnvironment::Manual {
                            reason: "secret environment values require explicit manual entry",
                        })
                    }
                }
            }
            OperationKind::AppendUserPath { entries } => {
                if entries.len() > MAX_PATH_ENTRIES {
                    return Err(operation_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "user PATH operation contains too many entries",
                    ));
                }
                let mut resolved = Vec::with_capacity(entries.len());
                for token in entries {
                    token.validate().map_err(|_| {
                        operation_error(
                            ReforgeErrorCode::InvalidPath,
                            "user PATH entry contains an invalid tokenized path",
                        )
                    })?;
                    let path = self.roots.resolve(token)?;
                    let path = path.to_string_lossy().into_owned();
                    validate_path_entry(&path)?;
                    resolved.push(path);
                }
                let current = self.backend.read("Path")?.unwrap_or_default();
                Ok(DesiredEnvironment::Path(append_unique_path(
                    &current, resolved,
                )?))
            }
            _ => Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "environment handler received an unsupported operation kind",
            )),
        }
    }

    fn apply(&self, desired: DesiredEnvironment) -> RestoreResult<OperationOutcome> {
        match desired {
            DesiredEnvironment::Manual { reason } => {
                Ok(OperationOutcome::waiting_for_user(Some(json!({
                    "changed": false,
                    "reason": reason,
                }))))
            }
            DesiredEnvironment::Value { name, value } => {
                let previous = self.backend.read(&name)?;
                if previous.as_deref() == Some(value.as_str()) {
                    return Ok(OperationOutcome::skipped(Some(json!({
                        "changed": false,
                        "scope": "user",
                        "name": name,
                        "reason": "environment value already matches",
                    }))));
                }
                self.backend.write(&name, &value)?;
                self.backend.broadcast()?;
                Ok(OperationOutcome::completed(Some(json!({
                    "changed": true,
                    "scope": "user",
                    "name": name,
                    "previous_present": previous.is_some(),
                    "value_hash": reforge_domain::ObjectId::from_content(value.as_bytes()).as_str(),
                }))))
            }
            DesiredEnvironment::Path(value) => {
                let previous = self.backend.read("Path")?;
                if previous.as_deref() == Some(value.as_str()) {
                    return Ok(OperationOutcome::skipped(Some(json!({
                        "changed": false,
                        "scope": "user",
                        "name": "Path",
                        "reason": "user PATH already contains the requested entries",
                    }))));
                }
                self.backend.write("Path", &value)?;
                self.backend.broadcast()?;
                Ok(OperationOutcome::completed(Some(json!({
                    "changed": true,
                    "scope": "user",
                    "name": "Path",
                    "previous_present": previous.is_some(),
                    "value_hash": reforge_domain::ObjectId::from_content(value.as_bytes()).as_str(),
                }))))
            }
        }
    }
}

#[async_trait]
impl OperationHandler for EnvironmentRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::SetUserEnvironment { .. } | OperationKind::AppendUserPath { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        if cancellation.is_cancelled() {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        match self.desired(operation)? {
            DesiredEnvironment::Manual { .. } => Ok(OperationSatisfaction::NotSatisfied),
            DesiredEnvironment::Value { name, value } => {
                if self.backend.read(&name)?.as_deref() == Some(value.as_str()) {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "scope": "user",
                        "name": name,
                        "reason": "environment value already matches",
                    }))))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
            DesiredEnvironment::Path(value) => {
                if self.backend.read("Path")?.as_deref() == Some(value.as_str()) {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "scope": "user",
                        "name": "Path",
                        "reason": "user PATH already contains the requested entries",
                    }))))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "reason": "cancelled before environment update",
            }))));
        }
        self.apply(self.desired(operation)?)
    }
}

enum DesiredEnvironment {
    Value { name: String, value: String },
    Path(String),
    Manual { reason: &'static str },
}

fn append_unique_path(current: &str, entries: Vec<String>) -> RestoreResult<String> {
    let mut result = Vec::new();
    let mut seen = BTreeMap::<String, ()>::new();
    for value in current.split(';').chain(entries.iter().map(String::as_str)) {
        if value.is_empty() {
            continue;
        }
        validate_path_entry(value)?;
        let key = path_comparison_key(value);
        if seen.insert(key, ()).is_none() {
            result.push(value.to_owned());
        }
        if result.len() > MAX_PATH_ENTRIES {
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "user PATH contains too many entries",
            ));
        }
    }
    Ok(result.join(";"))
}

fn path_comparison_key(value: &str) -> String {
    let mut key = value.to_lowercase();
    while key.len() > 3 && matches!(key.chars().last(), Some('\\' | '/')) {
        key.pop();
    }
    key
}

fn validate_environment_name(name: &str) -> RestoreResult<()> {
    if name.is_empty()
        || name.len() > MAX_ENV_NAME_BYTES
        || name.contains('=')
        || name.chars().any(char::is_control)
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "environment variable name is invalid",
        ));
    }
    Ok(())
}

fn validate_environment_value(value: &str) -> RestoreResult<()> {
    if value.len() > MAX_ENV_VALUE_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "environment variable value is invalid",
        ));
    }
    Ok(())
}

fn validate_path_entry(value: &str) -> RestoreResult<()> {
    if value.is_empty()
        || value.contains(';')
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(operation_error(
            ReforgeErrorCode::InvalidPath,
            "user PATH entry is invalid",
        ));
    }
    Ok(())
}

fn looks_secret(name: &str, value: &str) -> bool {
    looks_secret_name(name)
        || [
            "-----begin",
            "bearer ",
            "api_key=",
            "apikey=",
            "token=",
            "password=",
        ]
        .iter()
        .any(|marker| value.to_ascii_lowercase().contains(marker))
}

fn looks_secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
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
        "credential",
    ]
    .iter()
    .any(|fragment| name.contains(fragment))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnvironmentKeyAccess {
    Read,
    Write,
}

fn open_environment_key(access: EnvironmentKeyAccess) -> RestoreResult<Option<HKEY>> {
    let mut key = HKEY::default();
    let key_name = wide_null(ENVIRONMENT_KEY);
    let status = unsafe {
        match access {
            EnvironmentKeyAccess::Read => RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_name.as_ptr()),
                None,
                KEY_READ,
                &mut key,
            ),
            EnvironmentKeyAccess::Write => RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_name.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut key,
                None,
            ),
        }
    };
    if status == ERROR_FILE_NOT_FOUND && access == EnvironmentKeyAccess::Read {
        return Ok(None);
    }
    if status.0 != 0 {
        return Err(registry_error(
            ReforgeErrorCode::OperationFailed,
            "open current-user environment key",
            status.0,
        ));
    }
    Ok(Some(key))
}

fn close_key(key: HKEY) {
    let _ = unsafe { RegCloseKey(key) };
}

fn decode_registry_string(bytes: &[u8]) -> RestoreResult<Option<String>> {
    if !bytes.len().is_multiple_of(2) {
        return Err(operation_error(
            ReforgeErrorCode::OperationFailed,
            "current-user environment string has an invalid encoding",
        ));
    }
    let mut values = bytes
        .chunks(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    while values.last() == Some(&0) {
        values.pop();
    }
    String::from_utf16(&values).map(Some).map_err(|_| {
        operation_error(
            ReforgeErrorCode::OperationFailed,
            "current-user environment string is not UTF-16",
        )
    })
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_bytes(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn registry_error(
    code: ReforgeErrorCode,
    message: &str,
    status: u32,
) -> Box<reforge_domain::ErrorEnvelope> {
    restore_error(
        code,
        message,
        Some(&format!("win32_status={status}")),
        None,
        None,
        Some("restore-environment-registry"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_deduplication_is_case_insensitive_and_ordered() {
        let merged = append_unique_path(
            r"C:\Tools;C:\Windows",
            vec![r"c:\tools\".to_owned(), r"C:\Rust".to_owned()],
        )
        .expect("path merge");
        assert_eq!(merged, r"C:\Tools;C:\Windows;C:\Rust");
    }
}
