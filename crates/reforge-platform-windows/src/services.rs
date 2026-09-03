//! Read-only Windows Service Control Manager observations.
//!
//! Service configuration is metadata only. Binary command lines are reduced to
//! an executable basename and never become executable restore instructions.

use std::{mem, path::Path, slice};

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode, redact_text};
use windows::{
    Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
        SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_BOOT_START,
        SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
        SERVICE_STATE_ALL, SERVICE_SYSTEM_START, SERVICE_WIN32,
    },
    core::{Error as WindowsError, PCWSTR, PWSTR},
};

const MAX_SERVICES: usize = 100_000;
const MAX_ENUM_BUFFER_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONFIG_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_SERVICE_TEXT_CHARS: usize = 32 * 1024;
const MAX_BINARY_NAME_CHARS: usize = 512;

/// Current state reported by the Service Control Manager.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown(u32),
}

/// Start mode reported by service configuration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceStartMode {
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,
    Unknown(u32),
}

/// Safe metadata for one registered Windows service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceObservation {
    pub name: String,
    pub display_name: Option<String>,
    pub state: ServiceState,
    pub start_mode: Option<ServiceStartMode>,
    pub service_type: u32,
    pub process_id: Option<u32>,
    pub binary_name: Option<String>,
}

/// SCM operation associated with an access failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceOperation {
    OpenManager,
    Enumerate,
    OpenService,
    QueryConfig,
}

/// A non-fatal SCM access failure retaining only bounded service metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAccessError {
    pub service_name: Option<String>,
    pub operation: ServiceOperation,
    pub win32_code: u32,
    pub error: ErrorEnvelope,
}

/// Complete bounded service enumeration result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceSnapshot {
    pub observations: Vec<ServiceObservation>,
    pub errors: Vec<ServiceAccessError>,
}

/// Enumerate Win32 services and read their configuration without starting,
/// stopping, creating, deleting, or changing any service.
pub fn enumerate_services() -> ServiceSnapshot {
    let mut snapshot = ServiceSnapshot::default();
    let manager = match unsafe {
        OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    } {
        Ok(manager) => OwnedServiceHandle(manager),
        Err(error) => {
            snapshot.errors.push(ServiceAccessError {
                service_name: None,
                operation: ServiceOperation::OpenManager,
                win32_code: win32_code(&error),
                error: win32_error("open Service Control Manager", &error),
            });
            return snapshot;
        }
    };

    let records = match enumerate_service_records(manager.0) {
        Ok(records) => records,
        Err(error) => {
            snapshot.errors.push(ServiceAccessError {
                service_name: None,
                operation: ServiceOperation::Enumerate,
                win32_code: error.0,
                error: *error.1,
            });
            return snapshot;
        }
    };

    for record in records {
        if snapshot.observations.len() >= MAX_SERVICES {
            snapshot.errors.push(ServiceAccessError {
                service_name: None,
                operation: ServiceOperation::Enumerate,
                win32_code: 0,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "The service enumeration exceeded its reviewed bound",
                ),
            });
            break;
        }

        let mut observation = ServiceObservation {
            name: record.name.clone(),
            display_name: safe_service_text(&record.display_name),
            state: service_state(record.state),
            start_mode: None,
            service_type: record.service_type,
            process_id: (record.process_id != 0).then_some(record.process_id),
            binary_name: None,
        };

        let name_wide: Vec<u16> = record
            .name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let service = match unsafe {
            OpenServiceW(
                manager.0,
                PCWSTR(name_wide.as_ptr()),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
            )
        } {
            Ok(service) => OwnedServiceHandle(service),
            Err(error) => {
                snapshot.errors.push(ServiceAccessError {
                    service_name: Some(record.name),
                    operation: ServiceOperation::OpenService,
                    win32_code: win32_code(&error),
                    error: win32_error("open Windows service", &error),
                });
                snapshot.observations.push(observation);
                continue;
            }
        };

        match query_service_config(service.0) {
            Ok(config) => {
                observation.start_mode = Some(service_start_mode(config.start_type));
                observation.binary_name = config
                    .binary_path
                    .as_deref()
                    .and_then(binary_name)
                    .map(str::to_owned);
            }
            Err((code, error)) => snapshot.errors.push(ServiceAccessError {
                service_name: Some(record.name),
                operation: ServiceOperation::QueryConfig,
                win32_code: code,
                error: *error,
            }),
        }
        snapshot.observations.push(observation);
    }

    snapshot
        .observations
        .sort_by(|left, right| left.name.cmp(&right.name));
    snapshot.errors.sort_by(|left, right| {
        (&left.service_name, left.operation, left.win32_code).cmp(&(
            &right.service_name,
            right.operation,
            right.win32_code,
        ))
    });
    snapshot
}

#[derive(Clone, Debug)]
struct RawService {
    name: String,
    display_name: String,
    service_type: u32,
    state: u32,
    process_id: u32,
}

#[derive(Clone, Debug)]
struct ServiceConfig {
    start_type: u32,
    binary_path: Option<String>,
}

fn enumerate_service_records(
    manager: SC_HANDLE,
) -> Result<Vec<RawService>, (u32, Box<ErrorEnvelope>)> {
    let mut resume = 0u32;
    let mut records = Vec::new();

    loop {
        let mut bytes_needed = 0u32;
        let mut returned = 0u32;
        let initial = unsafe {
            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };
        if initial.is_ok() && returned == 0 {
            break;
        }
        if bytes_needed == 0 {
            let error = initial
                .err()
                .map(|error| {
                    let code = win32_code(&error);
                    (
                        code,
                        Box::new(win32_error("enumerate Windows services", &error)),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        0,
                        Box::new(ErrorEnvelope::new(
                            ReforgeErrorCode::OperationFailed,
                            "Windows returned no service records",
                        )),
                    )
                });
            return Err(error);
        }

        let mut capacity = bounded_capacity(bytes_needed as usize, MAX_ENUM_BUFFER_BYTES)?;
        let mut buffer = service_buffer(capacity)?;
        let (page, more) = loop {
            bytes_needed = 0;
            returned = 0;
            let result = unsafe {
                EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(as_bytes(&mut buffer)),
                    &mut bytes_needed,
                    &mut returned,
                    Some(&mut resume),
                    PCWSTR::null(),
                )
            };
            if result.is_ok() || win32_code_from_result(&result) == Some(234) {
                if returned as usize > buffer.len() {
                    return Err((
                        0,
                        Box::new(ErrorEnvelope::new(
                            ReforgeErrorCode::SecurityPolicy,
                            "Windows returned an invalid service record count",
                        )),
                    ));
                }
                let page = buffer[..returned as usize]
                    .iter()
                    .map(|record| -> Result<RawService, (u32, Box<ErrorEnvelope>)> {
                        Ok(RawService {
                            name: unsafe { bounded_pwstr(record.lpServiceName) }.ok_or_else(
                                || {
                                    (
                                        0,
                                        Box::new(ErrorEnvelope::new(
                                            ReforgeErrorCode::OperationFailed,
                                            "Windows returned invalid service name metadata",
                                        )),
                                    )
                                },
                            )?,
                            display_name: unsafe { bounded_pwstr(record.lpDisplayName) }
                                .unwrap_or_default(),
                            service_type: record.ServiceStatusProcess.dwServiceType.0,
                            state: record.ServiceStatusProcess.dwCurrentState.0,
                            process_id: record.ServiceStatusProcess.dwProcessId,
                        })
                    })
                    .collect::<Result<Vec<_>, (u32, Box<ErrorEnvelope>)>>()?;
                break (page, win32_code_from_result(&result) == Some(234));
            }
            let error = result.expect_err("failed service enumeration result");
            if bytes_needed as usize > capacity {
                capacity = bounded_capacity(bytes_needed as usize, MAX_ENUM_BUFFER_BYTES)?;
                buffer = service_buffer(capacity)?;
                continue;
            }
            return Err((
                win32_code(&error),
                Box::new(win32_error("enumerate Windows services", &error)),
            ));
        };

        records.extend(page);
        if records.len() > MAX_SERVICES {
            return Err((
                0,
                Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "The service enumeration exceeded its reviewed bound",
                )),
            ));
        }
        if !more {
            break;
        }
    }

    Ok(records)
}

fn query_service_config(service: SC_HANDLE) -> Result<ServiceConfig, (u32, Box<ErrorEnvelope>)> {
    let mut bytes_needed = 0u32;
    let initial = unsafe { QueryServiceConfigW(service, None, 0, &mut bytes_needed) };
    if bytes_needed == 0 {
        let error = initial.err().map(|error| {
            let code = win32_code(&error);
            (
                code,
                Box::new(win32_error("query Windows service configuration", &error)),
            )
        });
        return Err(error.unwrap_or_else(|| {
            (
                0,
                Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::OperationFailed,
                    "Windows returned no service configuration",
                )),
            )
        }));
    }

    let bytes = bounded_capacity(bytes_needed as usize, MAX_CONFIG_BUFFER_BYTES)?;
    let units = bytes.div_ceil(mem::size_of::<u64>());
    let mut storage = vec![0u64; units];
    let mut required = 0u32;
    let config = unsafe {
        QueryServiceConfigW(
            service,
            Some(storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            u32::try_from(storage.len() * mem::size_of::<u64>()).unwrap_or(u32::MAX),
            &mut required,
        )
    };
    if let Err(error) = config {
        return Err((
            win32_code(&error),
            Box::new(win32_error("query Windows service configuration", &error)),
        ));
    }

    let raw = unsafe { storage.as_ptr().cast::<QUERY_SERVICE_CONFIGW>().read() };
    Ok(ServiceConfig {
        start_type: raw.dwStartType.0,
        binary_path: unsafe { bounded_pwstr(raw.lpBinaryPathName) },
    })
}

fn service_buffer(
    bytes: usize,
) -> Result<Vec<ENUM_SERVICE_STATUS_PROCESSW>, (u32, Box<ErrorEnvelope>)> {
    let count = bytes
        .div_ceil(mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>())
        .max(1);
    if count > MAX_SERVICES.saturating_mul(2) {
        return Err((
            0,
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "The service buffer has too many records",
            )),
        ));
    }
    Ok(vec![ENUM_SERVICE_STATUS_PROCESSW::default(); count])
}

fn as_bytes(buffer: &mut [ENUM_SERVICE_STATUS_PROCESSW]) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), mem::size_of_val(buffer)) }
}
fn bounded_capacity(requested: usize, maximum: usize) -> Result<usize, (u32, Box<ErrorEnvelope>)> {
    if requested == 0 || requested > maximum {
        return Err((
            0,
            Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "Windows registration buffer exceeds the reviewed bound",
            )),
        ));
    }
    Ok(requested)
}

unsafe fn bounded_pwstr(pointer: PWSTR) -> Option<String> {
    unsafe {
        if pointer.is_null() {
            return None;
        }
        let mut length = 0usize;
        while length < MAX_SERVICE_TEXT_CHARS && *pointer.0.add(length) != 0 {
            length += 1;
        }
        if length == MAX_SERVICE_TEXT_CHARS {
            return None;
        }
        String::from_utf16(slice::from_raw_parts(pointer.0, length)).ok()
    }
}

fn safe_service_text(value: &str) -> Option<String> {
    redact_text(value.trim()).filter(|value| !value.is_empty())
}
fn binary_name(command: &str) -> Option<&str> {
    let command = command.trim();
    let executable = if let Some(rest) = command.strip_prefix("\\\"") {
        rest.split("\\\"").next().unwrap_or_default()
    } else if let Some(rest) = command.strip_prefix('"') {
        rest.split('"').next().unwrap_or_default()
    } else {
        command.split_whitespace().next().unwrap_or_default()
    };
    let name = Path::new(executable).file_name()?.to_str()?;
    if name.is_empty()
        || name.chars().count() > MAX_BINARY_NAME_CHARS
        || name.chars().any(|character| character.is_control())
    {
        return None;
    }
    Some(name)
}

fn service_state(value: u32) -> ServiceState {
    match value {
        1 => ServiceState::Stopped,
        2 => ServiceState::StartPending,
        3 => ServiceState::StopPending,
        4 => ServiceState::Running,
        5 => ServiceState::ContinuePending,
        6 => ServiceState::PausePending,
        7 => ServiceState::Paused,
        other => ServiceState::Unknown(other),
    }
}

fn service_start_mode(value: u32) -> ServiceStartMode {
    match value {
        value if value == SERVICE_BOOT_START.0 => ServiceStartMode::Boot,
        value if value == SERVICE_SYSTEM_START.0 => ServiceStartMode::System,
        value if value == SERVICE_AUTO_START.0 => ServiceStartMode::Automatic,
        value if value == SERVICE_DEMAND_START.0 => ServiceStartMode::Manual,
        value if value == SERVICE_DISABLED.0 => ServiceStartMode::Disabled,
        other => ServiceStartMode::Unknown(other),
    }
}

fn win32_code(error: &WindowsError) -> u32 {
    error.code().0 as u32 & 0xffff
}

fn win32_code_from_result(result: &windows::core::Result<()>) -> Option<u32> {
    result.as_ref().err().map(win32_code)
}

fn win32_error(operation: &str, error: &WindowsError) -> ErrorEnvelope {
    let code = win32_code(error);
    let kind = if code == 5 {
        ReforgeErrorCode::AccessDenied
    } else {
        ReforgeErrorCode::OperationFailed
    };
    ErrorEnvelope::new(kind, format!("{operation} failed"))
        .with_technical_detail(format!("WIN32_ERROR={code}"))
}

struct OwnedServiceHandle(SC_HANDLE);

impl Drop for OwnedServiceHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_is_reduced_to_executable_basename() {
        assert_eq!(
            binary_name(r#"\"C:\\Program Files\\Tool\\tool.exe\" --service"#),
            Some("tool.exe")
        );
        assert_eq!(binary_name("tool.exe -k"), Some("tool.exe"));
        assert_eq!(
            binary_name("--not-an-executable"),
            Some("--not-an-executable")
        );
    }

    #[test]
    fn unknown_service_states_remain_unknown() {
        assert_eq!(service_state(99), ServiceState::Unknown(99));
        assert_eq!(service_start_mode(99), ServiceStartMode::Unknown(99));
    }
}
