//! Windows elevation boundaries.
//!
//! An explicit full-process restart launches only the canonical current
//! executable with no arguments. The separately packaged helper remains a
//! nonce-bound, per-operation broker and never accepts command text, package
//! paths, arbitrary arguments, or environment data.

use std::{
    ffi::{OsStr, c_void},
    io, mem,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Path, PathBuf},
    time::Duration,
};

use reforge_domain::{ErrorEnvelope, OperationId, ReforgeErrorCode, RunId};
pub use reforge_elevation_helper::{ElevationRequest, RejectionReason};
use reforge_elevation_helper::{
    ElevationResponse, MAX_FRAME_BYTES, PROTOCOL_VERSION, decode_response, encode_request,
    pipe_name,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        System::{
            Pipes::GetNamedPipeServerProcessId,
            Threading::{GetProcessId, WaitForSingleObject},
        },
        UI::{
            Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL},
        },
    },
    core::{HRESULT, PCWSTR, w},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const PIPE_RETRY_DELAY: Duration = Duration::from_millis(25);
const NONCE_BYTES: usize = 32;

/// Relaunch Reforge as Administrator after an explicit user request.
///
/// The target is always the canonical current `.exe`, the working directory is
/// its parent, and no arguments or command data are forwarded. The original
/// process remains usable when the UAC prompt is cancelled.
pub fn relaunch_current_process_elevated() -> Result<(), Box<ErrorEnvelope>> {
    let executable = std::env::current_exe()
        .map_err(|error| io_error("resolve current Reforge executable", &error))?;
    let executable = validate_relaunch_executable_path(&executable)?;
    let working_directory = executable.parent().ok_or_else(|| {
        security_error("current Reforge executable has no safe working directory")
    })?;

    launch_current_executable_runas(&executable, working_directory)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElevationOutcome {
    Authorized {
        run_id: RunId,
        operation: OperationId,
    },
    Rejected {
        reason: RejectionReason,
    },
    ManualRelaunchRequired,
}

/// Installed helper boundary. The helper location comes from application
/// installation state, never from package metadata or command input.
#[derive(Clone, Debug)]
pub struct PrivilegeBroker {
    helper_path: PathBuf,
}

impl PrivilegeBroker {
    pub fn new(helper_path: impl Into<PathBuf>) -> Self {
        Self {
            helper_path: helper_path.into(),
        }
    }

    /// Request authorization for one journaled privileged operation.
    ///
    /// A missing installed helper is a visible manual fallback. Every other
    /// malformed helper path is a security failure rather than a fallback.
    pub async fn request_elevation(
        &self,
        run_id: RunId,
        operation: OperationId,
    ) -> Result<ElevationOutcome, Box<ErrorEnvelope>> {
        let Some(helper_path) = validate_helper_path(&self.helper_path)? else {
            return Ok(ElevationOutcome::ManualRelaunchRequired);
        };
        let nonce = generate_nonce()?;
        let request = ElevationRequest {
            protocol_version: PROTOCOL_VERSION,
            run_id: run_id.clone(),
            operation: operation.clone(),
            nonce: nonce.clone(),
        };
        let pipe_name = pipe_name(&run_id, &nonce)
            .map_err(|_| security_error("elevation pipe identity is invalid"))?;

        let run_id_argument = run_id.as_str();
        let nonce_argument = nonce.clone();
        let launched = tokio::task::spawn_blocking(move || {
            launch_runas(&helper_path, &run_id_argument, &nonce_argument)
        })
        .await
        .map_err(|_| elevation_error("elevation launch task failed"))??;
        let process = OwnedProcessHandle(HANDLE(launched.handle as *mut c_void));

        let mut pipe = connect_to_helper(&pipe_name, &process, launched.process_id).await?;
        write_request(&mut pipe, &request).await?;
        let response = read_response(&mut pipe).await?;
        match response {
            ElevationResponse::Authorized {
                run_id: response_run,
                operation: response_operation,
            } if response_run == run_id && response_operation == operation => {
                Ok(ElevationOutcome::Authorized { run_id, operation })
            }
            ElevationResponse::Authorized { .. } => Err(security_error(
                "elevation helper returned a mismatched authorization identity",
            )),
            ElevationResponse::Rejected { reason } => Ok(ElevationOutcome::Rejected { reason }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LaunchedProcess {
    handle: usize,
    process_id: u32,
}

fn validate_relaunch_executable_path(path: &Path) -> Result<PathBuf, Box<ErrorEnvelope>> {
    if !path.is_absolute() {
        return Err(security_error(
            "current Reforge executable path must be absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect current Reforge executable", &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(security_error(
            "current Reforge executable must be a regular non-symlink file",
        ));
    }
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Err(security_error(
            "current Reforge executable must be a native .exe",
        ));
    }

    std::fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize current Reforge executable", &error))
}

fn launch_current_executable_runas(
    executable: &Path,
    working_directory: &Path,
) -> Result<(), Box<ErrorEnvelope>> {
    let executable = wide_os(executable.as_os_str());
    let working_directory = wide_os(working_directory.as_os_str());
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR::null(),
        lpDirectory: PCWSTR(working_directory.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    let launch = unsafe { ShellExecuteExW(&mut execute) };
    let process = OwnedProcessHandle(execute.hProcess);
    if let Err(error) = launch {
        return Err(relaunch_windows_error(&error));
    }
    if process.0.is_invalid() {
        return Err(relaunch_error(
            "Windows accepted the administrator restart without a process handle",
        ));
    }
    Ok(())
}

fn validate_helper_path(path: &Path) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
    if !path.is_absolute() {
        return Err(security_error("elevation helper path must be absolute"));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("inspect elevation helper", &error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(security_error(
            "elevation helper must be a regular non-symlink file",
        ));
    }
    std::fs::canonicalize(path)
        .map(Some)
        .map_err(|error| io_error("canonicalize elevation helper", &error))
}

fn generate_nonce() -> Result<String, Box<ErrorEnvelope>> {
    let mut bytes = [0u8; NONCE_BYTES];
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.0 < 0 {
        return Err(elevation_error("Windows secure random generation failed"));
    }
    let mut nonce = String::with_capacity(NONCE_BYTES * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        nonce.push(HEX[(byte >> 4) as usize] as char);
        nonce.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(nonce)
}

fn launch_runas(
    helper_path: &Path,
    run_id: &str,
    nonce: &str,
) -> Result<LaunchedProcess, Box<ErrorEnvelope>> {
    if run_id.contains(char::is_whitespace) || nonce.contains(char::is_whitespace) {
        return Err(security_error(
            "elevation launch identity contains whitespace",
        ));
    }
    let helper = wide_os(helper_path.as_os_str());
    let parameters = wide_os(OsStr::new(&format!("{run_id} {nonce}")));
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX),
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(helper.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut execute) }
        .map_err(|error| windows_error("start elevation helper", &error))?;
    if execute.hProcess.is_invalid() {
        return Err(elevation_error(
            "Windows did not return an elevation helper process handle",
        ));
    }
    let process_id = unsafe { GetProcessId(execute.hProcess) };
    if process_id == 0 {
        unsafe {
            let _ = CloseHandle(execute.hProcess);
        }
        return Err(elevation_error(
            "Windows did not return an elevation helper process ID",
        ));
    }
    Ok(LaunchedProcess {
        handle: execute.hProcess.0 as usize,
        process_id,
    })
}

async fn connect_to_helper(
    pipe_name: &str,
    process: &OwnedProcessHandle,
    process_id: u32,
) -> Result<NamedPipeClient, Box<ErrorEnvelope>> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(pipe) => {
                validate_server_process(&pipe, process_id)?;
                return Ok(pipe);
            }
            Err(error) if pipe_not_ready(&error) => match helper_process_state(process)? {
                HelperProcessState::Exited => {
                    return Err(elevation_error(
                        "elevation helper exited before opening its pipe",
                    ));
                }
                HelperProcessState::Running if Instant::now() < deadline => {
                    tokio::time::sleep(PIPE_RETRY_DELAY).await;
                }
                HelperProcessState::Running => {
                    return Err(elevation_error(
                        "elevation helper pipe connection timed out",
                    ));
                }
            },
            Err(error) => return Err(io_error("open elevation helper pipe", &error)),
        }
    }
}

fn validate_server_process(
    pipe: &NamedPipeClient,
    expected_process_id: u32,
) -> Result<(), Box<ErrorEnvelope>> {
    let mut actual_process_id = 0u32;
    let handle = HANDLE(pipe.as_raw_handle());
    unsafe { GetNamedPipeServerProcessId(handle, &mut actual_process_id) }
        .map_err(|error| windows_error("identify elevation pipe server", &error))?;
    if actual_process_id != expected_process_id {
        return Err(security_error(
            "elevation pipe server process does not match the runas helper",
        ));
    }
    Ok(())
}

async fn write_request(
    pipe: &mut NamedPipeClient,
    request: &ElevationRequest,
) -> Result<(), Box<ErrorEnvelope>> {
    let bytes = encode_request(request)
        .map_err(|_| security_error("elevation request failed protocol validation"))?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| security_error("elevation request exceeds frame length"))?;
    tokio::time::timeout(IO_TIMEOUT, async {
        pipe.write_all(&length.to_le_bytes()).await?;
        pipe.write_all(&bytes).await?;
        pipe.flush().await
    })
    .await
    .map_err(|_| elevation_error("elevation request timed out"))?
    .map_err(|error| io_error("write elevation request", &error))
}

async fn read_response(
    pipe: &mut NamedPipeClient,
) -> Result<ElevationResponse, Box<ErrorEnvelope>> {
    let mut length = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, pipe.read_exact(&mut length))
        .await
        .map_err(|_| elevation_error("elevation response timed out"))?
        .map_err(|error| io_error("read elevation response length", &error))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(security_error("elevation response length is invalid"));
    }
    let mut bytes = vec![0u8; length];
    tokio::time::timeout(IO_TIMEOUT, pipe.read_exact(&mut bytes))
        .await
        .map_err(|_| elevation_error("elevation response timed out"))?
        .map_err(|error| io_error("read elevation response", &error))?;
    decode_response(&bytes)
        .map_err(|_| security_error("elevation response failed protocol validation"))
}

fn pipe_not_ready(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(2 | 231))
        || matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
        )
}

enum HelperProcessState {
    Running,
    Exited,
}

fn helper_process_state(
    process: &OwnedProcessHandle,
) -> Result<HelperProcessState, Box<ErrorEnvelope>> {
    let state = unsafe { WaitForSingleObject(process.0, 0) };
    if state == WAIT_TIMEOUT {
        Ok(HelperProcessState::Running)
    } else if state == WAIT_OBJECT_0 {
        Ok(HelperProcessState::Exited)
    } else {
        Err(elevation_error(
            "Windows could not query the elevation helper state",
        ))
    }
}

struct OwnedProcessHandle(HANDLE);

impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "The elevation request was rejected by security policy",
        )
        .with_technical_detail(detail),
    )
}

fn elevation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "The elevation helper could not be completed",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(
        error,
        format!("{operation} failed"),
    ))
}

fn relaunch_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Reforge could not restart as Administrator",
        )
        .with_technical_detail(detail),
    )
}

fn relaunch_windows_error(error: &windows::core::Error) -> Box<ErrorEnvelope> {
    if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            "Restart as Administrator was cancelled; this Reforge session remains available",
        ))
    } else {
        relaunch_error(&format!(
            "ShellExecuteExW returned HRESULT 0x{:08x}",
            error.code().0 as u32
        ))
    }
}

fn windows_error(operation: &str, error: &windows::core::Error) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "A required Windows elevation operation failed",
        )
        .with_technical_detail(format!(
            "{operation}: HRESULT 0x{:08x}",
            error.code().0 as u32
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    #[test]
    fn nonce_uses_the_fixed_lowercase_wire_format() {
        let first = generate_nonce().expect("secure nonce");
        let second = generate_nonce().expect("secure nonce");
        assert!(reforge_elevation_helper::is_valid_nonce(&first));
        assert!(reforge_elevation_helper::is_valid_nonce(&second));
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn missing_helper_yields_manual_relaunch() {
        let path = std::env::temp_dir().join(format!(
            "reforge-missing-helper-{}-{}.exe",
            std::process::id(),
            crate::process::next_process_local_id()
        ));
        let outcome = PrivilegeBroker::new(path)
            .request_elevation(run_id(), operation_id())
            .await
            .expect("manual fallback");
        assert_eq!(outcome, ElevationOutcome::ManualRelaunchRequired);
    }

    #[test]
    fn only_uac_cancellation_maps_to_a_retryable_cancelled_error() {
        let cancellation =
            windows::core::Error::from_hresult(HRESULT::from_win32(ERROR_CANCELLED.0));
        let cancelled = relaunch_windows_error(&cancellation);
        assert_eq!(cancelled.code, ReforgeErrorCode::Cancelled);
        assert_eq!(
            cancelled.retryability,
            reforge_domain::Retryability::SafeRetry
        );
        assert!(cancelled.technical_detail.is_none());

        let access_denied =
            windows::core::Error::from_hresult(HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
        assert_ne!(
            relaunch_windows_error(&access_denied).code,
            ReforgeErrorCode::Cancelled
        );
    }

    fn run_id() -> RunId {
        RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("valid run ID")
    }

    fn operation_id() -> OperationId {
        OperationId::new("op_018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31_1").expect("valid operation ID")
    }
}
