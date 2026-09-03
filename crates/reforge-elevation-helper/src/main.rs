use reforge_elevation_helper as protocol;

use std::{
    ffi::c_void,
    io, mem,
    path::{Path, PathBuf},
    time::Duration,
};

use protocol::{
    ElevationRequest, ElevationResponse, JOURNAL_DIRECTORY, JOURNAL_FILE_NAME, MAX_FRAME_BYTES,
    RejectionReason, decode_request, encode_response, pipe_name,
};
use reforge_domain::{OperationId, RunId};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        System::{
            Com::CoTaskMemFree,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath},
    },
    core::PCWSTR,
};
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
const IO_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupArgs {
    run_id: RunId,
    nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalRecord {
    approval_state: String,
    operation_run_id: String,
    operation_state: String,
    requires_elevation: bool,
}

fn main() {
    let result = parse_startup_args(std::env::args_os().skip(1))
        .and_then(|startup| run_helper(startup).map_err(|error| error.to_string()));
    if result.is_err() {
        std::process::exit(1);
    }
}

fn run_helper(startup: StartupArgs) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_helper_async(startup))
}

async fn run_helper_async(startup: StartupArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_name = pipe_name(&startup.run_id, &startup.nonce)?;
    let mut security = PipeSecurity::current_user_and_system()?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1);
    let mut pipe = unsafe {
        options.create_with_security_attributes_raw(
            &pipe_name,
            (&mut security.attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )?
    };

    tokio::time::timeout(CONNECT_TIMEOUT, pipe.connect()).await??;
    let request = match tokio::time::timeout(IO_TIMEOUT, read_request(&mut pipe)).await {
        Ok(Ok(request)) => request,
        _ => {
            write_response(
                &mut pipe,
                &ElevationResponse::Rejected {
                    reason: RejectionReason::InvalidRequest,
                },
            )
            .await?;
            return Ok(());
        }
    };

    let response = match default_journal_path() {
        Ok(path) => authorize_request(&startup, &request, &path),
        Err(_) => rejected(RejectionReason::JournalUnavailable),
    };
    write_response(&mut pipe, &response).await?;
    Ok(())
}

fn parse_startup_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<StartupArgs, String> {
    let mut args = args.into_iter();
    let run_id = RunId::try_from(
        args.next()
            .ok_or_else(|| "missing run ID".to_owned())?
            .into_string()
            .map_err(|_| "run ID is not valid Unicode".to_owned())?,
    )
    .map_err(|_| "run ID is invalid".to_owned())?;
    let nonce = args
        .next()
        .ok_or_else(|| "missing nonce".to_owned())?
        .into_string()
        .map_err(|_| "nonce is not valid Unicode".to_owned())?;
    if args.next().is_some() {
        return Err("unexpected elevation helper argument".to_owned());
    }
    if !protocol::is_valid_nonce(&nonce) {
        return Err("nonce is invalid".to_owned());
    }
    Ok(StartupArgs { run_id, nonce })
}

async fn read_request(pipe: &mut NamedPipeServer) -> Result<ElevationRequest, io::Error> {
    let mut length = [0u8; 4];
    pipe.read_exact(&mut length).await?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid elevation request length",
        ));
    }
    let mut bytes = vec![0u8; length];
    pipe.read_exact(&mut bytes).await?;
    decode_request(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

async fn write_response(
    pipe: &mut NamedPipeServer,
    response: &ElevationResponse,
) -> Result<(), io::Error> {
    let bytes = encode_response(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let length = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "elevation response is too large",
        )
    })?;
    tokio::time::timeout(IO_TIMEOUT, async {
        pipe.write_all(&length.to_le_bytes()).await?;
        pipe.write_all(&bytes).await?;
        pipe.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "elevation response timed out"))??;
    Ok(())
}

fn authorize_request(
    startup: &StartupArgs,
    request: &ElevationRequest,
    journal_path: &Path,
) -> ElevationResponse {
    if request.run_id != startup.run_id {
        return rejected(RejectionReason::WrongRun);
    }
    if request.nonce != startup.nonce {
        return rejected(RejectionReason::WrongNonce);
    }

    match read_approval(journal_path, &request.run_id, &request.operation) {
        Ok(Some(record)) if record.operation_run_id != request.run_id.as_str() => {
            rejected(RejectionReason::WrongRun)
        }
        Ok(Some(record)) if record.approval_state != "APPROVED" => {
            rejected(RejectionReason::ApprovalMissing)
        }
        Ok(Some(record)) if !record.requires_elevation => {
            rejected(RejectionReason::OperationNotElevated)
        }
        Ok(Some(record)) if operation_is_terminal(&record.operation_state) => {
            rejected(RejectionReason::OperationAlreadyCompleted)
        }
        Ok(Some(_)) => ElevationResponse::Authorized {
            run_id: request.run_id.clone(),
            operation: request.operation.clone(),
        },
        Ok(None) => rejected(RejectionReason::OperationMissing),
        Err(_) => rejected(RejectionReason::JournalUnavailable),
    }
}

fn read_approval(
    journal_path: &Path,
    run_id: &RunId,
    operation: &OperationId,
) -> rusqlite::Result<Option<ApprovalRecord>> {
    let connection = Connection::open_with_flags(
        journal_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection
        .query_row(
            "SELECT r.approval_state, o.run_id, o.state, o.requires_elevation
             FROM runs AS r
             INNER JOIN operations AS o ON o.run_id = r.id
             WHERE r.id = ?1 AND o.id = ?2
             LIMIT 1",
            (run_id.as_str(), operation.as_str()),
            |row| {
                Ok(ApprovalRecord {
                    approval_state: row.get(0)?,
                    operation_run_id: row.get(1)?,
                    operation_state: row.get(2)?,
                    requires_elevation: row.get::<_, i64>(3)? == 1,
                })
            },
        )
        .optional()
}

fn operation_is_terminal(state: &str) -> bool {
    matches!(state, "COMPLETED" | "SKIPPED" | "CANCELLED") || state.starts_with("SKIPPED_")
}

fn rejected(reason: RejectionReason) -> ElevationResponse {
    ElevationResponse::Rejected { reason }
}

fn default_journal_path() -> windows::core::Result<PathBuf> {
    let pointer =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG(0), None)? };
    if pointer.is_null() {
        return Err(windows::core::Error::from_win32());
    }
    let converted = unsafe { pointer.to_string() };
    unsafe { CoTaskMemFree(Some(pointer.as_ptr().cast())) };
    let root = converted.map_err(|_| windows::core::Error::from_win32())?;
    Ok(PathBuf::from(root)
        .join(JOURNAL_DIRECTORY)
        .join(JOURNAL_FILE_NAME))
}
struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn current_user_and_system() -> windows::core::Result<Self> {
        let sid = current_process_sid_string()?;
        let sddl = to_wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                None,
            )?;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_invalid() {
            unsafe {
                LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }
}

fn current_process_sid_string() -> windows::core::Result<String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)? };
    let token = OwnedHandle(token);

    let mut size = 0u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut size) };
    let mut buffer = vec![0u8; size as usize];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        )?;
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut string_sid = windows::core::PWSTR::null();
    unsafe {
        windows::Win32::Security::Authorization::ConvertSidToStringSidW(
            token_user.User.Sid,
            &mut string_sid,
        )?;
    }
    let converted =
        unsafe { string_sid.to_string() }.map_err(|_| windows::core::Error::from_win32());
    unsafe {
        LocalFree(Some(HLOCAL(string_sid.as_ptr().cast())));
    }
    converted
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_id() -> RunId {
        RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("valid run ID")
    }

    fn operation_id() -> OperationId {
        OperationId::new("op_018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31_1").expect("valid operation ID")
    }

    fn startup() -> StartupArgs {
        StartupArgs {
            run_id: run_id(),
            nonce: "a".repeat(64),
        }
    }

    fn request() -> ElevationRequest {
        ElevationRequest {
            protocol_version: protocol::PROTOCOL_VERSION,
            run_id: run_id(),
            operation: operation_id(),
            nonce: "a".repeat(64),
        }
    }

    fn create_journal(path: &Path, approval: &str, operation_run: &RunId, elevated: bool) {
        let connection = Connection::open(path).expect("open journal");
        connection
            .execute_batch(
                "CREATE TABLE runs(id TEXT PRIMARY KEY, approval_state TEXT NOT NULL);
                 CREATE TABLE operations(
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    requires_elevation INTEGER NOT NULL
                 );",
            )
            .expect("create schema");
        connection
            .execute(
                "INSERT INTO runs(id, approval_state) VALUES (?1, ?2)",
                (run_id().as_str(), approval),
            )
            .expect("insert run");
        connection
            .execute(
                "INSERT INTO operations(id, run_id, state, requires_elevation)
                 VALUES (?1, ?2, 'PENDING', ?3)",
                (
                    operation_id().as_str(),
                    operation_run.as_str(),
                    i64::from(elevated),
                ),
            )
            .expect("insert operation");
    }

    #[test]
    fn startup_accepts_exactly_run_and_nonce() {
        let parsed = parse_startup_args([run_id().as_str().into(), "a".repeat(64).into()])
            .expect("valid args");
        assert_eq!(parsed, startup());
        assert!(
            parse_startup_args([
                run_id().as_str().into(),
                "a".repeat(64).into(),
                "cmd.exe".into(),
            ])
            .is_err()
        );
    }
    #[tokio::test]
    async fn named_pipe_accepts_current_user_acl() {
        let name = protocol::pipe_name(&run_id(), &"c".repeat(64)).expect("pipe name");
        let mut security = PipeSecurity::current_user_and_system().expect("pipe security");
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .max_instances(1);
        let pipe = unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut security.attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
        .expect("ACL-restricted named pipe");
        drop(pipe);
    }

    #[test]
    fn helper_rejects_wrong_nonce_before_journal_access() {
        let temp = std::env::temp_dir().join(format!("reforge-helper-{}", std::process::id()));
        let mut wrong = request();
        wrong.nonce = "b".repeat(64);
        assert_eq!(
            authorize_request(&startup(), &wrong, &temp),
            rejected(RejectionReason::WrongNonce)
        );
    }

    #[test]
    fn helper_rejects_wrong_run_before_journal_access() {
        let temp = std::env::temp_dir().join(format!("reforge-helper-{}", std::process::id()));
        let mut wrong = request();
        wrong.run_id = RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e32".to_owned())
            .expect("valid run ID");
        assert_eq!(
            authorize_request(&startup(), &wrong, &temp),
            rejected(RejectionReason::WrongRun)
        );
    }

    #[test]
    fn approved_elevated_operation_is_authorized() {
        let path = temporary_journal_path("approved");
        create_journal(&path, "APPROVED", &run_id(), true);
        assert_eq!(
            authorize_request(&startup(), &request(), &path),
            ElevationResponse::Authorized {
                run_id: run_id(),
                operation: operation_id(),
            }
        );
        std::fs::remove_file(path).expect("remove journal");
    }

    #[test]
    fn unapproved_operation_is_rejected() {
        let path = temporary_journal_path("pending");
        create_journal(&path, "PENDING", &run_id(), true);
        assert_eq!(
            authorize_request(&startup(), &request(), &path),
            rejected(RejectionReason::ApprovalMissing)
        );
        std::fs::remove_file(path).expect("remove journal");
    }

    #[test]
    fn non_elevated_operation_is_rejected() {
        let path = temporary_journal_path("unelevated");
        create_journal(&path, "APPROVED", &run_id(), false);
        assert_eq!(
            authorize_request(&startup(), &request(), &path),
            rejected(RejectionReason::OperationNotElevated)
        );
        std::fs::remove_file(path).expect("remove journal");
    }

    fn temporary_journal_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "reforge-helper-{label}-{}-{}.sqlite3",
            std::process::id(),
            protocol::MAX_FRAME_BYTES
        ))
    }
}
