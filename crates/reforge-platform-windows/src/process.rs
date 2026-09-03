//! Typed, shell-free provider process execution.
//!
//! Only built-in executable identities or executable paths registered against
//! an observed component can reach `tokio::process::Command`.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reforge_domain::{ComponentId, ErrorEnvelope, RedactionPolicy, ReforgeErrorCode};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinHandle,
    time::Instant,
};
pub use tokio_util::sync::CancellationToken;

const MAX_ARGUMENT_COUNT: usize = 4_096;
const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;

static NEXT_LOCAL_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLocalId {
    process_id: u32,
    unix_nanos: u128,
    sequence: u64,
}

impl fmt::Display for ProcessLocalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{:032x}-{:016x}",
            self.process_id, self.unix_nanos, self.sequence
        )
    }
}

pub(crate) fn next_process_local_id() -> ProcessLocalId {
    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    ProcessLocalId {
        process_id: std::process::id(),
        unix_nanos,
        sequence: NEXT_LOCAL_ID.fetch_add(1, Ordering::Relaxed),
    }
}

/// Reviewed executables that adapters may probe or invoke without a shell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuiltinExecutable {
    WinGet,
    Chocolatey,
    Scoop,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Python,
    Pipx,
    Uv,
    Cargo,
    Rustup,
    Go,
    Dotnet,
    PowerShell,
    Wsl,
    Docker,
    Code,
}

impl BuiltinExecutable {
    fn executable_name(self) -> &'static str {
        match self {
            Self::WinGet => "winget.exe",
            Self::Chocolatey => "choco.exe",
            Self::Scoop => "scoop.exe",
            Self::Npm => "npm.exe",
            Self::Pnpm => "pnpm.exe",
            Self::Yarn => "yarn.exe",
            Self::Bun => "bun.exe",
            Self::Python => "python.exe",
            Self::Pipx => "pipx.exe",
            Self::Uv => "uv.exe",
            Self::Cargo => "cargo.exe",
            Self::Rustup => "rustup.exe",
            Self::Go => "go.exe",
            Self::Dotnet => "dotnet.exe",
            Self::PowerShell => "powershell.exe",
            Self::Wsl => "wsl.exe",
            Self::Docker => "docker.exe",
            Self::Code => "code.exe",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustedExecutable {
    Builtin(BuiltinExecutable),
    Observed { component: ComponentId },
}

/// Complete, bounded command contract. There is deliberately no command-line
/// string, shell flag, working directory, or package-controlled environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub executable: TrustedExecutable,
    pub args: Vec<OsString>,
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}

impl CommandSpec {
    pub fn new(
        executable: TrustedExecutable,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        timeout: Duration,
        output_limit_bytes: usize,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let spec = Self {
            executable,
            args: args.into_iter().map(Into::into).collect(),
            timeout,
            output_limit_bytes,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), Box<ErrorEnvelope>> {
        if self.timeout.is_zero() || self.timeout > MAX_TIMEOUT {
            return Err(security_error(
                "process timeout is outside the reviewed bound",
            ));
        }
        if self.output_limit_bytes == 0 || self.output_limit_bytes > MAX_OUTPUT_LIMIT_BYTES {
            return Err(security_error(
                "process output limit is outside the reviewed bound",
            ));
        }
        if self.args.len() > MAX_ARGUMENT_COUNT {
            return Err(security_error(
                "process argument count exceeds the reviewed bound",
            ));
        }
        let mut total_bytes = 0usize;
        for argument in &self.args {
            let text = argument.to_string_lossy();
            if text.chars().any(|character| character == '\0') {
                return Err(security_error("process argument contains NUL"));
            }
            total_bytes = total_bytes
                .checked_add(text.len())
                .ok_or_else(|| security_error("process argument size overflow"))?;
            if total_bytes > MAX_ARGUMENT_BYTES {
                return Err(security_error(
                    "process arguments exceed the reviewed bound",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
}

/// Registry of executable identities observed on the current target.
#[derive(Clone, Debug, Default)]
pub struct ProcessRunner {
    observed: BTreeMap<ComponentId, PathBuf>,
}

impl ProcessRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a reviewed built-in executable resolves from the current
    /// process PATH without launching it. Empty PATH segments are ignored so
    /// discovery never treats the current working directory as a provider.
    pub fn builtin_available(&self, executable: BuiltinExecutable) -> bool {
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&path)
            .filter(|directory| !directory.as_os_str().is_empty())
            .map(|directory| directory.join(executable.executable_name()))
            .any(|candidate| {
                candidate
                    .metadata()
                    .is_ok_and(|metadata| metadata.is_file())
            })
    }

    /// Register one canonical, existing executable path for an observed target
    /// component. The path is accepted only after local regular-file and
    /// reparse checks; callers cannot pass a path to [`Self::run`].
    pub fn register_observed(
        &mut self,
        component: ComponentId,
        executable: impl AsRef<Path>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let executable = executable.as_ref();
        if !executable.is_absolute() {
            return Err(security_error("observed executable path must be absolute"));
        }
        let metadata = std::fs::symlink_metadata(executable)
            .map_err(|error| io_error("inspect observed executable", &error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(security_error(
                "observed executable must be a regular non-symlink file",
            ));
        }
        if !executable
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            return Err(security_error(
                "observed executable must be a native .exe, not a shell or batch script",
            ));
        }
        let canonical = std::fs::canonicalize(executable)
            .map_err(|error| io_error("canonicalize observed executable", &error))?;
        self.observed.insert(component, canonical);
        Ok(())
    }

    pub async fn run(
        &self,
        spec: &CommandSpec,
        cancellation: &CancellationToken,
    ) -> Result<ProcessResult, Box<ErrorEnvelope>> {
        spec.validate()?;
        let executable = self.resolve(&spec.executable)?;
        let environment = sanitized_environment()?;
        let mut command = Command::new(executable);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear()
            .envs(environment);

        let mut child = command
            .spawn()
            .map_err(|error| io_error("start trusted process", &error))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| operation_error("trusted process stdout was not captured"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| operation_error("trusted process stderr was not captured"))?;
        let total_output = Arc::new(AtomicUsize::new(0));
        let output_failure = CancellationToken::new();
        let stdout_task = tokio::spawn(read_bounded(
            stdout,
            spec.output_limit_bytes,
            Arc::clone(&total_output),
            output_failure.clone(),
        ));
        let stderr_task = tokio::spawn(read_bounded(
            stderr,
            spec.output_limit_bytes,
            total_output,
            output_failure.clone(),
        ));

        let deadline = Instant::now() + spec.timeout;
        let mut timed_out = false;
        let mut cancelled = false;
        let mut output_failed = false;
        let exit_status = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                cancelled = true;
                terminate_and_wait(&mut child).await?;
                None
            }
            _ = tokio::time::sleep_until(deadline) => {
                timed_out = true;
                terminate_and_wait(&mut child).await?;
                None
            }
            _ = output_failure.cancelled() => {
                output_failed = true;
                terminate_and_wait(&mut child).await?;
                None
            }
            status = child.wait() => {
                Some(status.map_err(|error| io_error("wait for trusted process", &error))?)
            }
        };

        let stdout = join_output(stdout_task, "stdout").await?;
        let stderr = join_output(stderr_task, "stderr").await?;
        let total_output = stdout
            .len()
            .checked_add(stderr.len())
            .ok_or_else(|| security_error("process output size overflow"))?;
        if output_failed || total_output > spec.output_limit_bytes {
            return Err(security_error("combined process output limit exceeded"));
        }

        let policy = RedactionPolicy::with_max_bytes(spec.output_limit_bytes);
        let redacted = policy.redact_provider_output(&stdout, &stderr);
        Ok(ProcessResult {
            exit_code: exit_status.and_then(|status| status.code()),
            stdout: redacted.stdout.unwrap_or_default(),
            stderr: redacted.stderr.unwrap_or_default(),
            timed_out,
            cancelled,
        })
    }

    fn resolve(&self, executable: &TrustedExecutable) -> Result<OsString, Box<ErrorEnvelope>> {
        match executable {
            TrustedExecutable::Builtin(executable) => {
                Ok(OsString::from(executable.executable_name()))
            }
            TrustedExecutable::Observed { component } => self
                .observed
                .get(component)
                .map(|path| path.as_os_str().to_owned())
                .ok_or_else(|| {
                    Box::new(ErrorEnvelope::new(
                        ReforgeErrorCode::ProviderUnavailable,
                        "The observed executable is unavailable on this target",
                    ))
                }),
        }
    }
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
    total: Arc<AtomicUsize>,
    failure: CancellationToken,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(error) => {
                failure.cancel();
                return Err(io_error("read trusted process output", &error));
            }
        };
        if read == 0 {
            return Ok(bytes);
        }
        let previous = total.fetch_add(read, Ordering::AcqRel);
        if previous > limit.saturating_sub(read) {
            failure.cancel();
            return Err(security_error("process output limit exceeded"));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

async fn join_output(
    task: JoinHandle<Result<Vec<u8>, Box<ErrorEnvelope>>>,
    stream: &str,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    task.await
        .map_err(|_| operation_error(&format!("trusted process {stream} task failed")))?
}

async fn terminate_and_wait(child: &mut Child) -> Result<(), Box<ErrorEnvelope>> {
    child
        .kill()
        .await
        .map_err(|error| io_error("terminate trusted process", &error))
}

fn sanitized_environment() -> Result<Vec<(OsString, OsString)>, Box<ErrorEnvelope>> {
    let mut safe = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0usize;
    for (name, value) in std::env::vars_os() {
        let Some(name_text) = name.to_str() else {
            continue;
        };
        let normalized = normalize_environment_name(name_text);
        if normalized.is_empty()
            || is_sensitive_environment_name(&normalized)
            || !seen.insert(normalized)
        {
            continue;
        }
        let bytes = name.to_string_lossy().len() + value.to_string_lossy().len();
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| security_error("process environment size overflow"))?;
        if safe.len() == MAX_ENVIRONMENT_ENTRIES || total_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(security_error(
                "process environment exceeds the reviewed bound",
            ));
        }
        safe.push((name, value));
    }
    Ok(safe)
}

fn normalize_environment_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_sensitive_environment_name(name: &str) -> bool {
    [
        "apikey",
        "accesstoken",
        "authtoken",
        "refreshtoken",
        "clientsecret",
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "privatekey",
        "credential",
    ]
    .iter()
    .any(|fragment| name.contains(fragment))
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "The process request was rejected by security policy",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "The trusted process could not be completed",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_local_ids_are_unique_within_the_process() {
        let first = next_process_local_id().to_string();
        let second = next_process_local_id().to_string();
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("{}-", std::process::id())));
    }

    #[test]
    fn sanitized_environment_removes_secret_named_values() {
        assert!(is_sensitive_environment_name("context7apikey"));
        assert!(is_sensitive_environment_name("githubtoken"));
        assert!(!is_sensitive_environment_name("systemroot"));
    }

    #[test]
    fn builtin_availability_ignores_empty_path_segments() {
        let empty = OsString::from(";");
        assert!(std::env::split_paths(&empty).all(|path| path.as_os_str().is_empty()));
    }

    #[test]
    fn builtin_resolution_is_a_fixed_executable_name() {
        let runner = ProcessRunner::new();
        let resolved = runner
            .resolve(&TrustedExecutable::Builtin(BuiltinExecutable::WinGet))
            .unwrap();
        assert_eq!(resolved, std::ffi::OsStr::new("winget.exe"));
    }

    #[test]
    fn every_builtin_resolves_to_a_native_executable() {
        let builtins = [
            BuiltinExecutable::WinGet,
            BuiltinExecutable::Chocolatey,
            BuiltinExecutable::Scoop,
            BuiltinExecutable::Npm,
            BuiltinExecutable::Pnpm,
            BuiltinExecutable::Yarn,
            BuiltinExecutable::Bun,
            BuiltinExecutable::Python,
            BuiltinExecutable::Pipx,
            BuiltinExecutable::Uv,
            BuiltinExecutable::Cargo,
            BuiltinExecutable::Rustup,
            BuiltinExecutable::Go,
            BuiltinExecutable::Dotnet,
            BuiltinExecutable::PowerShell,
            BuiltinExecutable::Wsl,
            BuiltinExecutable::Docker,
            BuiltinExecutable::Code,
        ];
        assert!(
            builtins
                .iter()
                .all(|executable| { executable.executable_name().ends_with(".exe") })
        );
    }

    #[tokio::test]
    async fn shell_metacharacters_remain_one_literal_argument() {
        let (runner, executable) = self_test_runner();
        let marker = "REFORGE_SHELL_INJECTION_MARKER";
        let spec = CommandSpec::new(
            executable,
            ["--list", &format!("missing&echo {marker}")],
            Duration::from_secs(10),
            64 * 1024,
        )
        .expect("valid command");
        let result = runner
            .run(&spec, &CancellationToken::new())
            .await
            .expect("run test process");
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.stdout.contains(marker));
        assert!(!result.stderr.contains(marker));
    }

    #[tokio::test]
    async fn timeout_terminates_the_child() {
        let (runner, executable) = self_test_runner();
        let spec = child_test_spec(executable, Duration::from_millis(50));
        let result = runner
            .run(&spec, &CancellationToken::new())
            .await
            .expect("timed process result");
        assert!(result.timed_out);
        assert!(!result.cancelled);
        assert_eq!(result.exit_code, None);
    }

    #[tokio::test]
    async fn cancellation_terminates_the_child() {
        let (runner, executable) = self_test_runner();
        let spec = child_test_spec(executable, Duration::from_secs(10));
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });
        let result = runner
            .run(&spec, &cancellation)
            .await
            .expect("cancelled process result");
        cancel_task.await.expect("cancellation task");
        assert!(result.cancelled);
        assert!(!result.timed_out);
        assert_eq!(result.exit_code, None);
    }

    #[tokio::test]
    async fn output_above_the_cap_is_rejected() {
        let (runner, executable) = self_test_runner();
        let spec = CommandSpec::new(
            executable,
            [
                "--ignored",
                "--exact",
                "process::tests::child_large_output",
                "--nocapture",
            ],
            Duration::from_secs(10),
            128,
        )
        .expect("valid command");
        let error = runner
            .run(&spec, &CancellationToken::new())
            .await
            .expect_err("oversized output must fail");
        assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
    }

    #[test]
    #[ignore = "spawned by timeout and cancellation tests"]
    fn child_sleeper() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "spawned by output cap test"]
    fn child_large_output() {
        println!("{}", "x".repeat(4 * 1024));
    }

    fn self_test_runner() -> (ProcessRunner, TrustedExecutable) {
        let component =
            ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("valid component ID");
        let mut runner = ProcessRunner::new();
        runner
            .register_observed(
                component.clone(),
                std::env::current_exe().expect("test executable"),
            )
            .expect("register test executable");
        (runner, TrustedExecutable::Observed { component })
    }

    fn child_test_spec(executable: TrustedExecutable, timeout: Duration) -> CommandSpec {
        CommandSpec::new(
            executable,
            [
                "--ignored",
                "--exact",
                "process::tests::child_sleeper",
                "--nocapture",
            ],
            timeout,
            64 * 1024,
        )
        .expect("valid child command")
    }
}
