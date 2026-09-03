//! WSL distribution import and verification.
//!
//! The handler owns only the typed `ImportWsl` operation.  WSL command lines
//! are constructed from validated domain fields and run through the same
//! shell-free process bridge as package providers.

use std::{ffi::OsString, fs, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use reforge_domain::{
    ComponentKind, ContentType, Operation, OperationKind, ReforgeErrorCode, TargetFacts, WslSpec,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, TrustedExecutable,
};
use serde_json::json;

use super::{ProviderProcessBridge, stage_subsystem_object, subsystem_capacity_waiting};
use crate::handlers::operation_error;
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

const PROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const IMPORT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MAX_DISTRIBUTION_NAME_BYTES: usize = 128;
const DEFAULT_INSTALL_ROOT: &str = r"C:\ProgramData\Reforge\wsl";

/// Restores an exported WSL distribution through `wsl.exe --import`.
pub struct WslRestoreHandler {
    bridge: Arc<dyn ProviderProcessBridge>,
    install_root: PathBuf,
}

impl WslRestoreHandler {
    /// Use the real shell-free Windows process runner and the managed install root.
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(reforge_platform_windows::ProcessRunner::new()),
            install_root: PathBuf::from(DEFAULT_INSTALL_ROOT),
        }
    }

    /// Use a caller-supplied process boundary for deterministic tests and
    /// offline environments.
    pub fn with_bridge<B>(bridge: Arc<B>) -> Self
    where
        B: ProviderProcessBridge + 'static,
    {
        Self {
            bridge,
            install_root: PathBuf::from(DEFAULT_INSTALL_ROOT),
        }
    }

    /// Use an already-erased process boundary.
    pub fn from_bridge(bridge: Arc<dyn ProviderProcessBridge>) -> Self {
        Self {
            bridge,
            install_root: PathBuf::from(DEFAULT_INSTALL_ROOT),
        }
    }

    /// Override the managed WSL install root.  The path is still checked for
    /// absoluteness before it reaches the process boundary.
    pub fn with_install_root(mut self, install_root: impl Into<PathBuf>) -> Self {
        self.install_root = install_root.into();
        self
    }

    async fn execute_import(
        &self,
        spec: &WslSpec,
        object: &reforge_domain::ObjectId,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        validate_wsl_spec(spec)?;
        if cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        if !self.bridge.builtin_available(BuiltinExecutable::Wsl) {
            return Ok(waiting_for_wsl("wsl.exe is unavailable on the target"));
        }
        if !provider_available(context.target, "wsl") {
            return Ok(waiting_for_wsl(
                "the target does not report WSL as available",
            ));
        }
        if let Some(outcome) = subsystem_capacity_waiting(context, object, "wsl") {
            return Ok(outcome);
        }
        let Some(version) = spec.wsl_version else {
            return Ok(waiting_for_wsl(
                "the source WSL export has no verified distribution version",
            ));
        };
        let version_arg = version.to_string();

        let status = self
            .bridge
            .run(&command(["--status"], STATUS_TIMEOUT)?, cancellation)
            .await?;
        if status.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        if !process_succeeded(&status) {
            return Ok(waiting_for_wsl(
                "WSL prerequisite status could not be confirmed; review WSL installation and reboot state",
            ));
        }

        let staged = stage_subsystem_object(context, object, ContentType::Archive)?;
        let install_location = self.install_location(spec)?;
        if fs::symlink_metadata(&install_location).is_ok() {
            return Ok(waiting_for_wsl(
                "the managed WSL install location already exists; review the target before replacing it",
            ));
        }
        fs::create_dir_all(&self.install_root)
            .map_err(|error| super::io_error("create the managed WSL install root", &error))?;

        if cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        let import = self
            .bridge
            .run(
                &command(
                    [
                        "--import",
                        spec.distribution.as_str(),
                        install_location.to_string_lossy().as_ref(),
                        staged.path.to_string_lossy().as_ref(),
                        "--version",
                        version_arg.as_str(),
                    ],
                    IMPORT_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if import.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        if !process_succeeded(&import) {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "WSL distribution import failed",
            ));
        }

        if cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        let verification = self
            .bridge
            .run(
                &command(["--list", "--verbose"], VERIFY_TIMEOUT)?,
                cancellation,
            )
            .await?;
        if verification.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_outcome(spec));
        }
        if !process_succeeded(&verification) || !wsl_listing_contains(&verification.stdout, spec) {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "WSL distribution import could not be verified",
            ));
        }

        Ok(OperationOutcome::completed(Some(json!({
            "subsystem": "wsl",
            "distribution": spec.distribution,
            "wsl_version": spec.wsl_version,
            "restored": true,
        })))
        .with_evidence([json!({
            "kind": "wsl_distribution",
            "distribution": spec.distribution,
            "wsl_version": spec.wsl_version,
            "object": object.as_str(),
            "verified": true,
        })]))
    }

    fn install_location(&self, spec: &WslSpec) -> RestoreResult<PathBuf> {
        if !self.install_root.is_absolute() {
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "the managed WSL install root must be absolute",
            ));
        }
        let suffix = blake3::hash(spec.distribution.as_bytes()).to_hex();
        Ok(self
            .install_root
            .join(format!("distribution-{}", suffix.as_str())))
    }
}

impl Default for WslRestoreHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OperationHandler for WslRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::ImportWsl { .. })
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        let OperationKind::ImportWsl { distro, .. } = &operation.kind else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        validate_wsl_spec(distro)?;
        if target_contains_distribution(context.target, distro) {
            Ok(OperationSatisfaction::satisfied(Some(json!({
                "subsystem": "wsl",
                "distribution": distro.distribution,
                "wsl_version": distro.wsl_version,
                "already_present": true,
            })))
            .with_evidence([json!({
                "kind": "wsl_distribution",
                "distribution": distro.distribution,
                "wsl_version": distro.wsl_version,
                "verified": true,
            })]))
        } else {
            Ok(OperationSatisfaction::NotSatisfied)
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        let OperationKind::ImportWsl { distro, object } = &operation.kind else {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "WSL handler received an unsupported operation kind",
            ));
        };
        if target_contains_distribution(context.target, distro) {
            return Ok(OperationOutcome::skipped(Some(json!({
                "subsystem": "wsl",
                "distribution": distro.distribution,
                "wsl_version": distro.wsl_version,
                "already_present": true,
            }))));
        }
        self.execute_import(distro, object, context, cancellation)
            .await
    }
}

fn validate_wsl_spec(spec: &WslSpec) -> RestoreResult<()> {
    // Match the bounded discovery grammar. The typed process boundary passes a
    // distribution name as one argv item, so spaces remain valid metadata.
    if spec.distribution.is_empty()
        || spec.distribution.len() > MAX_DISTRIBUTION_NAME_BYTES
        || spec.distribution.trim() != spec.distribution
        || spec.distribution.starts_with('-')
        || spec.distribution.chars().any(char::is_control)
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "WSL distribution name is outside the reviewed argument grammar",
        ));
    }
    if spec
        .wsl_version
        .is_some_and(|version| !matches!(version, 1 | 2))
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "WSL version must be 1 or 2 when specified",
        ));
    }
    Ok(())
}

fn command(
    args: impl IntoIterator<Item = impl Into<OsString>>,
    timeout: Duration,
) -> RestoreResult<CommandSpec> {
    CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::Wsl),
        args,
        timeout,
        PROCESS_OUTPUT_BYTES,
    )
}
fn process_succeeded(result: &ProcessResult) -> bool {
    !result.timed_out && !result.cancelled && result.exit_code == Some(0)
}

fn provider_available(target: &TargetFacts, provider: &str) -> bool {
    target
        .providers
        .iter()
        .any(|fact| fact.id.as_str() == provider && fact.available)
}

fn target_contains_distribution(target: &TargetFacts, spec: &WslSpec) -> bool {
    target.installed.iter().any(|fact| {
        fact.kind == ComponentKind::WslDistribution
            && fact.identity.provider_source.as_deref() == Some("distribution")
            && fact
                .identity
                .provider_package
                .as_ref()
                .is_some_and(|(provider, package)| {
                    provider.as_str() == "wsl"
                        && (package == &format!("distribution:{}", spec.distribution)
                            || package == &spec.distribution)
                })
            && spec.wsl_version.is_some_and(|expected| {
                let expected = expected.to_string();
                fact.version.as_ref().is_some_and(|version| {
                    version.raw == expected
                        || version.normalized.as_deref() == Some(expected.as_str())
                })
            })
    })
}

fn wsl_listing_contains(stdout: &str, spec: &WslSpec) -> bool {
    let expected_version = spec.wsl_version.map(|version| version.to_string());
    let text = normalize_wsl_text(stdout);
    let mut found_distribution = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty()
            || line
                .chars()
                .all(|character| character == '-' || character.is_whitespace())
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if (lower.contains("name") && lower.contains("state") && lower.contains("version"))
            || lower.contains("no installed distributions")
            || lower.starts_with("wsl version")
        {
            continue;
        }
        let line = line.strip_prefix('*').map_or(line, str::trim_start);
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 {
            return false;
        }
        let version = fields.last().and_then(|value| value.parse::<u8>().ok());
        let Some(version) = version else {
            return false;
        };
        let name = fields[..fields.len() - 2].join(" ");
        if name == spec.distribution
            && expected_version
                .as_deref()
                .is_some_and(|expected| expected == version.to_string())
        {
            found_distribution = true;
        }
    }
    found_distribution
}

fn normalize_wsl_text(text: &str) -> String {
    if !text.as_bytes().contains(&0) {
        return text.trim_start_matches('\u{feff}').to_owned();
    }
    let bytes = text.as_bytes();
    let mut code_units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        code_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&code_units)
        .trim_start_matches('\u{feff}')
        .to_owned()
}

fn waiting_for_wsl(reason: &'static str) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "subsystem": "wsl",
        "manual_action_required": true,
        "reason": reason,
    })))
}

fn cancelled_outcome(spec: &WslSpec) -> OperationOutcome {
    OperationOutcome::cancelled(Some(json!({
        "subsystem": "wsl",
        "distribution": spec.distribution,
        "cancelled": true,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_distribution_name_and_version() {
        assert!(
            validate_wsl_spec(&WslSpec {
                distribution: "Ubuntu 22.04".to_owned(),
                wsl_version: Some(2),
            })
            .is_ok()
        );
        assert!(
            validate_wsl_spec(&WslSpec {
                distribution: "--import".to_owned(),
                wsl_version: Some(2),
            })
            .is_err()
        );
        assert!(
            validate_wsl_spec(&WslSpec {
                distribution: "Ubuntu".to_owned(),
                wsl_version: Some(3),
            })
            .is_err()
        );
    }

    #[test]
    fn verifies_exact_distribution_and_version_from_listing() {
        let spec = WslSpec {
            distribution: "Ubuntu-22.04".to_owned(),
            wsl_version: Some(2),
        };
        assert!(wsl_listing_contains(
            "  NAME           STATE           VERSION\n* Ubuntu-22.04 Running         2\n",
            &spec
        ));
        assert!(!wsl_listing_contains(
            "  NAME           STATE           VERSION\n* Ubuntu-22.04 Running         1\n",
            &spec
        ));
    }
}
