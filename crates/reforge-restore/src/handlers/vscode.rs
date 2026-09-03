//! Typed VS Code extension restore.
//!
//! Only the reviewed `code` executable is invoked.  The extension identity,
//! optional exact version, and optional profile name are validated before they
//! become argv; package content never becomes a command or script.

use std::{ffi::OsString, sync::Arc, time::Duration};

use async_trait::async_trait;
use reforge_domain::{Operation, OperationKind, ReforgeErrorCode};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, TrustedExecutable,
};
use serde_json::json;

use super::{ProviderProcessBridge, operation_error};
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

const EXTENSION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXTENSION_ID_BYTES: usize = 256;
const MAX_EXTENSION_VERSION_BYTES: usize = 256;
const MAX_PROFILE_NAME_BYTES: usize = 256;

/// Handler for explicit VS Code extension identity/version operations.
pub struct VsCodeRestoreHandler {
    bridge: Arc<dyn ProviderProcessBridge>,
}

impl VsCodeRestoreHandler {
    /// Use the real shell-free Windows process runner.
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(reforge_platform_windows::ProcessRunner::new()),
        }
    }

    /// Use a caller-supplied process boundary for deterministic tests.
    pub fn with_bridge<B>(bridge: Arc<B>) -> Self
    where
        B: ProviderProcessBridge + 'static,
    {
        Self { bridge }
    }

    /// Alias accepting an already-erased process bridge.
    pub fn from_bridge(bridge: Arc<dyn ProviderProcessBridge>) -> Self {
        Self { bridge }
    }

    async fn list_extensions(
        &self,
        profile: Option<&str>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<ProcessResult> {
        let mut args = vec![
            OsString::from("--list-extensions"),
            OsString::from("--show-versions"),
        ];
        if let Some(profile) = profile {
            args.push(OsString::from("--profile"));
            args.push(OsString::from(profile));
        }
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Code),
            args,
            VERIFICATION_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        self.bridge.run(&command, cancellation).await
    }

    fn validate_request(
        id: &str,
        version: Option<&str>,
        profile: Option<&str>,
    ) -> RestoreResult<()> {
        if !valid_extension_id(id) {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "VS Code extension ID is outside the reviewed identity grammar",
            ));
        }
        if let Some(version) = version
            && !valid_version(version)
        {
            return Err(operation_error(
                ReforgeErrorCode::UnsupportedVersion,
                "VS Code extension version is outside the reviewed exact-version grammar",
            ));
        }
        if let Some(profile) = profile
            && !valid_profile_name(profile)
        {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "VS Code profile name is outside the reviewed name grammar",
            ));
        }
        Ok(())
    }

    fn installed(
        &self,
        output: &ProcessResult,
        requested_id: &str,
        requested_version: Option<&str>,
    ) -> bool {
        parse_extensions(&output.stdout).into_iter().any(|entry| {
            entry.id.eq_ignore_ascii_case(requested_id)
                && requested_version.is_none_or(|version| entry.version.as_deref() == Some(version))
        })
    }
}

impl Default for VsCodeRestoreHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OperationHandler for VsCodeRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::InstallVsCodeExtension { .. })
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        let OperationKind::InstallVsCodeExtension {
            id,
            version,
            profile,
        } = &operation.kind
        else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        Self::validate_request(id, version.as_deref(), profile.as_deref())?;
        if cancellation.is_cancelled() || !self.bridge.builtin_available(BuiltinExecutable::Code) {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let output = self
            .list_extensions(profile.as_deref(), cancellation)
            .await?;
        if output.cancelled || output.timed_out || output.exit_code != Some(0) {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        if self.installed(&output, id, version.as_deref()) {
            Ok(OperationSatisfaction::satisfied(Some(json!({
                "editor": "vscode",
                "extension": id,
                "version": version,
                "profile": profile,
                "already_installed": true,
            })))
            .with_evidence([json!({
                "extension": id,
                "version": version,
                "profile": profile,
                "verified": true,
            })]))
        } else {
            Ok(OperationSatisfaction::NotSatisfied)
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
                "cancelled": true,
            }))));
        }
        let OperationKind::InstallVsCodeExtension {
            id,
            version,
            profile,
        } = &operation.kind
        else {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "VS Code handler received an unsupported operation kind",
            ));
        };
        Self::validate_request(id, version.as_deref(), profile.as_deref())?;
        if !self.bridge.builtin_available(BuiltinExecutable::Code) {
            return Ok(OperationOutcome::waiting_for_user(Some(json!({
                "editor": "vscode",
                "extension": id,
                "version": version,
                "profile": profile,
                "manual_action_required": true,
                "reason": "the reviewed VS Code code executable is unavailable on the target",
            }))));
        }

        let current = self
            .list_extensions(profile.as_deref(), cancellation)
            .await?;
        if current.cancelled || cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "editor": "vscode",
                "extension": id,
                "cancelled": true,
            }))));
        }
        if current.timed_out {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "VS Code extension inventory timed out",
            ));
        }
        if current.exit_code == Some(0) && self.installed(&current, id, version.as_deref()) {
            return Ok(OperationOutcome::skipped(Some(json!({
                "editor": "vscode",
                "extension": id,
                "version": version,
                "profile": profile,
                "already_installed": true,
            }))));
        }
        if current.exit_code != Some(0) {
            return Err(operation_error(
                ReforgeErrorCode::ProviderUnavailable,
                "VS Code extension inventory could not be queried safely",
            ));
        }
        let Some(version) = version.as_deref() else {
            return Ok(OperationOutcome::waiting_for_user(Some(json!({
                "editor": "vscode",
                "extension": id,
                "profile": profile,
                "manual_action_required": true,
                "reason": "an exact VS Code extension version was not captured; automatic latest-version installation is forbidden",
            }))));
        };

        let requested = format!("{id}@{version}");
        let mut args = vec![
            OsString::from("--install-extension"),
            OsString::from(requested),
            OsString::from("--force"),
        ];
        if let Some(profile) = profile {
            args.push(OsString::from("--profile"));
            args.push(OsString::from(profile));
        }
        let install = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Code),
            args,
            EXTENSION_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let result = self.bridge.run(&install, cancellation).await?;
        if result.cancelled || cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "editor": "vscode",
                "extension": id,
                "cancelled": true,
            }))));
        }
        if result.timed_out || result.exit_code != Some(0) {
            return Err(operation_error(
                ReforgeErrorCode::InstallFailed,
                "VS Code extension installation returned a failure",
            ));
        }

        let verification = self
            .list_extensions(profile.as_deref(), cancellation)
            .await?;
        if verification.cancelled || cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "editor": "vscode",
                "extension": id,
                "cancelled": true,
            }))));
        }
        if verification.timed_out {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "VS Code extension verification timed out",
            ));
        }
        if verification.exit_code != Some(0) || !self.installed(&verification, id, Some(version)) {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "VS Code did not report the requested extension identity and version",
            ));
        }
        Ok(OperationOutcome::completed(Some(json!({
            "editor": "vscode",
            "extension": id,
            "version": version,
            "profile": profile,
            "installed": true,
            "verified": true,
        })))
        .with_evidence([json!({
            "editor": "vscode",
            "extension": id,
            "version": version,
            "profile": profile,
            "verified": true,
        })]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExtensionRecord {
    id: String,
    version: Option<String>,
}

fn parse_extensions(output: &str) -> Vec<ExtensionRecord> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let token = line.split_whitespace().next()?;
            let (id, version) = token
                .rsplit_once('@')
                .filter(|(id, version)| !id.is_empty() && !version.is_empty())
                .map_or((token, None), |(id, version)| {
                    (id, Some(version.to_owned()))
                });
            valid_extension_id(id).then(|| ExtensionRecord {
                id: id.to_owned(),
                version,
            })
        })
        .collect()
}

fn valid_extension_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXTENSION_ID_BYTES
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXTENSION_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_profile_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'))
        && value
            .chars()
            .next()
            .is_some_and(|character| !character.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_show_versions_output_without_accepting_command_text() {
        let entries = parse_extensions("ms-python.python@2025.1.0\nnot an extension\n");
        assert_eq!(
            entries,
            vec![ExtensionRecord {
                id: "ms-python.python".to_owned(),
                version: Some("2025.1.0".to_owned()),
            }]
        );
    }

    #[test]
    fn validates_exact_identity_and_version_grammar() {
        assert!(valid_extension_id("ms-python.python"));
        assert!(valid_version("2025.1.0-pre"));
        assert!(!valid_extension_id("ms-python.python & whoami"));
        assert!(!valid_version("latest;whoami"));
        assert!(!valid_profile_name("..\\secret"));
    }
}
