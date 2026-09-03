//! Typed package-provider restore handlers.
//!
//! Provider operations are converted to argv at this boundary.  Package data
//! never becomes a command line, shell script, executable path, or environment
//! override.  The process bridge is deliberately injectable so the handler can
//! be exercised without launching a package manager.

use std::{ffi::OsString, sync::Arc, time::Duration};

use async_trait::async_trait;
use reforge_domain::{
    Architecture, Identity, Operation, OperationKind, PackageInstallPolicy, PackageSpec,
    ProviderId, ReforgeErrorCode, TargetFacts, VersionValue,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, ProcessRunner,
    TrustedExecutable,
};
use serde_json::{Value, json};

use super::operation_error;
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
    restore_error,
};

const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKAGE_ID_BYTES: usize = 512;
const MAX_VERSION_BYTES: usize = 256;
const MAX_SOURCE_BYTES: usize = 2_048;
const MAX_HASH_BYTES: usize = 512;

/// Process capability used by [`ProviderInstallHandler`].
///
/// Implementations must preserve the platform process boundary.  In
/// production this is implemented by [`ProcessRunner`]; tests can return
/// deterministic [`ProcessResult`] values without launching a process.
#[async_trait]
pub trait ProviderProcessBridge: Send + Sync {
    fn builtin_available(&self, executable: BuiltinExecutable) -> bool;

    async fn run(
        &self,
        command: &CommandSpec,
        cancellation: &CancellationToken,
    ) -> RestoreResult<ProcessResult>;
}

#[async_trait]
impl ProviderProcessBridge for ProcessRunner {
    fn builtin_available(&self, executable: BuiltinExecutable) -> bool {
        ProcessRunner::builtin_available(self, executable)
    }

    async fn run(
        &self,
        command: &CommandSpec,
        cancellation: &CancellationToken,
    ) -> RestoreResult<ProcessResult> {
        ProcessRunner::run(self, command, cancellation).await
    }
}

/// Provider install and provider-presence handler.
pub struct ProviderInstallHandler {
    bridge: Arc<dyn ProviderProcessBridge>,
}

impl ProviderInstallHandler {
    /// Use the real shell-free Windows process runner.
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(ProcessRunner::new()),
        }
    }

    /// Use a caller-supplied process boundary, primarily for deterministic
    /// integration tests and offline execution environments.
    pub fn with_bridge<B>(bridge: Arc<B>) -> Self
    where
        B: ProviderProcessBridge + 'static,
    {
        Self { bridge }
    }

    /// Alias accepting an already-erased bridge.
    pub fn from_bridge(bridge: Arc<dyn ProviderProcessBridge>) -> Self {
        Self { bridge }
    }
}

impl Default for ProviderInstallHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Compatibility name for callers that group all restore handlers by effect.
pub type ProviderRestoreHandler = ProviderInstallHandler;

#[async_trait]
impl OperationHandler for ProviderInstallHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::EnsureProvider { .. } | OperationKind::InstallPackage { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        match &operation.kind {
            OperationKind::EnsureProvider { provider } => {
                let Some(executable) = executable_for(provider) else {
                    return Ok(OperationSatisfaction::NotSatisfied);
                };
                if self.bridge.builtin_available(executable) {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "provider": provider.as_str(),
                        "available": true,
                    })))
                    .with_evidence([provider_evidence(provider, "provider executable resolves")]))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
            OperationKind::InstallPackage {
                provider, package, ..
            } => {
                validate_package_identity(provider, package)?;
                validate_source_metadata(package)?;
                validate_hash(package)?;
                validate_provider_specific_id(provider, package)?;
                validate_architecture(package, context.target)?;

                if let Some(installed) = installed_exact(context.target, provider, package) {
                    return Ok(OperationSatisfaction::satisfied(Some(json!({
                        "provider": provider.as_str(),
                        "package_id": package.id,
                        "version": package.version,
                        "already_installed": true,
                    })))
                    .with_evidence([installed_evidence(provider, package, installed)]));
                }
                Ok(OperationSatisfaction::NotSatisfied)
            }
            _ => Ok(OperationSatisfaction::NotSatisfied),
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "cancelled": true,
            }))));
        }

        match &operation.kind {
            OperationKind::EnsureProvider { provider } => {
                self.execute_ensure_provider(provider, cancellation).await
            }
            OperationKind::InstallPackage {
                provider,
                package,
                policy,
            } => {
                self.execute_install(operation, provider, package, policy, context, cancellation)
                    .await
            }
            _ => Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "provider handler received an unsupported operation kind",
            )),
        }
    }
}

impl ProviderInstallHandler {
    async fn execute_ensure_provider(
        &self,
        provider: &ProviderId,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        let Some(executable) = executable_for(provider) else {
            return Ok(waiting_for_provider(
                provider,
                "the provider has no reviewed built-in executable",
            ));
        };
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "provider": provider.as_str(),
                "cancelled": true,
            }))));
        }
        if !self.bridge.builtin_available(executable) {
            return Ok(waiting_for_provider(
                provider,
                "the provider executable is unavailable on the target",
            ));
        }
        Ok(OperationOutcome::completed(Some(json!({
            "provider": provider.as_str(),
            "available": true,
        })))
        .with_evidence([provider_evidence(provider, "provider executable resolves")]))
    }

    async fn execute_install(
        &self,
        operation: &Operation,
        provider: &ProviderId,
        package: &PackageSpec,
        policy: &PackageInstallPolicy,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        validate_package_identity(provider, package)?;
        validate_source_metadata(package)?;
        validate_hash(package)?;
        validate_provider_specific_id(provider, package)?;
        validate_architecture(package, context.target)?;

        if let Some(installed) = installed_exact(context.target, provider, package) {
            return Ok(OperationOutcome::skipped(Some(json!({
                "provider": provider.as_str(),
                "package_id": package.id,
                "version": package.version,
                "already_installed": true,
            })))
            .with_evidence([installed_evidence(provider, package, installed)]));
        }

        let Some(executable) = executable_for(provider) else {
            return Ok(waiting_for_provider(
                provider,
                "the provider has no reviewed package-install recipe",
            ));
        };
        if !self.bridge.builtin_available(executable) {
            return Ok(waiting_for_provider(
                provider,
                "the provider executable is unavailable on the target",
            ));
        }

        let recipe = match build_recipe(provider, package, policy)? {
            RecipeDecision::Automatic(recipe) => recipe,
            RecipeDecision::Manual(reason) => {
                return Ok(waiting_for_package(provider, package, reason));
            }
        };

        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "provider": provider.as_str(),
                "package_id": package.id,
                "cancelled": true,
            }))));
        }

        let installed_result = self.bridge.run(&recipe.install, cancellation).await?;
        if installed_result.cancelled || cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "provider": provider.as_str(),
                "package_id": package.id,
                "cancelled": true,
            }))));
        }
        if installed_result.timed_out {
            return Err(install_error(
                ReforgeErrorCode::InstallFailed,
                "provider package installation timed out",
            ));
        }

        let reboot_required = matches!(installed_result.exit_code, Some(3010 | 1641));
        if installed_result.exit_code != Some(0) && !reboot_required {
            return Err(install_error(
                ReforgeErrorCode::InstallFailed,
                "provider package installation returned a failure exit code",
            ));
        }

        let verification = self.bridge.run(&recipe.verify, cancellation).await?;
        if verification.cancelled || cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "provider": provider.as_str(),
                "package_id": package.id,
                "cancelled": true,
            }))));
        }

        if verification.timed_out {
            if reboot_required {
                return Ok(waiting_for_reboot(provider, package, false));
            }
            return Err(install_error(
                ReforgeErrorCode::VerificationFailed,
                "provider package verification timed out",
            ));
        }

        let verified =
            verification.exit_code == Some(0) && output_contains_identity(&verification, package);
        if !verified && !reboot_required {
            return Err(install_error(
                ReforgeErrorCode::VerificationFailed,
                "provider did not verify the installed package identity and version",
            ));
        }
        if reboot_required {
            return Ok(waiting_for_reboot(provider, package, verified));
        }

        let evidence = [package_evidence(
            provider,
            package,
            "provider install and exact verification",
        )];
        Ok(OperationOutcome::completed(Some(json!({
            "provider": provider.as_str(),
            "package_id": package.id,
            "version": package.version,
            "installed": true,
            "verified": true,
            "exit_code": installed_result.exit_code,
            "operation_id": operation.id,
        })))
        .with_evidence(evidence))
    }
}

struct ProviderCommands {
    install: CommandSpec,
    verify: CommandSpec,
}

enum RecipeDecision {
    Automatic(ProviderCommands),
    Manual(&'static str),
}

fn build_recipe(
    provider: &ProviderId,
    package: &PackageSpec,
    policy: &PackageInstallPolicy,
) -> RestoreResult<RecipeDecision> {
    let Some(executable) = executable_for(provider) else {
        return Ok(RecipeDecision::Manual(
            "no reviewed built-in package-install recipe exists for this provider",
        ));
    };
    validate_package_identity(provider, package)?;

    let Some(version) = package.version.as_deref() else {
        return Ok(RecipeDecision::Manual(
            "an exact package version is required; latest-version fallback is disabled",
        ));
    };
    validate_exact_version(version)?;
    validate_source_metadata(package)?;
    validate_hash(package)?;
    if let Some(reason) = unsupported_policy(provider, policy) {
        return Ok(RecipeDecision::Manual(reason));
    }

    // WinGet only exposes a bypass for its own manifest hash check, not a
    // caller-supplied expected hash. A recorded hash therefore cannot justify
    // automatic execution by any current provider recipe.
    if package.installer_hash.is_some() {
        return Ok(RecipeDecision::Manual(
            "the recorded installer hash cannot be enforced by the reviewed provider install recipe",
        ));
    }

    let mut install_args = Vec::<OsString>::new();
    let mut verify_args = Vec::<OsString>::new();
    match provider.as_str() {
        "winget" => {
            let Some(source_name) = package.source_name.as_deref() else {
                return Ok(RecipeDecision::Manual(
                    "WinGet installation requires the recorded source name",
                ));
            };
            if package.source_identifier.is_none() {
                return Ok(RecipeDecision::Manual(
                    "WinGet installation requires the stable source identifier",
                ));
            }
            install_args.extend(args([
                "install",
                "--id",
                &package.id,
                "--exact",
                "--version",
                version,
                "--source",
                source_name,
            ]));
            append_winget_policy(&mut install_args, policy);
            install_args.push(OsString::from("--disable-interactivity"));
            verify_args.extend(args([
                "list",
                "--id",
                &package.id,
                "--exact",
                "--source",
                source_name,
                "--disable-interactivity",
            ]));
        }
        "chocolatey" => {
            match reviewed_chocolatey_source(package) {
                Ok(()) => {}
                Err(reason) => return Ok(RecipeDecision::Manual(reason)),
            }
            install_args.extend(args([
                "install",
                &package.id,
                "--version",
                version,
                "--no-progress",
            ]));
            if policy.accept_source_agreements || policy.accept_package_agreements {
                install_args.push(OsString::from("--accept-license"));
            }
            if policy.accept_package_agreements {
                install_args.push(OsString::from("--yes"));
            }
            if let Some(source) = package.source.as_ref() {
                install_args.extend(args(["--source", source.as_str()]));
            }
            verify_args.extend(args(["list", "--exact", &package.id, "--limit-output"]));
        }
        "scoop" => {
            match reviewed_scoop_source(package) {
                Ok(bucket) => {
                    let package_spec = format!("{bucket}/{}@{version}", package.id);
                    install_args.extend(args(["install", &package_spec]));
                }
                Err(reason) => return Ok(RecipeDecision::Manual(reason)),
            }
            verify_args.extend(args(["list"]));
        }
        "npm" | "pnpm" | "yarn" | "bun" => {
            if package.installer_hash.is_some() {
                return Ok(RecipeDecision::Manual(
                    "the JavaScript package integrity value cannot be pinned by this argv recipe",
                ));
            }
            let package_spec = format!("{}@{version}", package.id);
            match provider.as_str() {
                "yarn" => install_args.extend(args(["global", "add", &package_spec])),
                "bun" => install_args.extend(args(["add", "--global", &package_spec])),
                "npm" | "pnpm" => install_args.extend(args(["install", "--global", &package_spec])),
                _ => unreachable!(),
            }
            if policy.silent {
                install_args.push(OsString::from("--silent"));
            }
            match provider.as_str() {
                "yarn" => verify_args.extend(args(["global", "list", "--json", "--depth=0"])),
                "bun" => verify_args.extend(args(["pm", "ls", "--json", "--global"])),
                "npm" | "pnpm" => {
                    verify_args.extend(args(["ls", "--global", "--json", "--depth=0"]))
                }
                _ => unreachable!(),
            }
        }
        "python" => {
            if !package.source_name.as_deref().is_some_and(|name| {
                name.eq_ignore_ascii_case("pypi") || name.eq_ignore_ascii_case("registry")
            }) {
                return Ok(RecipeDecision::Manual(
                    "Python package source is not a reviewed registry",
                ));
            }
            let Some(source) = package.source.as_ref() else {
                return Ok(RecipeDecision::Manual(
                    "Python installation requires a recorded public package index",
                ));
            };
            install_args.extend(args([
                "-m",
                "pip",
                "install",
                "--no-input",
                "--disable-pip-version-check",
                "--no-deps",
                &format!("{}=={version}", package.id),
            ]));
            install_args.extend(args(["--index-url", source.as_str()]));
            if policy.silent {
                install_args.push(OsString::from("--quiet"));
            }
            verify_args.extend(args(["-m", "pip", "show", &package.id]));
        }
        "rust" => {
            if !package.source_name.as_deref().is_some_and(|name| {
                name.eq_ignore_ascii_case("crates.io") || name.eq_ignore_ascii_case("registry")
            }) {
                return Ok(RecipeDecision::Manual(
                    "Rust package source is not the reviewed registry",
                ));
            }
            install_args.extend(args(["install", &package.id, "--version", version]));
            if policy.silent {
                install_args.push(OsString::from("--quiet"));
            }
            verify_args.extend(args(["install", "--list"]));
        }
        "go" => {
            return Ok(RecipeDecision::Manual(
                "Go package installation has no bounded installed-identity verification recipe",
            ));
        }
        "dotnet" => {
            if !package
                .source_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("nuget"))
            {
                return Ok(RecipeDecision::Manual(
                    ".NET package source is not the reviewed NuGet registry",
                ));
            }
            install_args.extend(args([
                "tool",
                "install",
                "--global",
                &package.id,
                "--version",
                version,
            ]));
            if let Some(source) = package.source.as_ref() {
                install_args.extend(args(["--source", source.as_str()]));
            }
            if policy.silent {
                install_args.extend(args(["--verbosity", "quiet"]));
            }
            verify_args.extend(args(["tool", "list", "--global", "--format=json"]));
        }
        "powershell" => {
            return Ok(RecipeDecision::Manual(
                "PowerShell module installation remains manual because it is a script-capable boundary",
            ));
        }
        _ => {
            return Ok(RecipeDecision::Manual(
                "no reviewed package-install recipe exists for this provider",
            ));
        }
    }

    Ok(RecipeDecision::Automatic(ProviderCommands {
        install: make_command(executable, install_args, INSTALL_TIMEOUT)?,
        verify: make_command(executable, verify_args, VERIFICATION_TIMEOUT)?,
    }))
}

fn executable_for(provider: &ProviderId) -> Option<BuiltinExecutable> {
    Some(match provider.as_str() {
        "winget" => BuiltinExecutable::WinGet,
        "chocolatey" => BuiltinExecutable::Chocolatey,
        "scoop" => BuiltinExecutable::Scoop,
        "npm" => BuiltinExecutable::Npm,
        "pnpm" => BuiltinExecutable::Pnpm,
        "yarn" => BuiltinExecutable::Yarn,
        "bun" => BuiltinExecutable::Bun,
        "python" => BuiltinExecutable::Python,
        "rust" => BuiltinExecutable::Cargo,
        "go" => BuiltinExecutable::Go,
        "dotnet" => BuiltinExecutable::Dotnet,
        "powershell" => BuiltinExecutable::PowerShell,
        _ => return None,
    })
}

fn make_command(
    executable: BuiltinExecutable,
    args: Vec<OsString>,
    timeout: Duration,
) -> RestoreResult<CommandSpec> {
    CommandSpec::new(
        TrustedExecutable::Builtin(executable),
        args,
        timeout,
        PROCESS_OUTPUT_BYTES,
    )
}

fn args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn append_winget_policy(args: &mut Vec<OsString>, policy: &PackageInstallPolicy) {
    if policy.accept_source_agreements {
        args.push(OsString::from("--accept-source-agreements"));
    }
    if policy.accept_package_agreements {
        args.push(OsString::from("--accept-package-agreements"));
    }
    if policy.silent {
        args.push(OsString::from("--silent"));
    }
    if policy.allow_reboot {
        args.push(OsString::from("--allow-reboot"));
    }
}

fn validate_package_identity(provider: &ProviderId, package: &PackageSpec) -> RestoreResult<()> {
    if package.provider != *provider {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "package provider identity does not match the operation provider",
        ));
    }
    validate_identifier(&package.id, true, "package ID", MAX_PACKAGE_ID_BYTES)?;
    if let Some(version) = package.version.as_deref() {
        validate_exact_version(version)?;
    }
    if let Some(name) = package.source_name.as_deref() {
        validate_source_text(name, "package source name")?;
    }
    if let Some(identifier) = package.source_identifier.as_deref() {
        validate_source_text(identifier, "package source identifier")?;
    }
    Ok(())
}

fn validate_provider_specific_id(
    provider: &ProviderId,
    package: &PackageSpec,
) -> RestoreResult<()> {
    let allows_slash = matches!(provider.as_str(), "go");
    let is_javascript = matches!(provider.as_str(), "npm" | "pnpm" | "yarn" | "bun");
    let slash_count = package.id.bytes().filter(|byte| *byte == b'/').count();

    if package.id.contains('\\') || (!allows_slash && package.id.contains('/')) {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "package ID contains a path separator unsupported by the provider",
        ));
    }
    if is_javascript {
        let scoped = package.id.starts_with('@');
        if (scoped
            && (package
                .id
                .split('/')
                .next()
                .is_none_or(|scope| scope.len() <= 1)
                || slash_count != 1
                || package.id.split('/').any(|part| part.is_empty())))
            || (!scoped && slash_count != 0)
        {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "JavaScript package ID is outside the reviewed grammar",
            ));
        }
    }
    Ok(())
}

fn installed_exact<'a>(
    target: &'a TargetFacts,
    provider: &ProviderId,
    package: &PackageSpec,
) -> Option<&'a Identity> {
    if package.installer_hash.is_some() {
        return None;
    }
    target.installed.iter().find_map(|fact| {
        let (installed_provider, installed_id) = fact.identity.provider_package.as_ref()?;
        if installed_provider != provider || installed_id != &package.id {
            return None;
        }
        if !versions_equal(fact.version.as_ref(), package.version.as_deref()?) {
            return None;
        }
        if !source_matches(&fact.identity, package) {
            return None;
        }
        Some(&fact.identity)
    })
}

fn validate_identifier(
    value: &str,
    allow_slash: bool,
    kind: &str,
    max_bytes: usize,
) -> RestoreResult<()> {
    let invalid = value.is_empty()
        || value.starts_with('-')
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || (!allow_slash && matches!(character, '/' | '\\'))
                || matches!(
                    character,
                    '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '&' | ';' | '`' | '$' | '%'
                )
        });
    if invalid || value == "." || value == ".." {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{kind} is outside the reviewed command argument grammar"),
        ));
    }
    Ok(())
}

fn validate_source_text(value: &str, kind: &str) -> RestoreResult<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.len() > MAX_SOURCE_BYTES
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{kind} is outside the reviewed grammar"),
        ));
    }
    Ok(())
}

fn validate_exact_version(value: &str) -> RestoreResult<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.len() > MAX_VERSION_BYTES
        || value.trim() != value
        || value.eq_ignore_ascii_case("latest")
        || value.eq_ignore_ascii_case("next")
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(
                    character,
                    '\\' | '/'
                        | ':'
                        | '*'
                        | '?'
                        | '"'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                        | ';'
                        | '`'
                        | '$'
                        | '%'
                        | '^'
                        | '~'
                        | '='
                )
        })
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "package version is not an exact safe provider argument",
        ));
    }
    Ok(())
}

fn validate_source_metadata(package: &PackageSpec) -> RestoreResult<()> {
    if let Some(source) = package.source.as_ref()
        && !(matches!(source.scheme(), "http" | "https")
            && source.username().is_empty()
            && source.password().is_none()
            && source.query().is_none()
            && source.fragment().is_none())
    {
        return Err(operation_error(
            ReforgeErrorCode::SecurityPolicy,
            "package source URL is not a public credential-free HTTP(S) URL",
        ));
    }
    Ok(())
}

fn validate_hash(package: &PackageSpec) -> RestoreResult<()> {
    if let Some(hash) = package.installer_hash.as_deref()
        && (hash.is_empty()
            || hash.len() > MAX_HASH_BYTES
            || hash.trim() != hash
            || hash
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()))
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "installer hash is outside the reviewed grammar",
        ));
    }
    Ok(())
}

fn unsupported_policy(
    provider: &ProviderId,
    policy: &PackageInstallPolicy,
) -> Option<&'static str> {
    match provider.as_str() {
        "winget" => None,
        "chocolatey" => {
            if policy.silent {
                Some("Chocolatey has no reviewed silent install mapping")
            } else if policy.allow_reboot {
                Some("Chocolatey has no reviewed allow-reboot mapping")
            } else {
                None
            }
        }
        "scoop" => {
            if policy.accept_source_agreements
                || policy.accept_package_agreements
                || policy.silent
                || policy.allow_reboot
            {
                Some("Scoop has no reviewed policy flag mapping")
            } else {
                None
            }
        }
        "npm" | "pnpm" | "yarn" | "bun" | "python" | "rust" | "dotnet" => {
            if policy.accept_source_agreements || policy.accept_package_agreements {
                Some("this provider has no reviewed agreement acceptance mapping")
            } else if policy.allow_reboot {
                Some("this provider has no reviewed allow-reboot mapping")
            } else {
                None
            }
        }
        "go" | "powershell" => None,
        _ => Some("this provider has no reviewed package policy mapping"),
    }
}

fn reviewed_chocolatey_source(package: &PackageSpec) -> Result<(), &'static str> {
    if package.source_name.is_none()
        && package.source_identifier.is_none()
        && package.source.is_none()
    {
        return Ok(());
    }
    if package
        .source_name
        .as_ref()
        .is_some_and(|name| !name.eq_ignore_ascii_case("community"))
    {
        return Err("Chocolatey custom source requires explicit manual review");
    }
    if package.source_identifier.as_deref() != Some("community") {
        return Err("Chocolatey source identity is not the reviewed community source");
    }
    let Some(source) = package.source.as_ref() else {
        return Err("Chocolatey source URL is required when source metadata is recorded");
    };
    if !source
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("community.chocolatey.org"))
        || source.path().trim_end_matches('/') != "/api/v2"
    {
        return Err("Chocolatey custom source requires explicit manual review");
    }
    Ok(())
}

fn reviewed_scoop_source(package: &PackageSpec) -> Result<&str, &'static str> {
    let Some(bucket) = package.source_name.as_deref() else {
        return Err("Scoop installation requires a reviewed bucket name");
    };
    let Some(identifier) = package.source_identifier.as_deref() else {
        return Err("Scoop installation requires a stable bucket identifier");
    };
    let Some(source) = package.source.as_ref() else {
        return Err("Scoop installation requires a reviewed bucket URL");
    };
    if !matches!(
        bucket.to_ascii_lowercase().as_str(),
        "main" | "extras" | "versions"
    ) || identifier != format!("bucket:{bucket}")
        || !source
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
        || !source
            .path()
            .trim_matches('/')
            .eq_ignore_ascii_case(&format!("scoopinstaller/{bucket}"))
    {
        return Err("Scoop custom bucket requires explicit manual review");
    }
    Ok(bucket)
}

fn validate_architecture(package: &PackageSpec, target: &TargetFacts) -> RestoreResult<()> {
    let Some(required) = package.architecture.as_ref() else {
        return Ok(());
    };
    let host = &target.host.architecture;
    let compatible = matches!(
        (required, host),
        (Architecture::Neutral, _)
            | (Architecture::X86, Architecture::X86 | Architecture::X64)
            | (Architecture::X64, Architecture::X64)
            | (Architecture::Arm64, Architecture::Arm64)
    );
    if compatible {
        Ok(())
    } else {
        Err(operation_error(
            ReforgeErrorCode::ArchitectureConflict,
            "package architecture is incompatible with the target architecture",
        ))
    }
}

fn versions_equal(value: Option<&VersionValue>, expected: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    value.raw == expected || value.normalized.as_deref() == Some(expected)
}

fn source_matches(identity: &Identity, package: &PackageSpec) -> bool {
    let Some(observed) = identity.provider_source.as_deref() else {
        return package.source_identifier.is_none()
            && package.source.is_none()
            && package.source_name.is_none();
    };
    if matches!(package.provider.as_str(), "npm" | "pnpm" | "yarn" | "bun")
        && package.source_identifier.is_none()
        && package.source_name.is_none()
    {
        return observed == "global";
    }
    let mut expected = Vec::with_capacity(6);
    if let Some(identifier) = package.source_identifier.as_deref() {
        expected.push(identifier.to_owned());
        expected.push(format!("identifier:{identifier}"));
    }
    if let Some(source) = package.source.as_ref() {
        expected.push(source.to_string());
        expected.push(format!("url:{source}"));
    }
    if let Some(name) = package.source_name.as_deref() {
        expected.push(name.to_owned());
        expected.push(format!("kind:{name}"));
    }
    expected.is_empty() || expected.iter().any(|value| value == observed)
}

fn output_contains_identity(result: &ProcessResult, package: &PackageSpec) -> bool {
    let output = format!("{}\n{}", result.stdout, result.stderr).to_ascii_lowercase();
    let id = package.id.to_ascii_lowercase();
    let Some(version) = package.version.as_deref() else {
        return false;
    };
    output.contains(&id) && output.contains(&version.to_ascii_lowercase())
}

fn waiting_for_provider(provider: &ProviderId, reason: &'static str) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "provider": provider.as_str(),
        "manual_action_required": true,
        "reason": reason,
    })))
}

fn waiting_for_package(
    provider: &ProviderId,
    package: &PackageSpec,
    reason: &'static str,
) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "provider": provider.as_str(),
        "package_id": package.id,
        "version": package.version,
        "manual_action_required": true,
        "reason": reason,
    })))
}

fn waiting_for_reboot(
    provider: &ProviderId,
    package: &PackageSpec,
    verified: bool,
) -> OperationOutcome {
    OperationOutcome::waiting_for_reboot(Some(json!({
        "provider": provider.as_str(),
        "package_id": package.id,
        "version": package.version,
        "installed": true,
        "verified": verified,
        "reboot_required": true,
    })))
}

fn provider_evidence(provider: &ProviderId, detail: &str) -> Value {
    json!({
        "kind": "provider",
        "provider": provider.as_str(),
        "detail": detail,
    })
}

fn package_evidence(provider: &ProviderId, package: &PackageSpec, detail: &str) -> Value {
    json!({
        "kind": "provider_package",
        "provider": provider.as_str(),
        "package_id": package.id,
        "version": package.version,
        "detail": detail,
    })
}

fn installed_evidence(provider: &ProviderId, package: &PackageSpec, identity: &Identity) -> Value {
    json!({
        "kind": "target_package",
        "provider": provider.as_str(),
        "package_id": package.id,
        "version": package.version,
        "source": identity.provider_source,
    })
}

fn install_error(
    code: ReforgeErrorCode,
    message: &'static str,
) -> Box<reforge_domain::ErrorEnvelope> {
    restore_error(
        code,
        message,
        None,
        None,
        None,
        Some("restore-provider-install"),
    )
}
