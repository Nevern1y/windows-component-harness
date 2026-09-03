#![allow(clippy::too_many_arguments, dead_code, unused_imports)]
mod support;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use reforge_domain::{
    Architecture, ComponentId, ComponentKind, Identity, IdentityQuality, InstalledFact,
    ObjectIndex, Operation, OperationId, OperationKind, PackageInstallPolicy, PackageSpec,
    Precondition, ProviderId, ReforgeErrorCode, RunId, TargetFacts, VersionValue,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, TrustedExecutable,
};
use reforge_restore::{
    ExecutionContext, OperationDisposition, OperationHandler, OperationSatisfaction,
    ProviderInstallHandler, ProviderProcessBridge, RestoreResult,
};

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID")
}

fn policy(
    accept_source_agreements: bool,
    accept_package_agreements: bool,
    silent: bool,
    allow_reboot: bool,
) -> PackageInstallPolicy {
    PackageInstallPolicy {
        accept_source_agreements,
        accept_package_agreements,
        silent,
        allow_reboot,
    }
}

fn winget_package(id: &str) -> PackageSpec {
    PackageSpec {
        provider: ProviderId::new("winget").expect("provider ID"),
        id: id.to_owned(),
        version: Some("2.47.1".to_owned()),
        source_name: Some("winget".to_owned()),
        source_identifier: Some("Microsoft.Winget.Source_8wekyb3d8bbwe".to_owned()),
        source: Some(
            "https://cdn.winget.microsoft.com/cache"
                .parse()
                .expect("source URL"),
        ),
        architecture: Some(Architecture::X64),
        installer_hash: None,
    }
}

fn operation(package: PackageSpec, install_policy: PackageInstallPolicy) -> Operation {
    let provider = package.provider.clone();
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind: OperationKind::InstallPackage {
            provider,
            package,
            policy: install_policy,
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:provider-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn process(exit_code: Option<i32>, stdout: &str) -> ProcessResult {
    ProcessResult {
        exit_code,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        timed_out: false,
        cancelled: false,
    }
}

static EMPTY_OBJECT_INDEX: ObjectIndex = ObjectIndex {
    objects: Vec::new(),
};

fn context<'a>(target: &'a TargetFacts) -> ExecutionContext<'a> {
    ExecutionContext::new(target, &EMPTY_OBJECT_INDEX)
}

#[derive(Debug)]
struct FakeBridge {
    available: bool,
    results: Mutex<VecDeque<ProcessResult>>,
    commands: Mutex<Vec<CommandSpec>>,
}

impl FakeBridge {
    fn new(available: bool, results: impl IntoIterator<Item = ProcessResult>) -> Self {
        Self {
            available,
            results: Mutex::new(results.into_iter().collect()),
            commands: Mutex::new(Vec::new()),
        }
    }

    fn commands(&self) -> Vec<CommandSpec> {
        self.commands.lock().expect("commands lock").clone()
    }
}

#[async_trait]
impl ProviderProcessBridge for FakeBridge {
    fn builtin_available(&self, _executable: BuiltinExecutable) -> bool {
        self.available
    }

    async fn run(
        &self,
        command: &CommandSpec,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<ProcessResult> {
        self.commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        self.results
            .lock()
            .expect("results lock")
            .pop_front()
            .ok_or_else(|| {
                reforge_restore::restore_error(
                    ReforgeErrorCode::OperationFailed,
                    "fake provider result queue is empty",
                    None,
                    None,
                    None,
                    Some("provider-test"),
                )
            })
    }
}

fn command_args(command: &CommandSpec) -> Vec<String> {
    command
        .args
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn already_installed_package_is_skipped_without_provider_execution() {
    let package = winget_package("Git.Git");
    let mut target = support::fixtures::target_facts();
    target.installed.push(InstalledFact {
        kind: ComponentKind::Package,
        identity: Identity {
            provider_package: Some((package.provider.clone(), package.id.clone())),
            provider_source: package.source_identifier.clone(),
            package_family: None,
            product_name: None,
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        },
        version: Some(VersionValue {
            raw: "2.47.1".to_owned(),
            normalized: None,
        }),
        publisher: None,
        provenance: None,
    });
    let bridge = Arc::new(FakeBridge::new(false, []));
    let handler = ProviderInstallHandler::with_bridge(bridge.clone());
    let operation = operation(package, policy(false, false, false, false));

    let satisfaction = handler
        .is_satisfied(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("satisfaction check");
    assert!(matches!(
        satisfaction,
        OperationSatisfaction::Satisfied { .. }
    ));

    let outcome = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("skip outcome");
    assert_eq!(outcome.disposition, OperationDisposition::Skipped);
    assert!(bridge.commands().is_empty());
}

#[tokio::test]
async fn exact_winget_install_and_verification_args_are_shell_free() {
    let bridge = Arc::new(FakeBridge::new(
        true,
        [process(Some(0), ""), process(Some(0), "Git.Git 2.47.1")],
    ));
    let handler = ProviderInstallHandler::with_bridge(bridge.clone());
    let operation = operation(winget_package("Git.Git"), policy(true, true, true, true));
    let target = support::fixtures::target_facts();

    let outcome = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("provider install");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(bridge.commands().len(), 2);
    assert!(matches!(
        bridge.commands()[0].executable,
        TrustedExecutable::Builtin(BuiltinExecutable::WinGet)
    ));
    assert_eq!(
        command_args(&bridge.commands()[0]),
        [
            "install",
            "--id",
            "Git.Git",
            "--exact",
            "--version",
            "2.47.1",
            "--source",
            "winget",
            "--accept-source-agreements",
            "--accept-package-agreements",
            "--silent",
            "--allow-reboot",
            "--disable-interactivity",
        ]
    );
    assert_eq!(
        command_args(&bridge.commands()[1]),
        [
            "list",
            "--id",
            "Git.Git",
            "--exact",
            "--source",
            "winget",
            "--disable-interactivity",
        ]
    );
}

#[tokio::test]
async fn recorded_installer_hash_requires_manual_review_without_provider_execution() {
    let bridge = Arc::new(FakeBridge::new(true, []));
    let handler = ProviderInstallHandler::with_bridge(bridge.clone());
    let mut package = winget_package("Git.Git");
    package.installer_hash = Some("a".repeat(64));
    let operation = operation(package, policy(false, false, false, false));
    let target = support::fixtures::target_facts();

    let outcome = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("hashed provider install becomes a manual action");
    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(bridge.commands().is_empty());
    let result = outcome.result.expect("manual action result");
    assert_eq!(result["manual_action_required"], true);
    assert_eq!(
        result["reason"],
        "the recorded installer hash cannot be enforced by the reviewed provider install recipe"
    );
}

#[tokio::test]
async fn missing_provider_becomes_manual_without_execution() {
    let bridge = Arc::new(FakeBridge::new(false, []));
    let handler = ProviderInstallHandler::with_bridge(bridge.clone());
    let operation = operation(
        winget_package("Git.Git"),
        policy(false, false, false, false),
    );
    let target = support::fixtures::target_facts();

    let outcome = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("manual provider outcome");
    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(bridge.commands().is_empty());
}

#[tokio::test]
async fn nonzero_provider_exit_is_a_typed_install_failure() {
    let bridge = Arc::new(FakeBridge::new(true, [process(Some(1), "failure")]));
    let handler = ProviderInstallHandler::with_bridge(bridge);
    let operation = operation(
        winget_package("Git.Git"),
        policy(false, false, false, false),
    );
    let target = support::fixtures::target_facts();

    let error = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect_err("nonzero install must fail");
    assert_eq!(error.code, ReforgeErrorCode::InstallFailed);
}

#[tokio::test]
async fn reboot_exit_is_visible_as_waiting_for_reboot() {
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(3010), "reboot"),
            process(Some(0), "Git.Git 2.47.1"),
        ],
    ));
    let handler = ProviderInstallHandler::with_bridge(bridge);
    let operation = operation(winget_package("Git.Git"), policy(false, false, false, true));
    let target = support::fixtures::target_facts();

    let outcome = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect("reboot outcome");
    assert_eq!(outcome.disposition, OperationDisposition::WaitingForReboot);
}

#[tokio::test]
async fn malicious_package_id_is_rejected_before_provider_execution() {
    let bridge = Arc::new(FakeBridge::new(true, []));
    let handler = ProviderInstallHandler::with_bridge(bridge.clone());
    let operation = operation(
        winget_package("Git.Git & whoami"),
        policy(false, false, false, false),
    );
    let target = support::fixtures::target_facts();

    let error = handler
        .execute(&operation, &context(&target), &CancellationToken::new())
        .await
        .expect_err("malicious package ID must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
    assert!(bridge.commands().is_empty());
}
