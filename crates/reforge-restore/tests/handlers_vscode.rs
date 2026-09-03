#![allow(dead_code)]

mod support;

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use reforge_domain::{
    ComponentId, ObjectIndex, Operation, OperationId, OperationKind, Precondition,
    ReforgeErrorCode, RunId, TargetFacts,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, TrustedExecutable,
};
use reforge_restore::{
    ExecutionContext, OperationDisposition, OperationHandler, ProviderProcessBridge, RestoreResult,
    VsCodeRestoreHandler,
};

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "v".repeat(52))).expect("component ID")
}

fn operation(id: &str, version: Option<&str>, profile: Option<&str>) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind: OperationKind::InstallVsCodeExtension {
            id: id.to_owned(),
            version: version.map(str::to_owned),
            profile: profile.map(str::to_owned),
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:vscode-handler-test".to_owned(),
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

fn context(target: &TargetFacts) -> ExecutionContext<'_> {
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
    fn builtin_available(&self, executable: BuiltinExecutable) -> bool {
        self.available && executable == BuiltinExecutable::Code
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
                    "fake VS Code result queue is empty",
                    None,
                    None,
                    None,
                    Some("vscode-test"),
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
async fn installs_and_verifies_the_exact_extension_version_without_a_shell() {
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), ""),
            process(Some(0), "installed"),
            process(Some(0), "ms-python.python@2026.12.0\n"),
        ],
    ));
    let handler = VsCodeRestoreHandler::with_bridge(bridge.clone());
    let target = support::target_facts();

    let outcome = handler
        .execute(
            &operation("ms-python.python", Some("2026.12.0"), Some("Work Profile")),
            &context(&target),
            &CancellationToken::new(),
        )
        .await
        .expect("extension restore");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let commands = bridge.commands();
    assert_eq!(commands.len(), 3);
    assert!(commands.iter().all(|command| matches!(
        command.executable,
        TrustedExecutable::Builtin(BuiltinExecutable::Code)
    )));
    assert_eq!(
        command_args(&commands[0]),
        [
            "--list-extensions",
            "--show-versions",
            "--profile",
            "Work Profile",
        ]
    );
    assert_eq!(
        command_args(&commands[1]),
        [
            "--install-extension",
            "ms-python.python@2026.12.0",
            "--force",
            "--profile",
            "Work Profile",
        ]
    );
    assert_eq!(command_args(&commands[2]), command_args(&commands[0]));
}

#[tokio::test]
async fn missing_version_never_falls_back_to_latest() {
    let bridge = Arc::new(FakeBridge::new(true, [process(Some(0), "")]));
    let handler = VsCodeRestoreHandler::with_bridge(bridge.clone());
    let target = support::target_facts();

    let outcome = handler
        .execute(
            &operation("rust-lang.rust-analyzer", None, None),
            &context(&target),
            &CancellationToken::new(),
        )
        .await
        .expect("manual version decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert_eq!(bridge.commands().len(), 1, "no install command may run");
    assert!(
        outcome
            .result
            .as_ref()
            .and_then(|value| value["reason"].as_str())
            .is_some_and(|reason| reason.contains("exact"))
    );
}

#[tokio::test]
async fn extension_identity_metacharacters_are_rejected_before_execution() {
    let bridge = Arc::new(FakeBridge::new(true, []));
    let handler = VsCodeRestoreHandler::with_bridge(bridge.clone());
    let target = support::target_facts();

    let error = handler
        .execute(
            &operation("ms-python.python & whoami", Some("2026.12.0"), None),
            &context(&target),
            &CancellationToken::new(),
        )
        .await
        .expect_err("command text must not become extension identity");

    assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
    assert!(bridge.commands().is_empty());
}
