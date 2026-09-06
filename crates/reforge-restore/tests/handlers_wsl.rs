#![allow(clippy::too_many_arguments, dead_code, unused_imports)]

mod support;

use std::{
    collections::VecDeque,
    io::Write,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use reforge_domain::{
    ContentType, ObjectEntry, ObjectId, ObjectIndex, Operation, OperationId, OperationKind,
    Precondition, ProviderFact, ProviderId, ReforgeErrorCode, RunId, WslSpec,
};
use reforge_platform_windows::{BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult};
use reforge_restore::{
    ExecutionContext, ObjectSource, OperationDisposition, OperationHandler, ProviderProcessBridge,
    RestoreResult, WslRestoreHandler,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", "w".repeat(52))).expect("component ID")
}

fn spec() -> WslSpec {
    WslSpec {
        distribution: "Ubuntu-22.04".to_owned(),
        wsl_version: Some(2),
    }
}

fn operation(distro: WslSpec, object: ObjectId) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind: OperationKind::ImportWsl { distro, object },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:wsl-handler-test".to_owned(),
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

fn archive_object(bytes: &[u8]) -> (ObjectId, ObjectIndex, ObjectEntry, MemoryObjectSource) {
    let object = ObjectId::from_content(bytes);
    let entry = ObjectEntry {
        id: object.clone(),
        uncompressed_bytes: bytes.len() as u64,
        compressed_bytes: bytes.len() as u64,
        content_type: ContentType::Archive,
    };
    let index = ObjectIndex {
        objects: vec![entry.clone()],
    };
    let source = MemoryObjectSource {
        bytes: bytes.to_vec(),
        entry: entry.clone(),
    };
    (object, index, entry, source)
}

fn target() -> reforge_domain::TargetFacts {
    let mut target = support::fixtures::target_facts();
    target.providers.push(ProviderFact {
        id: ProviderId::new("wsl").expect("provider ID"),
        version: None,
        available: true,
    });
    target
}

fn command_args(command: &CommandSpec) -> Vec<String> {
    command
        .args
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

struct MemoryObjectSource {
    bytes: Vec<u8>,
    entry: ObjectEntry,
}

impl ObjectSource for MemoryObjectSource {
    fn copy_verified_object(
        &self,
        _object: &ObjectId,
        output: &mut dyn Write,
    ) -> RestoreResult<ObjectEntry> {
        output.write_all(&self.bytes).map_err(|error| {
            reforge_restore::restore_error(
                ReforgeErrorCode::OperationFailed,
                "fixture object write failed",
                Some(&error.to_string()),
                None,
                None,
                Some("wsl-handler-test"),
            )
        })?;
        Ok(self.entry.clone())
    }
}

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
        self.available && executable == BuiltinExecutable::Wsl
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
                    "fake WSL result queue is empty",
                    None,
                    None,
                    None,
                    Some("wsl-handler-test"),
                )
            })
    }
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    index: &'a ObjectIndex,
    source: &'a MemoryObjectSource,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, index).with_object_source(source)
}

#[tokio::test]
async fn missing_wsl_prerequisite_is_manual_without_process_execution() {
    let (object, index, _entry, source) = archive_object(b"wsl archive");
    let target = support::fixtures::target_facts();
    let bridge = Arc::new(FakeBridge::new(false, []));
    let handler = WslRestoreHandler::with_bridge(bridge.clone());

    let outcome = handler
        .execute(
            &operation(spec(), object),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("manual prerequisite outcome");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert_eq!(bridge.commands().len(), 0);
    assert_eq!(
        outcome
            .result
            .as_ref()
            .and_then(|value| value["subsystem"].as_str()),
        Some("wsl")
    );
}

#[tokio::test]
async fn wsl_artifact_waits_for_insufficient_capacity_before_status_or_import() {
    let bytes = b"small fixture bytes";
    let (object, index, _entry, source) = archive_object(bytes);
    let mut target = target();
    target.host.free_bytes[0].bytes = 0;
    let bridge = Arc::new(FakeBridge::new(true, []));
    let handler = WslRestoreHandler::with_bridge(bridge.clone());

    let outcome = handler
        .execute(
            &operation(spec(), object),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("capacity outcome");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert_eq!(bridge.commands().len(), 0);
    assert_eq!(
        outcome
            .result
            .as_ref()
            .and_then(|value| value["manual_action_required"].as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn successful_wsl_import_stages_archive_and_verifies_exact_state() {
    let fixture = FixtureRoot::new("handlers-wsl-success").expect("fixture root");
    let bytes = b"wsl archive bytes";
    let (object, index, _entry, source) = archive_object(bytes);
    let target = target();
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "Default Distribution: Ubuntu-22.04\n"),
            process(Some(0), ""),
            process(
                Some(0),
                "  NAME           STATE           VERSION\n* Ubuntu-22.04 Running         2\n",
            ),
        ],
    ));
    let handler = WslRestoreHandler::with_bridge(bridge.clone())
        .with_install_root(fixture.root().join("managed-wsl"));

    let outcome = handler
        .execute(
            &operation(spec(), object),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("WSL import");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(outcome.evidence[0]["verified"].as_bool(), Some(true));
    let commands = bridge.commands();
    assert_eq!(commands.len(), 3);
    assert_eq!(command_args(&commands[0]), ["--status"]);
    let import_args = command_args(&commands[1]);
    assert_eq!(import_args[0], "--import");
    assert_eq!(import_args[1], "Ubuntu-22.04");
    assert_eq!(&import_args[4..6], ["--version", "2"]);
    assert_eq!(command_args(&commands[2]), ["--list", "--verbose"]);
    assert!(!std::path::Path::new(&import_args[3]).exists());
}

#[tokio::test]
async fn wsl_import_preserves_a_discovered_distribution_name_with_spaces() {
    let fixture = FixtureRoot::new("handlers-wsl-spaced-name").expect("fixture root");
    let (object, index, _entry, source) = archive_object(b"wsl archive bytes");
    let distro = WslSpec {
        distribution: "Ubuntu 22.04".to_owned(),
        wsl_version: Some(2),
    };
    let target = target();
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "Default Distribution: Ubuntu 22.04\n"),
            process(Some(0), ""),
            process(
                Some(0),
                "  NAME           STATE           VERSION\n* Ubuntu 22.04 Running         2\n",
            ),
        ],
    ));
    let handler = WslRestoreHandler::with_bridge(bridge.clone())
        .with_install_root(fixture.root().join("managed-wsl"));

    let outcome = handler
        .execute(
            &operation(distro, object),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("WSL import with a spaced distribution name");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(command_args(&bridge.commands()[1])[1], "Ubuntu 22.04");
}

#[tokio::test]
async fn wsl_import_failure_is_reported_without_claiming_completion() {
    let fixture = FixtureRoot::new("handlers-wsl-failure").expect("fixture root");
    let (object, index, _entry, source) = archive_object(b"wsl archive bytes");
    let target = target();
    let bridge = Arc::new(FakeBridge::new(
        true,
        [process(Some(0), ""), process(Some(1), "import failed")],
    ));
    let handler = WslRestoreHandler::with_bridge(bridge.clone())
        .with_install_root(fixture.root().join("managed-wsl"));

    let error = handler
        .execute(
            &operation(spec(), object),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("failed import");

    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert_eq!(bridge.commands().len(), 2);
}
