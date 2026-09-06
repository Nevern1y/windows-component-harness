#![allow(clippy::too_many_arguments, dead_code, unused_imports)]

mod support;

use std::{
    collections::VecDeque,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use reforge_domain::{
    ContentType, DockerImageSpec, DockerVolumeSpec, ObjectEntry, ObjectId, ObjectIndex, Operation,
    OperationId, OperationKind, Precondition, ProviderFact, ProviderId, ReforgeErrorCode, RunId,
};
use reforge_platform_windows::{BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult};
use reforge_restore::{
    DockerRestoreHandler, ExecutionContext, ObjectSource, OperationDisposition, OperationHandler,
    ProviderProcessBridge, RestoreResult,
};

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", "d".repeat(52))).expect("component ID")
}

fn image() -> DockerImageSpec {
    DockerImageSpec {
        repository: "ghcr.io/contoso/editor".to_owned(),
        tag: Some("1.2.3".to_owned()),
        image_id: Some(format!("sha256:{}", "a".repeat(64))),
    }
}

fn volume() -> DockerVolumeSpec {
    DockerVolumeSpec {
        name: "workspace-data".to_owned(),
        driver: Some("local".to_owned()),
    }
}

fn operation(kind: OperationKind) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind,
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:docker-handler-test".to_owned(),
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

fn archive_object(bytes: &[u8]) -> (ObjectId, ObjectIndex, MemoryObjectSource) {
    let object = ObjectId::from_content(bytes);
    let entry = ObjectEntry {
        id: object.clone(),
        uncompressed_bytes: bytes.len() as u64,
        compressed_bytes: bytes.len() as u64,
        content_type: ContentType::Archive,
    };
    (
        object,
        ObjectIndex {
            objects: vec![entry.clone()],
        },
        MemoryObjectSource {
            bytes: bytes.to_vec(),
            entry,
        },
    )
}

fn target() -> reforge_domain::TargetFacts {
    let mut target = support::fixtures::target_facts();
    target.providers.push(ProviderFact {
        id: ProviderId::new("docker").expect("provider ID"),
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
                Some("docker-handler-test"),
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
        self.available && executable == BuiltinExecutable::Docker
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
                    "fake Docker result queue is empty",
                    None,
                    None,
                    None,
                    Some("docker-handler-test"),
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
async fn missing_docker_prerequisite_is_manual_without_process_execution() {
    let (object, index, source) = archive_object(b"docker archive");
    let target = support::fixtures::target_facts();
    let bridge = Arc::new(FakeBridge::new(false, []));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerImage {
        image: image(),
        object,
    });

    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("manual prerequisite outcome");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(bridge.commands().is_empty());
}

#[tokio::test]
async fn docker_artifact_waits_for_insufficient_capacity_before_loading() {
    let bytes = b"small fixture bytes";
    let (object, index, source) = archive_object(bytes);
    let mut target = target();
    target.host.free_bytes[0].bytes = 0;
    let bridge = Arc::new(FakeBridge::new(true, []));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerImage {
        image: image(),
        object,
    });

    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("capacity outcome");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(bridge.commands().is_empty());
}

#[tokio::test]
async fn successful_docker_image_load_stages_archive_and_verifies_id_and_tag() {
    let (object, index, source) = archive_object(b"docker image archive");
    let target = target();
    let image = image();
    let inspect = format!(
        r#"{{"Id":"{}","RepoTags":["ghcr.io/contoso/editor:1.2.3"]}}"#,
        image.image_id.as_deref().expect("image ID")
    );
    let bridge = Arc::new(FakeBridge::new(
        true,
        [process(Some(0), "Loaded image"), process(Some(0), &inspect)],
    ));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerImage { image, object });

    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("Docker image restore");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(outcome.evidence[0]["verified"].as_bool(), Some(true));
    let commands = bridge.commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(command_args(&commands[0])[..2], ["load", "--input"]);
    assert_eq!(
        command_args(&commands[1]),
        [
            "image",
            "inspect",
            "--format",
            "{{json .}}",
            "ghcr.io/contoso/editor:1.2.3"
        ]
    );
    let load_args = command_args(&commands[0]);
    assert!(!Path::new(&load_args[2]).exists());
}

#[tokio::test]
async fn successful_docker_volume_restore_uses_local_helper_and_verifies_volume() {
    let (object, index, source) = archive_object(b"docker volume archive");
    let target = target();
    let volume = volume();
    let helper_id = format!("sha256:{}", "b".repeat(64));
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "27.5.1"),
            process(Some(0), &helper_id),
            process(Some(1), "No such volume"),
            process(Some(0), "workspace-data"),
            process(Some(0), ""),
            process(Some(0), r#"{"Name":"workspace-data","Driver":"local"}"#),
        ],
    ));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerVolume { volume, object });

    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("Docker volume restore");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert_eq!(outcome.evidence[0]["verified"].as_bool(), Some(true));
    let commands = bridge.commands();
    assert_eq!(commands.len(), 6);
    let restore_args = command_args(&commands[4]);
    assert!(restore_args.contains(&"--pull=never".to_owned()));
    assert!(restore_args.contains(&helper_id));
    assert!(restore_args.contains(&"tar".to_owned()));
    assert!(restore_args.iter().all(|argument| !argument.contains("&&")));
}

#[tokio::test]
async fn volume_verification_driver_mismatch_is_reported_as_failed() {
    let (object, index, source) = archive_object(b"docker volume archive");
    let target = target();
    let helper_id = format!("sha256:{}", "b".repeat(64));
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "27.5.1"),
            process(Some(0), &helper_id),
            process(Some(1), "No such volume"),
            process(Some(0), "workspace-data"),
            process(Some(0), ""),
            process(Some(0), r#"{"Name":"workspace-data","Driver":"other"}"#),
        ],
    ));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerVolume {
        volume: volume(),
        object,
    });

    let error = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("volume verification failure");

    assert_eq!(error.code, ReforgeErrorCode::VerificationFailed);
    assert_eq!(bridge.commands().len(), 6);
}

#[tokio::test]
async fn unverified_local_archive_helper_requires_manual_action() {
    let (object, index, source) = archive_object(b"docker volume archive");
    let target = target();
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "27.5.1"),
            process(Some(0), "not-an-image-id"),
        ],
    ));
    let handler = DockerRestoreHandler::with_bridge(bridge.clone());
    let operation = operation(OperationKind::RestoreDockerVolume {
        volume: volume(),
        object,
    });

    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("unverified helper becomes manual");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert_eq!(bridge.commands().len(), 2);
}

#[tokio::test]
async fn image_verification_failure_is_reported_as_failed() {
    let (object, index, source) = archive_object(b"docker image archive");
    let target = target();
    let bridge = Arc::new(FakeBridge::new(
        true,
        [
            process(Some(0), "Loaded image"),
            process(
                Some(0),
                r#"{"Id":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","RepoTags":["ghcr.io/contoso/editor:9.9.9"]}"#,
            ),
        ],
    ));
    let handler = DockerRestoreHandler::with_bridge(bridge);
    let operation = operation(OperationKind::RestoreDockerImage {
        image: image(),
        object,
    });

    let error = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("verification failure");

    assert_eq!(error.code, ReforgeErrorCode::VerificationFailed);
}
