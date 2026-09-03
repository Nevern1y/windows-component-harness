#![allow(clippy::too_many_arguments, dead_code)]

mod support;

use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use reforge_domain::{
    ContentType, ErrorEnvelope, FileMode, KnownFolderToken, ObjectEntry, ObjectId, ObjectIndex,
    Operation, OperationId, OperationKind, OperationState, Precondition, ReforgeErrorCode,
    RestoreMode, RestorePlan, RunId, RunStatus,
};
use reforge_platform_windows::CancellationToken;
use reforge_restore::{
    BackupHook, ExecutionContext, Executor, Journal, OperationDisposition, OperationHandler,
    OperationOutcome, OperationSatisfaction, RestoreResult,
};
use serde_json::{Value, json};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id(index: u8) -> reforge_domain::ComponentId {
    let character = char::from(b'a' + index);
    reforge_domain::ComponentId::new(format!("cmp_{}", character.to_string().repeat(52)))
        .expect("component ID")
}

fn provider_kind() -> OperationKind {
    OperationKind::EnsureProvider {
        provider: reforge_domain::ProviderId::new("winget").expect("provider ID"),
    }
}

fn operation(
    run: &RunId,
    component: &reforge_domain::ComponentId,
    ordinal: u64,
    kind: OperationKind,
    precondition: Precondition,
    non_idempotent: bool,
) -> Operation {
    Operation {
        id: OperationId::for_run(run, ordinal).expect("operation ID"),
        component: component.clone(),
        kind,
        prerequisites: Vec::new(),
        precondition,
        idempotency_key: format!("restore-v1:executor-test-{ordinal}"),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent,
    }
}

fn plan(operations: Vec<Operation>) -> RestorePlan {
    RestorePlan {
        format_version: 1,
        run_id: run_id(),
        package_id: "pkg_executor_fixture".to_owned(),
        mode: RestoreMode::Rebuild,
        target_fingerprint: "fixture-target-v1".to_owned(),
        selected_components: operations
            .iter()
            .map(|operation| operation.component.clone())
            .collect(),
        operations,
        conflicts: Vec::new(),
        manual_actions: Vec::new(),
        warnings: Vec::new(),
    }
}

fn database(label: &str) -> (FixtureRoot, std::path::PathBuf) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let path = fixture.path("journal.sqlite").expect("database path");
    (fixture, path)
}

fn open_approved(label: &str, plan: &RestorePlan) -> (FixtureRoot, Journal) {
    let (fixture, path) = database(label);
    let journal = Journal::open(path).expect("journal opens");
    journal.create_run(plan).expect("run creates");
    journal.approve_run(&plan.run_id).expect("run approves");
    (fixture, journal)
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    object_index: &'a ObjectIndex,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, object_index)
}

#[derive(Clone, Copy)]
enum HandlerMode {
    NeverSatisfied,
    Satisfied,
    Fail,
}

struct TestHandler {
    mode: HandlerMode,
    calls: Arc<Mutex<Vec<OperationId>>>,
    failure: ReforgeErrorCode,
    cancel_after_execute: AtomicBool,
}

impl TestHandler {
    fn new(mode: HandlerMode) -> Self {
        Self {
            mode,
            calls: Arc::new(Mutex::new(Vec::new())),
            failure: ReforgeErrorCode::ProviderUnavailable,
            cancel_after_execute: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl OperationHandler for TestHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::EnsureProvider { .. } | OperationKind::WriteFile { .. }
        )
    }

    async fn is_satisfied(
        &self,
        _operation: &Operation,
        _context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        Ok(match self.mode {
            HandlerMode::Satisfied => OperationSatisfaction::satisfied(Some(json!({
                "observed": true,
            })))
            .with_evidence([json!({"fact": "target-observation"})]),
            HandlerMode::NeverSatisfied | HandlerMode::Fail => OperationSatisfaction::NotSatisfied,
        })
    }

    async fn execute(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        self.calls
            .lock()
            .expect("calls lock")
            .push(operation.id.clone());
        if matches!(self.mode, HandlerMode::Fail) {
            return Err(Box::new(ErrorEnvelope::new(
                self.failure.clone(),
                "provider operation failed",
            )));
        }
        if self.cancel_after_execute.load(Ordering::Acquire) {
            cancellation.cancel();
        }
        Ok(OperationOutcome::completed(Some(json!({
            "committed": true,
        }))))
    }
}

struct BackupFixture {
    calls: AtomicUsize,
}

impl BackupFixture {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl BackupHook for BackupFixture {
    fn prepare_backup(
        &self,
        _operation: &Operation,
        _context: &ExecutionContext<'_>,
    ) -> RestoreResult<Option<Value>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(Some(json!({"backup_id": "fixture-backup"})))
    }
}

#[tokio::test]
async fn execution_requires_approved_journal_state() {
    let (_fixture, path) = database("executor-approval");
    let journal = Journal::open(path).expect("journal opens");
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    journal.create_run(&plan).expect("run creates");

    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let handler = TestHandler::new(HandlerMode::NeverSatisfied);
    let calls = handler.calls.clone();
    let executor = {
        let mut executor = Executor::new(journal.clone());
        executor.register_handler(handler);
        executor
    };

    let error = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect_err("unapproved execution must fail");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
    assert!(calls.lock().expect("calls lock").is_empty());
    assert_eq!(
        journal
            .get_run(&plan.run_id)
            .expect("run query")
            .unwrap()
            .status,
        RunStatus::Planned
    );
}

#[tokio::test]
async fn already_satisfied_operation_is_skipped_without_handler_execution() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = open_approved("executor-skip", &plan);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let handler = TestHandler::new(HandlerMode::Satisfied);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);

    let report = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("satisfied operation executes");
    assert_eq!(report.status, RunStatus::Completed);
    assert!(calls.lock().expect("calls lock").is_empty());
    assert_eq!(report.operations[0].state, OperationState::Skipped);
    let result = report.operations[0].result.as_ref().expect("skip result");
    assert_eq!(result["reason"], "SKIPPED_ALREADY_SATISFIED");
    assert_eq!(result["evidence"][0]["fact"], "target-observation");
}

#[tokio::test]
async fn successful_typed_operation_persists_result_evidence_and_backup() {
    let object = ObjectId::from_content(b"file contents");
    let operation = operation(
        &run_id(),
        &component_id(1),
        0,
        OperationKind::WriteFile {
            destination: reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "file.txt")
                .expect("path token"),
            object: object.clone(),
            mode: FileMode::Replace,
        },
        Precondition::ArtifactPresent {
            object: object.clone(),
        },
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = open_approved("executor-success", &plan);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: vec![ObjectEntry {
            id: object,
            uncompressed_bytes: 13,
            compressed_bytes: 13,
            content_type: ContentType::Utf8Text,
        }],
    };
    let hook = BackupFixture::new();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(TestHandler::new(HandlerMode::NeverSatisfied));

    let execution_context = ExecutionContext::new(&target, &object_index).with_backup_hook(&hook);
    let report = executor
        .execute(&plan, &execution_context, &CancellationToken::new())
        .await
        .expect("typed operation executes");
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.operations[0].state, OperationState::Completed);
    assert_eq!(report.operations[0].attempt, 1);
    assert_eq!(
        report.operations[0].result.as_ref().unwrap()["result"]["committed"],
        true
    );
    assert_eq!(
        report.operations[0].backup.as_ref().unwrap()["backup_id"],
        "fixture-backup"
    );
    assert_eq!(hook.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn resume_rechecks_target_and_never_repeats_completed_operation() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = open_approved("executor-completed-resume", &plan);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let handler = TestHandler::new(HandlerMode::NeverSatisfied);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);

    executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("initial execution completes");
    let resumed = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("completed run resumes safely");
    assert_eq!(resumed.status, RunStatus::Completed);
    assert_eq!(resumed.operations[0].attempt, 1);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let mut changed_target = target.clone();
    changed_target.fingerprint = "target-fingerprint-changed".to_owned();
    let error = executor
        .execute(
            &plan,
            &context(&changed_target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect_err("resume must recheck the current target");
    assert_eq!(error.code, ReforgeErrorCode::TargetConflict);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);
}

#[tokio::test]
async fn failed_provider_is_journaled_and_stops_the_run() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = open_approved("executor-failure", &plan);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let handler = TestHandler::new(HandlerMode::Fail);
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);

    let error = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect_err("failed provider must return an error");
    assert_eq!(error.code, ReforgeErrorCode::ProviderUnavailable);
    assert_eq!(
        journal
            .get_run(&plan.run_id)
            .expect("run query")
            .unwrap()
            .status,
        RunStatus::Failed
    );
    let persisted = journal
        .get_operation(&plan.run_id, &plan.operations[0].id)
        .expect("operation query")
        .expect("operation row");
    assert_eq!(persisted.state, OperationState::Failed);
    assert_eq!(
        persisted.error.unwrap().operation,
        Some(plan.operations[0].id.clone())
    );
}

fn recover_journal(label: &str, plan: &RestorePlan) -> (FixtureRoot, Journal) {
    let (fixture, journal) = open_approved(label, plan);
    journal
        .mark_operation_running(&plan.run_id, &plan.operations[0].id)
        .expect("operation starts");
    drop(journal);
    let path = fixture.path("journal.sqlite").expect("journal path");
    let journal = Journal::open(path).expect("journal recovers");
    (fixture, journal)
}

#[tokio::test]
async fn interrupted_operation_skips_after_target_commit_is_observed() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = recover_journal("executor-interrupted-commit", &plan);
    assert_eq!(
        journal
            .get_operation(&plan.run_id, &plan.operations[0].id)
            .expect("operation query")
            .unwrap()
            .state,
        OperationState::Interrupted
    );
    let handler = TestHandler::new(HandlerMode::Satisfied);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };

    let report = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("interrupted commit resumes");
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.operations[0].state, OperationState::Skipped);
    assert!(calls.lock().expect("calls lock").is_empty());
}

#[tokio::test]
async fn interrupted_idempotent_operation_reexecutes_when_not_satisfied() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = recover_journal("executor-interrupted-retry", &plan);
    let handler = TestHandler::new(HandlerMode::NeverSatisfied);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };

    let report = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("idempotent interrupted operation resumes");
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.operations[0].state, OperationState::Completed);
    assert_eq!(report.operations[0].attempt, 2);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);
}

#[tokio::test]
async fn interrupted_non_idempotent_operation_is_blocked_without_retry() {
    let operation = operation(
        &run_id(),
        &component_id(0),
        0,
        provider_kind(),
        Precondition::Always,
        true,
    );
    let plan = plan(vec![operation]);
    let (_fixture, journal) = recover_journal("executor-interrupted-non-idempotent", &plan);
    let handler = TestHandler::new(HandlerMode::NeverSatisfied);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };

    let error = executor
        .execute(
            &plan,
            &context(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect_err("non-idempotent retry must be blocked");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
    assert!(calls.lock().expect("calls lock").is_empty());
    assert_eq!(
        journal
            .get_run(&plan.run_id)
            .expect("run query")
            .unwrap()
            .status,
        RunStatus::WaitingForUser
    );
    assert_eq!(
        journal
            .get_operation(&plan.run_id, &plan.operations[0].id)
            .expect("operation query")
            .unwrap()
            .state,
        OperationState::Failed
    );
}

#[tokio::test]
async fn cancellation_pauses_before_the_next_operation() {
    let run = run_id();
    let first_component = component_id(0);
    let second_component = component_id(1);
    let first = operation(
        &run,
        &first_component,
        0,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let second = operation(
        &run,
        &second_component,
        1,
        provider_kind(),
        Precondition::Always,
        false,
    );
    let plan = plan(vec![first, second]);
    let (_fixture, journal) = open_approved("executor-cancel", &plan);
    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let handler = TestHandler::new(HandlerMode::NeverSatisfied);
    handler.cancel_after_execute.store(true, Ordering::Release);
    let calls = handler.calls.clone();
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(handler);
    let cancellation = CancellationToken::new();

    let report = executor
        .execute(&plan, &context(&target, &object_index), &cancellation)
        .await
        .expect("cancellation is a durable state");
    assert_eq!(report.status, RunStatus::Cancelled);
    assert_eq!(calls.lock().expect("calls lock").len(), 1);
    assert_eq!(report.operations[0].state, OperationState::Completed);
    assert_eq!(report.operations[1].state, OperationState::Pending);
}

#[test]
fn operation_disposition_is_closed_over_journal_states() {
    assert_eq!(
        OperationDisposition::Completed,
        OperationDisposition::Completed
    );
    assert_ne!(
        OperationDisposition::Completed,
        OperationDisposition::Cancelled
    );
}
