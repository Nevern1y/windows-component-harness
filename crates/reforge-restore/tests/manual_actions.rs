#![allow(dead_code)]

mod support;

use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use reforge_domain::{
    ComponentId, ManualAction, ManualActionState, ObjectIndex, Operation, OperationId,
    OperationKind, Precondition, ReforgeErrorCode, RestoreMode, RestorePlan, RiskLevel, RunId,
};
use reforge_package::{
    EncryptedVault, SecretKind, SecretRecord, SecretSelection, SecretString, SecretTarget,
    VaultDocument,
};
use reforge_platform_windows::CancellationToken;
use reforge_restore::{
    ExecutionContext, Executor, Journal, ManualActionHandler, ManualActionQueue, OperationHandler,
    OperationOutcome, RestoreResult, SecretRestoreAdapter, SecretRestoreGate,
};
use serde_json::json;
use support::FixtureRoot;

const PASSPHRASE: &str = "correct horse battery staple";
const SECRET_VALUE: &[u8] = b"secret-value-never-in-report";

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id(character: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", character.to_string().repeat(52))).expect("component ID")
}

fn action(id: &str, component: Option<ComponentId>) -> ManualAction {
    ManualAction {
        id: id.to_owned(),
        component,
        title: "Sign in to the restored tool".to_owned(),
        reason: "The tool keeps account-bound state outside the portable configuration".to_owned(),
        risk: RiskLevel::High,
        instructions: vec![
            "Open the tool after configuration restore".to_owned(),
            "Complete the supported sign-in flow".to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

fn database(label: &str) -> (FixtureRoot, Journal) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let path = fixture.path("journal.sqlite").expect("journal path");
    let journal = Journal::open(path).expect("journal opens");
    (fixture, journal)
}

fn plan(run: &RunId, operations: Vec<Operation>, manual_actions: Vec<ManualAction>) -> RestorePlan {
    RestorePlan {
        format_version: 1,
        run_id: run.clone(),
        package_id: "pkg_manual_action_fixture".to_owned(),
        mode: RestoreMode::Rebuild,
        target_fingerprint: "fixture-target-v1".to_owned(),
        selected_components: operations
            .iter()
            .map(|operation| operation.component.clone())
            .collect(),
        operations,
        conflicts: Vec::new(),
        manual_actions,
        warnings: Vec::new(),
    }
}

fn manual_operation(run: &RunId, component: &ComponentId, action: ManualAction) -> Operation {
    Operation {
        id: OperationId::for_run(run, 1).expect("manual operation ID"),
        component: component.clone(),
        kind: OperationKind::OpenManualAction { action },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:manual-action-operation".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn provider_operation(
    run: &RunId,
    component: &ComponentId,
    ordinal: u64,
    provider: &str,
) -> Operation {
    Operation {
        id: OperationId::for_run(run, ordinal).expect("provider operation ID"),
        component: component.clone(),
        kind: OperationKind::EnsureProvider {
            provider: reforge_domain::ProviderId::new(provider).expect("provider ID"),
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: format!("restore-v1:provider-operation:{provider}"),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl OperationHandler for CountingProvider {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::EnsureProvider { .. })
    }

    async fn execute(
        &self,
        _operation: &Operation,
        _context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(OperationOutcome::completed(Some(json!({
            "provider": "fixture",
        }))))
    }
}

struct RuntimeBlockingProvider {
    blocker_calls: Arc<AtomicUsize>,
    independent_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl OperationHandler for RuntimeBlockingProvider {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::EnsureProvider { .. })
    }

    async fn execute(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        let OperationKind::EnsureProvider { provider } = &operation.kind else {
            return Ok(OperationOutcome::completed(None));
        };
        if provider.as_str() == "blocked" {
            if self.blocker_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                return Ok(OperationOutcome::waiting_for_user(Some(json!({
                    "manual_action_required": true,
                    "reason": "provider credential token=runtime-secret-97531 must be refreshed",
                }))));
            }
            return Ok(OperationOutcome::completed(Some(json!({
                "provider": "blocked",
            }))));
        }
        self.independent_calls.fetch_add(1, Ordering::AcqRel);
        Ok(OperationOutcome::completed(Some(json!({
            "provider": provider.as_str(),
        }))))
    }
}

struct RecordingSecretAdapter {
    secure: bool,
    policy_checks: Cell<usize>,
    restores: Vec<(ComponentId, usize)>,
}

impl RecordingSecretAdapter {
    fn insecure() -> Self {
        Self {
            secure: false,
            policy_checks: Cell::new(0),
            restores: Vec::new(),
        }
    }
}

impl SecretRestoreAdapter for RecordingSecretAdapter {
    fn secure_target_policy_proven(&self, _target: &SecretTarget) -> bool {
        self.policy_checks.set(self.policy_checks.get() + 1);
        self.secure
    }

    fn restore_secret(&mut self, record: &SecretRecord) -> RestoreResult<()> {
        self.restores
            .push((record.id.clone(), record.expose_value().len()));
        Ok(())
    }
}

fn encrypted_vault(target: SecretTarget) -> (EncryptedVault, ComponentId) {
    let id = component_id('s');
    let record = SecretRecord::new(
        id.clone(),
        "fixture token",
        SecretKind::ApiToken,
        target,
        SECRET_VALUE.to_vec().into(),
    )
    .expect("secret record");
    let document = VaultDocument::new(vec![record]).expect("vault document");
    let pending = document
        .encrypt(SecretString::from(PASSPHRASE.to_owned()), false)
        .expect("vault encryption");
    (pending.finish().expect("encrypted vault"), id)
}

#[test]
fn action_persistence_is_monotonic_and_redacted() {
    let (_fixture, journal) = database("manual-action-persistence");
    let run = run_id();
    let run_plan = plan(&run, Vec::new(), Vec::new());
    journal.create_run(&run_plan).expect("run creates");

    let mut queued = action("manual-reauth", None);
    queued.reason = "token=manual-secret-884422".to_owned();
    let queue = ManualActionQueue::new(journal.clone());
    let created = queue.create(&run, &queued).expect("action creates");
    assert_eq!(created.state, ManualActionState::Pending);
    assert!(!created.reason.contains("manual-secret-884422"));

    let same = queue.create(&run, &queued).expect("retry is idempotent");
    assert_eq!(same.id, created.id);
    assert_eq!(queue.pending(&run).expect("pending query").len(), 1);
    assert_eq!(queue.unresolved(&run).expect("unresolved query").len(), 1);

    let acknowledged = queue
        .acknowledge(&run, &created.id)
        .expect("acknowledgement persists");
    assert_eq!(acknowledged.state, ManualActionState::Acknowledged);
    assert!(acknowledged.acknowledged_at.is_some());
    let completed = queue
        .complete(&run, &created.id)
        .expect("completion persists");
    assert_eq!(completed.state, ManualActionState::Completed);
    let skipped_action = action("manual-skip", None);
    queue
        .create(&run, &skipped_action)
        .expect("skip action creates");
    let skipped = queue.skip(&run, "manual-skip").expect("skip persists");
    assert_eq!(skipped.state, ManualActionState::Skipped);
    assert!(queue.unresolved(&run).expect("unresolved query").is_empty());

    assert!(queue.pending(&run).expect("pending query").is_empty());
    assert!(queue.unresolved(&run).expect("unresolved query").is_empty());

    let events = journal.list_events(&run).expect("event query");
    let event_text = events
        .iter()
        .map(|event| event.event.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!event_text.contains("manual-secret-884422"));
}

#[tokio::test]
async fn independent_operation_runs_before_manual_blocker_and_resume_continues() {
    let (_fixture, journal) = database("manual-action-independent");
    let run = run_id();
    let manual_component = component_id('m');
    let provider_component = component_id('p');
    let manual = action("manual-independent", Some(manual_component.clone()));
    let manual_operation = manual_operation(&run, &manual_component, manual.clone());
    let provider = provider_operation(&run, &provider_component, 0, "winget");
    let run_plan = plan(&run, vec![provider, manual_operation], vec![manual]);
    journal.create_run(&run_plan).expect("run creates");
    journal.approve_run(&run).expect("run approves");

    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(CountingProvider {
        calls: Arc::clone(&calls),
    });
    executor.register_handler(ManualActionHandler::new(journal.clone()));

    let first = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("first execution pauses for manual action");
    assert_eq!(first.status, reforge_domain::RunStatus::WaitingForUser);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(
        first.operations[0].state,
        reforge_domain::OperationState::Completed
    );
    assert_eq!(
        first.operations[1].state,
        reforge_domain::OperationState::WaitingForUser
    );

    ManualActionQueue::new(journal.clone())
        .acknowledge(&run, "manual-independent")
        .expect("manual acknowledgement");
    let second = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("resume completes after acknowledgement");
    assert_eq!(second.status, reforge_domain::RunStatus::Completed);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(
        second.operations[1].state,
        reforge_domain::OperationState::Completed
    );
    assert_eq!(
        journal.list_manual_actions(&run).expect("action query")[0].state,
        ManualActionState::Completed
    );
}

#[tokio::test]
async fn runtime_blocker_is_durable_gated_and_allows_independent_work() {
    let (_fixture, journal) = database("runtime-manual-blocker");
    let run = run_id();
    let blocked_component = component_id('b');
    let independent_component = component_id('i');
    let blocked = provider_operation(&run, &blocked_component, 0, "blocked");
    let independent = provider_operation(&run, &independent_component, 1, "independent");
    let run_plan = plan(&run, vec![blocked.clone(), independent], Vec::new());
    journal.create_run(&run_plan).expect("run creates");
    journal.approve_run(&run).expect("run approves");

    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let blocker_calls = Arc::new(AtomicUsize::new(0));
    let independent_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(RuntimeBlockingProvider {
        blocker_calls: Arc::clone(&blocker_calls),
        independent_calls: Arc::clone(&independent_calls),
    });

    let first = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("runtime blocker pauses after independent work");
    assert_eq!(first.status, reforge_domain::RunStatus::WaitingForUser);
    assert_eq!(blocker_calls.load(Ordering::Acquire), 1);
    assert_eq!(independent_calls.load(Ordering::Acquire), 1);
    let actions = journal
        .list_manual_actions(&run)
        .expect("manual actions query");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].id, format!("operation-blocker:{}:1", blocked.id));
    assert_eq!(actions[0].state, ManualActionState::Pending);
    assert!(!actions[0].reason.contains("runtime-secret-97531"));

    let pending = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("pending action keeps the run paused");
    assert_eq!(pending.status, reforge_domain::RunStatus::WaitingForUser);
    assert_eq!(blocker_calls.load(Ordering::Acquire), 1);
    assert_eq!(independent_calls.load(Ordering::Acquire), 1);

    ManualActionQueue::new(journal.clone())
        .acknowledge(&run, &actions[0].id)
        .expect("acknowledgement persists");
    let completed = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("acknowledged runtime blocker retries");
    assert_eq!(completed.status, reforge_domain::RunStatus::Completed);
    assert_eq!(blocker_calls.load(Ordering::Acquire), 2);
    assert_eq!(independent_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        journal.list_manual_actions(&run).expect("action query")[0].state,
        ManualActionState::Completed
    );
}

#[tokio::test]
async fn skipped_runtime_blocker_skips_the_waiting_operation() {
    let (_fixture, journal) = database("runtime-manual-skip");
    let run = run_id();
    let component = component_id('k');
    let blocked = provider_operation(&run, &component, 0, "blocked");
    let run_plan = plan(&run, vec![blocked.clone()], Vec::new());
    journal.create_run(&run_plan).expect("run creates");
    journal.approve_run(&run).expect("run approves");

    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let blocker_calls = Arc::new(AtomicUsize::new(0));
    let independent_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(RuntimeBlockingProvider {
        blocker_calls: Arc::clone(&blocker_calls),
        independent_calls,
    });

    let waiting = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("runtime blocker waits");
    assert_eq!(waiting.status, reforge_domain::RunStatus::WaitingForUser);
    let action = journal
        .list_manual_actions(&run)
        .expect("manual action query")
        .pop()
        .expect("runtime action");
    ManualActionQueue::new(journal.clone())
        .skip(&run, &action.id)
        .expect("skip persists");

    let completed = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("skipped action completes the run");
    assert_eq!(completed.status, reforge_domain::RunStatus::Completed);
    assert_eq!(blocker_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        journal
            .get_operation(&run, &blocked.id)
            .expect("operation query")
            .expect("operation")
            .state,
        reforge_domain::OperationState::Skipped
    );
}

#[test]
fn wrong_vault_input_is_generic_and_secret_free() {
    let (_fixture, journal) = database("manual-action-wrong-vault");
    let run = run_id();
    journal
        .create_run(&plan(&run, Vec::new(), Vec::new()))
        .expect("run creates");
    let (vault, id) = encrypted_vault(SecretTarget::WindowsCredentialManager);
    let selection = SecretSelection::new([id]).expect("selection");
    let gate = SecretRestoreGate::new(journal);
    let mut adapter = RecordingSecretAdapter::insecure();

    let error = gate
        .restore_with_passphrase(
            &run,
            &vault,
            &selection,
            SecretString::from("wrong-passphrase-with-secret".to_owned()),
            &mut adapter,
        )
        .expect_err("wrong vault input must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::VaultDecryptFailed);
    let error_text = error.to_json();
    assert!(!error_text.contains("wrong-passphrase-with-secret"));
    assert!(!error_text.contains(std::str::from_utf8(SECRET_VALUE).expect("UTF-8 fixture")));
    assert!(adapter.restores.is_empty());
}

#[test]
fn plaintext_target_creates_warning_and_manual_action_without_adapter_write() {
    let (_fixture, journal) = database("manual-action-plaintext-target");
    let run = run_id();
    journal
        .create_run(&plan(&run, Vec::new(), Vec::new()))
        .expect("run creates");
    let (vault, id) = encrypted_vault(SecretTarget::EnvironmentVariable {
        name: "FIXTURE_SECRET".to_owned(),
    });
    let selection = SecretSelection::new([id.clone()]).expect("selection");
    let gate = SecretRestoreGate::new(journal.clone());
    let mut adapter = RecordingSecretAdapter::insecure();

    let report = gate
        .restore_with_passphrase(
            &run,
            &vault,
            &selection,
            SecretString::from(PASSPHRASE.to_owned()),
            &mut adapter,
        )
        .expect("plaintext target is a manual result");
    assert!(report.restored.is_empty());
    assert_eq!(report.manual_actions.len(), 1);
    assert_eq!(report.manual_actions[0].state, ManualActionState::Pending);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("no plaintext value was written"))
    );
    assert!(adapter.restores.is_empty());
    assert_eq!(adapter.policy_checks.get(), 1);
    let persisted = journal
        .list_manual_actions(&run)
        .expect("manual action query");
    assert_eq!(persisted.len(), 1);
    let second_run =
        RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e32".to_owned()).expect("second run ID");
    journal
        .create_run(&plan(&second_run, Vec::new(), Vec::new()))
        .expect("second run creates");
    let mut second_adapter = RecordingSecretAdapter::insecure();
    let second_report = gate
        .restore_with_passphrase(
            &second_run,
            &vault,
            &selection,
            SecretString::from(PASSPHRASE.to_owned()),
            &mut second_adapter,
        )
        .expect("second plaintext target is a manual result");
    assert_eq!(second_report.manual_actions.len(), 1);
    assert_ne!(
        report.manual_actions[0].id,
        second_report.manual_actions[0].id
    );
    assert_eq!(
        journal
            .list_manual_actions(&second_run)
            .expect("second manual action query")
            .len(),
        1
    );
    let visible = serde_json::to_string(&report).expect("report JSON");
    assert!(!visible.contains(std::str::from_utf8(SECRET_VALUE).expect("UTF-8 fixture")));
}

#[tokio::test]
async fn reauthentication_action_completes_after_acknowledgement() {
    let (_fixture, journal) = database("manual-action-reauth");
    let run = run_id();
    let component = component_id('r');
    let manual = action("manual-reauth-completion", Some(component.clone()));
    let operation = manual_operation(&run, &component, manual.clone());
    let run_plan = plan(&run, vec![operation], vec![manual]);
    journal.create_run(&run_plan).expect("run creates");
    journal.approve_run(&run).expect("run approves");

    let target = support::fixtures::target_facts();
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(ManualActionHandler::new(journal.clone()));

    let waiting = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("manual action waits");
    assert_eq!(waiting.status, reforge_domain::RunStatus::WaitingForUser);

    let queue = ManualActionQueue::new(journal.clone());
    queue
        .acknowledge(&run, "manual-reauth-completion")
        .expect("acknowledgement persists");
    let completed = executor
        .execute(
            &run_plan,
            &ExecutionContext::new(&target, &object_index),
            &CancellationToken::new(),
        )
        .await
        .expect("resume completes reauthentication action");
    assert_eq!(completed.status, reforge_domain::RunStatus::Completed);
    assert_eq!(
        journal
            .get_operation(&run, &run_plan.operations[0].id)
            .expect("operation query")
            .expect("operation")
            .state,
        reforge_domain::OperationState::Completed
    );
    assert_eq!(
        journal.list_manual_actions(&run).expect("action query")[0].state,
        ManualActionState::Completed
    );
}
