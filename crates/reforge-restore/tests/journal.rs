#![allow(clippy::too_many_arguments, dead_code)]

mod support;

use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
    thread,
};

use chrono::{TimeZone, Utc};
use reforge_domain::{
    ApprovalState, ComponentId, ErrorEnvelope, ManualAction, ManualActionState, Operation,
    OperationId, OperationKind, OperationState, Precondition, RestoreMode, RestorePlan, RiskLevel,
    RunId, RunStatus,
};
use reforge_restore::Journal;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::json;
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID")
}

fn operation(run: &RunId, component: &ComponentId) -> Operation {
    Operation {
        id: OperationId::for_run(run, 0).expect("operation ID"),
        component: component.clone(),
        kind: OperationKind::EnsureProvider {
            provider: reforge_domain::ProviderId::new("winget").expect("provider ID"),
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:operation-key".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn plan(with_manual_action: bool) -> RestorePlan {
    let run = run_id();
    let component = component_id();
    RestorePlan {
        format_version: 1,
        run_id: run,
        package_id: "pkg_journal_fixture".to_owned(),
        mode: RestoreMode::Rebuild,
        target_fingerprint: "target-fingerprint".to_owned(),
        selected_components: vec![component.clone()],
        operations: vec![operation(&run_id(), &component)],
        conflicts: Vec::new(),
        manual_actions: if with_manual_action {
            vec![ManualAction {
                id: "manual-action".to_owned(),
                component: Some(component),
                title: "Sign in".to_owned(),
                reason: "The provider requires user authentication".to_owned(),
                risk: RiskLevel::Medium,
                instructions: vec!["Complete sign-in in the provider UI".to_owned()],
                docs_url: None,
                state: ManualActionState::Pending,
                independent_operations_may_continue: true,
                acknowledged_at: None,
                verification: None,
            }]
        } else {
            Vec::new()
        },
        warnings: Vec::new(),
    }
}

fn database(label: &str) -> (FixtureRoot, std::path::PathBuf) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let path = fixture.path("journal.sqlite").expect("database path");
    (fixture, path)
}

#[test]
fn migration_enables_wal_foreign_keys_and_read_only_queries() {
    let (_fixture, path) = database("journal-migration");
    let journal = Journal::open(&path).expect("journal opens");
    let reader = journal.reader().expect("read-only reader opens");
    assert_eq!(
        reader.list_events(&run_id()).expect("empty event query"),
        Vec::new()
    );
    let foreign_key_error = journal
        .append_event(&run_id(), "INFO", &json!({"type": "orphan"}))
        .expect_err("foreign keys reject events for an unknown run");
    assert_eq!(
        foreign_key_error.code,
        reforge_domain::ReforgeErrorCode::OperationFailed
    );

    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("raw read-only connection");
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

    for table in ["runs", "operations", "events", "manual_actions"] {
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .expect("table query");
        assert_eq!(exists, 1, "missing table {table}");
    }
}

#[test]
fn plan_and_lifecycle_rows_are_durable_and_approval_gated() {
    let (_fixture, path) = database("journal-lifecycle");
    let journal = Journal::open(&path).expect("journal opens");
    let plan = plan(true);
    let created_at = Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap();
    let created = journal
        .create_run_at(&plan, created_at)
        .expect("run creates atomically");
    assert_eq!(created.status, RunStatus::Planned);
    assert_eq!(created.approval_state, ApprovalState::Pending);
    assert!(
        journal
            .set_run_status(&created.id, RunStatus::Running)
            .expect_err("unapproved run must not run")
            .code
            == reforge_domain::ReforgeErrorCode::SecurityPolicy
    );

    let approved_at = created_at + chrono::Duration::seconds(1);
    let approved = journal
        .set_approval_at(&created.id, ApprovalState::Approved, approved_at)
        .expect("approval persists");
    assert_eq!(approved.approved_at, Some(approved_at));
    journal
        .require_approved(&created.id)
        .expect("approved run is executable");

    let operation_id = plan.operations[0].id.clone();
    let started_at = approved_at + chrono::Duration::seconds(1);
    let running = journal
        .transition_operation_at(
            &created.id,
            &operation_id,
            OperationState::Running,
            None,
            None,
            None,
            started_at,
        )
        .expect("operation starts");
    assert_eq!(running.state, OperationState::Running);
    assert_eq!(running.attempt, 1);
    let ended_at = started_at + chrono::Duration::seconds(2);
    let completed = journal
        .transition_operation_at(
            &created.id,
            &operation_id,
            OperationState::Completed,
            Some(json!({"status": "ok"})),
            None,
            Some(json!({"backup": "none"})),
            ended_at,
        )
        .expect("operation completes");
    assert_eq!(completed.state, OperationState::Completed);
    assert_eq!(completed.ended_at, Some(ended_at));
    assert_eq!(completed.result, Some(json!({"status": "ok"})));

    let persisted = journal
        .get_run(&created.id)
        .expect("run query")
        .expect("run");
    assert_eq!(persisted.approval_state, ApprovalState::Approved);
    let operations = journal
        .list_operations(&created.id)
        .expect("operation query");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].state, OperationState::Completed);
    let actions = journal
        .list_manual_actions(&created.id)
        .expect("manual-action query");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Sign in");
    assert!(
        journal
            .acknowledge_manual_action(&created.id, "manual-action")
            .expect("acknowledge action")
            .acknowledged_at
            .is_some()
    );
}

#[test]
fn concurrent_event_writes_are_serialized_and_redacted() {
    let (_fixture, path) = database("journal-concurrency");
    let journal = Arc::new(Journal::open(&path).expect("journal opens"));
    let plan = plan(false);
    let run = journal.create_run(&plan).expect("run creates");

    let mut workers = Vec::new();
    for worker in 0..8 {
        let journal = Arc::clone(&journal);
        let run_id = run.id.clone();
        workers.push(thread::spawn(move || {
            (0..10)
                .map(|event| {
                    journal
                        .append_event(
                            &run_id,
                            "INFO",
                            &json!({
                                "worker": worker,
                                "event": event,
                                "api_key": "super-secret-value",
                                "path": "C:\\Users\\Alice\\secret.txt",
                            }),
                        )
                        .expect("event append")
                })
                .collect::<Vec<_>>()
        }));
    }
    let sequences = workers
        .into_iter()
        .flat_map(|worker| worker.join().expect("worker join"))
        .collect::<Vec<_>>();
    let unique = sequences.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(sequences.len(), 80);
    assert_eq!(unique.len(), 80, "SQLite sequence numbers must be unique");

    let events = journal.list_events(&run.id).expect("event query");
    assert_eq!(events.len(), 81, "one creation event plus worker events");
    assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    assert!(events.iter().skip(1).all(|event| {
        event.event["api_key"] == "<REDACTED>" && event.event["path"] == "<PATH>"
    }));

    let connection = Connection::open(&path).expect("raw inspection connection");
    let stored: String = connection
        .query_row(
            "SELECT event_json FROM events WHERE run_id = ?1 AND event_json LIKE '%REDACTED%' LIMIT 1",
            params![run.id.to_string()],
            |row| row.get(0),
        )
        .expect("redacted event row");
    assert!(!stored.contains("super-secret-value"));
}

#[test]
fn concurrent_readers_observe_durable_state_while_writer_commits() {
    let (_fixture, path) = database("journal-readers");
    let journal = Arc::new(Journal::open(&path).expect("journal opens"));
    let run = journal.create_run(&plan(false)).expect("run creates");
    let barrier = Arc::new(Barrier::new(9));
    let mut readers = Vec::new();

    for _ in 0..8 {
        let journal = Arc::clone(&journal);
        let barrier = Arc::clone(&barrier);
        let run_id = run.id.clone();
        readers.push(thread::spawn(move || {
            let reader = journal.reader().expect("reader opens");
            barrier.wait();
            let persisted = reader
                .get_run(&run_id)
                .expect("reader sees durable run")
                .expect("run exists");
            let events = reader.list_events(&run_id).expect("reader lists events");
            (persisted, events.len())
        }));
    }

    barrier.wait();
    journal
        .append_event(&run.id, "INFO", &json!({"type": "concurrent_write"}))
        .expect("writer commits while readers query");

    for reader in readers {
        let (persisted, event_count) = reader.join().expect("reader joins");
        assert_eq!(persisted.id, run.id);
        assert!(event_count >= 1, "reader sees the creation event");
    }
}

#[test]
fn running_operations_are_marked_interrupted_on_reopen() {
    let (_fixture, path) = database("journal-recovery");
    let plan = plan(false);
    let run_id = plan.run_id.clone();
    let operation_id = plan.operations[0].id.clone();
    {
        let journal = Journal::open(&path).expect("journal opens");
        journal.create_run(&plan).expect("run creates");
        journal.approve_run(&run_id).expect("run approves");
        journal
            .mark_operation_running(&run_id, &operation_id)
            .expect("operation starts");
    }

    let journal = Journal::open(&path).expect("journal reopens");
    let operation = journal
        .get_operation(&run_id, &operation_id)
        .expect("operation query")
        .expect("operation");
    assert_eq!(operation.state, OperationState::Interrupted);
    let run = journal.get_run(&run_id).expect("run query").expect("run");
    assert_eq!(run.status, RunStatus::Interrupted);
    assert_eq!(run.approval_state, ApprovalState::Approved);
}

#[test]
fn duplicate_operation_keys_and_corrupt_schema_fail_closed() {
    let (_fixture, path) = database("journal-corruption");
    let plan = plan(false);
    let journal = Journal::open(&path).expect("journal opens");
    journal.create_run(&plan).expect("first run creates");

    let alternate_run = RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e32".to_owned())
        .expect("alternate run ID");
    let mut duplicate_key_plan = plan.clone();
    duplicate_key_plan.run_id = alternate_run.clone();
    duplicate_key_plan.operations[0].id =
        OperationId::for_run(&alternate_run, 0).expect("alternate operation ID");
    let duplicate = journal
        .create_run(&duplicate_key_plan)
        .expect_err("duplicate operation key must fail");
    assert_eq!(
        duplicate.code,
        reforge_domain::ReforgeErrorCode::OperationFailed
    );
    drop(journal);

    let connection = Connection::open(&path).expect("raw database");
    connection
        .execute("DROP TABLE operations", [])
        .expect("corrupt schema");
    drop(connection);
    let error = Journal::open(&path).expect_err("corrupt schema must block opening");
    assert_eq!(error.code, reforge_domain::ReforgeErrorCode::SchemaInvalid);
}

#[test]
fn operation_error_payload_is_redacted_before_persistence() {
    let (_fixture, path) = database("journal-error-redaction");
    let journal = Journal::open(&path).expect("journal opens");
    let plan = plan(false);
    let run = journal.create_run(&plan).expect("run creates");
    journal.approve_run(&run.id).expect("run approves");
    let operation = journal
        .mark_operation_running(&run.id, &plan.operations[0].id)
        .expect("operation starts");
    let error = ErrorEnvelope::new(
        reforge_domain::ReforgeErrorCode::OperationFailed,
        "provider failed with api_key=super-secret-value",
    );
    let completed = journal
        .transition_operation(
            &run.id,
            &operation.id,
            OperationState::Failed,
            None,
            Some(error),
            Some(json!({"path": "C:\\secret.txt"})),
        )
        .expect("failed operation persists");
    assert_eq!(completed.state, OperationState::Failed);
    let persisted = journal
        .get_operation(&run.id, &operation.id)
        .expect("operation query")
        .expect("operation");
    assert_eq!(
        persisted
            .error
            .as_ref()
            .and_then(|error| error.technical_detail.as_deref()),
        None,
        "the ErrorEnvelope constructor keeps the message safe and has no technical detail"
    );
    assert_eq!(persisted.backup.expect("backup")["path"], "<PATH>");
}
