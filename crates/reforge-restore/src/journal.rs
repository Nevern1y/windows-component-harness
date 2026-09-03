//! Durable SQLite journal for restore runs.
//!
//! The journal owns one write connection on one actor thread.  Query callers
//! receive independent read-only connections so a slow inspection cannot block
//! lifecycle writes.  Values crossing the journal boundary are serialized and
//! redacted before they are persisted; an unsafe payload is rejected.

use std::{
    any::Any,
    collections::BTreeSet,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use reforge_domain::{
    ApprovalState, ComponentId, ErrorEnvelope, ManualAction, ManualActionState, Operation,
    OperationId, OperationKind, OperationState, ReforgeErrorCode, RestoreMode, RestorePlan,
    RiskLevel, RunId, RunStatus, redaction::RedactionPolicy,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{RestoreResult, restore_error};

const JOURNAL_MIGRATION: &str = include_str!("../migrations/0001_initial.sql");
const JOURNAL_SCHEMA_VERSION: i64 = 1;
const JOURNAL_BUSY_TIMEOUT_MS: u64 = 5_000;
const MAX_RUN_TEXT_BYTES: usize = 4_096;
const MAX_OPERATION_KEY_BYTES: usize = 1_024;
const MAX_EVENT_LEVEL_BYTES: usize = 32;
const MAX_MANUAL_TEXT_BYTES: usize = 1_024;
const MAX_MANUAL_INSTRUCTIONS: usize = 256;

/// A persisted restore run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRun {
    pub id: RunId,
    pub package_id: String,
    pub mode: RestoreMode,
    pub target_fingerprint: String,
    pub status: RunStatus,
    pub approval_state: ApprovalState,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A persisted operation together with its lifecycle state.
#[derive(Clone, Debug, PartialEq)]
pub struct JournalOperation {
    pub id: OperationId,
    pub run_id: RunId,
    pub operation: Operation,
    pub state: OperationState,
    pub attempt: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
    pub error: Option<ErrorEnvelope>,
    pub backup: Option<Value>,
}

impl Eq for JournalOperation {}

impl JournalOperation {
    /// Return the stable operation key used by the journal's uniqueness gate.
    pub fn op_key(&self) -> &str {
        &self.operation.idempotency_key
    }
}

/// A journal event in insertion order.
#[derive(Clone, Debug, PartialEq)]
pub struct JournalEvent {
    pub seq: i64,
    pub run_id: RunId,
    pub time: DateTime<Utc>,
    pub level: String,
    pub event: Value,
}

impl Eq for JournalEvent {}

/// A persisted manual-action row.
///
/// The SQL contract intentionally stores only the action queue fields.  Rich
/// plan-only fields such as component and verification remain in the plan and
/// are not reconstructed from this row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalManualAction {
    pub id: String,
    pub run_id: RunId,
    pub state: ManualActionState,
    pub title: String,
    pub reason: String,
    pub risk: RiskLevel,
    pub instructions: Vec<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

impl JournalManualAction {
    /// Convert the durable queue row to the domain action shape.
    pub fn to_manual_action(&self) -> ManualAction {
        ManualAction {
            id: self.id.clone(),
            component: None,
            title: self.title.clone(),
            reason: self.reason.clone(),
            risk: self.risk.clone(),
            instructions: self.instructions.clone(),
            docs_url: None,
            state: self.state.clone(),
            independent_operations_may_continue: true,
            acknowledged_at: self.acknowledged_at,
            verification: None,
        }
    }
}

/// A journal with one serialized writer actor and read-only query accessors.
#[derive(Clone)]
pub struct Journal {
    writer: Arc<JournalWriter>,
}

impl fmt::Debug for Journal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Journal")
            .field("path", &self.writer.path)
            .finish()
    }
}

struct JournalWriter {
    path: PathBuf,
    sender: Sender<WriterCommand>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for JournalWriter {
    fn drop(&mut self) {
        let _ = self.sender.send(WriterCommand::Shutdown);
        if let Ok(mut handle) = self.handle.lock()
            && let Some(handle) = handle.take()
        {
            let _ = handle.join();
        }
    }
}

type WriterResult = Result<Box<dyn Any + Send>, Box<ErrorEnvelope>>;
type WriterJob = Box<dyn FnOnce(&mut Connection) -> WriterResult + Send + 'static>;

enum WriterCommand {
    Job {
        job: WriterJob,
        response: Sender<WriterResult>,
    },
    Shutdown,
}

impl Journal {
    /// Open or create the local journal and run the atomic schema migration.
    pub fn open(path: impl Into<PathBuf>) -> RestoreResult<Self> {
        let path = path.into();
        validate_journal_path(&path)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                Box::new(ErrorEnvelope::from_io_error(
                    &error,
                    "journal directory could not be created",
                ))
            })?;
        }

        let (sender, receiver) = mpsc::channel::<WriterCommand>();
        let (ready_sender, ready_receiver) = mpsc::sync_channel::<RestoreResult<()>>(1);
        let thread_path = path.clone();
        let handle = thread::Builder::new()
            .name("reforge-journal-writer".to_owned())
            .spawn(move || {
                let mut connection = match open_writer(&thread_path) {
                    Ok(connection) => {
                        let _ = ready_sender.send(Ok(()));
                        connection
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                        return;
                    }
                };
                writer_loop(&mut connection, receiver);
            })
            .map_err(|error| {
                restore_error(
                    ReforgeErrorCode::OperationFailed,
                    "journal writer could not be started",
                    Some(&error.to_string()),
                    None,
                    None,
                    None,
                )
            })?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                writer: Arc::new(JournalWriter {
                    path,
                    sender,
                    handle: Mutex::new(Some(handle)),
                }),
            }),
            Ok(Err(error)) => {
                let _ = handle.join();
                Err(error)
            }
            Err(_) => {
                let _ = handle.join();
                Err(journal_error(
                    ReforgeErrorCode::OperationFailed,
                    "journal writer stopped during initialization",
                ))
            }
        }
    }

    /// Return the filesystem path backing this journal.
    pub fn path(&self) -> &Path {
        &self.writer.path
    }

    /// Open an independent read-only query connection.
    pub fn reader(&self) -> RestoreResult<JournalReader> {
        JournalReader::open(&self.writer.path)
    }

    /// Alias for [`Journal::reader`].
    pub fn read(&self) -> RestoreResult<JournalReader> {
        self.reader()
    }

    /// Persist a plan and its initial operation/action rows atomically.
    pub fn create_run(&self, plan: &RestorePlan) -> RestoreResult<JournalRun> {
        self.create_run_at(plan, Utc::now())
    }

    /// Deterministic-time variant used by tests and reproducible callers.
    pub fn create_run_at(
        &self,
        plan: &RestorePlan,
        now: DateTime<Utc>,
    ) -> RestoreResult<JournalRun> {
        let plan = plan.clone();
        let now_text = timestamp(now);
        self.write(move |connection| create_run_record(connection, &plan, &now_text))
    }

    /// Set the approval state, recording the approval timestamp and event.
    pub fn set_approval(&self, run_id: &RunId, state: ApprovalState) -> RestoreResult<JournalRun> {
        self.set_approval_at(run_id, state, Utc::now())
    }

    /// Deterministic-time approval transition.
    pub fn set_approval_at(
        &self,
        run_id: &RunId,
        state: ApprovalState,
        now: DateTime<Utc>,
    ) -> RestoreResult<JournalRun> {
        let run_id = run_id.clone();
        let state_text = enum_text(&state, "approval state")?;
        let now_text = timestamp(now);
        self.write(move |connection| {
            set_approval_record(connection, &run_id, &state_text, &now_text)
        })
    }

    /// Approve a planned run for execution.
    pub fn approve_run(&self, run_id: &RunId) -> RestoreResult<JournalRun> {
        self.set_approval(run_id, ApprovalState::Approved)
    }

    /// Reject a planned run.
    pub fn reject_run(&self, run_id: &RunId) -> RestoreResult<JournalRun> {
        self.set_approval(run_id, ApprovalState::Rejected)
    }

    /// Move a planned run into the explicit approval-waiting state.
    pub fn wait_for_approval(&self, run_id: &RunId) -> RestoreResult<JournalRun> {
        self.set_run_status(run_id, RunStatus::WaitingForApproval)
    }

    /// Update the run lifecycle status and record a transition event.
    pub fn set_run_status(&self, run_id: &RunId, status: RunStatus) -> RestoreResult<JournalRun> {
        self.set_run_status_at(run_id, status, Utc::now())
    }

    /// Deterministic-time run status transition.
    pub fn set_run_status_at(
        &self,
        run_id: &RunId,
        status: RunStatus,
        now: DateTime<Utc>,
    ) -> RestoreResult<JournalRun> {
        let run_id = run_id.clone();
        let status_text = enum_text(&status, "run status")?;
        let now_text = timestamp(now);
        self.write(move |connection| {
            set_run_status_record(connection, &run_id, &status_text, &now_text)
        })
    }

    /// Return an error unless the journal run is explicitly approved.
    pub fn require_approved(&self, run_id: &RunId) -> RestoreResult<()> {
        let run = self.get_run(run_id)?.ok_or_else(|| {
            journal_error(ReforgeErrorCode::OperationFailed, "journal run not found")
        })?;
        if run.approval_state != ApprovalState::Approved {
            return Err(journal_error(
                ReforgeErrorCode::SecurityPolicy,
                "restore execution requires explicit journal approval",
            ));
        }
        Ok(())
    }

    /// Mark an operation as running and increment its attempt atomically.
    pub fn mark_operation_running(
        &self,
        run_id: &RunId,
        operation_id: &OperationId,
    ) -> RestoreResult<JournalOperation> {
        self.transition_operation(
            run_id,
            operation_id,
            OperationState::Running,
            None,
            None,
            None,
        )
    }

    /// Persist an operation state boundary, result, error, and backup metadata.
    pub fn transition_operation(
        &self,
        run_id: &RunId,
        operation_id: &OperationId,
        state: OperationState,
        result: Option<Value>,
        error: Option<ErrorEnvelope>,
        backup: Option<Value>,
    ) -> RestoreResult<JournalOperation> {
        self.transition_operation_at(
            run_id,
            operation_id,
            state,
            result,
            error,
            backup,
            Utc::now(),
        )
    }

    /// Deterministic-time operation state transition.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_operation_at(
        &self,
        run_id: &RunId,
        operation_id: &OperationId,
        state: OperationState,
        result: Option<Value>,
        error: Option<ErrorEnvelope>,
        backup: Option<Value>,
        now: DateTime<Utc>,
    ) -> RestoreResult<JournalOperation> {
        let run_id = run_id.clone();
        let operation_id = operation_id.clone();
        let state_text = enum_text(&state, "operation state")?;
        let result_text = result
            .as_ref()
            .map(|value| safe_json_text(value, "operation result"))
            .transpose()?;
        let error_text = error
            .as_ref()
            .map(|value| {
                let value = serde_json::to_value(value).map_err(|_| {
                    journal_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "operation error could not be serialized",
                    )
                })?;
                safe_json_text(&value, "operation error")
            })
            .transpose()?;
        let backup_text = backup
            .as_ref()
            .map(|value| safe_json_text(value, "operation backup"))
            .transpose()?;
        let now_text = timestamp(now);
        self.write(move |connection| {
            transition_operation_record(
                connection,
                &run_id,
                &operation_id,
                &state_text,
                result_text,
                error_text,
                backup_text,
                &now_text,
            )
        })
    }

    /// Append a redacted event and return its SQLite sequence number.
    pub fn append_event(&self, run_id: &RunId, level: &str, event: &Value) -> RestoreResult<i64> {
        self.append_event_at(run_id, level, event, Utc::now())
    }

    /// Deterministic-time event append.
    pub fn append_event_at(
        &self,
        run_id: &RunId,
        level: &str,
        event: &Value,
        now: DateTime<Utc>,
    ) -> RestoreResult<i64> {
        let run_id = run_id.clone();
        let level = bounded_text(level, MAX_EVENT_LEVEL_BYTES, "event level")?;
        let event_json = safe_json_text(event, "journal event")?;
        let now_text = timestamp(now);
        self.write(move |connection| {
            let tx = immediate_transaction(connection)?;
            let seq = insert_event_tx(&tx, &run_id, &level, &event_json, &now_text)?;
            tx.commit()
                .map_err(|error| sqlite_error("journal event commit failed", error))?;
            Ok(seq)
        })
    }

    /// Insert one manual action into an existing run.
    pub fn add_manual_action(
        &self,
        run_id: &RunId,
        action: &ManualAction,
    ) -> RestoreResult<JournalManualAction> {
        let run_id = run_id.clone();
        let action = action.clone();
        self.write(move |connection| add_manual_action_record(connection, &run_id, &action))
    }

    /// Transition a manual action and persist its acknowledgement timestamp.
    pub fn set_manual_action_state(
        &self,
        run_id: &RunId,
        action_id: &str,
        state: ManualActionState,
    ) -> RestoreResult<JournalManualAction> {
        self.set_manual_action_state_at(run_id, action_id, state, Utc::now())
    }

    /// Deterministic-time manual-action transition.
    pub fn set_manual_action_state_at(
        &self,
        run_id: &RunId,
        action_id: &str,
        state: ManualActionState,
        now: DateTime<Utc>,
    ) -> RestoreResult<JournalManualAction> {
        let run_id = run_id.clone();
        let action_id = bounded_text(action_id, MAX_MANUAL_TEXT_BYTES, "manual action ID")?;
        let state_text = enum_text(&state, "manual action state")?;
        let now_text = timestamp(now);
        self.write(move |connection| {
            set_manual_action_state_record(connection, &run_id, &action_id, &state_text, &now_text)
        })
    }

    /// Acknowledge a manual action without changing any other action data.
    pub fn acknowledge_manual_action(
        &self,
        run_id: &RunId,
        action_id: &str,
    ) -> RestoreResult<JournalManualAction> {
        self.set_manual_action_state(run_id, action_id, ManualActionState::Acknowledged)
    }

    /// Read one run through a fresh read-only connection.
    pub fn get_run(&self, run_id: &RunId) -> RestoreResult<Option<JournalRun>> {
        self.reader()?.get_run(run_id)
    }

    /// Read one operation through a fresh read-only connection.
    pub fn get_operation(
        &self,
        run_id: &RunId,
        operation_id: &OperationId,
    ) -> RestoreResult<Option<JournalOperation>> {
        self.reader()?.get_operation(run_id, operation_id)
    }

    /// Read all operations for a run in deterministic ID order.
    pub fn list_operations(&self, run_id: &RunId) -> RestoreResult<Vec<JournalOperation>> {
        self.reader()?.list_operations(run_id)
    }

    /// Read all events for a run in insertion order.
    pub fn list_events(&self, run_id: &RunId) -> RestoreResult<Vec<JournalEvent>> {
        self.reader()?.list_events(run_id)
    }

    /// Read all manual actions for a run in deterministic ID order.
    pub fn list_manual_actions(&self, run_id: &RunId) -> RestoreResult<Vec<JournalManualAction>> {
        self.reader()?.list_manual_actions(run_id)
    }

    fn write<T, F>(&self, job: F) -> RestoreResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> RestoreResult<T> + Send + 'static,
    {
        let (response_sender, response_receiver) = mpsc::channel::<WriterResult>();
        let job = Box::new(move |connection: &mut Connection| {
            job(connection).map(|value| Box::new(value) as Box<dyn Any + Send>)
        });
        self.writer
            .sender
            .send(WriterCommand::Job {
                job,
                response: response_sender,
            })
            .map_err(|_| {
                journal_error(
                    ReforgeErrorCode::OperationFailed,
                    "journal writer is unavailable",
                )
            })?;
        let result = response_receiver.recv().map_err(|_| {
            journal_error(
                ReforgeErrorCode::OperationFailed,
                "journal writer stopped before completing the write",
            )
        })?;
        let value = result?;
        value.downcast::<T>().map(|value| *value).map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "journal writer returned an unexpected value",
            )
        })
    }
}

/// A read-only SQLite view of a journal.
pub struct JournalReader {
    path: PathBuf,
    connection: Connection,
}

impl fmt::Debug for JournalReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalReader")
            .field("path", &self.path)
            .finish()
    }
}

impl JournalReader {
    fn open(path: &Path) -> RestoreResult<Self> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| sqlite_error("journal read connection could not open", error))?;
        configure_connection(&connection, true)?;
        validate_schema(&connection)?;
        Ok(Self {
            path: path.to_owned(),
            connection,
        })
    }

    /// Return the path backing this read-only view.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a run by ID.
    pub fn get_run(&self, run_id: &RunId) -> RestoreResult<Option<JournalRun>> {
        fetch_run(&self.connection, run_id)
    }

    /// Read an operation by run and operation ID.
    pub fn get_operation(
        &self,
        run_id: &RunId,
        operation_id: &OperationId,
    ) -> RestoreResult<Option<JournalOperation>> {
        fetch_operation(&self.connection, run_id, operation_id)
    }

    /// Read all operations for a run in deterministic ID order.
    pub fn list_operations(&self, run_id: &RunId) -> RestoreResult<Vec<JournalOperation>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, run_id, op_key, component_id, kind, state, attempt, \
                 requires_elevation, started_at, ended_at, input_json, result_json, \
                 error_json, backup_json FROM operations WHERE run_id = ?1 ORDER BY id ASC",
            )
            .map_err(|error| sqlite_error("journal operations query could not prepare", error))?;
        let rows = statement
            .query_map(params![run_id.to_string()], raw_operation_from_row)
            .map_err(|error| sqlite_error("journal operations query failed", error))?;
        rows.map(|row| {
            let raw =
                row.map_err(|error| sqlite_error("journal operation row could not read", error))?;
            parse_operation(raw, run_id)
        })
        .collect()
    }

    /// Read all events in SQLite sequence order.
    pub fn list_events(&self, run_id: &RunId) -> RestoreResult<Vec<JournalEvent>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT seq, run_id, time, level, event_json FROM events \
                 WHERE run_id = ?1 ORDER BY seq ASC",
            )
            .map_err(|error| sqlite_error("journal events query could not prepare", error))?;
        let rows = statement
            .query_map(params![run_id.to_string()], raw_event_from_row)
            .map_err(|error| sqlite_error("journal events query failed", error))?;
        rows.map(|row| {
            let raw =
                row.map_err(|error| sqlite_error("journal event row could not read", error))?;
            parse_event(raw, run_id)
        })
        .collect()
    }

    /// Read all manual actions in deterministic ID order.
    pub fn list_manual_actions(&self, run_id: &RunId) -> RestoreResult<Vec<JournalManualAction>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, run_id, state, title, reason, risk, instructions_json, \
                 acknowledged_at FROM manual_actions WHERE run_id = ?1 ORDER BY id ASC",
            )
            .map_err(|error| {
                sqlite_error("journal manual-action query could not prepare", error)
            })?;
        let rows = statement
            .query_map(params![run_id.to_string()], raw_manual_action_from_row)
            .map_err(|error| sqlite_error("journal manual-action query failed", error))?;
        rows.map(|row| {
            let raw = row
                .map_err(|error| sqlite_error("journal manual-action row could not read", error))?;
            parse_manual_action(raw, run_id)
        })
        .collect()
    }
}

fn writer_loop(connection: &mut Connection, receiver: Receiver<WriterCommand>) {
    while let Ok(command) = receiver.recv() {
        match command {
            WriterCommand::Shutdown => break,
            WriterCommand::Job { job, response } => {
                let _ = response.send(job(connection));
            }
        }
    }
}

fn open_writer(path: &Path) -> RestoreResult<Connection> {
    let mut connection = Connection::open(path)
        .map_err(|error| sqlite_error("journal write connection could not open", error))?;
    configure_connection(&connection, false)?;
    migrate(&mut connection)?;
    validate_schema(&connection)?;
    recover_running_operations(&mut connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection, read_only: bool) -> RestoreResult<()> {
    connection
        .busy_timeout(Duration::from_millis(JOURNAL_BUSY_TIMEOUT_MS))
        .map_err(|error| sqlite_error("journal busy timeout could not be configured", error))?;
    if read_only {
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA query_only = ON;")
            .map_err(|error| sqlite_error("journal read pragmas could not be configured", error))?;
    } else {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
            )
            .map_err(|error| {
                sqlite_error("journal write pragmas could not be configured", error)
            })?;
    }

    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| sqlite_error("journal foreign-key pragma could not be read", error))?;
    if foreign_keys != 1 {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "journal foreign-key enforcement is unavailable",
        ));
    }
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| sqlite_error("journal mode could not be read", error))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "journal must use SQLite WAL mode",
        ));
    }
    if read_only {
        let query_only: i64 = connection
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .map_err(|error| sqlite_error("journal query-only pragma could not be read", error))?;
        if query_only != 1 {
            return Err(journal_error(
                ReforgeErrorCode::SecurityPolicy,
                "journal reader is not query-only",
            ));
        }
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> RestoreResult<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| sqlite_error("journal schema version could not be read", error))?;
    if version > JOURNAL_SCHEMA_VERSION {
        return Err(journal_error(
            ReforgeErrorCode::UnsupportedVersion,
            "journal schema version is newer than this application",
        ));
    }
    if version == JOURNAL_SCHEMA_VERSION {
        return Ok(());
    }

    let tx = immediate_transaction(connection)?;
    tx.execute_batch(JOURNAL_MIGRATION)
        .map_err(|error| sqlite_error("journal schema migration failed", error))?;
    tx.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
        params![JOURNAL_SCHEMA_VERSION, timestamp(Utc::now())],
    )
    .map_err(|error| sqlite_error("journal migration record could not be written", error))?;
    tx.execute_batch("PRAGMA user_version = 1;")
        .map_err(|error| sqlite_error("journal schema version could not be stored", error))?;
    tx.commit()
        .map_err(|error| sqlite_error("journal migration commit failed", error))?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> RestoreResult<()> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| sqlite_error("journal schema version could not be read", error))?;
    if version != JOURNAL_SCHEMA_VERSION {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal schema version is not supported",
        ));
    }

    let required_tables: [(&str, &[&str]); 5] = [
        ("schema_migrations", &["version", "applied_at"]),
        (
            "runs",
            &[
                "id",
                "package_id",
                "mode",
                "target_fingerprint",
                "status",
                "approval_state",
                "approved_at",
                "created_at",
                "updated_at",
            ],
        ),
        (
            "operations",
            &[
                "id",
                "run_id",
                "op_key",
                "component_id",
                "kind",
                "state",
                "attempt",
                "requires_elevation",
                "started_at",
                "ended_at",
                "input_json",
                "result_json",
                "error_json",
                "backup_json",
            ],
        ),
        ("events", &["seq", "run_id", "time", "level", "event_json"]),
        (
            "manual_actions",
            &[
                "id",
                "run_id",
                "state",
                "title",
                "reason",
                "risk",
                "instructions_json",
                "acknowledged_at",
            ],
        ),
    ];

    for (table, columns) in required_tables {
        let sql = format!("PRAGMA table_info({table})");
        let mut statement = connection
            .prepare(&sql)
            .map_err(|error| sqlite_error("journal schema could not be inspected", error))?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| sqlite_error("journal schema columns could not be read", error))?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|error| sqlite_error("journal schema columns could not be read", error))?;
        if columns.iter().any(|column| !names.contains(*column)) {
            return Err(journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "journal schema is missing a required column",
            ));
        }
    }

    let migration_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
            params![JOURNAL_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error("journal migration record could not be read", error))?;
    if migration_count != 1 {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal migration record is missing",
        ));
    }
    Ok(())
}

fn recover_running_operations(connection: &mut Connection) -> RestoreResult<()> {
    let now_text = timestamp(Utc::now());
    let tx = immediate_transaction(connection)?;
    let mut statement = tx
        .prepare(
            "SELECT id FROM runs WHERE status = 'RUNNING' \
             UNION SELECT DISTINCT run_id FROM operations WHERE state = 'RUNNING'",
        )
        .map_err(|error| sqlite_error("journal recovery query could not prepare", error))?;
    let run_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| sqlite_error("journal recovery query failed", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| sqlite_error("journal recovery rows could not be read", error))?;
    drop(statement);

    tx.execute(
        "UPDATE operations SET state = 'INTERRUPTED', ended_at = ?1 WHERE state = 'RUNNING'",
        params![&now_text],
    )
    .map_err(|error| sqlite_error("journal operation recovery failed", error))?;
    tx.execute(
        "UPDATE runs SET status = 'INTERRUPTED', updated_at = ?1 WHERE status = 'RUNNING'",
        params![&now_text],
    )
    .map_err(|error| sqlite_error("journal run recovery failed", error))?;
    for run_id in run_ids {
        tx.execute(
            "UPDATE runs SET status = 'INTERRUPTED', updated_at = ?1 WHERE id = ?2",
            params![&now_text, &run_id],
        )
        .map_err(|error| sqlite_error("journal recovered run could not be updated", error))?;
        let event = json!({
            "type": "journal_recovered",
            "operation_state": "INTERRUPTED",
        });
        let event_json = safe_json_text(&event, "journal recovery event")?;
        insert_event_tx(
            &tx,
            &RunId::try_from(run_id).map_err(|_| {
                journal_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "journal recovery row contains an invalid run ID",
                )
            })?,
            "WARN",
            &event_json,
            &now_text,
        )?;
    }
    tx.commit()
        .map_err(|error| sqlite_error("journal recovery commit failed", error))?;
    Ok(())
}

fn create_run_record(
    connection: &mut Connection,
    plan: &RestorePlan,
    now_text: &str,
) -> RestoreResult<JournalRun> {
    let run_id = plan.run_id.to_string();
    let package_id = bounded_text(
        &safe_text(&plan.package_id, "package ID")?,
        MAX_RUN_TEXT_BYTES,
        "package ID",
    )?;
    let target_fingerprint = bounded_text(
        &safe_text(&plan.target_fingerprint, "target fingerprint")?,
        MAX_RUN_TEXT_BYTES,
        "target fingerprint",
    )?;
    let mode = enum_text(&plan.mode, "restore mode")?;
    let status = enum_text(&RunStatus::Planned, "run status")?;
    let approval_state = enum_text(&ApprovalState::Pending, "approval state")?;

    let mut operations = Vec::with_capacity(plan.operations.len());
    let mut operation_ids = BTreeSet::new();
    let mut operation_keys = BTreeSet::new();
    for operation in &plan.operations {
        let id = operation.id.to_string();
        if !operation_ids.insert(id.clone()) {
            return Err(journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains duplicate operation IDs",
            ));
        }
        let op_key = bounded_text(
            &operation.idempotency_key,
            MAX_OPERATION_KEY_BYTES,
            "operation key",
        )?;
        if !operation_keys.insert(op_key.clone()) {
            return Err(journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains duplicate operation keys",
            ));
        }
        let operation_value = serde_json::to_value(operation).map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore operation could not be serialized",
            )
        })?;
        let input_json = safe_json_text(&operation_value, "restore operation input")?;
        let kind = operation_kind_label(&operation.kind)?;
        operations.push((
            id,
            op_key,
            operation.component.to_string(),
            kind,
            operation.requires_elevation,
            input_json,
        ));
    }

    let mut actions = Vec::with_capacity(plan.manual_actions.len());
    let mut action_ids = BTreeSet::new();
    for action in &plan.manual_actions {
        let id = bounded_text(&action.id, MAX_MANUAL_TEXT_BYTES, "manual action ID")?;
        if !action_ids.insert(id.clone()) {
            return Err(journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains duplicate manual action IDs",
            ));
        }
        let title = bounded_text(
            &safe_text(&action.title, "manual action title")?,
            MAX_MANUAL_TEXT_BYTES,
            "manual action title",
        )?;
        let reason = bounded_text(
            &safe_text(&action.reason, "manual action reason")?,
            MAX_MANUAL_TEXT_BYTES,
            "manual action reason",
        )?;
        if action.instructions.len() > MAX_MANUAL_INSTRUCTIONS {
            return Err(journal_error(
                ReforgeErrorCode::SecurityPolicy,
                "manual action has too many instructions",
            ));
        }
        let instructions = action
            .instructions
            .iter()
            .map(|instruction| {
                bounded_text(
                    &safe_text(instruction, "manual action instruction")?,
                    MAX_MANUAL_TEXT_BYTES,
                    "manual action instruction",
                )
            })
            .collect::<RestoreResult<Vec<_>>>()?;
        let instructions_json = safe_json_text(
            &serde_json::to_value(&instructions).map_err(|_| {
                journal_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "manual action instructions could not be serialized",
                )
            })?,
            "manual action instructions",
        )?;
        let state = enum_text(&action.state, "manual action state")?;
        let risk = enum_text(&action.risk, "manual action risk")?;
        let acknowledged_at = action.acknowledged_at.map(timestamp);
        actions.push((
            id,
            state,
            title,
            reason,
            risk,
            instructions_json,
            acknowledged_at,
        ));
    }

    let tx = immediate_transaction(connection)?;
    tx.execute(
        "INSERT INTO runs(id, package_id, mode, target_fingerprint, status, approval_state, \
         approved_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
        params![
            &run_id,
            &package_id,
            &mode,
            &target_fingerprint,
            &status,
            &approval_state,
            now_text,
        ],
    )
    .map_err(|error| sqlite_error("journal run could not be inserted", error))?;
    for (id, op_key, component_id, kind, requires_elevation, input_json) in operations {
        tx.execute(
            "INSERT INTO operations(id, run_id, op_key, component_id, kind, state, attempt, \
             requires_elevation, started_at, ended_at, input_json, result_json, error_json, backup_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'PENDING', 0, ?6, NULL, NULL, ?7, NULL, NULL, NULL)",
            params![
                &id,
                &run_id,
                &op_key,
                &component_id,
                &kind,
                bool_to_sql(requires_elevation),
                &input_json,
            ],
        )
        .map_err(|error| sqlite_error("journal operation could not be inserted", error))?;
    }
    for (id, state, title, reason, risk, instructions_json, acknowledged_at) in actions {
        tx.execute(
            "INSERT INTO manual_actions(id, run_id, state, title, reason, risk, instructions_json, \
             acknowledged_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &id,
                &run_id,
                &state,
                &title,
                &reason,
                &risk,
                &instructions_json,
                acknowledged_at.as_deref(),
            ],
        )
        .map_err(|error| sqlite_error("journal manual action could not be inserted", error))?;
    }
    let event = json!({"type": "run_created"});
    let event_json = safe_json_text(&event, "run creation event")?;
    insert_event_tx(
        &tx,
        &RunId::try_from(run_id.clone()).map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains an invalid run ID",
            )
        })?,
        "INFO",
        &event_json,
        now_text,
    )?;
    tx.commit()
        .map_err(|error| sqlite_error("journal run creation commit failed", error))?;

    Ok(JournalRun {
        id: RunId::try_from(run_id).map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains an invalid run ID",
            )
        })?,
        package_id,
        mode: plan.mode.clone(),
        target_fingerprint,
        status: RunStatus::Planned,
        approval_state: ApprovalState::Pending,
        approved_at: None,
        created_at: parse_timestamp(now_text)?,
        updated_at: parse_timestamp(now_text)?,
    })
}

fn set_approval_record(
    connection: &mut Connection,
    run_id: &RunId,
    state_text: &str,
    now_text: &str,
) -> RestoreResult<JournalRun> {
    let tx = immediate_transaction(connection)?;
    let current: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT approval_state, status, approved_at FROM runs WHERE id = ?1",
            params![run_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("journal approval state could not be read", error))?;
    let Some((current_state, _status, current_approved_at)) = current else {
        return Err(journal_error(
            ReforgeErrorCode::OperationFailed,
            "journal run not found",
        ));
    };
    if !valid_approval_transition(&current_state, state_text) {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "journal approval state cannot move backwards",
        ));
    }
    let approved_at = if state_text == "APPROVED" {
        current_approved_at.or_else(|| Some(now_text.to_owned()))
    } else {
        None
    };
    tx.execute(
        "UPDATE runs SET approval_state = ?1, approved_at = ?2, updated_at = ?3 WHERE id = ?4",
        params![
            state_text,
            approved_at.as_deref(),
            now_text,
            run_id.to_string()
        ],
    )
    .map_err(|error| sqlite_error("journal approval state could not be updated", error))?;
    let event = json!({"type": "approval_state", "state": state_text});
    let event_json = safe_json_text(&event, "approval event")?;
    insert_event_tx(&tx, run_id, "INFO", &event_json, now_text)?;
    tx.commit()
        .map_err(|error| sqlite_error("journal approval commit failed", error))?;
    fetch_run(connection, run_id)?.ok_or_else(|| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal run disappeared after approval update",
        )
    })
}

fn set_run_status_record(
    connection: &mut Connection,
    run_id: &RunId,
    status_text: &str,
    now_text: &str,
) -> RestoreResult<JournalRun> {
    let tx = immediate_transaction(connection)?;
    let approval_state: Option<String> = tx
        .query_row(
            "SELECT approval_state FROM runs WHERE id = ?1",
            params![run_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| sqlite_error("journal run status could not be read", error))?;
    let Some(approval_state) = approval_state else {
        return Err(journal_error(
            ReforgeErrorCode::OperationFailed,
            "journal run not found",
        ));
    };
    if status_text == "RUNNING" && approval_state != "APPROVED" {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "running a journal run requires explicit approval",
        ));
    }
    tx.execute(
        "UPDATE runs SET status = ?1, updated_at = ?2 WHERE id = ?3",
        params![status_text, now_text, run_id.to_string()],
    )
    .map_err(|error| sqlite_error("journal run status could not be updated", error))?;
    let event = json!({"type": "run_status", "status": status_text});
    let event_json = safe_json_text(&event, "run status event")?;
    insert_event_tx(&tx, run_id, "INFO", &event_json, now_text)?;
    tx.commit()
        .map_err(|error| sqlite_error("journal run status commit failed", error))?;
    fetch_run(connection, run_id)?.ok_or_else(|| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal run disappeared after status update",
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn transition_operation_record(
    connection: &mut Connection,
    run_id: &RunId,
    operation_id: &OperationId,
    state_text: &str,
    result_json: Option<String>,
    error_json: Option<String>,
    backup_json: Option<String>,
    now_text: &str,
) -> RestoreResult<JournalOperation> {
    let tx = immediate_transaction(connection)?;
    let current: Option<(String, i64, Option<String>, String)> = tx
        .query_row(
            "SELECT operations.state, operations.attempt, operations.started_at, runs.approval_state \
             FROM operations JOIN runs ON runs.id = operations.run_id \
             WHERE operations.id = ?1 AND operations.run_id = ?2",
            params![operation_id.to_string(), run_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("journal operation state could not be read", error))?;
    let Some((current_state, current_attempt, current_started_at, approval_state)) = current else {
        return Err(journal_error(
            ReforgeErrorCode::OperationFailed,
            "journal operation not found",
        ));
    };
    if state_text == "RUNNING" {
        if approval_state != "APPROVED" {
            return Err(journal_error(
                ReforgeErrorCode::SecurityPolicy,
                "running a journal operation requires explicit approval",
            ));
        }
        if matches!(current_state.as_str(), "RUNNING" | "COMPLETED" | "SKIPPED") {
            return Err(journal_error(
                ReforgeErrorCode::SecurityPolicy,
                "journal operation cannot be started from its current state",
            ));
        }
    }
    if (current_state == "COMPLETED" && state_text != "COMPLETED")
        || (current_state == "SKIPPED" && state_text != "SKIPPED")
    {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "verified journal operation cannot change state",
        ));
    }
    if (current_state == "COMPLETED" && state_text == "COMPLETED")
        || (current_state == "SKIPPED" && state_text == "SKIPPED")
    {
        drop(tx);
        return fetch_operation(connection, run_id, operation_id)?.ok_or_else(|| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "journal operation disappeared during idempotent transition",
            )
        });
    }
    let current_attempt = u32::try_from(current_attempt).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal operation attempt is invalid",
        )
    })?;
    let (attempt, started_at, ended_at, result_json, error_json, backup_json) =
        if state_text == "RUNNING" {
            (
                current_attempt.checked_add(1).ok_or_else(|| {
                    journal_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "journal operation attempt overflowed",
                    )
                })?,
                Some(now_text.to_owned()),
                None,
                None,
                None,
                None,
            )
        } else if state_text == "PENDING" {
            (
                current_attempt,
                current_started_at,
                None,
                result_json,
                error_json,
                backup_json,
            )
        } else {
            (
                current_attempt,
                current_started_at,
                Some(now_text.to_owned()),
                result_json,
                error_json,
                backup_json,
            )
        };

    tx.execute(
        "UPDATE operations SET state = ?1, attempt = ?2, started_at = ?3, ended_at = ?4, \
         result_json = ?5, error_json = ?6, backup_json = ?7 \
         WHERE id = ?8 AND run_id = ?9",
        params![
            state_text,
            i64::from(attempt),
            started_at.as_deref(),
            ended_at.as_deref(),
            result_json.as_deref(),
            error_json.as_deref(),
            backup_json.as_deref(),
            operation_id.to_string(),
            run_id.to_string(),
        ],
    )
    .map_err(|error| sqlite_error("journal operation state could not be updated", error))?;

    if state_text == "RUNNING" {
        tx.execute(
            "UPDATE runs SET status = 'RUNNING', updated_at = ?1 \
             WHERE id = ?2 AND status IN ('PLANNED', 'WAITING_FOR_APPROVAL', 'WAITING_FOR_USER', \
             'WAITING_FOR_REBOOT', 'INTERRUPTED')",
            params![now_text, run_id.to_string()],
        )
        .map_err(|error| sqlite_error("journal run could not enter running state", error))?;
    }
    let event = json!({
        "type": "operation_state",
        "operation_id": operation_id.to_string(),
        "state": state_text,
        "attempt": attempt,
    });
    let event_json = safe_json_text(&event, "operation state event")?;
    insert_event_tx(&tx, run_id, "INFO", &event_json, now_text)?;
    tx.commit()
        .map_err(|error| sqlite_error("journal operation state commit failed", error))?;
    fetch_operation(connection, run_id, operation_id)?.ok_or_else(|| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal operation disappeared after state update",
        )
    })
}

fn add_manual_action_record(
    connection: &mut Connection,
    run_id: &RunId,
    action: &ManualAction,
) -> RestoreResult<JournalManualAction> {
    let id = bounded_text(&action.id, MAX_MANUAL_TEXT_BYTES, "manual action ID")?;
    let title = bounded_text(
        &safe_text(&action.title, "manual action title")?,
        MAX_MANUAL_TEXT_BYTES,
        "manual action title",
    )?;
    let reason = bounded_text(
        &safe_text(&action.reason, "manual action reason")?,
        MAX_MANUAL_TEXT_BYTES,
        "manual action reason",
    )?;
    if action.instructions.len() > MAX_MANUAL_INSTRUCTIONS {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "manual action has too many instructions",
        ));
    }
    let instructions = action
        .instructions
        .iter()
        .map(|instruction| {
            bounded_text(
                &safe_text(instruction, "manual action instruction")?,
                MAX_MANUAL_TEXT_BYTES,
                "manual action instruction",
            )
        })
        .collect::<RestoreResult<Vec<_>>>()?;
    let instructions_json = safe_json_text(
        &serde_json::to_value(&instructions).map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "manual action instructions could not be serialized",
            )
        })?,
        "manual action instructions",
    )?;
    let state = enum_text(&action.state, "manual action state")?;
    let risk = enum_text(&action.risk, "manual action risk")?;
    let acknowledged_at = action.acknowledged_at.map(timestamp);
    let row = JournalManualAction {
        id: id.clone(),
        run_id: run_id.clone(),
        state: action.state.clone(),
        title: title.clone(),
        reason: reason.clone(),
        risk: action.risk.clone(),
        instructions,
        acknowledged_at: action.acknowledged_at,
    };
    let tx = immediate_transaction(connection)?;
    tx.execute(
        "INSERT INTO manual_actions(id, run_id, state, title, reason, risk, instructions_json, \
         acknowledged_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            &id,
            run_id.to_string(),
            &state,
            &title,
            &reason,
            &risk,
            &instructions_json,
            acknowledged_at.as_deref(),
        ],
    )
    .map_err(|error| sqlite_error("journal manual action could not be inserted", error))?;
    let event = json!({"type": "manual_action_added", "action_id": id});
    let event_json = safe_json_text(&event, "manual-action event")?;
    insert_event_tx(&tx, run_id, "INFO", &event_json, &timestamp(Utc::now()))?;
    tx.commit()
        .map_err(|error| sqlite_error("journal manual action commit failed", error))?;
    Ok(row)
}

fn set_manual_action_state_record(
    connection: &mut Connection,
    run_id: &RunId,
    action_id: &str,
    state_text: &str,
    now_text: &str,
) -> RestoreResult<JournalManualAction> {
    let tx = immediate_transaction(connection)?;
    let current: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT state, acknowledged_at FROM manual_actions WHERE id = ?1 AND run_id = ?2",
            params![action_id, run_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| sqlite_error("manual-action state could not be read", error))?;
    let Some((current_state, current_acknowledged_at)) = current else {
        return Err(journal_error(
            ReforgeErrorCode::OperationFailed,
            "journal manual action not found",
        ));
    };
    if !valid_manual_action_transition(&current_state, state_text) {
        return Err(journal_error(
            ReforgeErrorCode::UserActionRequired,
            "manual action cannot move backwards",
        ));
    }
    let acknowledged_at = if state_text == "PENDING" {
        current_acknowledged_at
    } else {
        current_acknowledged_at.or_else(|| Some(now_text.to_owned()))
    };
    tx.execute(
        "UPDATE manual_actions SET state = ?1, acknowledged_at = ?2 WHERE id = ?3 AND run_id = ?4",
        params![
            state_text,
            acknowledged_at.as_deref(),
            action_id,
            run_id.to_string()
        ],
    )
    .map_err(|error| sqlite_error("manual-action state could not be updated", error))?;
    let event = json!({
        "type": "manual_action_state",
        "action_id": action_id,
        "state": state_text,
    });
    let event_json = safe_json_text(&event, "manual-action state event")?;
    insert_event_tx(&tx, run_id, "INFO", &event_json, now_text)?;
    tx.commit()
        .map_err(|error| sqlite_error("manual-action state commit failed", error))?;
    fetch_manual_action(connection, run_id, action_id)?.ok_or_else(|| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "manual action disappeared after state update",
        )
    })
}

fn insert_event_tx(
    tx: &Transaction<'_>,
    run_id: &RunId,
    level: &str,
    event_json: &str,
    now_text: &str,
) -> RestoreResult<i64> {
    let level = bounded_text(level, MAX_EVENT_LEVEL_BYTES, "event level")?;
    tx.execute(
        "INSERT INTO events(run_id, time, level, event_json) VALUES (?1, ?2, ?3, ?4)",
        params![run_id.to_string(), now_text, level, event_json],
    )
    .map_err(|error| sqlite_error("journal event could not be inserted", error))?;
    Ok(tx.last_insert_rowid())
}

fn fetch_run(connection: &Connection, run_id: &RunId) -> RestoreResult<Option<JournalRun>> {
    let raw = connection
        .query_row(
            "SELECT id, package_id, mode, target_fingerprint, status, approval_state, \
             approved_at, created_at, updated_at FROM runs WHERE id = ?1",
            params![run_id.to_string()],
            raw_run_from_row,
        )
        .optional()
        .map_err(|error| sqlite_error("journal run query failed", error))?;
    raw.map(parse_run).transpose()
}

fn fetch_operation(
    connection: &Connection,
    run_id: &RunId,
    operation_id: &OperationId,
) -> RestoreResult<Option<JournalOperation>> {
    let raw = connection
        .query_row(
            "SELECT id, run_id, op_key, component_id, kind, state, attempt, \
             requires_elevation, started_at, ended_at, input_json, result_json, error_json, backup_json \
             FROM operations WHERE id = ?1 AND run_id = ?2",
            params![operation_id.to_string(), run_id.to_string()],
            raw_operation_from_row,
        )
        .optional()
        .map_err(|error| sqlite_error("journal operation query failed", error))?;
    raw.map(|raw| parse_operation(raw, run_id)).transpose()
}

fn fetch_manual_action(
    connection: &Connection,
    run_id: &RunId,
    action_id: &str,
) -> RestoreResult<Option<JournalManualAction>> {
    let raw = connection
        .query_row(
            "SELECT id, run_id, state, title, reason, risk, instructions_json, acknowledged_at \
             FROM manual_actions WHERE id = ?1 AND run_id = ?2",
            params![action_id, run_id.to_string()],
            raw_manual_action_from_row,
        )
        .optional()
        .map_err(|error| sqlite_error("journal manual-action query failed", error))?;
    raw.map(|raw| parse_manual_action(raw, run_id)).transpose()
}

type RawRun = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
);

fn raw_run_from_row(row: &Row<'_>) -> rusqlite::Result<RawRun> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn parse_run(raw: RawRun) -> RestoreResult<JournalRun> {
    let id = parse_id(raw.0, "run ID")?;
    let package_id = bounded_text(
        &safe_text(&raw.1, "package ID")?,
        MAX_RUN_TEXT_BYTES,
        "package ID",
    )?;
    let mode = parse_enum(&raw.2, "restore mode")?;
    let target_fingerprint = bounded_text(
        &safe_text(&raw.3, "target fingerprint")?,
        MAX_RUN_TEXT_BYTES,
        "target fingerprint",
    )?;
    let status = parse_enum(&raw.4, "run status")?;
    let approval_state = parse_enum(&raw.5, "approval state")?;
    let approved_at = parse_optional_timestamp(raw.6)?;
    let created_at = parse_timestamp(&raw.7)?;
    let updated_at = parse_timestamp(&raw.8)?;
    Ok(JournalRun {
        id,
        package_id,
        mode,
        target_fingerprint,
        status,
        approval_state,
        approved_at,
        created_at,
        updated_at,
    })
}

type RawOperation = (
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn raw_operation_from_row(row: &Row<'_>) -> rusqlite::Result<RawOperation> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    ))
}

fn parse_operation(raw: RawOperation, expected_run_id: &RunId) -> RestoreResult<JournalOperation> {
    let id: OperationId = parse_id(raw.0, "operation ID")?;
    let run_id: RunId = parse_id(raw.1, "operation run ID")?;
    if &run_id != expected_run_id {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal operation references a different run",
        ));
    }
    let op_key = bounded_text(&raw.2, MAX_OPERATION_KEY_BYTES, "operation key")?;
    let component_id: ComponentId = parse_id(raw.3, "operation component ID")?;
    let kind = bounded_text(&raw.4, MAX_EVENT_LEVEL_BYTES, "operation kind")?;
    let state = parse_enum(&raw.5, "operation state")?;
    let attempt = u32::try_from(raw.6).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal operation attempt is invalid",
        )
    })?;
    let requires_elevation = sql_to_bool(raw.7)?;
    let operation: Operation =
        serde_json::from_value(parse_persisted_json(&raw.10, "operation input")?).map_err(
            |_| {
                journal_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "journal operation input is not a valid operation",
                )
            },
        )?;
    if operation.id != id
        || operation.component != component_id
        || operation.idempotency_key != op_key
        || operation.requires_elevation != requires_elevation
        || operation_kind_label(&operation.kind)? != kind
    {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal operation columns disagree with its input",
        ));
    }
    let result = parse_optional_json(raw.11, "operation result")?;
    let error = parse_optional_value(raw.12, "operation error")?;
    let backup = parse_optional_json(raw.13, "operation backup")?;
    Ok(JournalOperation {
        id,
        run_id,
        operation,
        state,
        attempt,
        started_at: parse_optional_timestamp(raw.8)?,
        ended_at: parse_optional_timestamp(raw.9)?,
        result,
        error,
        backup,
    })
}

type RawEvent = (i64, String, String, String, String);

fn raw_event_from_row(row: &Row<'_>) -> rusqlite::Result<RawEvent> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn parse_event(raw: RawEvent, expected_run_id: &RunId) -> RestoreResult<JournalEvent> {
    let run_id: RunId = parse_id(raw.1, "event run ID")?;
    if &run_id != expected_run_id || raw.0 <= 0 {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal event row is invalid",
        ));
    }
    let time = parse_timestamp(&raw.2)?;
    let level = bounded_text(&raw.3, MAX_EVENT_LEVEL_BYTES, "event level")?;
    let event = parse_persisted_json(&raw.4, "journal event")?;
    Ok(JournalEvent {
        seq: raw.0,
        run_id,
        time,
        level,
        event,
    })
}

type RawManualAction = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn raw_manual_action_from_row(row: &Row<'_>) -> rusqlite::Result<RawManualAction> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn parse_manual_action(
    raw: RawManualAction,
    expected_run_id: &RunId,
) -> RestoreResult<JournalManualAction> {
    let run_id: RunId = parse_id(raw.1, "manual action run ID")?;
    if &run_id != expected_run_id {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal manual action references a different run",
        ));
    }
    let instructions: Vec<String> =
        serde_json::from_value(parse_persisted_json(&raw.6, "manual action instructions")?)
            .map_err(|_| {
                journal_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "journal manual action instructions are invalid",
                )
            })?;
    if instructions.len() > MAX_MANUAL_INSTRUCTIONS {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            "journal manual action has too many instructions",
        ));
    }
    for instruction in &instructions {
        bounded_text(
            &safe_text(instruction, "manual action instruction")?,
            MAX_MANUAL_TEXT_BYTES,
            "manual action instruction",
        )?;
    }
    Ok(JournalManualAction {
        id: bounded_text(&raw.0, MAX_MANUAL_TEXT_BYTES, "manual action ID")?,
        run_id,
        state: parse_enum(&raw.2, "manual action state")?,
        title: bounded_text(
            &safe_text(&raw.3, "manual action title")?,
            MAX_MANUAL_TEXT_BYTES,
            "manual action title",
        )?,
        reason: bounded_text(
            &safe_text(&raw.4, "manual action reason")?,
            MAX_MANUAL_TEXT_BYTES,
            "manual action reason",
        )?,
        risk: parse_enum(&raw.5, "manual action risk")?,
        instructions,
        acknowledged_at: parse_optional_timestamp(raw.7)?,
    })
}

fn immediate_transaction(connection: &mut Connection) -> RestoreResult<Transaction<'_>> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| sqlite_error("journal transaction could not begin", error))
}

fn valid_approval_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("PENDING", "PENDING" | "APPROVED" | "REJECTED")
            | ("APPROVED", "APPROVED")
            | ("REJECTED", "REJECTED")
    )
}

fn valid_manual_action_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("PENDING", "PENDING" | "ACKNOWLEDGED" | "SKIPPED")
            | ("ACKNOWLEDGED", "ACKNOWLEDGED" | "COMPLETED" | "SKIPPED")
            | ("COMPLETED", "COMPLETED")
            | ("SKIPPED", "SKIPPED")
    )
}

fn operation_kind_label(kind: &OperationKind) -> RestoreResult<String> {
    let value = serde_json::to_value(kind).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "operation kind could not be serialized",
        )
    })?;
    value
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "operation kind has no stable type label",
            )
        })
}

fn enum_text<T: Serialize>(value: &T, context: &str) -> RestoreResult<String> {
    let value = serde_json::to_value(value).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} could not be serialized"),
        )
    })?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is not a scalar enum"),
        )
    })
}

fn parse_enum<T: DeserializeOwned>(value: &str, context: &str) -> RestoreResult<T> {
    serde_json::from_value(Value::String(value.to_owned())).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("journal {context} is invalid"),
        )
    })
}

fn safe_json_text(value: &Value, context: &str) -> RestoreResult<String> {
    let redacted = RedactionPolicy::default()
        .redact_json(value)
        .ok_or_else(|| {
            journal_error(
                ReforgeErrorCode::SecurityPolicy,
                format!("{context} could not be proven safe to persist"),
            )
        })?;
    serde_json::to_string(&redacted).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} could not be serialized"),
        )
    })
}

fn safe_text(value: &str, context: &str) -> RestoreResult<String> {
    RedactionPolicy::default()
        .redact_text(value)
        .ok_or_else(|| {
            journal_error(
                ReforgeErrorCode::SecurityPolicy,
                format!("{context} could not be proven safe to persist"),
            )
        })
}

fn bounded_text(value: &str, max_bytes: usize, context: &str) -> RestoreResult<String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is invalid"),
        ));
    }
    Ok(value.to_owned())
}

fn parse_json<T: DeserializeOwned>(value: &str, context: &str) -> RestoreResult<T> {
    serde_json::from_str(value).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("journal {context} is invalid JSON"),
        )
    })
}

fn parse_persisted_json(value: &str, context: &str) -> RestoreResult<Value> {
    let parsed: Value = parse_json(value, context)?;
    let serialized = serde_json::to_string(&parsed).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("journal {context} could not be serialized"),
        )
    })?;
    let safe = safe_json_text(&parsed, context)?;
    if serialized != safe {
        return Err(journal_error(
            ReforgeErrorCode::SecurityPolicy,
            format!("journal {context} contains an unsafe value"),
        ));
    }
    Ok(parsed)
}

fn parse_optional_json(value: Option<String>, context: &str) -> RestoreResult<Option<Value>> {
    value
        .map(|value| parse_persisted_json(&value, context))
        .transpose()
}

fn parse_optional_value<T: DeserializeOwned>(
    value: Option<String>,
    context: &str,
) -> RestoreResult<Option<T>> {
    value
        .map(|value| {
            let value = parse_persisted_json(&value, context)?;
            serde_json::from_value(value).map_err(|_| {
                journal_error(
                    ReforgeErrorCode::SchemaInvalid,
                    format!("journal {context} has an invalid value"),
                )
            })
        })
        .transpose()
}

fn parse_id<T>(value: String, context: &str) -> RestoreResult<T>
where
    T: TryFrom<String>,
{
    T::try_from(value).map_err(|_| {
        journal_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("journal {context} is invalid"),
        )
    })
}

fn parse_timestamp(value: &str) -> RestoreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            journal_error(
                ReforgeErrorCode::SchemaInvalid,
                "journal timestamp is invalid",
            )
        })
}

fn parse_optional_timestamp(value: Option<String>) -> RestoreResult<Option<DateTime<Utc>>> {
    value.map(|value| parse_timestamp(&value)).transpose()
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn bool_to_sql(value: bool) -> i64 {
    i64::from(value)
}

fn sql_to_bool(value: i64) -> RestoreResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(journal_error(
            ReforgeErrorCode::SchemaInvalid,
            "journal boolean field is invalid",
        )),
    }
}

fn validate_journal_path(path: &Path) -> RestoreResult<()> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(journal_error(
            ReforgeErrorCode::InvalidPath,
            "journal path must identify a local database file",
        ));
    }
    Ok(())
}

fn journal_error(code: ReforgeErrorCode, message: impl Into<String>) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, None)
}

fn sqlite_error(context: &str, error: rusqlite::Error) -> Box<ErrorEnvelope> {
    restore_error(
        ReforgeErrorCode::OperationFailed,
        context,
        Some(&error.to_string()),
        None,
        None,
        None,
    )
}
