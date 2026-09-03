//! Typed, redacted events emitted by the desktop application.
//!
//! Event payloads are versioned and correlated with a UUIDv7 run identity. The
//! UI can render the stream, but never becomes the source of truth for state.

use reforge_domain::{
    ErrorEnvelope, OperationId, OperationState, ProgressEvent, ReportStatus, RestoreReport, RunId,
    RunStatus,
};
use reforge_restore::redact_restore_report;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const PROGRESS_EVENT: &str = "reforge://progress";
pub const RESTORE_PROGRESS_EVENT: &str = "reforge://restore-progress";
pub const REPORT_EVENT: &str = "reforge://report";
pub const ERROR_EVENT: &str = "reforge://error";

/// Common envelope for every backend-to-UI event.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EventEnvelope<T> {
    pub schema_version: u16,
    pub event_id: String,
    pub run_id: RunId,
    pub payload: T,
}

/// A restore lifecycle delta. Operation details remain typed and bounded.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestoreProgressDelta {
    pub status: RunStatus,
    pub operation_id: Option<OperationId>,
    pub operation_state: Option<OperationState>,
    pub completed: u64,
    pub total: Option<u64>,
    pub message: String,
}

/// A report delta is always redacted again at the desktop boundary.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReportDelta {
    pub status: ReportStatus,
    pub report: RestoreReport,
}

/// Emit one scan progress event.
pub fn emit_progress<R: Runtime>(
    app: &AppHandle<R>,
    progress: ProgressEvent,
) -> Result<(), Box<ErrorEnvelope>> {
    let run_id = progress.run_id.clone();
    emit(
        app,
        PROGRESS_EVENT,
        EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: event_id(),
            run_id,
            payload: progress,
        },
    )
}

/// Emit one restore lifecycle delta.
pub fn emit_restore_progress<R: Runtime>(
    app: &AppHandle<R>,
    run_id: RunId,
    payload: RestoreProgressDelta,
) -> Result<(), Box<ErrorEnvelope>> {
    emit(
        app,
        RESTORE_PROGRESS_EVENT,
        EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: event_id(),
            run_id,
            payload,
        },
    )
}

/// Emit a redacted final report.
pub fn emit_report<R: Runtime>(
    app: &AppHandle<R>,
    report: RestoreReport,
) -> Result<(), Box<ErrorEnvelope>> {
    let report = redact_restore_report(report);
    let run_id = report.run_id.clone();
    emit(
        app,
        REPORT_EVENT,
        EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: event_id(),
            run_id,
            payload: ReportDelta {
                status: report.status.clone(),
                report,
            },
        },
    )
}

/// Emit one already-safe backend error.
pub fn emit_error<R: Runtime>(
    app: &AppHandle<R>,
    run_id: RunId,
    error: ErrorEnvelope,
) -> Result<(), Box<ErrorEnvelope>> {
    emit(
        app,
        ERROR_EVENT,
        EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: event_id(),
            run_id,
            payload: error,
        },
    )
}

fn emit<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    name: &str,
    envelope: EventEnvelope<T>,
) -> Result<(), Box<ErrorEnvelope>> {
    app.emit(name, &envelope).map_err(|error| {
        Box::new(
            ErrorEnvelope::new(
                reforge_domain::ReforgeErrorCode::OperationFailed,
                "The desktop event could not be delivered",
            )
            .with_technical_detail(error.to_string()),
        )
    })
}

fn event_id() -> String {
    Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{ComponentId, ProgressStatus, ReportCounts, ReportStatus, ScanPhase};

    fn run_id() -> RunId {
        RunId::new(Uuid::now_v7()).expect("UUIDv7 run ID")
    }

    #[test]
    fn progress_envelope_is_versioned_and_correlated() {
        let run_id = run_id();
        let envelope = EventEnvelope {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: event_id(),
            run_id: run_id.clone(),
            payload: ProgressEvent {
                run_id: run_id.clone(),
                phase: ScanPhase::HostPreflight,
                status: ProgressStatus::Started,
                current_component: None,
                completed: 0,
                total: Some(1),
                bytes: None,
                message: "started".to_owned(),
            },
        };
        let value = serde_json::to_value(envelope).expect("event JSON");
        assert_eq!(value["schema_version"], EVENT_SCHEMA_VERSION);
        assert_eq!(value["run_id"], run_id.to_string());
        assert!(value["event_id"].as_str().is_some());
    }

    #[test]
    fn report_delta_contains_no_raw_secret_or_absolute_user_path() {
        let component = ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component");
        let report = RestoreReport {
            format_version: 1,
            run_id: run_id(),
            package_id: "pkg".to_owned(),
            status: ReportStatus::Failed,
            counts: ReportCounts {
                verified: 0,
                partial: 0,
                already_present: 0,
                waiting_for_user: 0,
                reauth_required: 0,
                reboot_required: 0,
                unsupported: 0,
                failed: 1,
            },
            components: vec![reforge_domain::ComponentReport {
                component,
                status: ReportStatus::Failed,
                evidence: Vec::new(),
                manual_actions: Vec::new(),
                warnings: vec!["token=secret C:\\Users\\Alice\\config".to_owned()],
            }],
            manual_actions: Vec::new(),
            warnings: Vec::new(),
            elapsed_ms: 0,
            bytes_written: 0,
        };
        let redacted = redact_restore_report(report);
        let value = serde_json::to_string(&redacted).expect("report JSON");
        assert!(!value.contains("secret"));
        assert!(!value.contains("Alice"));
    }
}
