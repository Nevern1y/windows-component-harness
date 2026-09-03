//! Typed Tauri commands for the Reforge desktop shell.
//!
//! Every command accepts a versioned domain envelope, validates all paths at
//! the Rust boundary, and delegates orchestration to the shared application
//! service. The webview has no filesystem or shell capability.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use reforge_cli::{ApplicationRunDetails, ApplicationService};
use reforge_domain::{
    ApprovalState, ErrorEnvelope, Inventory, Operation, OperationId, OperationState, ProgressEvent,
    ReportStatus, RestoreMode, RestorePlan, RestoreReport, RunId, RunStatus, SelectionInput,
    TransportReceipt, TrustState, WireEnvelope,
};
use reforge_platform_windows::CancellationToken;
use reforge_restore::{JournalEvent, JournalManualAction, JournalOperation};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

use crate::events;

pub const BRIDGE_SCHEMA_VERSION: u16 = 1;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_ACTION_ID_BYTES: usize = 1_024;
const MAX_RETAINED_SELECTIONS: usize = 128;
const MAX_RETAINED_RUNS: usize = 1_024;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StartScanRequest {}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelRunRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InspectPackageRequest {
    pub selection_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreatePackageRequest {
    pub output_selection_id: String,
    pub selection: SelectionInput,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BuildPlanRequest {
    pub package_selection_id: String,
    pub mode: RestoreMode,
    pub package_approved: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StartRestoreRequest {
    pub package_selection_id: String,
    pub mode: RestoreMode,
    pub package_approved: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResumeRestoreRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GetRunRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AckManualActionRequest {
    pub run_id: String,
    pub action_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SaveReportRequest {
    pub run_id: String,
    pub output_selection_id: String,
}

/// Result returned by a backend-owned native file dialog.
///
/// The path itself remains in the Rust process. The selection ID is an opaque
/// capability accepted only by the command that requested the dialog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NativeDialogResult {
    Cancelled,
    Selected { selection_id: String },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunHandle {
    pub run_id: RunId,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InventoryResponse {
    pub inventory: Inventory,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageInspection {
    pub package_id: String,
    pub format_version: u16,
    pub manifest: reforge_domain::PackageManifest,
    pub graph: reforge_domain::PackageGraph,
    pub selection: SelectionInput,
    pub object_index: reforge_domain::ObjectIndex,
    pub trust: TrustState,
    pub has_vault: bool,
    pub archive_bytes: u64,
    pub warnings: Vec<String>,
    pub sources: reforge_package::PackageSources,
    pub signature: Option<reforge_package::SignatureMetadata>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageResponse {
    pub receipt: TransportReceipt,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PlanResponse {
    pub plan: RestorePlan,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReportResponse {
    pub report: RestoreReport,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunLifecycle {
    Starting,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunLifecycleView {
    pub status: RunLifecycle,
    pub error: Option<ErrorEnvelope>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunView {
    pub run_id: RunId,
    pub package_id: String,
    pub mode: RestoreMode,
    pub target_fingerprint: String,
    pub status: RunStatus,
    pub approval_state: ApprovalState,
    pub created_at: String,
    pub updated_at: String,
    pub operations: Vec<OperationView>,
    pub events: Vec<EventView>,
    pub manual_actions: Vec<reforge_domain::ManualAction>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OperationView {
    pub id: OperationId,
    pub operation: Operation,
    pub state: OperationState,
    pub attempt: u32,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<ErrorEnvelope>,
    pub backup: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EventView {
    pub seq: i64,
    pub run_id: RunId,
    pub time: String,
    pub level: String,
    pub event: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunResponse {
    pub run: Option<RunView>,
    pub lifecycle: Option<RunLifecycleView>,
    pub report: Option<RestoreReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ManualActionResponse {
    pub action: reforge_domain::ManualAction,
}

#[derive(Clone, Debug)]
struct RetainedRun {
    status: RunLifecycle,
    error: Option<ErrorEnvelope>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionKind {
    PackageInput,
    PackageOutput,
    ReportOutput,
}

#[derive(Clone, Debug)]
struct NativeSelection {
    path: PathBuf,
    kind: SelectionKind,
}

#[derive(Default)]
struct SelectionStore {
    entries: Mutex<BTreeMap<String, NativeSelection>>,
}

impl SelectionStore {
    fn insert(&self, path: PathBuf, kind: SelectionKind) -> Result<String, Box<ErrorEnvelope>> {
        let selection_id = Uuid::now_v7().to_string();
        let mut entries = lock(&self.entries)?;
        entries.insert(selection_id.clone(), NativeSelection { path, kind });
        while entries.len() > MAX_RETAINED_SELECTIONS {
            let Some(first) = entries.keys().next().cloned() else {
                break;
            };
            entries.remove(&first);
        }
        Ok(selection_id)
    }

    fn resolve(&self, value: &str, kind: SelectionKind) -> Result<PathBuf, Box<ErrorEnvelope>> {
        validate_selection_id(value)?;
        let entries = lock(&self.entries)?;
        let selection = entries
            .get(value)
            .ok_or_else(|| schema_error("native dialog selection is unknown or expired"))?;
        if selection.kind != kind {
            return Err(schema_error(
                "native dialog selection kind is not valid here",
            ));
        }
        Ok(selection.path.clone())
    }
}

#[derive(Default)]
struct RunRegistry {
    active: Mutex<BTreeMap<RunId, CancellationToken>>,
    retained: Mutex<BTreeMap<RunId, RetainedRun>>,
}

impl RunRegistry {
    fn register(&self, run_id: RunId, token: CancellationToken) -> Result<(), Box<ErrorEnvelope>> {
        let mut active = lock(&self.active)?;
        if active.insert(run_id.clone(), token).is_some() {
            return Err(operation_error("run identity is already active"));
        }
        drop(active);
        self.retain(run_id, RunLifecycle::Starting, None)
    }

    fn cancel(&self, run_id: &RunId) -> Result<bool, Box<ErrorEnvelope>> {
        let active = lock(&self.active)?;
        if let Some(token) = active.get(run_id) {
            token.cancel();
            return Ok(true);
        }
        Ok(false)
    }

    fn mark_running(&self, run_id: &RunId) -> Result<(), Box<ErrorEnvelope>> {
        self.retain(run_id.clone(), RunLifecycle::Running, None)
    }

    fn finish(
        &self,
        run_id: &RunId,
        status: RunLifecycle,
        error: Option<ErrorEnvelope>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        lock(&self.active)?.remove(run_id);
        self.retain(run_id.clone(), status, error)
    }

    fn get(&self, run_id: &RunId) -> Result<Option<RunLifecycleView>, Box<ErrorEnvelope>> {
        Ok(lock(&self.retained)?
            .get(run_id)
            .map(|run| RunLifecycleView {
                status: run.status.clone(),
                error: run.error.clone(),
            }))
    }

    fn retain(
        &self,
        run_id: RunId,
        status: RunLifecycle,
        error: Option<ErrorEnvelope>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let mut retained = lock(&self.retained)?;
        retained.insert(run_id, RetainedRun { status, error });
        while retained.len() > MAX_RETAINED_RUNS {
            let Some(first) = retained.keys().next().cloned() else {
                break;
            };
            retained.remove(&first);
        }
        Ok(())
    }
}

/// Tauri-managed application state. The service is shared with the CLI.
#[derive(Clone)]
pub struct AppState {
    pub(crate) service: Arc<ApplicationService>,
    registry: Arc<RunRegistry>,
    selections: Arc<SelectionStore>,
}

impl AppState {
    pub fn new() -> Result<Self, Box<ErrorEnvelope>> {
        let service = ApplicationService::new()?;
        Ok(Self {
            service: Arc::new(service),
            registry: Arc::new(RunRegistry::default()),
            selections: Arc::new(SelectionStore::default()),
        })
    }
}

#[tauri::command]
pub fn start_scan(
    request: WireEnvelope<StartScanRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<RunHandle>, Box<ErrorEnvelope>> {
    let (request_id, _) = unpack(request)?;
    let run_id = ApplicationService::allocate_run_id()?;
    let response_run_id = run_id.clone();
    let token = CancellationToken::new();
    state.registry.register(run_id.clone(), token.clone())?;
    let service = state.service.clone();
    let registry = state.registry.clone();
    tauri::async_runtime::spawn(async move {
        let _ = registry.mark_running(&run_id);
        let event_app = app.clone();
        let progress = move |event: ProgressEvent| {
            let _ = events::emit_progress(&event_app, event);
        };
        let result = service.scan(run_id.clone(), &token, progress).await;
        match result {
            Ok(_) => {
                let _ = registry.finish(&run_id, RunLifecycle::Completed, None);
            }
            Err(error) => {
                let status = if error.code == reforge_domain::ReforgeErrorCode::Cancelled {
                    RunLifecycle::Cancelled
                } else {
                    RunLifecycle::Failed
                };
                let _ = events::emit_error(&app, run_id.clone(), (*error).clone());
                let _ = registry.finish(&run_id, status, Some((*error).clone()));
            }
        }
    });
    Ok(reply(
        request_id,
        RunHandle {
            run_id: response_run_id,
        },
    ))
}

#[tauri::command]
pub fn cancel_run(
    request: WireEnvelope<CancelRunRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<CancelResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    let accepted = state.registry.cancel(&run_id)?;
    Ok(reply(request_id, CancelResponse { run_id, accepted }))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelResponse {
    pub run_id: RunId,
    pub accepted: bool,
}

#[tauri::command]
pub fn get_inventory(
    request: WireEnvelope<EmptyRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<InventoryResponse>, Box<ErrorEnvelope>> {
    let (request_id, _) = unpack(request)?;
    let inventory = state.service.inventory()?;
    Ok(reply(request_id, InventoryResponse { inventory }))
}

#[tauri::command]
pub fn inspect_package(
    request: WireEnvelope<InspectPackageRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<PackageInspection>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let path = selected_path(&state, &request.selection_id, SelectionKind::PackageInput)?;
    let package = state.service.inspect_package(&path)?;
    let archive_bytes = package.archive_bytes();
    let signature = package.signature_metadata().cloned();
    Ok(reply(
        request_id,
        PackageInspection {
            package_id: package.manifest.package_id.clone(),
            format_version: package.manifest.format_version,
            manifest: package.manifest,
            graph: package.graph,
            selection: package.selection,
            object_index: package.object_index,
            trust: package.trust,
            has_vault: package.has_vault,
            archive_bytes,
            sources: package.sources,
            warnings: package.warnings,
            signature,
        },
    ))
}

#[tauri::command]
pub fn create_package(
    request: WireEnvelope<CreatePackageRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<PackageResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let output = selected_path(
        &state,
        &request.output_selection_id,
        SelectionKind::PackageOutput,
    )?;
    let receipt = state.service.create_package(&output, request.selection)?;
    Ok(reply(request_id, PackageResponse { receipt }))
}

#[tauri::command]
pub async fn build_plan(
    request: WireEnvelope<BuildPlanRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<PlanResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let package = selected_path(
        &state,
        &request.package_selection_id,
        SelectionKind::PackageInput,
    )?;
    let run_id = ApplicationService::allocate_run_id()?;
    let token = CancellationToken::new();
    let event_app = app.clone();
    let progress = move |event: ProgressEvent| {
        let _ = events::emit_progress(&event_app, event);
    };
    let plan = state
        .service
        .build_plan(
            &package,
            request.mode,
            run_id,
            request.package_approved,
            &token,
            progress,
        )
        .await?;
    Ok(reply(request_id, PlanResponse { plan }))
}

#[tauri::command]
pub fn start_restore(
    request: WireEnvelope<StartRestoreRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<RunHandle>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let package = selected_path(
        &state,
        &request.package_selection_id,
        SelectionKind::PackageInput,
    )?;
    let run_id = ApplicationService::allocate_run_id()?;
    let token = CancellationToken::new();
    state.registry.register(run_id.clone(), token.clone())?;
    spawn_restore(RestoreJob {
        service: state.service.clone(),
        registry: state.registry.clone(),
        app,
        run_id: run_id.clone(),
        token,
        package,
        mode: request.mode,
        package_approved: request.package_approved,
    });
    Ok(reply(request_id, RunHandle { run_id }))
}

#[tauri::command]
pub fn resume_restore(
    request: WireEnvelope<ResumeRestoreRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<RunHandle>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    let token = CancellationToken::new();
    state.registry.register(run_id.clone(), token.clone())?;
    spawn_resume(
        state.service.clone(),
        state.registry.clone(),
        app,
        run_id.clone(),
        token,
    );
    Ok(reply(request_id, RunHandle { run_id }))
}

#[tauri::command]
pub async fn verify(
    request: WireEnvelope<GetRunRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<ReportResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    let token = CancellationToken::new();
    let event_app = app.clone();
    let progress = move |event: ProgressEvent| {
        let _ = events::emit_progress(&event_app, event);
    };
    let report = state.service.verify(run_id, &token, progress).await?;
    let _ = events::emit_report(&app, report.clone());
    Ok(reply(request_id, ReportResponse { report }))
}

#[tauri::command]
pub fn get_run(
    request: WireEnvelope<GetRunRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<RunResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    let details = state.service.run_details(&run_id)?;
    let run = details.as_ref().map(run_view);
    let report = match state.service.report(&run_id) {
        Ok(report) => Some(report),
        Err(error) if error.code == reforge_domain::ReforgeErrorCode::PathNotFound => None,
        Err(error) => return Err(error),
    };
    let lifecycle = state.registry.get(&run_id)?;
    Ok(reply(
        request_id,
        RunResponse {
            run,
            lifecycle,
            report,
        },
    ))
}

#[tauri::command]
pub fn ack_manual_action(
    request: WireEnvelope<AckManualActionRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<ManualActionResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    validate_action_id(&request.action_id)?;
    let action = state
        .service
        .acknowledge_manual_action(&run_id, &request.action_id)?
        .to_manual_action();
    Ok(reply(request_id, ManualActionResponse { action }))
}

#[tauri::command]
pub fn save_report(
    request: WireEnvelope<SaveReportRequest>,
    state: State<'_, AppState>,
) -> Result<WireEnvelope<ReportResponse>, Box<ErrorEnvelope>> {
    let (request_id, request) = unpack(request)?;
    let run_id = parse_run_id(&request.run_id)?;
    let output = selected_path(
        &state,
        &request.output_selection_id,
        SelectionKind::ReportOutput,
    )?;
    let report = state.service.save_report(&run_id, &output)?;
    Ok(reply(request_id, ReportResponse { report }))
}

/// Open a native package picker. The absolute path remains in Rust state.
#[tauri::command]
pub async fn select_package_file(
    request: WireEnvelope<EmptyRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<NativeDialogResult>, Box<ErrorEnvelope>> {
    let (request_id, _) = unpack(request)?;
    let selections = state.selections.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Open Reforge package")
            .add_filter("Reforge package", &["reforge"])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| {
        operation_error_with_detail("native package dialog failed", error.to_string())
    })?;
    let result = match selected {
        None => NativeDialogResult::Cancelled,
        Some(path) => {
            let path = path.into_path().map_err(|error| {
                operation_error_with_detail("native package path is invalid", error.to_string())
            })?;
            let path = package_path(path)?;
            let selection_id = selections.insert(path, SelectionKind::PackageInput)?;
            NativeDialogResult::Selected { selection_id }
        }
    };
    Ok(reply(request_id, result))
}

/// Open a native package destination picker. The destination is write-only
/// backend state and is accepted by create_package only for this selection.
#[tauri::command]
pub async fn select_package_destination(
    request: WireEnvelope<EmptyRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<NativeDialogResult>, Box<ErrorEnvelope>> {
    let (request_id, _) = unpack(request)?;
    let selections = state.selections.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Save Reforge package")
            .set_file_name("environment.reforge")
            .add_filter("Reforge package", &["reforge"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| {
        operation_error_with_detail("native package save dialog failed", error.to_string())
    })?;
    let result = match selected {
        None => NativeDialogResult::Cancelled,
        Some(path) => {
            let path = path.into_path().map_err(|error| {
                operation_error_with_detail(
                    "native package destination is invalid",
                    error.to_string(),
                )
            })?;
            let path = package_output_path(path)?;
            let selection_id = selections.insert(path, SelectionKind::PackageOutput)?;
            NativeDialogResult::Selected { selection_id }
        }
    };
    Ok(reply(request_id, result))
}

/// Open a native report destination picker. The report writer validates the
/// destination again immediately before its atomic write.
#[tauri::command]
pub async fn select_report_destination(
    request: WireEnvelope<EmptyRequest>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<WireEnvelope<NativeDialogResult>, Box<ErrorEnvelope>> {
    let (request_id, _) = unpack(request)?;
    let selections = state.selections.clone();
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Save Reforge report")
            .set_file_name("reforge-report.json")
            .add_filter("JSON report", &["json"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| {
        operation_error_with_detail("native report dialog failed", error.to_string())
    })?;
    let result = match selected {
        None => NativeDialogResult::Cancelled,
        Some(path) => {
            let path = path.into_path().map_err(|error| {
                operation_error_with_detail(
                    "native report destination is invalid",
                    error.to_string(),
                )
            })?;
            let path = report_output_path(path)?;
            let selection_id = selections.insert(path, SelectionKind::ReportOutput)?;
            NativeDialogResult::Selected { selection_id }
        }
    };
    Ok(reply(request_id, result))
}

struct RestoreJob<R: tauri::Runtime> {
    service: Arc<ApplicationService>,
    registry: Arc<RunRegistry>,
    app: AppHandle<R>,
    run_id: RunId,
    token: CancellationToken,
    package: PathBuf,
    mode: RestoreMode,
    package_approved: bool,
}

fn spawn_restore<R: tauri::Runtime + 'static>(job: RestoreJob<R>) {
    let RestoreJob {
        service,
        registry,
        app,
        run_id,
        token,
        package,
        mode,
        package_approved,
    } = job;
    tauri::async_runtime::spawn(async move {
        let _ = registry.mark_running(&run_id);
        let _ = events::emit_restore_progress(
            &app,
            run_id.clone(),
            events::RestoreProgressDelta {
                status: RunStatus::Running,
                operation_id: None,
                operation_state: None,
                completed: 0,
                total: None,
                message: "Restore started".to_owned(),
            },
        );
        let event_app = app.clone();
        let progress = move |event: ProgressEvent| {
            let _ = events::emit_progress(&event_app, event);
        };
        let result = service
            .start_restore(
                &package,
                mode,
                run_id.clone(),
                package_approved,
                &token,
                progress,
            )
            .await;
        match result {
            Ok(report) => {
                let status = report_status_to_run_status(&report.status);
                let _ = events::emit_restore_progress(
                    &app,
                    run_id.clone(),
                    events::RestoreProgressDelta {
                        status,
                        operation_id: None,
                        operation_state: None,
                        completed: report.counts.verified
                            + report.counts.partial
                            + report.counts.already_present
                            + report.counts.waiting_for_user
                            + report.counts.reauth_required
                            + report.counts.reboot_required
                            + report.counts.unsupported
                            + report.counts.failed,
                        total: None,
                        message: "Restore finished".to_owned(),
                    },
                );
                let _ = events::emit_report(&app, report);
                let _ = registry.finish(&run_id, RunLifecycle::Completed, None);
            }
            Err(error) => {
                let status = if error.code == reforge_domain::ReforgeErrorCode::Cancelled {
                    RunLifecycle::Cancelled
                } else {
                    RunLifecycle::Failed
                };
                let _ = events::emit_error(&app, run_id.clone(), (*error).clone());
                let _ = registry.finish(&run_id, status, Some((*error).clone()));
            }
        }
    });
}

fn spawn_resume<R: tauri::Runtime + 'static>(
    service: Arc<ApplicationService>,
    registry: Arc<RunRegistry>,
    app: AppHandle<R>,
    run_id: RunId,
    token: CancellationToken,
) {
    tauri::async_runtime::spawn(async move {
        let _ = registry.mark_running(&run_id);
        let _ = events::emit_restore_progress(
            &app,
            run_id.clone(),
            events::RestoreProgressDelta {
                status: RunStatus::Running,
                operation_id: None,
                operation_state: None,
                completed: 0,
                total: None,
                message: "Restore resume started".to_owned(),
            },
        );
        let event_app = app.clone();
        let progress = move |event: ProgressEvent| {
            let _ = events::emit_progress(&event_app, event);
        };
        let result = service
            .resume_restore(run_id.clone(), &token, progress)
            .await;
        match result {
            Ok(report) => {
                let status = report_status_to_run_status(&report.status);
                let _ = events::emit_restore_progress(
                    &app,
                    run_id.clone(),
                    events::RestoreProgressDelta {
                        status,
                        operation_id: None,
                        operation_state: None,
                        completed: report.counts.verified
                            + report.counts.partial
                            + report.counts.already_present
                            + report.counts.waiting_for_user
                            + report.counts.reauth_required
                            + report.counts.reboot_required
                            + report.counts.unsupported
                            + report.counts.failed,
                        total: None,
                        message: "Restore resume finished".to_owned(),
                    },
                );
                let _ = events::emit_report(&app, report);
                let _ = registry.finish(&run_id, RunLifecycle::Completed, None);
            }
            Err(error) => {
                let status = if error.code == reforge_domain::ReforgeErrorCode::Cancelled {
                    RunLifecycle::Cancelled
                } else {
                    RunLifecycle::Failed
                };
                let _ = events::emit_error(&app, run_id.clone(), (*error).clone());
                let _ = registry.finish(&run_id, status, Some((*error).clone()));
            }
        }
    });
}

fn run_view(details: &ApplicationRunDetails) -> RunView {
    RunView {
        run_id: details.run.id.clone(),
        package_id: details.run.package_id.clone(),
        mode: details.run.mode.clone(),
        target_fingerprint: details.run.target_fingerprint.clone(),
        status: details.run.status.clone(),
        approval_state: details.run.approval_state.clone(),
        created_at: details.run.created_at.to_rfc3339(),
        updated_at: details.run.updated_at.to_rfc3339(),
        operations: details.operations.iter().map(operation_view).collect(),
        events: details.events.iter().map(event_view).collect(),
        manual_actions: details
            .manual_actions
            .iter()
            .map(JournalManualAction::to_manual_action)
            .collect(),
    }
}

fn operation_view(operation: &JournalOperation) -> OperationView {
    OperationView {
        id: operation.id.clone(),
        operation: operation.operation.clone(),
        state: operation.state.clone(),
        attempt: operation.attempt,
        started_at: operation.started_at.map(|time| time.to_rfc3339()),
        ended_at: operation.ended_at.map(|time| time.to_rfc3339()),
        result: operation.result.clone(),
        error: operation.error.clone(),
        backup: operation.backup.clone(),
    }
}

fn event_view(event: &JournalEvent) -> EventView {
    EventView {
        seq: event.seq,
        run_id: event.run_id.clone(),
        time: event.time.to_rfc3339(),
        level: event.level.clone(),
        event: event.event.clone(),
    }
}

fn report_status_to_run_status(status: &ReportStatus) -> RunStatus {
    match status {
        ReportStatus::Verified | ReportStatus::AlreadyPresent => RunStatus::Completed,
        ReportStatus::WaitingForUser | ReportStatus::ReauthRequired => RunStatus::WaitingForUser,
        ReportStatus::RebootRequired => RunStatus::WaitingForReboot,
        ReportStatus::PartiallyVerified | ReportStatus::Skipped | ReportStatus::Unsupported => {
            RunStatus::Partial
        }
        ReportStatus::Failed => RunStatus::Failed,
    }
}

fn unpack<T>(request: WireEnvelope<T>) -> Result<(String, T), Box<ErrorEnvelope>> {
    if request.schema_version != BRIDGE_SCHEMA_VERSION {
        return Err(schema_error("request schema version is unsupported"));
    }
    validate_request_id(&request.request_id)?;
    Ok((request.request_id, request.payload))
}

fn reply<T>(request_id: String, payload: T) -> WireEnvelope<T> {
    WireEnvelope {
        schema_version: BRIDGE_SCHEMA_VERSION,
        request_id,
        payload,
    }
}

fn parse_run_id(value: &str) -> Result<RunId, Box<ErrorEnvelope>> {
    let uuid = Uuid::parse_str(value).map_err(|_| schema_error("run ID must be a UUIDv7"))?;
    RunId::new(uuid).map_err(|_| schema_error("run ID must be a UUIDv7"))
}

fn validate_request_id(value: &str) -> Result<(), Box<ErrorEnvelope>> {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(schema_error("request ID is invalid"));
    }
    Ok(())
}

fn validate_action_id(value: &str) -> Result<(), Box<ErrorEnvelope>> {
    if value.is_empty() || value.len() > MAX_ACTION_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(schema_error("manual action ID is invalid"));
    }
    Ok(())
}

fn selected_path(
    state: &AppState,
    selection_id: &str,
    kind: SelectionKind,
) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let path = state.selections.resolve(selection_id, kind)?;
    match kind {
        SelectionKind::PackageInput => package_path(path),
        SelectionKind::PackageOutput => package_output_path(path),
        SelectionKind::ReportOutput => report_output_path(path),
    }
}

fn validate_selection_id(value: &str) -> Result<(), Box<ErrorEnvelope>> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || value.chars().any(char::is_control)
        || Uuid::parse_str(value).is_err()
    {
        return Err(schema_error("native dialog selection ID is invalid"));
    }
    Ok(())
}

fn package_path(value: PathBuf) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let path = absolute_path(value, "package")?;
    if !has_extension(&path, "reforge") {
        return Err(schema_error("package path must use the .reforge extension"));
    }
    Ok(path)
}

fn package_output_path(value: PathBuf) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let path = absolute_path(value, "package output")?;
    if !has_extension(&path, "reforge") {
        return Err(schema_error(
            "package output must use the .reforge extension",
        ));
    }
    Ok(path)
}

fn report_output_path(value: PathBuf) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let path = absolute_path(value, "report output")?;
    if !has_extension(&path, "json") {
        return Err(schema_error("report output must use the .json extension"));
    }
    Ok(path)
}

fn absolute_path(path: PathBuf, label: &str) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let text = path.to_string_lossy();
    if text.is_empty() || text.len() > MAX_PATH_BYTES || text.chars().any(char::is_control) {
        return Err(schema_error(format!("{label} path is invalid")));
    }
    if !path.is_absolute() {
        return Err(schema_error(format!("{label} path must be absolute")));
    }
    Ok(path)
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, Box<ErrorEnvelope>> {
    mutex
        .lock()
        .map_err(|_| operation_error("desktop run registry is unavailable"))
}

fn schema_error(message: impl Into<String>) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        reforge_domain::ReforgeErrorCode::SchemaInvalid,
        message,
    ))
}

fn operation_error(message: impl Into<String>) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        reforge_domain::ReforgeErrorCode::OperationFailed,
        message,
    ))
}

fn operation_error_with_detail(
    message: impl Into<String>,
    detail: impl AsRef<str>,
) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(reforge_domain::ReforgeErrorCode::OperationFailed, message)
            .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_id() -> RunId {
        RunId::new(Uuid::now_v7()).expect("UUIDv7 run ID")
    }

    #[test]
    fn scan_request_rejects_unsupported_scope_field() {
        let request = serde_json::from_str::<WireEnvelope<StartScanRequest>>(
            r#"{"schema_version":1,"request_id":"req","payload":{}}"#,
        )
        .expect("empty scan request must deserialize");
        assert!(unpack(request).is_ok());

        let error = serde_json::from_str::<WireEnvelope<StartScanRequest>>(
            r#"{"schema_version":1,"request_id":"req","payload":{"scope":"user"}}"#,
        )
        .expect_err("removed scan scope must be rejected");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn request_schema_and_path_validation_are_fail_closed() {
        let request = WireEnvelope {
            schema_version: BRIDGE_SCHEMA_VERSION,
            request_id: "req".to_owned(),
            payload: EmptyRequest {},
        };
        assert!(unpack(request).is_ok());
        assert!(absolute_path(PathBuf::from("relative/file.reforge"), "package").is_err());
        assert!(
            absolute_path(PathBuf::from("C:\\Users\\Alice\\file\0.reforge"), "package").is_err()
        );
    }

    #[test]
    fn native_selection_is_scoped_to_the_dialog_operation() {
        let selections = SelectionStore::default();
        let path = PathBuf::from("C:\\Users\\Alice\\package.reforge");
        let selection_id = selections
            .insert(path.clone(), SelectionKind::PackageInput)
            .expect("selection");
        assert_eq!(
            selections
                .resolve(&selection_id, SelectionKind::PackageInput)
                .expect("matching selection"),
            path
        );
        assert!(
            selections
                .resolve(&selection_id, SelectionKind::PackageOutput)
                .is_err()
        );
    }

    #[test]
    fn cancellation_registry_cancels_only_active_run() {
        let registry = RunRegistry::default();
        let active_run_id = run_id();
        let token = CancellationToken::new();
        registry
            .register(active_run_id.clone(), token.clone())
            .expect("register run");
        assert!(registry.cancel(&active_run_id).expect("cancel run"));
        assert!(token.is_cancelled());
        assert!(
            !registry
                .cancel(&run_id())
                .expect("unknown run is not active")
        );
    }

    #[test]
    fn native_dialog_result_has_stable_opaque_wire_shape() {
        let selection_id = Uuid::now_v7().to_string();
        let value = serde_json::to_value(NativeDialogResult::Selected {
            selection_id: selection_id.clone(),
        })
        .expect("dialog result JSON");
        assert_eq!(value["status"], "selected");
        assert_eq!(value["selection_id"], selection_id);
        assert!(value.get("path").is_none());
    }

    #[test]
    fn capability_has_no_desktop_control_and_configuration_is_valid_json() {
        let capability = include_str!("../capabilities/main.json");
        assert!(!capability.contains("core:default"));
        assert!(!capability.contains("fs:"));
        assert!(!capability.contains("shell:"));
        assert!(!capability.contains("core:event:"));
        assert!(!capability.contains("dialog:"));
        assert!(capability.contains("\"permissions\": []"));
        let configuration: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json"))
                .expect("Tauri configuration JSON");
        assert!(configuration.get("plugins").is_none());
    }
}
