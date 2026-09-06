mod interactive;
#[path = "report.rs"]
pub mod report;
#[path = "secret_prompt.rs"]
pub mod secret_prompt;
mod tui;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Cursor, Seek, SeekFrom, Write},
    path::{Component as PathComponent, Path, PathBuf, Prefix},
    process,
    sync::Arc,
};

use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use reforge_discovery::{
    DiscoveryCoordinator,
    generic::GenericExecutableAdapter,
    harnesses::{
        AgentCatalogAdapter, AgentRuntimeAdapter, AgentRuntimeKind, HarnessKind,
        HarnessRegistryAdapter,
    },
    providers::{
        AdapterRegistry, ChocolateyAdapter, DockerAdapter, DotnetAdapter, GoAdapter,
        JavaScriptAdapter, NodePackageManager, PowerShellAdapter, PythonAdapter, RustAdapter,
        ScoopAdapter, WinGetAdapter, WindowsRegistrationAdapter, WslAdapter,
    },
};
use reforge_domain::RedactionPolicy;
use reforge_domain::selection::build_selection_closure;
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactSelection, Component, ComponentId, ComponentKind,
    ContentType, ErrorEnvelope, HostFacts, Inventory, KnownFolderToken, ManualAction, ObjectEntry,
    ObjectIndex, Operation, OperationState, PackageGraph, PackageManifest, PathToken,
    ProgressEvent, ReforgeErrorCode, RestoreMode, RestorePlan, RestoreReport, RestoreStrategy,
    RunId, ScanPhase, SecretSelectionPolicy, SelectionInput, SelectionPolicy, TargetFacts,
    TransportReceipt, TrustState,
};
use reforge_package::{
    InspectedPackage, ObjectStore, PackageReader, PackageWriteRequest, PackageWriter, canonicalize,
};
use reforge_platform_windows::{
    AtomicWriteSpec, BoundedFileReader, CancellationToken, FileAttributes, KnownFolderMap,
    ProcessRunner, SafePath, atomic_replace, host_preflight,
};
use reforge_restore::{
    BrowserAwareRestoreHandler, CompatibilityEngine, ComponentDisposition, DiffEngine,
    DockerRestoreHandler, EnvironmentRestoreHandler, ExecutionContext, Executor,
    HarnessRestoreHandler, Journal, JournalEvent, JournalManualAction, JournalOperation,
    JournalRun, ManualActionHandler, ManualActionQueue, ObjectSource, ProviderInstallHandler,
    RestorePlanner, TargetDiff, TargetScanner, VerificationEngine, VerificationInput,
    VsCodeRestoreHandler, WslRestoreHandler, recommended_free_bytes,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::runtime::Builder;
use uuid::Uuid;

const CLI_SCHEMA_VERSION: u16 = 1;
const STATE_SCHEMA_VERSION: u16 = 1;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "reforge",
    version,
    about = "Reforge environment reconstruction"
)]
struct Cli {
    /// Emit exactly one versioned JSON document on stdout.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover the current Windows environment.
    Scan,
    /// Start the guided quick-backup workflow.
    Backup,
    /// Inspect or create a portable package.
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Show the last persisted inventory.
    Inventory {
        #[command(subcommand)]
        command: InventoryCommand,
    },
    /// Capture normalized target facts.
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Build a journaled restore plan without executing it.
    Plan {
        #[arg(long)]
        package: PathBuf,
        #[arg(long, value_enum)]
        mode: ModeArg,
    },
    /// Open guided restore, or execute an explicit automation restore when options are supplied.
    Restore {
        #[arg(long, requires = "mode")]
        package: Option<PathBuf>,
        #[arg(long, value_enum, requires = "package")]
        mode: Option<ModeArg>,
        #[arg(long, requires = "package")]
        yes_safe: bool,
    },
    /// Continue an approved interrupted or pending run.
    Resume {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
    },
    /// Inspect or acknowledge durable manual actions for a restore run.
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
    /// Re-scan and produce a redacted verification report.
    Verify {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
    },
    /// Print or save a previously generated report.
    Report {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Check host and local state prerequisites.
    Doctor,
    /// Open the interactive terminal-first interface.
    Interactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
enum ModeArg {
    Rebuild,
    Migrate,
}

impl From<ModeArg> for RestoreMode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Rebuild => Self::Rebuild,
            ModeArg::Migrate => Self::Migration,
        }
    }
}

#[derive(Debug, Subcommand)]
enum PackageCommand {
    Create {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        selection: Option<PathBuf>,
        #[arg(long)]
        secret_selection: Option<PathBuf>,
    },
    Inspect {
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum InventoryCommand {
    Show,
}

#[derive(Debug, Subcommand)]
enum TargetCommand {
    Scan,
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    /// List the redacted manual-action queue for a run.
    List {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
    },
    /// Record that a user resolved one listed action.
    Acknowledge {
        #[arg(value_parser = parse_run_id)]
        run_id: RunId,
        action_id: String,
    },
}

#[derive(Debug)]
struct CommandResult {
    payload: Value,
    human: String,
    exit_code: i32,
}

#[derive(Clone, Debug)]
struct StatePaths {
    root: PathBuf,
    inventory: PathBuf,
    target: PathBuf,
    journal: PathBuf,
}

impl StatePaths {
    fn run_state(&self, run_id: &RunId) -> PathBuf {
        self.root.join("runs").join(format!("{run_id}.json"))
    }

    fn report_state(&self, run_id: &RunId) -> PathBuf {
        self.root.join("reports").join(format!("{run_id}.json"))
    }
}
/// Shared orchestration boundary used by both the CLI and the desktop shell.
///
/// The service owns the local state paths and one journal writer.  UI callers
/// never receive platform-only absolute roots or package object bytes; they
/// receive only domain models and redacted reports.
#[derive(Clone, Debug)]
pub struct ApplicationService {
    state: StatePaths,
    journal: Journal,
}

/// Read-only journal state exposed to a desktop caller.
#[derive(Clone, Debug)]
pub struct ApplicationRunDetails {
    pub run: JournalRun,
    pub operations: Vec<JournalOperation>,
    pub events: Vec<JournalEvent>,
    pub manual_actions: Vec<JournalManualAction>,
}

/// Result of the same conservative selection review used by package creation.
#[derive(Clone, Debug)]
pub(crate) struct SelectionReview {
    pub selection: SelectionInput,
    pub selected_components: Vec<ComponentId>,
    pub selected_artifacts: Vec<ArtifactId>,
    pub total_bytes: u64,
    pub secret_findings: Vec<SecretFinding>,
}

/// A secret-like value was detected without retaining or exposing its value.
#[derive(Clone, Debug)]
pub(crate) struct SecretFinding {
    pub component_name: String,
    pub artifact_path: String,
    pub reason: String,
}
/// Stable counts derived from the target diff used to build a restore preview.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct PlanSummary {
    pub install: usize,
    pub already_present: usize,
    pub update: usize,
    pub configurations: usize,
    pub manual: usize,
    pub reauth: usize,
}

impl ApplicationService {
    /// Open the process-local state directory and its single journal writer.
    pub fn new() -> Result<Self, Box<ErrorEnvelope>> {
        let state = state_paths()?;
        let journal = Journal::open(state.journal.clone())?;
        Ok(Self { state, journal })
    }

    /// Allocate a UUIDv7 identity before registering a cancellable operation.
    pub fn allocate_run_id() -> Result<RunId, Box<ErrorEnvelope>> {
        new_run_id()
    }

    /// Scan the current user environment and persist the authoritative inventory.
    pub async fn scan<F>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<Inventory, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let discovered = discover_current_host_with(run_id, cancellation, progress).await?;
        write_json_state(&self.state.inventory, &discovered.inventory)?;
        Ok(discovered.inventory)
    }

    /// Scan the current target and persist normalized target facts.
    pub async fn target_scan<F>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<TargetFacts, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let target = discover_target_with(run_id, cancellation, progress).await?;
        write_json_state(&self.state.target, &target.facts)?;
        Ok(target.facts)
    }

    /// Load the last persisted inventory without rescanning the host.
    pub fn inventory(&self) -> Result<Inventory, Box<ErrorEnvelope>> {
        read_json_state(&self.state.inventory)
    }

    /// Inspect a package through the bounded, fail-closed package reader.
    pub fn inspect_package(&self, path: &Path) -> Result<InspectedPackage, Box<ErrorEnvelope>> {
        let path = existing_file_path(path, "package")?;
        PackageReader::new(path).inspect()
    }

    /// Create a package from the persisted inventory and an explicit selection.
    pub fn create_package(
        &self,
        output: &Path,
        selection: SelectionInput,
    ) -> Result<reforge_domain::TransportReceipt, Box<ErrorEnvelope>> {
        self.create_package_with_cancel(output, selection, &CancellationToken::new())
    }

    /// Create a package without publishing a partial result when cancellation wins.
    pub(crate) fn create_package_with_cancel(
        &self,
        output: &Path,
        selection: SelectionInput,
        cancellation: &CancellationToken,
    ) -> Result<TransportReceipt, Box<ErrorEnvelope>> {
        ensure_not_cancelled(cancellation)?;
        require_vault_free_selection(&selection)?;
        let inventory = self.inventory()?;
        let output = prepare_package_output(output)?;
        let preflight = host_preflight()?;
        let closure = build_selection_closure(&inventory.graph, &selection)?;
        ensure_package_storage_available(
            &preflight.facts,
            &self.state.root,
            &output,
            closure.total_bytes,
        )?;
        let (manifest, graph, selection, object_index, store) = build_package_inputs(
            &inventory,
            selection,
            &preflight.known_folders,
            &self.state,
            cancellation,
        )?;
        ensure_not_cancelled(cancellation)?;
        let refreshed = host_preflight()?;
        ensure_package_output_available(&refreshed.facts, &output, &object_index)?;
        write_package_with_cancel(
            &output,
            PackageWriteRequest {
                manifest: &manifest,
                graph: &graph,
                selection: &selection,
                object_index: &object_index,
                signature: None,
                vault: None,
            },
            &store,
            cancellation,
        )
    }

    /// Review an input selection before it reaches the package writer.
    pub(crate) fn review_selection(
        &self,
        selection: SelectionInput,
    ) -> Result<SelectionReview, Box<ErrorEnvelope>> {
        let inventory = self.inventory()?;
        let preflight = host_preflight()?;
        review_selection(&inventory, selection, &preflight.known_folders)
    }
    /// Return the persisted, diff-backed counts for this exact preview.
    pub(crate) fn plan_summary(
        &self,
        plan: &RestorePlan,
    ) -> Result<PlanSummary, Box<ErrorEnvelope>> {
        let state: RunState = read_json_state(&self.state.run_state(&plan.run_id))?;
        if state.schema_version != STATE_SCHEMA_VERSION
            || state.run_id != plan.run_id
            || state.plan != *plan
        {
            return Err(boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "Persisted restore preview does not match the requested plan",
            ));
        }
        state.plan_summary.ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "This restore preview predates diff-backed plan summaries",
            )
        })
    }

    /// Build and persist a restore plan after explicit package trust approval.
    pub async fn build_plan<F>(
        &self,
        package_path: &Path,
        mode: RestoreMode,
        run_id: RunId,
        package_approved: bool,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<RestorePlan, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let package_path = existing_file_path(package_path, "package")?;
        let mut package = PackageReader::new(package_path.clone()).inspect()?;
        if package_approved {
            package.decide_trust(reforge_package::TrustDecision::Approve)?;
        } else {
            package.require_plan_approval()?;
        }
        let target = discover_target_with(run_id.clone(), cancellation, progress).await?;
        let (plan, summary) =
            build_plan_with_summary(&package, mode, run_id.clone(), &target.facts)?;
        self.journal.create_run(&plan)?;
        let run_state = make_run_state(&package_path, &package, plan.clone(), Some(summary))?;
        write_json_state(&self.state.run_state(&run_id), &run_state)?;
        Ok(plan)
    }

    /// Approve, execute, and persist a new restore run.
    pub async fn start_restore<F>(
        &self,
        package_path: &Path,
        mode: RestoreMode,
        run_id: RunId,
        package_approved: bool,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        if !package_approved {
            return Err(boxed_error(
                ReforgeErrorCode::PackageUntrusted,
                "Restore requires explicit package trust approval",
            ));
        }
        let package_path = existing_file_path(package_path, "package")?;
        let mut package = PackageReader::new(package_path.clone()).inspect()?;
        package.decide_trust(reforge_package::TrustDecision::Approve)?;
        let target = discover_target_with(run_id.clone(), cancellation, progress).await?;
        let (plan, summary) =
            build_plan_with_summary(&package, mode, run_id.clone(), &target.facts)?;
        self.journal.create_run(&plan)?;
        self.journal.approve_run(&run_id)?;
        let run_state = make_run_state(&package_path, &package, plan.clone(), Some(summary))?;
        write_json_state(&self.state.run_state(&run_id), &run_state)?;
        let (report, _) = self
            .execute_to_report(
                package,
                plan,
                target,
                package_path,
                cancellation,
                ignore_operation_progress,
            )
            .await?;
        Ok(report)
    }
    /// Approve and execute the exact plan already previewed by the terminal UI,
    /// reporting both target discovery and durable operation progress.
    pub(crate) async fn execute_planned_restore_with_operation_progress<F, G>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
        operation_progress: G,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
        G: Fn(&Operation, OperationState, u64, u64) + Send + Sync,
    {
        let run_state: RunState = read_json_state(&self.state.run_state(&run_id))?;
        if run_state.schema_version != STATE_SCHEMA_VERSION || run_state.run_id != run_id {
            return Err(boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "Persisted restore preview is invalid",
            ));
        }
        let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
        let mut package = PackageReader::new(package_path.clone()).inspect()?;
        validate_run_package(&run_state, &package)?;
        package.decide_trust(reforge_package::TrustDecision::Approve)?;
        self.journal.approve_run(&run_id)?;
        let target = discover_target_with(run_id.clone(), cancellation, progress).await?;
        let (report, _) = self
            .execute_to_report(
                package,
                run_state.plan,
                target,
                package_path,
                cancellation,
                operation_progress,
            )
            .await?;
        Ok(report)
    }

    /// Resume an already approved run after conservative package/target checks.
    pub async fn resume_restore<F>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        self.resume_restore_with_operation_progress(
            run_id,
            cancellation,
            progress,
            ignore_operation_progress,
        )
        .await
    }

    pub async fn resume_restore_with_operation_progress<F, G>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
        operation_progress: G,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
        G: Fn(&Operation, OperationState, u64, u64) + Send + Sync,
    {
        let run_state: RunState = read_json_state(&self.state.run_state(&run_id))?;
        if run_state.schema_version != STATE_SCHEMA_VERSION || run_state.run_id != run_id {
            return Err(boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "Persisted run state is invalid",
            ));
        }
        let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
        let mut package = PackageReader::new(package_path.clone()).inspect()?;
        validate_run_package(&run_state, &package)?;
        package.decide_trust(reforge_package::TrustDecision::Approve)?;
        let target = discover_target_with(run_id.clone(), cancellation, progress).await?;
        self.journal.require_approved(&run_id)?;
        let (report, _) = self
            .execute_to_report(
                package,
                run_state.plan,
                target,
                package_path,
                cancellation,
                operation_progress,
            )
            .await?;
        Ok(report)
    }

    /// Re-scan the target and persist a redacted verification report.
    pub async fn verify<F>(
        &self,
        run_id: RunId,
        cancellation: &CancellationToken,
        progress: F,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let run_state: RunState = read_json_state(&self.state.run_state(&run_id))?;
        let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
        let package = PackageReader::new(package_path).inspect()?;
        validate_run_package(&run_state, &package)?;
        let target = discover_target_with(run_id.clone(), cancellation, progress).await?;
        let report = build_report(&run_state.plan, &package, &target.facts, &self.journal)?;
        write_json_state(&self.state.report_state(&run_id), &report)?;
        Ok(report)
    }

    /// Return a previously persisted redacted report.
    pub fn report(&self, run_id: &RunId) -> Result<RestoreReport, Box<ErrorEnvelope>> {
        read_json_state(&self.state.report_state(run_id))
    }

    /// Save a persisted report through the atomic output boundary.
    pub fn save_report(
        &self,
        run_id: &RunId,
        output: &Path,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>> {
        let report = self.report(run_id)?;
        let output = output_file_path(output)?;
        let bytes = report::format_report_json(&report).map_err(|_| {
            boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "Report serialization failed",
            )
        })?;
        write_absolute_file(&output, bytes.as_bytes())?;
        Ok(report)
    }

    /// Acknowledge one persisted manual action without exposing journal writes.
    pub fn acknowledge_manual_action(
        &self,
        run_id: &RunId,
        action_id: &str,
    ) -> Result<JournalManualAction, Box<ErrorEnvelope>> {
        ManualActionQueue::new(self.journal.clone()).acknowledge(run_id, action_id)
    }

    /// Mark one pending manual action skipped without exposing journal details.
    pub(crate) fn skip_manual_action(
        &self,
        run_id: &RunId,
        action_id: &str,
    ) -> Result<JournalManualAction, Box<ErrorEnvelope>> {
        ManualActionQueue::new(self.journal.clone()).skip(run_id, action_id)
    }

    /// Read one run and its redacted journal projections.
    pub fn run_details(
        &self,
        run_id: &RunId,
    ) -> Result<Option<ApplicationRunDetails>, Box<ErrorEnvelope>> {
        let Some(run) = self.journal.get_run(run_id)? else {
            return Ok(None);
        };
        Ok(Some(ApplicationRunDetails {
            run,
            operations: self.journal.list_operations(run_id)?,
            events: self.journal.list_events(run_id)?,
            manual_actions: self.journal.list_manual_actions(run_id)?,
        }))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RunState {
    schema_version: u16,
    run_id: RunId,
    package_path: String,
    package_id: String,
    package_manifest_digest: String,
    package_graph_digest: String,
    package_selection_digest: String,
    package_object_index_digest: String,
    trust: TrustState,
    plan: RestorePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan_summary: Option<PlanSummary>,
}

#[derive(Debug)]
struct TargetSnapshot {
    facts: TargetFacts,
    known_folders: KnownFolderMap,
}

#[derive(Debug)]
struct PackageObjectSource {
    reader: PackageReader,
}

impl ObjectSource for PackageObjectSource {
    fn copy_verified_object(
        &self,
        object: &reforge_domain::ObjectId,
        output: &mut dyn Write,
    ) -> reforge_restore::RestoreResult<ObjectEntry> {
        self.reader.copy_verified_object(object, output)
    }
}

fn main() {
    let wants_json = std::env::args()
        .skip(1)
        .any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if !wants_json
                && matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                )
            {
                let exit_code = error.exit_code();
                let _ = error.print();
                process::exit(exit_code);
            }
            let envelope = ErrorEnvelope::new(
                ReforgeErrorCode::SchemaInvalid,
                "Invalid command-line arguments",
            )
            .with_technical_detail(error.to_string());
            emit_error(&envelope, wants_json, 2);
        }
    };

    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            let envelope = ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "The CLI runtime could not be initialized",
            )
            .with_technical_detail(error.to_string());
            emit_error(&envelope, wants_json, 1);
        }
    };

    match runtime.block_on(dispatch(cli)) {
        Ok(result) => emit_result(result, wants_json),
        Err(error) => {
            let code = error.code.clone();
            emit_error(&error, wants_json, error_exit_code(code));
        }
    }
}

fn parse_run_id(value: &str) -> Result<RunId, String> {
    let uuid = Uuid::parse_str(value).map_err(|_| "run ID must be a UUIDv7".to_owned())?;
    RunId::new(uuid).map_err(|_| "run ID must be a UUIDv7".to_owned())
}

async fn dispatch(cli: Cli) -> Result<CommandResult, Box<ErrorEnvelope>> {
    if cli.json
        && cli.command.as_ref().is_none_or(|command| {
            matches!(
                command,
                Command::Interactive
                    | Command::Backup
                    | Command::Restore {
                        package: None,
                        mode: None,
                        yes_safe: false
                    }
            )
        })
    {
        return Err(boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Interactive mode cannot emit JSON",
        ));
    }
    match cli.command {
        None | Some(Command::Interactive) => tui::run().await,
        Some(Command::Backup) => tui::run_quick_backup().await,
        Some(Command::Scan) => scan_command().await,
        Some(Command::Package { command }) => match command {
            PackageCommand::Create {
                output,
                selection,
                secret_selection,
            } => package_create_command(output, selection, secret_selection),
            PackageCommand::Inspect { path } => package_inspect_command(path),
        },
        Some(Command::Inventory { command }) => match command {
            InventoryCommand::Show => inventory_show_command(),
        },
        Some(Command::Target {
            command: TargetCommand::Scan,
        }) => target_scan_command().await,
        Some(Command::Plan { package, mode }) => plan_command(package, mode).await,
        Some(Command::Restore {
            package: None,
            mode: None,
            yes_safe: false,
        }) => tui::run_restore().await,
        Some(Command::Restore {
            package: Some(package),
            mode: Some(mode),
            yes_safe,
        }) => restore_command(package, mode, yes_safe).await,
        Some(Command::Restore { .. }) => Err(boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Explicit restore requires both --package and --mode",
        )),
        Some(Command::Resume { run_id }) => resume_command(run_id).await,
        Some(Command::Action { command }) => match command {
            ActionCommand::List { run_id } => action_list_command(run_id),
            ActionCommand::Acknowledge { run_id, action_id } => {
                action_acknowledge_command(run_id, action_id)
            }
        },
        Some(Command::Verify { run_id }) => verify_command(run_id).await,
        Some(Command::Report { run_id, output }) => report_command(run_id, output).await,
        Some(Command::Doctor) => doctor_command(),
    }
}

async fn scan_command() -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let discovered = discover_current_host().await?;
    write_json_state(&state.inventory, &discovered.inventory)?;
    let payload = safe_json(&json!({
        "status": "ok",
        "scan_id": discovered.inventory.scan_id,
        "component_count": discovered.inventory.graph.components.len(),
        "warning_count": discovered.inventory.warnings.len(),
    }))?;
    Ok(CommandResult {
        human: format!(
            "Scan completed: {} components, {} warnings.\n",
            discovered.inventory.graph.components.len(),
            discovered.inventory.warnings.len()
        ),
        payload,
        exit_code: 0,
    })
}

async fn target_scan_command() -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let target = discover_target().await?;
    write_json_state(&state.target, &target.facts)?;
    let payload = safe_json(&json!({
        "status": "ok",
        "target": target.facts,
    }))?;
    Ok(CommandResult {
        human: format!(
            "Target scan completed: {} installed facts, {} providers.\n",
            target.facts.installed.len(),
            target.facts.providers.len()
        ),
        payload,
        exit_code: 0,
    })
}

fn inventory_show_command() -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let inventory: Inventory = read_json_state(&state.inventory)?;
    let payload = safe_json(&json!({
        "status": "ok",
        "scan_id": inventory.scan_id,
        "component_count": inventory.graph.components.len(),
        "warning_count": inventory.warnings.len(),
        "inventory": inventory,
    }))?;
    Ok(CommandResult {
        human: format!(
            "Inventory: {} components, {} warnings.\n",
            inventory.graph.components.len(),
            inventory.warnings.len()
        ),
        payload,
        exit_code: 0,
    })
}

fn package_inspect_command(path: PathBuf) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let path = existing_file_path(&path, "package")?;
    let package = PackageReader::new(path).inspect()?;
    let payload = safe_json(&json!({
        "status": "ok",
        "package_id": package.manifest.package_id,
        "format_version": package.manifest.format_version,
        "trust": package.trust,
        "has_vault": package.has_vault,
        "archive_bytes": package.archive_bytes(),
        "component_count": package.graph.components.len(),
        "selected_component_count": package.selection.components.len(),
        "selected_artifact_count": package
            .selection
            .artifacts
            .iter()
            .filter(|selection| selection.include)
            .count(),
        "object_count": package.object_index.objects.len(),
        "warnings": package.warnings,
        "signature": package.signature_metadata(),
    }))?;
    Ok(CommandResult {
        human: format!(
            "Package inspected: {} (trust: {:?}, {} components, {} objects).\n",
            package.manifest.package_id,
            package.trust,
            package.graph.components.len(),
            package.object_index.objects.len()
        ),
        payload,
        exit_code: 0,
    })
}

fn package_create_command(
    output: PathBuf,
    selection_path: Option<PathBuf>,
    secret_selection_path: Option<PathBuf>,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let service = ApplicationService::new()?;
    let inventory = service.inventory()?;
    let selection = match selection_path {
        Some(path) => read_json_input(&path, "selection")?,
        None => default_selection(&inventory.graph),
    };
    if let Some(path) = secret_selection_path {
        let selected = read_secret_selection(&path)?;
        if !selected.is_empty() {
            return Err(boxed_error(
                ReforgeErrorCode::VaultRequired,
                "Explicit secret selection requires secure adapter values and an encrypted vault",
            ));
        }
    }
    let receipt = service.create_package(&output, selection)?;
    let payload = safe_json(&json!({
        "status": "ok",
        "package_id": receipt.package_id,
        "object_count": receipt.object_count,
        "index_digest": receipt.index_digest,
    }))?;
    Ok(CommandResult {
        human: format!(
            "Package created: {} ({} objects).\n",
            receipt.package_id, receipt.object_count
        ),
        payload,
        exit_code: 0,
    })
}

async fn plan_command(
    package_path: PathBuf,
    mode: ModeArg,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let package_path = existing_file_path(&package_path, "package")?;
    let mut package = PackageReader::new(package_path.clone()).inspect()?;
    // Planning is non-destructive. Invoking this explicit command is the
    // approval boundary for preview; restore still requires --yes-safe.
    package.decide_trust(reforge_package::TrustDecision::Approve)?;
    let target = discover_target().await?;
    let run_id = new_run_id()?;
    let (plan, summary) =
        build_plan_with_summary(&package, mode.into(), run_id.clone(), &target.facts)?;
    let journal = Journal::open(state.journal.clone())?;
    journal.create_run(&plan)?;
    let run_state = make_run_state(&package_path, &package, plan.clone(), Some(summary))?;
    write_json_state(&state.run_state(&run_id), &run_state)?;
    let payload = safe_json(&json!({
        "status": "planned",
        "plan": plan,
    }))?;
    Ok(CommandResult {
        human: format!(
            "Plan created: run {} ({} operations, {} manual actions).\n",
            run_id,
            plan.operations.len(),
            plan.manual_actions.len()
        ),
        payload,
        exit_code: 0,
    })
}

async fn restore_command(
    package_path: PathBuf,
    mode: ModeArg,
    yes_safe: bool,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    if !yes_safe {
        return Err(boxed_error(
            ReforgeErrorCode::PackageUntrusted,
            "Restore requires explicit --yes-safe approval",
        ));
    }
    let state = state_paths()?;
    let package_path = existing_file_path(&package_path, "package")?;
    let mut package = PackageReader::new(package_path.clone()).inspect()?;
    package.decide_trust(reforge_package::TrustDecision::Approve)?;
    let target = discover_target().await?;
    let run_id = new_run_id()?;
    let (plan, summary) =
        build_plan_with_summary(&package, mode.into(), run_id.clone(), &target.facts)?;
    let journal = Journal::open(state.journal.clone())?;
    journal.create_run(&plan)?;
    journal.approve_run(&run_id)?;
    let run_state = make_run_state(&package_path, &package, plan.clone(), Some(summary))?;
    write_json_state(&state.run_state(&run_id), &run_state)?;
    execute_and_report(state, package, plan, target, package_path).await
}

async fn resume_command(run_id: RunId) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let run_state: RunState = read_json_state(&state.run_state(&run_id))?;
    if run_state.schema_version != STATE_SCHEMA_VERSION || run_state.run_id != run_id {
        return Err(boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Persisted run state is invalid",
        ));
    }
    let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
    let mut package = PackageReader::new(package_path.clone()).inspect()?;
    validate_run_package(&run_state, &package)?;
    package.decide_trust(reforge_package::TrustDecision::Approve)?;
    let target = discover_target().await?;
    let journal = Journal::open(state.journal.clone())?;
    journal.require_approved(&run_id)?;
    execute_and_report(state, package, run_state.plan, target, package_path).await
}

fn action_list_command(run_id: RunId) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let service = ApplicationService::new()?;
    let details = service.run_details(&run_id)?.ok_or_else(|| {
        boxed_error(
            ReforgeErrorCode::PathNotFound,
            "Restore run was not found in local state",
        )
    })?;
    let actions = details
        .manual_actions
        .iter()
        .map(JournalManualAction::to_manual_action)
        .collect::<Vec<_>>();
    let mut human = format!("Manual actions for run {run_id}:\n");
    if actions.is_empty() {
        human.push_str(" - none\n");
    } else {
        for action in &actions {
            human.push_str(&format!(" - {} [{:?}]\n", action.id, action.state));
        }
    }
    let payload = safe_json(&json!({
        "status": "ok",
        "run_id": run_id.to_string(),
        "manual_actions": actions,
    }))?;
    Ok(CommandResult {
        payload,
        human,
        exit_code: 0,
    })
}

fn action_acknowledge_command(
    run_id: RunId,
    action_id: String,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let service = ApplicationService::new()?;
    let action = service
        .acknowledge_manual_action(&run_id, &action_id)?
        .to_manual_action();
    let payload = safe_json(&json!({
        "status": "acknowledged",
        "run_id": run_id.to_string(),
        "action": action,
    }))?;
    Ok(CommandResult {
        payload,
        human: format!(
            "Acknowledged manual action {} for run {run_id}.\n",
            action_id
        ),
        exit_code: 0,
    })
}

async fn verify_command(run_id: RunId) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let run_state: RunState = read_json_state(&state.run_state(&run_id))?;
    let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
    let package = PackageReader::new(package_path).inspect()?;
    validate_run_package(&run_state, &package)?;
    let target = discover_target().await?;
    let journal = Journal::open(state.journal.clone())?;
    let report = build_report(&run_state.plan, &package, &target.facts, &journal)?;
    write_json_state(&state.report_state(&run_id), &report)?;
    report_result(report)
}

async fn report_command(
    run_id: RunId,
    output: Option<PathBuf>,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let report: RestoreReport = match read_json_state(&state.report_state(&run_id)) {
        Ok(report) => report,
        Err(error) if error.code == ReforgeErrorCode::PathNotFound => {
            let run_state: RunState = read_json_state(&state.run_state(&run_id))?;
            let package_path = existing_file_path(Path::new(&run_state.package_path), "package")?;
            let package = PackageReader::new(package_path).inspect()?;
            validate_run_package(&run_state, &package)?;
            let target = discover_target().await?;
            let journal = Journal::open(state.journal.clone())?;
            let report = build_report(&run_state.plan, &package, &target.facts, &journal)?;
            write_json_state(&state.report_state(&run_id), &report)?;
            report
        }
        Err(error) => return Err(error),
    };
    if let Some(path) = output {
        let path = output_file_path(&path)?;
        let bytes = report::format_report_json(&report)
            .map_err(|_| {
                boxed_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "Report serialization failed",
                )
            })?
            .into_bytes();
        write_absolute_file(&path, &bytes)?;
    }
    report_result(report)
}

fn doctor_command() -> Result<CommandResult, Box<ErrorEnvelope>> {
    let state = state_paths()?;
    let preflight = host_preflight()?;
    let payload = safe_json(&json!({
        "status": "ok",
        "state_directory_ready": state.root,
        "os_version": preflight.facts.os_version,
        "os_build": preflight.facts.os_build,
        "elevated": preflight.facts.elevated,
        "free_bytes": preflight.facts.free_bytes,
        "known_folder_count": preflight.known_folders.entries.len(),
        "warning_count": preflight.warnings.len(),
    }))?;
    Ok(CommandResult {
        human: format!(
            "Doctor: ready ({} known folders, {} warnings, administrator: {}).\n",
            preflight.known_folders.entries.len(),
            preflight.warnings.len(),
            if preflight.facts.elevated {
                "yes"
            } else {
                "no"
            }
        ),
        payload,
        exit_code: 0,
    })
}
async fn execute_and_report(
    state: StatePaths,
    package: InspectedPackage,
    plan: RestorePlan,
    target: TargetSnapshot,
    package_path: PathBuf,
) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let journal = Journal::open(state.journal.clone())?;
    let (report, execution_error) = ApplicationService { state, journal }
        .execute_to_report(
            package,
            plan,
            target,
            package_path,
            &CancellationToken::new(),
            ignore_operation_progress,
        )
        .await?;
    let mut result = report_result(report)?;
    if let Some(error) = execution_error
        && result.exit_code == 0
    {
        result.exit_code = error_exit_code(error.code);
    }
    Ok(result)
}

impl ApplicationService {
    async fn execute_to_report<G>(
        &self,
        package: InspectedPackage,
        plan: RestorePlan,
        target: TargetSnapshot,
        package_path: PathBuf,
        cancellation: &CancellationToken,
        operation_progress: G,
    ) -> Result<(RestoreReport, Option<Box<ErrorEnvelope>>), Box<ErrorEnvelope>>
    where
        G: Fn(&Operation, OperationState, u64, u64) + Send + Sync,
    {
        let source = PackageObjectSource {
            reader: PackageReader::new(package_path),
        };
        let context = ExecutionContext::new(&target.facts, &package.object_index)
            .with_object_source(&source)
            .with_file_manifests(&package.file_manifests);
        let executor = configured_executor(self.journal.clone(), target.known_folders.clone());
        let execution_error = executor
            .execute_with_progress(&plan, &context, cancellation, operation_progress)
            .await
            .err();
        if let Some(error) = &execution_error
            && matches!(
                error.code,
                ReforgeErrorCode::TargetConflict
                    | ReforgeErrorCode::PackageUntrusted
                    | ReforgeErrorCode::SecurityPolicy
            )
        {
            return Err(error.clone());
        }

        let cancelled = cancellation.is_cancelled()
            || execution_error
                .as_ref()
                .is_some_and(|error| error.code == ReforgeErrorCode::Cancelled);
        let verification_target = if cancelled {
            target.facts
        } else {
            match discover_target_with(plan.run_id.clone(), cancellation, ignore_discovery_progress)
                .await
            {
                Ok(post_restore) => {
                    write_json_state(&self.state.target, &post_restore.facts)?;
                    post_restore.facts
                }
                Err(error)
                    if error.code == ReforgeErrorCode::Cancelled || cancellation.is_cancelled() =>
                {
                    target.facts
                }
                Err(error) => return Err(error),
            }
        };
        let report = build_report(&plan, &package, &verification_target, &self.journal)?;
        write_json_state(&self.state.report_state(&plan.run_id), &report)?;
        Ok((report, execution_error))
    }
}

fn ignore_discovery_progress(_: ProgressEvent) {}

fn ignore_operation_progress(_: &Operation, _: OperationState, _: u64, _: u64) {}

fn configured_executor(journal: Journal, roots: KnownFolderMap) -> Executor {
    let mut executor = Executor::new(journal.clone());
    executor.register_handler(ManualActionHandler::new(journal));
    executor.register_handler(BrowserAwareRestoreHandler::new(roots.clone()));
    executor.register_handler(EnvironmentRestoreHandler::new(roots.clone()));
    executor.register_handler(HarnessRestoreHandler::new(roots));
    executor.register_handler(ProviderInstallHandler::new());
    executor.register_handler(VsCodeRestoreHandler::new());
    executor.register_handler(WslRestoreHandler::new());
    executor.register_handler(DockerRestoreHandler::new());
    executor
}

fn build_report(
    plan: &RestorePlan,
    package: &InspectedPackage,
    target: &TargetFacts,
    journal: &Journal,
) -> Result<RestoreReport, Box<ErrorEnvelope>> {
    let operations = journal.list_operations(&plan.run_id)?;
    let manual_actions = materialize_manual_actions(plan, journal, &operations)?;
    let input = VerificationInput::from_plan(target, plan, &package.graph, &operations)
        .with_manual_actions(&manual_actions);
    VerificationEngine::new().verify(&input)
}

fn materialize_manual_actions(
    plan: &RestorePlan,
    journal: &Journal,
    operations: &[JournalOperation],
) -> Result<Vec<ManualAction>, Box<ErrorEnvelope>> {
    let mut planned = plan
        .manual_actions
        .iter()
        .cloned()
        .map(|action| (action.id.clone(), action))
        .collect::<BTreeMap<_, _>>();
    let operation_components = operations
        .iter()
        .map(|operation| {
            (
                operation.id.to_string(),
                operation.operation.component.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut actions = Vec::new();
    for persisted in journal.list_manual_actions(&plan.run_id)? {
        let action_id = persisted.id.clone();
        let (mut action, from_plan) = match planned.remove(&action_id) {
            Some(action) => (action, true),
            None => (persisted.to_manual_action(), false),
        };
        action.id = action_id.clone();
        action.title = persisted.title;
        action.reason = persisted.reason;
        action.risk = persisted.risk;
        action.instructions = persisted.instructions;
        action.state = persisted.state;
        action.acknowledged_at = persisted.acknowledged_at;
        if !from_plan && action.component.is_none() {
            action.component = Some(
                inferred_manual_action_component(&plan.run_id, &action_id, &operation_components)
                    .ok_or_else(|| {
                    boxed_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "Journal manual action has an unrecognized scoped identity",
                    )
                })?,
            );
        }
        actions.push(action);
    }
    if planned.is_empty() {
        Ok(actions)
    } else {
        Err(boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Journal manual action set does not match the approved plan",
        ))
    }
}

fn inferred_manual_action_component(
    run_id: &RunId,
    action_id: &str,
    operation_components: &BTreeMap<String, ComponentId>,
) -> Option<ComponentId> {
    action_id
        .strip_prefix("operation-blocker:")
        .and_then(|value| value.rsplit_once(':').map(|(operation_id, _)| operation_id))
        .and_then(|operation_id| operation_components.get(operation_id).cloned())
        // The journal intentionally omits plan-only component metadata. This
        // exact generated shape is bound to the report's current run before a
        // component ID is recovered from it.
        .or_else(|| {
            let prefix = format!("manual-action:{run_id}:secret-target:");
            action_id
                .strip_prefix(&prefix)
                .and_then(|component_id| ComponentId::try_from(component_id.to_owned()).ok())
        })
}

#[cfg(test)]
mod manual_action_component_tests {
    use super::*;

    #[test]
    fn report_infers_only_current_run_secret_target_actions() {
        let run_id =
            RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID");
        let other_run = RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e32".to_owned())
            .expect("other run ID");
        let component = ComponentId::new(format!("cmp_{}", "s".repeat(52))).expect("component ID");
        let action_id = format!("manual-action:{run_id}:secret-target:{component}");
        let other_action_id = format!("manual-action:{other_run}:secret-target:{component}");

        assert_eq!(
            inferred_manual_action_component(&run_id, &action_id, &BTreeMap::new()),
            Some(component.clone())
        );
        assert_eq!(
            inferred_manual_action_component(&run_id, &other_action_id, &BTreeMap::new()),
            None
        );
        assert_eq!(
            inferred_manual_action_component(
                &run_id,
                "manual-action:foreign:secret-target:unknown",
                &BTreeMap::new()
            ),
            None
        );
    }
}

#[cfg(test)]
mod secret_screening_tests {
    use super::*;

    const SECRETS: [&str; 5] = [
        "ctx7sk-json-secret",
        "ctx7sk-jsonc-secret",
        "ctx7sk-jsonc-comment-secret",
        "ctx7sk-toml-secret",
        "ctx7sk-metadata-secret",
    ];

    #[tokio::test]
    async fn context7_headers_and_safe_config_never_reach_package_or_object_bytes() {
        let root = std::env::temp_dir().join(format!(
            "reforge-secret-screen-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let profile = root.join("profile");
        let state_root = root.join("state");
        fs::create_dir_all(&profile).expect("screening fixture profile");
        fs::create_dir_all(&state_root).expect("screening fixture state");

        let fixtures = [
            (
                'j',
                "config.json",
                ContentType::Json,
                br#"{"context7":{"headers":{"CONTEXT7_API_KEY":"ctx7sk-json-secret"}},"safe":{"mode":"on"}}"#.to_vec(),
            ),
            (
                'c',
                "config.jsonc",
                ContentType::Jsonc,
                br#"// ctx7sk-jsonc-comment-secret
{"context7":{"headers":{"CONTEXT7_API_KEY":"ctx7sk-jsonc-secret"}},"safe":{"mode":"on"}}"#.to_vec(),
            ),
            (
                't',
                "config.toml",
                ContentType::Toml,
                br#"[context7.headers]
CONTEXT7_API_KEY = "ctx7sk-toml-secret"
[safe]
mode = "on"
"#.to_vec(),
            ),
        ];
        let mut components = Vec::new();
        for (suffix, relative, content_type, bytes) in fixtures {
            fs::write(profile.join(relative), &bytes).expect("write config fixture");
            let mut component = test_component(suffix);
            let artifact = reforge_domain::ArtifactRef {
                id: ArtifactId::new(format!("artifact-{suffix}")).expect("artifact ID"),
                source_path: PathToken::new(KnownFolderToken::UserProfile, relative)
                    .expect("path token"),
                scope: reforge_domain::ConfigScope::User,
                size_bytes: bytes.len() as u64,
                content_type,
                policy: ArtifactPolicy::Config,
                object: None,
            };
            component.selection.size_bytes = artifact.size_bytes;
            component.artifacts.push(artifact);
            component
                .verification
                .push(reforge_domain::VerificationRule::ConfigParses {
                    destination: component.artifacts[0].source_path.clone(),
                    content_type: component.artifacts[0].content_type.clone(),
                });
            component.extensions.insert(
                "safe_config".to_owned(),
                json!({
                    "context7": {"headers": {"CONTEXT7_API_KEY": "ctx7sk-metadata-secret"}},
                    "safe": {"mode": "on"}
                }),
            );
            components.push(component);
        }

        let folders = KnownFolderMap::from_entries(BTreeMap::from([(
            KnownFolderToken::UserProfile,
            profile,
        )]));
        let host = HostFacts {
            os_version: "Windows 11".to_owned(),
            os_build: "fixture".to_owned(),
            architecture: reforge_domain::Architecture::X64,
            elevated: false,
            account_scope: reforge_domain::AccountScope::User,
            sid_fingerprint: None,
            known_folders: vec![
                PathToken::new(KnownFolderToken::UserProfile, "").expect("root token"),
            ],
            drives: Vec::new(),
            free_bytes: vec![reforge_domain::DriveFreeSpace {
                token: "H:".to_owned(),
                bytes: 10 * 1024 * 1024 * 1024,
            }],
        };
        let inventory = Inventory {
            format_version: 1,
            scan_id: new_run_id().expect("scan ID"),
            captured_at: Utc::now(),
            host,
            graph: PackageGraph {
                components: components.clone(),
                edges: Vec::new(),
            },
            evidence: Vec::new(),
            warnings: Vec::new(),
        };
        let selection = SelectionInput {
            components: components
                .iter()
                .map(|component| component.id.clone())
                .collect(),
            artifacts: Vec::new(),
            policy: SelectionPolicy {
                secrets: SecretSelectionPolicy::Exclude,
                large_data: reforge_domain::LargeDataSelectionPolicy::Exclude,
                unknown_binaries: reforge_domain::UnknownBinarySelectionPolicy::Exclude,
                max_bytes: None,
            },
        };
        let review =
            review_selection(&inventory, selection.clone(), &folders).expect("selection screening");
        assert_eq!(review.selected_artifacts.len(), 3);
        assert!(!review.secret_findings.is_empty());
        for finding in &review.secret_findings {
            let rendered = format!(
                "{} {} {}",
                finding.component_name, finding.artifact_path, finding.reason
            );
            assert!(SECRETS.iter().all(|secret| !rendered.contains(secret)));
        }

        let state = StatePaths {
            inventory: state_root.join("inventory.json"),
            target: state_root.join("target.json"),
            journal: state_root.join("journal.sqlite"),
            root: state_root,
        };
        let (manifest, graph, selection, object_index, store) = build_package_inputs(
            &inventory,
            selection,
            &folders,
            &state,
            &CancellationToken::new(),
        )
        .expect("safe package inputs");
        let package_path = root.join("screened.reforge");
        let request = || PackageWriteRequest {
            manifest: &manifest,
            graph: &graph,
            selection: &selection,
            object_index: &object_index,
            signature: None,
            vault: None,
        };
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let error = write_package_with_cancel(&package_path, request(), &store, &cancelled)
            .expect_err("cancelled backup must not be published");
        assert_eq!(error.code, ReforgeErrorCode::Cancelled);
        assert!(!package_path.try_exists().expect("check cancelled output"));
        write_package_with_cancel(&package_path, request(), &store, &CancellationToken::new())
            .expect("write screened package");

        let occupied = root.join("occupied.reforge");
        fs::write(&occupied, b"existing backup").expect("existing backup fixture");
        write_package_with_cancel(&occupied, request(), &store, &CancellationToken::new())
            .expect_err("publication must not overwrite an existing backup");
        assert_eq!(fs::read(&occupied).unwrap(), b"existing backup");

        let package_bytes = fs::read(&package_path).expect("read package bytes");
        assert!(
            SECRETS
                .iter()
                .all(|secret| !contains_bytes(&package_bytes, secret))
        );
        let reader = PackageReader::new(package_path.clone());
        let mut inspected = reader.inspect().expect("inspect screened package");
        let graph_bytes = serde_json::to_vec(&inspected.graph).expect("serialize graph");
        assert!(
            SECRETS
                .iter()
                .all(|secret| !contains_bytes(&graph_bytes, secret))
        );
        for component in &inspected.graph.components {
            assert_eq!(component.extensions["safe_config"]["safe"]["mode"], "on");
        }
        for entry in &inspected.object_index.objects {
            let mut bytes = Vec::new();
            reader
                .copy_verified_object(&entry.id, &mut bytes)
                .expect("copy verified object");
            assert!(SECRETS.iter().all(|secret| !contains_bytes(&bytes, secret)));
        }

        // Exercise the actual planner, payload source, handlers and verifier:
        // the archive's artifact object names a file manifest, not config bytes.
        let destination = root.join("restored-profile");
        fs::create_dir(&destination).expect("restore destination");
        let target_roots = KnownFolderMap::from_entries(BTreeMap::from([(
            KnownFolderToken::UserProfile,
            destination.clone(),
        )]));
        let mut target_inventory = inventory.clone();
        target_inventory.graph.components.clear();
        target_inventory.graph.edges.clear();
        let target = TargetScanner::new()
            .scan(target_inventory)
            .expect("empty target");
        inspected
            .decide_trust(reforge_package::TrustDecision::Approve)
            .expect("approve fixture");
        let (plan, _) = build_plan_with_summary(
            &inspected,
            RestoreMode::Migration,
            new_run_id().expect("restore run ID"),
            &target,
        )
        .expect("plan configuration restore");
        let journal = Journal::open(state.journal.clone()).expect("fixture journal");
        journal.create_run(&plan).expect("persist unapproved plan");
        let source = PackageObjectSource {
            reader: PackageReader::new(package_path),
        };
        let context = ExecutionContext::new(&target, &inspected.object_index)
            .with_object_source(&source)
            .with_file_manifests(&inspected.file_manifests);
        let executor = configured_executor(journal.clone(), target_roots);
        executor
            .execute(&plan, &context, &CancellationToken::new())
            .await
            .expect_err("an unapproved plan must not mutate the target");
        assert!(!destination.join("config.json").exists());
        journal.approve_run(&plan.run_id).expect("approve restore");
        executor
            .execute(&plan, &context, &CancellationToken::new())
            .await
            .expect("restore verified file payloads");
        for (name, content_type) in [
            ("config.json", ContentType::Json),
            ("config.jsonc", ContentType::Json),
            ("config.toml", ContentType::Toml),
        ] {
            let restored = fs::read_to_string(destination.join(name)).expect("restored config");
            let document =
                parse_config_document(&restored, &content_type).expect("parse restored config");
            assert_eq!(document["safe"]["mode"], "on");
            assert!(
                document["context7"]["headers"]
                    .get("CONTEXT7_API_KEY")
                    .is_none()
            );
            assert!(SECRETS.iter().all(|secret| !restored.contains(secret)));
        }
        let report =
            build_report(&plan, &inspected, &target, &journal).expect("verified restore report");
        assert_eq!(report.counts.verified, 3);
        assert_eq!(report.counts.failed, 0);
        drop(executor);
        drop(journal);

        fs::remove_dir_all(root).expect("remove screening fixture");
    }

    #[test]
    fn package_capacity_checks_the_correct_volume_and_fails_closed() {
        let mut facts: HostFacts = serde_json::from_value(json!({
            "os_version": "Windows 11", "os_build": "fixture", "architecture": "X64",
            "elevated": false, "account_scope": "USER", "sid_fingerprint": null,
            "known_folders": [], "drives": [],
            "free_bytes": [{"token": "C:", "bytes": 1_000_000}, {"token": "D:", "bytes": 99}]
        }))
        .expect("host fixture");
        let output = Path::new(r"D:\backups\fixture.reforge");
        assert_eq!(
            ensure_volume_free_space(&facts, output, 100, "package output")
                .unwrap_err()
                .code,
            ReforgeErrorCode::InsufficientDisk
        );
        facts.free_bytes[1].bytes = 100;
        assert!(ensure_volume_free_space(&facts, output, 100, "package output").is_ok());
        facts.free_bytes.pop();
        assert_eq!(
            ensure_volume_free_space(&facts, output, 100, "package output")
                .unwrap_err()
                .code,
            ReforgeErrorCode::SourceUnavailable
        );
        let mut same_volume = facts.clone();
        same_volume.free_bytes[0].bytes = 100 * 1024 * 1024;
        assert_eq!(
            ensure_package_storage_available(
                &same_volume,
                Path::new(r"C:\state"),
                Path::new(r"C:\backups\fixture.reforge"),
                1,
            )
            .unwrap_err()
            .code,
            ReforgeErrorCode::InsufficientDisk
        );
        same_volume.free_bytes[0].bytes = 129 * 1024 * 1024;
        ensure_package_storage_available(
            &same_volume,
            Path::new(r"C:\state"),
            Path::new(r"C:\backups\fixture.reforge"),
            1,
        )
        .expect("combined same-volume reserve");
        assert_eq!(
            ensure_package_storage_available(&facts, Path::new(r"C:\state"), output, u64::MAX)
                .unwrap_err()
                .code,
            ReforgeErrorCode::InsufficientDisk
        );
    }

    #[test]
    fn unavailable_backup_directory_preserves_existing_file() {
        let root = std::env::temp_dir().join(format!("reforge-output-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("fixture directory");
        let blocker = root.join("not-a-directory");
        fs::write(&blocker, b"existing user data").expect("blocking file");
        let output = blocker.join("backup.reforge");
        prepare_package_output(&output).expect_err("unavailable directory must fail");
        assert_eq!(fs::read(&blocker).unwrap(), b"existing user data");
        assert!(!output.is_file());
        fs::remove_dir_all(root).expect("remove output fixture");
    }

    fn contains_bytes(bytes: &[u8], needle: &str) -> bool {
        bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    fn test_component(suffix: char) -> Component {
        serde_json::from_value(json!({
            "id": format!("cmp_{}", suffix.to_string().repeat(52)),
            "kind": "CONFIGURATION",
            "identity": {
                "provider_package": null,
                "provider_source": null,
                "package_family": null,
                "product_name": "Context7 fixture",
                "executable_name": null,
                "publisher": null,
                "executable_hash": null,
                "install_role": null,
                "identity_quality": "LOCAL"
            },
            "display_name": "Context7 configuration",
            "version": null,
            "architecture": null,
            "publisher": null,
            "provenance": null,
            "evidence": [],
            "confidence": "HIGH",
            "dependencies": [],
            "artifacts": [],
            "restore": {
                "primary": "CONFIG_PORTABLE",
                "alternatives": [],
                "portability": "PORTABLE",
                "requires_elevation": false,
                "requires_user_action": false,
                "rationale": []
            },
            "compatibility": {
                "required_os": null,
                "required_architecture": null,
                "requires_provider": null,
                "requires_runtime": null,
                "requires_elevation": false,
                "requires_wsl": false,
                "requires_docker": false
            },
            "verification": [],
            "selection": {
                "recommended": true,
                "score": 50,
                "selected_by_default": true,
                "sensitive": false,
                "size_bytes": 0
            }
        }))
        .expect("component fixture")
    }
}

fn report_result(report: RestoreReport) -> Result<CommandResult, Box<ErrorEnvelope>> {
    let exit_code = report_exit_code(&report);
    let human = report::format_report(&report);
    let payload = safe_json(&report)?;
    Ok(CommandResult {
        payload,
        human,
        exit_code,
    })
}

fn report_exit_code(report: &RestoreReport) -> i32 {
    match report.status {
        reforge_domain::ReportStatus::Verified | reforge_domain::ReportStatus::AlreadyPresent => 0,
        reforge_domain::ReportStatus::WaitingForUser
        | reforge_domain::ReportStatus::ReauthRequired => 3,
        reforge_domain::ReportStatus::RebootRequired => 6,
        reforge_domain::ReportStatus::PartiallyVerified
        | reforge_domain::ReportStatus::Skipped
        | reforge_domain::ReportStatus::Unsupported
        | reforge_domain::ReportStatus::Failed => 1,
    }
}

fn build_plan_with_summary(
    package: &InspectedPackage,
    mode: RestoreMode,
    run_id: RunId,
    target: &TargetFacts,
) -> Result<(RestorePlan, PlanSummary), Box<ErrorEnvelope>> {
    package.require_plan_approval()?;
    let selection = build_selection_closure(&package.graph, &package.selection)?;
    let diff = DiffEngine::new().compare(&package.graph, target)?;
    let compatibility = CompatibilityEngine::new().evaluate(
        &package.manifest,
        &package.graph,
        selection.total_bytes,
        target,
    );
    let input = reforge_restore::PlannerInput::new(
        run_id,
        package.manifest.package_id.clone(),
        mode,
        target.fingerprint.clone(),
        package.graph.clone(),
        selection,
        package.trust.clone(),
        diff.clone(),
        compatibility,
        package.object_index.clone(),
    );
    let plan = RestorePlanner::new().plan(input)?;
    let summary = summarize_plan(&package.graph, &plan, &diff);
    Ok((plan, summary))
}

fn summarize_plan(graph: &PackageGraph, plan: &RestorePlan, diff: &TargetDiff) -> PlanSummary {
    let mut mutating_components = BTreeSet::new();
    let mut configuration_components = BTreeSet::new();
    let mut reauth_components = BTreeSet::new();
    let reauth_candidates = graph
        .components
        .iter()
        .filter(|component| component.restore.primary == RestoreStrategy::ReauthRequired)
        .map(|component| component.id.clone())
        .collect::<BTreeSet<_>>();

    for operation in &plan.operations {
        match &operation.kind {
            reforge_domain::OperationKind::WriteFile { .. }
            | reforge_domain::OperationKind::MergeJson { .. }
            | reforge_domain::OperationKind::MergeToml { .. }
            | reforge_domain::OperationKind::SetUserEnvironment { .. }
            | reforge_domain::OperationKind::AppendUserPath { .. }
            | reforge_domain::OperationKind::RegisterMcp { .. } => {
                mutating_components.insert(operation.component.clone());
                configuration_components.insert(operation.component.clone());
            }
            reforge_domain::OperationKind::EnsureProvider { .. }
            | reforge_domain::OperationKind::InstallPackage { .. }
            | reforge_domain::OperationKind::EnsureRuntime { .. }
            | reforge_domain::OperationKind::ImportWsl { .. }
            | reforge_domain::OperationKind::RestoreDockerImage { .. }
            | reforge_domain::OperationKind::RestoreDockerVolume { .. }
            | reforge_domain::OperationKind::InstallVsCodeExtension { .. } => {
                mutating_components.insert(operation.component.clone());
            }
            reforge_domain::OperationKind::OpenManualAction { .. } => {
                if reauth_candidates.contains(&operation.component) {
                    reauth_components.insert(operation.component.clone());
                }
            }
            reforge_domain::OperationKind::RequireReboot { .. }
            | reforge_domain::OperationKind::Verify { .. } => {}
        }
    }

    let mut summary = PlanSummary {
        install: 0,
        already_present: 0,
        update: 0,
        configurations: 0,
        manual: plan.manual_actions.len(),
        reauth: reauth_components.len(),
    };
    for component in &plan.selected_components {
        let Some(component_diff) = diff.component(component) else {
            continue;
        };
        if matches!(
            component_diff.disposition,
            ComponentDisposition::Skip | ComponentDisposition::PreserveTarget
        ) {
            summary.already_present += 1;
        } else if configuration_components.contains(component) {
            summary.configurations += 1;
        } else if mutating_components.contains(component) {
            if component_diff.target_present {
                summary.update += 1;
            } else {
                summary.install += 1;
            }
        }
    }
    summary
}

fn make_run_state(
    package_path: &Path,
    package: &InspectedPackage,
    plan: RestorePlan,
    plan_summary: Option<PlanSummary>,
) -> Result<RunState, Box<ErrorEnvelope>> {
    Ok(RunState {
        schema_version: STATE_SCHEMA_VERSION,
        run_id: plan.run_id.clone(),
        package_path: package_path.to_string_lossy().into_owned(),
        package_id: package.manifest.package_id.clone(),
        package_manifest_digest: document_digest(&package.manifest)?,
        package_graph_digest: document_digest(&package.graph)?,
        package_selection_digest: document_digest(&package.selection)?,
        package_object_index_digest: package.manifest.object_index_digest.clone(),
        trust: package.trust.clone(),
        plan,
        plan_summary,
    })
}

fn validate_run_package(
    state: &RunState,
    package: &InspectedPackage,
) -> Result<(), Box<ErrorEnvelope>> {
    if package.manifest.package_id != state.package_id
        || package.manifest.object_index_digest != state.package_object_index_digest
        || document_digest(&package.manifest)? != state.package_manifest_digest
        || document_digest(&package.graph)? != state.package_graph_digest
        || document_digest(&package.selection)? != state.package_selection_digest
    {
        return Err(boxed_error(
            ReforgeErrorCode::PackageCorrupt,
            "The package no longer matches the approved run",
        ));
    }
    if state.trust != TrustState::UserApproved {
        return Err(boxed_error(
            ReforgeErrorCode::PackageUntrusted,
            "The persisted run does not contain explicit package approval",
        ));
    }
    Ok(())
}

const MAX_SECRET_SCAN_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FINDING_PATH_BYTES: usize = 512;
const PACKAGE_STORAGE_MARGIN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FieldPathPart {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FieldPath(Vec<FieldPathPart>);

impl FieldPath {
    fn root() -> Self {
        Self(Vec::new())
    }

    fn key(&self, key: &str) -> Self {
        let mut parts = self.0.clone();
        parts.push(FieldPathPart::Key(key.to_owned()));
        Self(parts)
    }

    fn index(&self, index: usize) -> Self {
        let mut parts = self.0.clone();
        parts.push(FieldPathPart::Index(index));
        Self(parts)
    }

    fn label(&self) -> String {
        let mut label = String::from("$");
        for part in &self.0 {
            match part {
                FieldPathPart::Key(key) => {
                    label.push('.');
                    label.push_str(&safe_field_name(key));
                }
                FieldPathPart::Index(index) => {
                    label.push('[');
                    label.push_str(&index.to_string());
                    label.push(']');
                }
            }
        }
        RedactionPolicy::with_max_bytes(MAX_FINDING_PATH_BYTES)
            .redact_text(&label)
            .unwrap_or_else(|| "$".to_owned())
    }
}

#[derive(Debug)]
struct ArtifactScreening {
    bytes: Option<Vec<u8>>,
    safe_config: Option<Value>,
    findings: BTreeSet<FieldPath>,
}

fn review_selection(
    inventory: &Inventory,
    mut selection: SelectionInput,
    known_folders: &KnownFolderMap,
) -> Result<SelectionReview, Box<ErrorEnvelope>> {
    let initial = build_selection_closure(&inventory.graph, &selection)?;
    let selected_components: BTreeSet<_> = initial.selected_components.iter().cloned().collect();
    let selected_artifacts: BTreeSet<_> = initial.selected_artifacts.iter().cloned().collect();
    let auto_added: BTreeSet<_> = initial.auto_added_dependencies.iter().cloned().collect();
    let mut findings = BTreeSet::<(String, String, String)>::new();

    for component in &inventory.graph.components {
        if !selected_components.contains(&component.id) {
            continue;
        }
        let dependency_auto_added = auto_added.contains(&component.id);
        if component.selection.sensitive || component.kind == ComponentKind::SecretReference {
            return Err(boxed_error(
                ReforgeErrorCode::VaultRequired,
                "Selected content requires an encrypted vault",
            ));
        }
        if dependency_auto_added && component_has_unsafe_binary_shape(component) {
            return Err(boxed_error(
                ReforgeErrorCode::SecurityPolicy,
                "A required dependency is not safe to add automatically",
            ));
        }

        let metadata_path = component
            .artifacts
            .iter()
            .find(|artifact| artifact.policy == ArtifactPolicy::Config)
            .map(|artifact| artifact.source_path.relative.as_str())
            .unwrap_or("package metadata");
        let metadata_findings = extension_findings(&component.extensions)?;
        for path in &metadata_findings {
            insert_secret_finding(&mut findings, component, metadata_path, path);
        }
        if dependency_auto_added && !metadata_findings.is_empty() {
            return Err(boxed_error(
                ReforgeErrorCode::SecurityPolicy,
                "A required dependency has unsafe metadata and cannot be added automatically",
            ));
        }

        for artifact in &component.artifacts {
            if !selected_artifacts.contains(&artifact.id) {
                continue;
            }
            if artifact.policy == ArtifactPolicy::SecretReference {
                return Err(boxed_error(
                    ReforgeErrorCode::VaultRequired,
                    "Selected secret content requires an encrypted vault",
                ));
            }
            if !is_screened_content_type(&artifact.content_type) {
                if dependency_auto_added {
                    return Err(boxed_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "A required dependency contains an unscreened artifact",
                    ));
                }
                continue;
            }
            let screening = scan_secret_like_artifact(
                known_folders,
                component.extensions.get("safe_config"),
                artifact,
            )?;
            for path in &screening.findings {
                insert_secret_finding(
                    &mut findings,
                    component,
                    &artifact.source_path.relative,
                    path,
                );
            }
            if dependency_auto_added && !screening.findings.is_empty() {
                return Err(boxed_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "A required dependency contains secret-like content and cannot be added automatically",
                ));
            }
            if screening.bytes.is_none() {
                set_artifact_inclusion(&mut selection, &artifact.id, false);
            }
        }
    }

    let final_closure = build_selection_closure(&inventory.graph, &selection)?;
    let secret_findings = findings
        .into_iter()
        .map(|(component_name, artifact_path, reason)| SecretFinding {
            component_name,
            artifact_path,
            reason,
        })
        .collect();
    Ok(SelectionReview {
        selection,
        selected_components: final_closure.selected_components,
        selected_artifacts: final_closure.selected_artifacts,
        total_bytes: final_closure.total_bytes,
        secret_findings,
    })
}

fn component_has_unsafe_binary_shape(component: &Component) -> bool {
    component.kind == ComponentKind::PortableBinary
        || component.restore.primary == RestoreStrategy::PortableBinary
        || component
            .artifacts
            .iter()
            .any(|artifact| artifact.policy == ArtifactPolicy::PortableBinary)
        || (component.kind == ComponentKind::Unknown
            && (component.identity.executable_name.is_some()
                || component.identity.executable_hash.is_some()))
}

fn scan_secret_like_artifact(
    known_folders: &KnownFolderMap,
    adapter_safe_config: Option<&Value>,
    artifact: &reforge_domain::ArtifactRef,
) -> Result<ArtifactScreening, Box<ErrorEnvelope>> {
    let bytes = match read_bounded_artifact(known_folders, artifact) {
        Ok(bytes) => bytes,
        Err(error) if error.code == ReforgeErrorCode::SecurityPolicy => {
            return Ok(ArtifactScreening {
                bytes: None,
                safe_config: None,
                findings: BTreeSet::from([FieldPath::root()]),
            });
        }
        Err(error) => return Err(error),
    };
    let Some(text) = std::str::from_utf8(&bytes).ok() else {
        return Ok(ArtifactScreening {
            bytes: None,
            safe_config: None,
            findings: BTreeSet::from([FieldPath::root()]),
        });
    };

    if artifact.content_type == ContentType::Utf8Text {
        let safe = RedactionPolicy::with_max_bytes(MAX_SECRET_SCAN_BYTES as usize)
            .redact_text(text)
            .is_some_and(|redacted| redacted == text);
        return Ok(if safe {
            ArtifactScreening {
                bytes: Some(bytes),
                safe_config: None,
                findings: BTreeSet::new(),
            }
        } else {
            ArtifactScreening {
                bytes: None,
                safe_config: None,
                findings: BTreeSet::from([FieldPath::root()]),
            }
        });
    }

    let Some(document) = parse_config_document(text, &artifact.content_type) else {
        return Ok(ArtifactScreening {
            bytes: None,
            safe_config: None,
            findings: BTreeSet::from([FieldPath::root()]),
        });
    };
    let blocked = unsafe_value_paths(&document);
    let mut findings = blocked.clone();

    if artifact.policy == ArtifactPolicy::Config
        && let Some(adapter_safe_config) = adapter_safe_config
    {
        let adapter_blocked = unsafe_value_paths(adapter_safe_config);
        // The normalized metadata is independently sanitized below.  Its paths
        // are reported against metadata, not blindly applied to file paths.
        findings.extend(adapter_blocked.iter().cloned());
    }
    let source_text_is_safe = RedactionPolicy::with_max_bytes(MAX_SECRET_SCAN_BYTES as usize)
        .redact_text(text)
        .is_some_and(|redacted| redacted == text);
    if !source_text_is_safe {
        // JSONC/TOML comments are not represented in the parsed tree. Rewriting
        // the safe tree drops any secret-like comment or header bytes.
        findings.insert(FieldPath::root());
    }

    let safe_document = filtered_value(&document, &FieldPath::root(), &blocked);
    let safe_bytes = if findings.is_empty() {
        Some(bytes)
    } else {
        safe_document
            .as_ref()
            .and_then(|value| serialize_config_document(value, &artifact.content_type))
    };
    Ok(ArtifactScreening {
        bytes: safe_bytes,
        safe_config: (artifact.policy == ArtifactPolicy::Config)
            .then_some(safe_document)
            .flatten(),
        findings,
    })
}

fn is_screened_content_type(content_type: &ContentType) -> bool {
    matches!(
        content_type,
        ContentType::Utf8Text | ContentType::Json | ContentType::Jsonc | ContentType::Toml
    )
}

fn read_bounded_artifact(
    known_folders: &KnownFolderMap,
    artifact: &reforge_domain::ArtifactRef,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let root = known_folders
        .entries
        .get(&artifact.source_path.root)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::PathNotFound,
                "The selected artifact root is unavailable",
            )
        })?;
    let safe_path = SafePath::new(artifact.source_path.relative.clone())?;
    let mut reader = BoundedFileReader::open(root, &safe_path, MAX_SECRET_SCAN_BYTES)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

fn parse_config_document(text: &str, content_type: &ContentType) -> Option<Value> {
    match content_type {
        ContentType::Json => serde_json::from_str(text).ok(),
        ContentType::Jsonc => json5::from_str(text).ok(),
        ContentType::Toml => toml::from_str::<toml::Value>(text)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok()),
        _ => None,
    }
}

fn serialize_config_document(value: &Value, content_type: &ContentType) -> Option<Vec<u8>> {
    match content_type {
        ContentType::Json | ContentType::Jsonc => serde_json::to_vec_pretty(value).ok(),
        ContentType::Toml => {
            let value = serde_json::from_value::<toml::Value>(value.clone()).ok()?;
            toml::to_string_pretty(&value).ok().map(String::into_bytes)
        }
        _ => None,
    }
}

fn unsafe_value_paths(value: &Value) -> BTreeSet<FieldPath> {
    let mut findings = BTreeSet::new();
    collect_unsafe_value_paths(value, &FieldPath::root(), 0, &mut findings);
    findings
}

fn collect_unsafe_value_paths(
    value: &Value,
    path: &FieldPath,
    depth: usize,
    findings: &mut BTreeSet<FieldPath>,
) {
    let policy = RedactionPolicy::default();
    if depth > policy.max_depth() {
        findings.insert(path.clone());
        return;
    }
    match value {
        Value::Object(object) => {
            if normalized_secret_marker(object) {
                findings.insert(path.clone());
                return;
            }
            for (key, value) in object {
                let child = path.key(key);
                if metadata_key_is_sensitive(key) {
                    findings.insert(child);
                } else {
                    collect_unsafe_value_paths(value, &child, depth + 1, findings);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_unsafe_value_paths(value, &path.index(index), depth + 1, findings);
            }
        }
        Value::String(value) => {
            let stable = !matches!(value.as_str(), "<REDACTED>" | "<PATH>")
                && policy
                    .redact_text(value)
                    .is_some_and(|redacted| redacted == *value);
            if !stable {
                findings.insert(path.clone());
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn normalized_secret_marker(object: &serde_json::Map<String, Value>) -> bool {
    object
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "SECRET_REFERENCE" | "REDACTED_UNKNOWN"))
        || (object.len() == 1 && object.get("redacted").and_then(Value::as_bool) == Some(true))
}

fn metadata_key_is_sensitive(key: &str) -> bool {
    RedactionPolicy::default().is_sensitive_key(key)
}

fn filtered_value(value: &Value, path: &FieldPath, blocked: &BTreeSet<FieldPath>) -> Option<Value> {
    if blocked.contains(path) {
        return None;
    }
    match value {
        Value::Object(object) => Some(Value::Object(
            object
                .iter()
                .filter_map(|(key, value)| {
                    filtered_value(value, &path.key(key), blocked).map(|value| (key.clone(), value))
                })
                .collect(),
        )),
        Value::Array(values) => Some(Value::Array(
            values
                .iter()
                .enumerate()
                .filter_map(|(index, value)| filtered_value(value, &path.index(index), blocked))
                .collect(),
        )),
        _ => Some(value.clone()),
    }
}

fn extension_findings(
    extensions: &BTreeMap<String, Value>,
) -> Result<BTreeSet<FieldPath>, Box<ErrorEnvelope>> {
    let value = serde_json::to_value(extensions).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Component metadata could not be screened",
        )
    })?;
    Ok(unsafe_value_paths(&value))
}

fn sanitize_extensions(
    extensions: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, Box<ErrorEnvelope>> {
    let value = serde_json::to_value(extensions).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Component metadata could not be screened",
        )
    })?;
    let blocked = unsafe_value_paths(&value);
    let filtered = filtered_value(&value, &FieldPath::root(), &blocked)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    serde_json::from_value(filtered).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Screened component metadata is invalid",
        )
    })
}

fn safe_field_name(key: &str) -> String {
    let safe = RedactionPolicy::with_max_bytes(128)
        .redact_text(key)
        .filter(|redacted| redacted == key && !redacted.is_empty());
    let Some(safe) = safe else {
        return "<redacted-field>".to_owned();
    };
    if safe.len() <= 128
        && safe
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        safe
    } else {
        format!("<field:{}>", &blake3::hash(safe.as_bytes()).to_hex()[..12])
    }
}

fn insert_secret_finding(
    findings: &mut BTreeSet<(String, String, String)>,
    component: &Component,
    artifact_path: &str,
    path: &FieldPath,
) {
    findings.insert((
        safe_finding_text(&component.display_name, 256, "Selected component"),
        safe_finding_text(artifact_path, 512, "selected artifact"),
        path.label(),
    ));
}

fn safe_finding_text(value: &str, max_bytes: usize, fallback: &str) -> String {
    RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn set_artifact_inclusion(selection: &mut SelectionInput, artifact: &ArtifactId, include: bool) {
    if let Some(existing) = selection
        .artifacts
        .iter_mut()
        .find(|item| item.artifact == *artifact)
    {
        existing.include = include;
    } else {
        selection.artifacts.push(ArtifactSelection {
            artifact: artifact.clone(),
            include,
        });
    }
}
fn require_vault_free_selection(selection: &SelectionInput) -> Result<(), Box<ErrorEnvelope>> {
    if selection.policy.secrets == SecretSelectionPolicy::VaultExplicit {
        return Err(boxed_error(
            ReforgeErrorCode::VaultRequired,
            "The CLI cannot include secret content without an encrypted vault",
        ));
    }
    Ok(())
}

fn ensure_component_metadata_safe(component: &Component) -> Result<(), Box<ErrorEnvelope>> {
    let value = serde_json::to_value(component).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Component metadata could not be screened",
        )
    })?;
    if unsafe_value_paths(&value).is_empty() {
        Ok(())
    } else {
        Err(boxed_error(
            ReforgeErrorCode::SecurityPolicy,
            "Selected component metadata contains unsafe values",
        ))
    }
}

struct IngestionTemp {
    path: PathBuf,
}

impl Drop for IngestionTemp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct CancellationWriter<'a, W> {
    inner: W,
    cancellation: &'a CancellationToken,
}

impl<W: Write> Write for CancellationWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        self.inner.flush()
    }
}

fn store_bounded_artifact(
    store: &ObjectStore,
    known_folders: &KnownFolderMap,
    artifact: &reforge_domain::ArtifactRef,
    state_root: &Path,
    cancellation: &CancellationToken,
) -> Result<reforge_package::StoredFile, Box<ErrorEnvelope>> {
    let root = known_folders
        .entries
        .get(&artifact.source_path.root)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::PathNotFound,
                "The selected artifact root is unavailable",
            )
        })?;
    let safe_path = SafePath::new(artifact.source_path.relative.clone())?;
    let mut source = BoundedFileReader::open(root, &safe_path, artifact.size_bytes)?;

    let staging = state_root.join("ingest");
    fs::create_dir_all(&staging).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Create bounded ingestion directory",
        ))
    })?;
    let metadata = fs::symlink_metadata(&staging).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Inspect bounded ingestion directory",
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(boxed_error(
            ReforgeErrorCode::ReparsePoint,
            "Bounded ingestion directory is not safe",
        ));
    }
    let temp = IngestionTemp {
        path: staging.join(format!("{}.tmp", Uuid::now_v7())),
    };
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&temp.path)
        .map_err(|error| {
            Box::new(ErrorEnvelope::from_io_error(
                &error,
                "Create bounded ingestion file",
            ))
        })?;
    let streamed = {
        let mut sink = CancellationWriter {
            inner: &mut file,
            cancellation,
        };
        source.stream_into(&mut sink)
    };
    ensure_not_cancelled(cancellation)?;
    streamed?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Rewind bounded ingestion file",
        ))
    })?;
    let stored = store.store_file(&mut file, artifact.content_type.clone(), 0)?;
    ensure_not_cancelled(cancellation)?;
    Ok(stored)
}

fn build_package_inputs(
    inventory: &Inventory,
    selection: SelectionInput,
    known_folders: &KnownFolderMap,
    state: &StatePaths,
    cancellation: &CancellationToken,
) -> Result<
    (
        PackageManifest,
        PackageGraph,
        SelectionInput,
        ObjectIndex,
        ObjectStore,
    ),
    Box<ErrorEnvelope>,
> {
    let review = review_selection(inventory, selection, known_folders)?;
    let mut selection = review.selection;
    let closure = build_selection_closure(&inventory.graph, &selection)?;
    let selected_components: BTreeSet<_> = closure.selected_components.iter().cloned().collect();
    let selected_artifacts: BTreeSet<_> = closure.selected_artifacts.iter().cloned().collect();
    selection
        .artifacts
        .retain(|decision| selected_artifacts.contains(&decision.artifact));
    let store = ObjectStore::open(state.root.join("objects"))?;
    let mut graph = PackageGraph {
        components: inventory
            .graph
            .components
            .iter()
            .filter(|component| selected_components.contains(&component.id))
            .cloned()
            .collect(),
        edges: inventory
            .graph
            .edges
            .iter()
            .filter(|edge| {
                selected_components.contains(&edge.from) && selected_components.contains(&edge.to)
            })
            .cloned()
            .collect(),
    };
    let mut objects = BTreeMap::<reforge_domain::ObjectId, ObjectEntry>::new();
    let mut actual_bytes = 0u64;
    ensure_not_cancelled(cancellation)?;
    for component in &mut graph.components {
        component.dependencies.retain(|edge| {
            selected_components.contains(&edge.from) && selected_components.contains(&edge.to)
        });
        component
            .artifacts
            .retain(|artifact| selected_artifacts.contains(&artifact.id));
        component.extensions = sanitize_extensions(&component.extensions)?;
        let adapter_safe_config = component.extensions.get("safe_config").cloned();
        ensure_not_cancelled(cancellation)?;
        for artifact in &mut component.artifacts {
            if artifact.policy == ArtifactPolicy::SecretReference
                || component.kind == ComponentKind::SecretReference
            {
                return Err(boxed_error(
                    ReforgeErrorCode::VaultRequired,
                    "Selected secret content requires an encrypted vault",
                ));
            }

            let stored = if is_screened_content_type(&artifact.content_type) {
                let screening = scan_secret_like_artifact(
                    known_folders,
                    adapter_safe_config.as_ref(),
                    artifact,
                )?;
                let bytes = screening.bytes.ok_or_else(|| {
                    boxed_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "Selected artifact could not be made safe for packaging",
                    )
                })?;
                if let Some(safe_config) = screening.safe_config {
                    component
                        .extensions
                        .insert("safe_config".to_owned(), safe_config);
                }
                // The JSONC sanitizer emits ordinary JSON. Identical JSON/JSONC
                // bytes must have one content type in the content-addressed store.
                if artifact.content_type == ContentType::Jsonc {
                    artifact.content_type = ContentType::Json;
                }
                store.store_file(Cursor::new(bytes), artifact.content_type.clone(), 0)?
            } else {
                store_bounded_artifact(&store, known_folders, artifact, &state.root, cancellation)?
            };
            actual_bytes = actual_bytes
                .checked_add(stored.manifest.size_bytes)
                .ok_or_else(|| {
                    boxed_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "Selected artifact size overflow",
                    )
                })?;
            ensure_not_cancelled(cancellation)?;
            artifact.size_bytes = stored.manifest.size_bytes;
            artifact.object = Some(stored.manifest_object.entry.id.clone());
            objects.insert(
                stored.manifest_object.entry.id.clone(),
                stored.manifest_object.entry.clone(),
            );
            for chunk in stored.chunk_objects {
                objects.insert(chunk.entry.id.clone(), chunk.entry);
            }
        }
        ensure_component_metadata_safe(component)?;
    }
    if let Some(max_bytes) = selection.policy.max_bytes
        && actual_bytes > max_bytes
    {
        return Err(boxed_error(
            ReforgeErrorCode::SecurityPolicy,
            "Selected artifacts exceed the configured byte limit",
        ));
    }
    let object_index = ObjectIndex {
        objects: objects.into_values().collect(),
    };
    let mut component_ids: Vec<_> = graph
        .components
        .iter()
        .map(|component| component.id.clone())
        .collect();
    component_ids.sort();
    let source_host = &inventory.host;
    let mut known_folder_tokens: Vec<_> = source_host
        .known_folders
        .iter()
        .map(|path| path.root.clone())
        .collect();
    known_folder_tokens.sort();
    known_folder_tokens.dedup();
    let manifest = PackageManifest {
        package_id: format!("pkg_{}", inventory.scan_id),
        format_version: 1,
        created_at: Utc::now(),
        source_host: reforge_domain::SourceHostSummary {
            os_version: source_host.os_version.clone(),
            os_build: source_host.os_build.clone(),
            architecture: source_host.architecture.clone(),
            known_folder_tokens,
        },
        required_os: Some("Windows".to_owned()),
        required_architecture: Some(source_host.architecture.clone()),
        component_ids,
        warnings: safe_package_warnings(&inventory.warnings, &closure.warnings),
        object_index_digest: PackageWriter::object_index_digest(&object_index)?,
    };
    let manifest_value = serde_json::to_value(&manifest).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Package manifest could not be screened",
        )
    })?;
    if !unsafe_value_paths(&manifest_value).is_empty() {
        return Err(boxed_error(
            ReforgeErrorCode::SecurityPolicy,
            "Package manifest contains unsafe metadata",
        ));
    }
    Ok((manifest, graph, selection, object_index, store))
}

fn default_selection(graph: &PackageGraph) -> SelectionInput {
    let recommendations = reforge_discovery::recommend(graph)
        .into_iter()
        .map(|recommendation| (recommendation.component, recommendation.recommended))
        .collect::<BTreeMap<_, _>>();
    let mut components: Vec<_> = graph
        .components
        .iter()
        .filter(|component| {
            let recommended = recommendations.get(&component.id).copied().unwrap_or(false);
            (component.selection.selected_by_default || recommended)
                && !component.selection.sensitive
                && component.kind != ComponentKind::SecretReference
        })
        .map(|component| component.id.clone())
        .collect();
    components.sort();
    SelectionInput {
        components,
        artifacts: Vec::new(),
        policy: SelectionPolicy {
            secrets: SecretSelectionPolicy::Exclude,
            large_data: reforge_domain::LargeDataSelectionPolicy::Exclude,
            unknown_binaries: reforge_domain::UnknownBinarySelectionPolicy::Exclude,
            max_bytes: None,
        },
    }
}

fn read_secret_selection(path: &Path) -> Result<Vec<ComponentId>, Box<ErrorEnvelope>> {
    let value: Value = read_json_input(path, "secret selection")?;
    let value = value
        .as_array()
        .cloned()
        .or_else(|| value.get("components").and_then(Value::as_array).cloned())
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::SchemaInvalid,
                "Secret selection must be an ID array",
            )
        })?;
    value
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|_| {
                boxed_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "Secret selection contains an invalid ID",
                )
            })
        })
        .collect()
}

async fn discover_current_host() -> Result<DiscoveryResult, Box<ErrorEnvelope>> {
    let cancellation = CancellationToken::new();
    discover_current_host_with(new_run_id()?, &cancellation, progress_to_stderr).await
}

async fn discover_current_host_with<F>(
    run_id: RunId,
    cancellation: &CancellationToken,
    progress: F,
) -> Result<DiscoveryResult, Box<ErrorEnvelope>>
where
    F: Fn(ProgressEvent) + Send + Sync,
{
    let preflight = host_preflight()?;
    let registry = default_registry()?;
    let coordinator = DiscoveryCoordinator::new(registry);
    let runner = ProcessRunner::new();
    let mut inventory = coordinator
        .scan_with_id(
            run_id,
            preflight.facts.clone(),
            &preflight.known_folders,
            &runner,
            cancellation,
            &progress,
        )
        .await?;
    inventory.warnings.extend(
        preflight
            .warnings
            .into_iter()
            .map(|warning| warning.message),
    );
    inventory.warnings.sort();
    inventory.warnings.dedup();
    Ok(DiscoveryResult {
        inventory,
        known_folders: preflight.known_folders,
    })
}

#[derive(Debug)]
struct DiscoveryResult {
    inventory: Inventory,
    known_folders: KnownFolderMap,
}

async fn discover_target() -> Result<TargetSnapshot, Box<ErrorEnvelope>> {
    let cancellation = CancellationToken::new();
    discover_target_with(new_run_id()?, &cancellation, progress_to_stderr).await
}

async fn discover_target_with<F>(
    run_id: RunId,
    cancellation: &CancellationToken,
    progress: F,
) -> Result<TargetSnapshot, Box<ErrorEnvelope>>
where
    F: Fn(ProgressEvent) + Send + Sync,
{
    let discovered = discover_current_host_with(run_id, cancellation, progress).await?;
    let facts = TargetScanner::new().scan(discovered.inventory)?;
    Ok(TargetSnapshot {
        facts,
        known_folders: discovered.known_folders,
    })
}

fn default_registry() -> Result<AdapterRegistry, Box<ErrorEnvelope>> {
    let mut registry = AdapterRegistry::new();
    registry.register(ScanPhase::PackageExports, Arc::new(WinGetAdapter::new()))?;
    registry.register(
        ScanPhase::PackageExports,
        Arc::new(ChocolateyAdapter::new()),
    )?;
    registry.register(ScanPhase::PackageExports, Arc::new(ScoopAdapter::new()))?;
    registry.register(ScanPhase::PackageExports, Arc::new(PythonAdapter::new()))?;
    registry.register(ScanPhase::PackageExports, Arc::new(RustAdapter::new()))?;
    registry.register(ScanPhase::PackageExports, Arc::new(GoAdapter::new()))?;
    registry.register(ScanPhase::PackageExports, Arc::new(DotnetAdapter::new()))?;
    registry.register(
        ScanPhase::PackageExports,
        Arc::new(PowerShellAdapter::new()),
    )?;
    for manager in NodePackageManager::ALL {
        registry.register(
            ScanPhase::PackageExports,
            Arc::new(JavaScriptAdapter::new(manager)),
        )?;
    }
    registry.register(
        ScanPhase::WindowsRegistration,
        Arc::new(WindowsRegistrationAdapter::new()),
    )?;
    for kind in HarnessKind::ALL {
        registry.register(
            ScanPhase::AppAdapters,
            Arc::new(HarnessRegistryAdapter::new(kind)),
        )?;
    }
    registry.register(ScanPhase::AppAdapters, Arc::new(AgentCatalogAdapter::new()))?;
    for kind in AgentRuntimeKind::ALL {
        registry.register(
            ScanPhase::AppAdapters,
            Arc::new(AgentRuntimeAdapter::new(kind)),
        )?;
    }
    registry.register(ScanPhase::RuntimeProbes, Arc::new(WslAdapter::new()))?;
    registry.register(ScanPhase::RuntimeProbes, Arc::new(DockerAdapter::new()))?;
    registry.register(
        ScanPhase::GenericExecutables,
        Arc::new(GenericExecutableAdapter::new()),
    )?;
    Ok(registry)
}

fn progress_to_stderr(event: ProgressEvent) {
    let total = event
        .total
        .map_or_else(|| "?".to_owned(), |total| total.to_string());
    eprintln!(
        "progress phase={:?} status={:?} completed={}/{}",
        event.phase, event.status, event.completed, total
    );
}

fn state_paths() -> Result<StatePaths, Box<ErrorEnvelope>> {
    let root = match std::env::var_os("REFORGE_STATE_DIR") {
        Some(value) => PathBuf::from(value),
        None => {
            let folders = KnownFolderMap::current_user()?;
            folders
                .entries
                .get(&KnownFolderToken::LocalAppData)
                .cloned()
                .ok_or_else(|| {
                    boxed_error(
                        ReforgeErrorCode::PathNotFound,
                        "Local application data folder is unavailable",
                    )
                })?
                .join("Reforge")
        }
    };
    if !root.is_absolute() {
        return Err(boxed_error(
            ReforgeErrorCode::InvalidPath,
            "REFORGE_STATE_DIR must be an absolute path",
        ));
    }
    fs::create_dir_all(&root).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Create Reforge state directory",
        ))
    })?;
    let metadata = fs::symlink_metadata(&root).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Inspect Reforge state directory",
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(boxed_error(
            ReforgeErrorCode::ReparsePoint,
            "Reforge state directory is not a safe directory",
        ));
    }
    Ok(StatePaths {
        inventory: root.join("inventory.json"),
        target: root.join("target.json"),
        journal: root.join("journal.sqlite"),
        root,
    })
}
fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<(), Box<ErrorEnvelope>> {
    if cancellation.is_cancelled() {
        Err(boxed_error(
            ReforgeErrorCode::Cancelled,
            "Package creation was cancelled",
        ))
    } else {
        Ok(())
    }
}

fn prepare_package_output(path: &Path) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let output = output_file_path(path)?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "Output path has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Create package output directory",
        ))
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Inspect package output directory",
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(boxed_error(
            ReforgeErrorCode::ReparsePoint,
            "Package output directory is not a safe directory",
        ));
    }
    if output.exists() {
        return Err(boxed_error(
            ReforgeErrorCode::TargetConflict,
            "Package output already exists",
        ));
    }
    Ok(output)
}

fn ensure_package_storage_available(
    facts: &HostFacts,
    state_root: &Path,
    output: &Path,
    selected_bytes: u64,
) -> Result<(), Box<ErrorEnvelope>> {
    let state_required = recommended_free_bytes(selected_bytes).ok_or_else(|| {
        boxed_error(
            ReforgeErrorCode::InsufficientDisk,
            "Package storage requirement overflow",
        )
    })?;
    let output_required = selected_bytes
        .checked_add(PACKAGE_STORAGE_MARGIN_BYTES)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::InsufficientDisk,
                "Package output requirement overflow",
            )
        })?;
    let same_volume = path_drive_token(state_root)
        .zip(path_drive_token(output))
        .is_some_and(|(state, output)| state.eq_ignore_ascii_case(&output));
    if same_volume {
        let combined = state_required.checked_add(output_required).ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::InsufficientDisk,
                "Combined package storage requirement overflow",
            )
        })?;
        ensure_volume_free_space(facts, output, combined, "package staging and output")
    } else {
        ensure_volume_free_space(facts, state_root, state_required, "state storage")?;
        ensure_volume_free_space(facts, output, output_required, "package output")
    }
}

fn ensure_package_output_available(
    facts: &HostFacts,
    output: &Path,
    object_index: &ObjectIndex,
) -> Result<(), Box<ErrorEnvelope>> {
    let object_bytes = object_index.objects.iter().try_fold(0u64, |total, entry| {
        total.checked_add(entry.compressed_bytes).ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::InsufficientDisk,
                "Package output requirement overflow",
            )
        })
    })?;
    let required = object_bytes
        .checked_add(PACKAGE_STORAGE_MARGIN_BYTES)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::InsufficientDisk,
                "Package output requirement overflow",
            )
        })?;
    ensure_volume_free_space(facts, output, required, "package output")
}

fn ensure_volume_free_space(
    facts: &HostFacts,
    path: &Path,
    required: u64,
    label: &str,
) -> Result<(), Box<ErrorEnvelope>> {
    let token = path_drive_token(path).ok_or_else(|| {
        boxed_error(
            ReforgeErrorCode::SourceUnavailable,
            format!("Free-space information for {label} is unavailable"),
        )
    })?;
    let available = facts
        .free_bytes
        .iter()
        .find(|space| space.token.eq_ignore_ascii_case(&token))
        .map(|space| space.bytes)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::SourceUnavailable,
                format!("Free-space information for {label} is unavailable"),
            )
        })?;
    if available < required {
        return Err(boxed_error(
            ReforgeErrorCode::InsufficientDisk,
            format!("Insufficient disk space for {label}"),
        ));
    }
    Ok(())
}

fn path_drive_token(path: &Path) -> Option<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    absolute.components().find_map(|component| match component {
        PathComponent::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Some(format!("{}:", char::from(letter).to_ascii_uppercase()))
            }
            _ => None,
        },
        _ => None,
    })
}

fn write_package_with_cancel(
    destination: &Path,
    request: PackageWriteRequest<'_>,
    store: &ObjectStore,
    cancellation: &CancellationToken,
) -> Result<TransportReceipt, Box<ErrorEnvelope>> {
    ensure_not_cancelled(cancellation)?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "Output path has no parent"))?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "Output filename is invalid"))?;
    let stage_name = format!(".{file_name}.{}.partial", Uuid::now_v7());
    let staged = parent.join(&stage_name);
    let writer = PackageWriter::default();
    let receipt = writer.write(&staged, request, store).inspect_err(|_| {
        let _ = fs::remove_file(&staged);
    })?;
    if cancellation.is_cancelled() {
        let _ = fs::remove_file(&staged);
        return Err(boxed_error(
            ReforgeErrorCode::Cancelled,
            "Package creation was cancelled",
        ));
    }
    reforge_platform_windows::publish_new_file(&staged, destination).inspect_err(|_| {
        let _ = fs::remove_file(&staged);
    })?;
    Ok(receipt)
}

pub(crate) fn default_backup_directory() -> Result<PathBuf, Box<ErrorEnvelope>> {
    let folders = KnownFolderMap::current_user()?;
    let token = PathToken::new(KnownFolderToken::Documents, "Reforge Backups").map_err(|_| {
        boxed_error(
            ReforgeErrorCode::InvalidPath,
            "The default backup directory token is invalid",
        )
    })?;
    folders.resolve(&token)
}

pub(crate) fn default_backup_path() -> Result<PathBuf, Box<ErrorEnvelope>> {
    let filename = format!("Reforge-{}.reforge", Utc::now().format("%Y-%m-%d-%H%M%S"));
    Ok(default_backup_directory()?.join(filename))
}

fn write_json_state<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<ErrorEnvelope>> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "State serialization failed",
        )
    })?;
    write_state_bytes(path, &bytes)
}

fn read_json_state<T: DeserializeOwned>(path: &Path) -> Result<T, Box<ErrorEnvelope>> {
    let bytes = read_bounded(path, "state")?;
    serde_json::from_slice(&bytes).map_err(|error| {
        Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::SchemaInvalid,
                "Persisted state is invalid",
            )
            .with_technical_detail(error.to_string()),
        )
    })
}

fn read_json_input<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, Box<ErrorEnvelope>> {
    let bytes = read_bounded(path, label)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::SchemaInvalid,
                format!("{label} is invalid"),
            )
            .with_technical_detail(error.to_string()),
        )
    })
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let metadata = fs::metadata(path).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            format!("Read {label}"),
        ))
    })?;
    if !metadata.is_file() {
        return Err(boxed_error(
            ReforgeErrorCode::InvalidPath,
            format!("{label} must be a regular file"),
        ));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(boxed_error(
            ReforgeErrorCode::SecurityPolicy,
            format!("{label} exceeds the input size limit"),
        ));
    }
    fs::read(path).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            format!("Read {label}"),
        ))
    })
}

fn write_state_bytes(path: &Path, bytes: &[u8]) -> Result<(), Box<ErrorEnvelope>> {
    let root = state_root_for(path)?;
    let relative = path.strip_prefix(&root).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::InvalidPath,
            "State path is outside the state directory",
        )
    })?;
    let safe = SafePath::new(relative.to_string_lossy())?;
    let spec = AtomicWriteSpec {
        expected_bytes: bytes.len() as u64,
        expected_blake3: *blake3::hash(bytes).as_bytes(),
        attributes: FileAttributes::default(),
    };
    atomic_replace(root, &safe, Cursor::new(bytes), spec).map(|_| ())
}

fn state_root_for(path: &Path) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let parent = path
        .parent()
        .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "State path has no parent"))?;
    let root = match parent.file_name().and_then(|name| name.to_str()) {
        Some("runs") | Some("reports") => parent
            .parent()
            .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "State path has no root"))?,
        _ => parent,
    };
    Ok(root.to_path_buf())
}

fn existing_file_path(path: &Path, label: &str) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            format!("Open {label}"),
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(boxed_error(
            ReforgeErrorCode::ReparsePoint,
            format!("{label} path is a reparse point"),
        ));
    }
    if !metadata.is_file() {
        return Err(boxed_error(
            ReforgeErrorCode::InvalidPath,
            format!("{label} path must be a regular file"),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            format!("Resolve {label} path"),
        ))
    })
}

fn output_file_path(path: &Path) -> Result<PathBuf, Box<ErrorEnvelope>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                Box::new(ErrorEnvelope::from_io_error(
                    &error,
                    "Resolve output directory",
                ))
            })?
            .join(path)
    };
    if absolute.file_name().is_none() {
        return Err(boxed_error(
            ReforgeErrorCode::InvalidPath,
            "Output path must name a file",
        ));
    }
    Ok(absolute)
}

fn write_absolute_file(path: &Path, bytes: &[u8]) -> Result<(), Box<ErrorEnvelope>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| boxed_error(ReforgeErrorCode::InvalidPath, "Output path has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Create report output directory",
        ))
    })?;
    let root = fs::canonicalize(parent).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Resolve report output directory",
        ))
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::InvalidPath,
                "Output filename is not valid UTF-8",
            )
        })?;
    let safe = SafePath::new(name)?;
    let spec = AtomicWriteSpec {
        expected_bytes: bytes.len() as u64,
        expected_blake3: *blake3::hash(bytes).as_bytes(),
        attributes: FileAttributes::default(),
    };
    atomic_replace(root, &safe, Cursor::new(bytes), spec).map(|_| ())
}

fn document_digest<T: Serialize>(value: &T) -> Result<String, Box<ErrorEnvelope>> {
    let canonical = canonicalize(value)?;
    Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
}

fn merge_warnings(first: &[String], second: &[String]) -> Vec<String> {
    let mut warnings = first.iter().chain(second).cloned().collect::<Vec<_>>();
    warnings.sort();
    warnings.dedup();
    warnings
}
fn safe_package_warnings(first: &[String], second: &[String]) -> Vec<String> {
    merge_warnings(first, second)
        .into_iter()
        .filter(|warning| {
            RedactionPolicy::default()
                .redact_text(warning)
                .is_some_and(|screened| screened == *warning)
        })
        .collect()
}

fn new_run_id() -> Result<RunId, Box<ErrorEnvelope>> {
    RunId::new(Uuid::now_v7()).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::OperationFailed,
            "Could not create run identity",
        )
    })
}

fn safe_json<T: Serialize>(value: &T) -> Result<Value, Box<ErrorEnvelope>> {
    let value = serde_json::to_value(value).map_err(|_| {
        boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Output serialization failed",
        )
    })?;
    reforge_domain::RedactionPolicy::with_limits(MAX_JSON_OUTPUT_BYTES, 64)
        .redact_json(&value)
        .ok_or_else(|| {
            boxed_error(
                ReforgeErrorCode::SecurityPolicy,
                "Output could not be redacted safely",
            )
        })
}

fn boxed_error(code: ReforgeErrorCode, message: impl Into<String>) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(code, message))
}

fn error_exit_code(code: ReforgeErrorCode) -> i32 {
    match code {
        ReforgeErrorCode::PathNotFound
        | ReforgeErrorCode::InvalidPath
        | ReforgeErrorCode::ProviderParseFailed
        | ReforgeErrorCode::VersionUnavailable
        | ReforgeErrorCode::PackageNotFound
        | ReforgeErrorCode::PackageCorrupt
        | ReforgeErrorCode::SchemaInvalid
        | ReforgeErrorCode::UnsupportedVersion
        | ReforgeErrorCode::SelectionIncomplete => 2,
        ReforgeErrorCode::ArchitectureConflict
        | ReforgeErrorCode::OsConflict
        | ReforgeErrorCode::InsufficientDisk
        | ReforgeErrorCode::TargetConflict => 4,
        ReforgeErrorCode::PackageUntrusted | ReforgeErrorCode::SecurityPolicy => 5,
        ReforgeErrorCode::ManualActionRequired
        | ReforgeErrorCode::UserActionRequired
        | ReforgeErrorCode::VaultRequired
        | ReforgeErrorCode::VaultDecryptFailed
        | ReforgeErrorCode::SecretNotPortable
        | ReforgeErrorCode::ManualSecretRequired => 3,
        ReforgeErrorCode::RebootRequired
        | ReforgeErrorCode::Interrupted
        | ReforgeErrorCode::Cancelled => 6,
        _ => 1,
    }
}

fn emit_result(result: CommandResult, json_output: bool) -> ! {
    if json_output {
        let envelope = json!({
            "schema_version": CLI_SCHEMA_VERSION,
            "request_id": Uuid::now_v7().to_string(),
            "payload": result.payload,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("JSON values are serializable")
        );
    } else {
        print!("{}", result.human);
    }
    let _ = std::io::stdout().flush();
    process::exit(result.exit_code);
}

fn emit_error(error: &ErrorEnvelope, json_output: bool, exit_code: i32) -> ! {
    if json_output {
        let envelope = json!({
            "schema_version": CLI_SCHEMA_VERSION,
            "request_id": Uuid::now_v7().to_string(),
            "payload": {
                "status": "error",
                "error": error,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("JSON values are serializable")
        );
    } else {
        eprintln!("{error}");
    }
    let _ = std::io::stdout().flush();
    process::exit(exit_code);
}
