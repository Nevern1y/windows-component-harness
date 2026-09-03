#[path = "report.rs"]
pub mod report;
#[path = "secret_prompt.rs"]
pub mod secret_prompt;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process,
    sync::Arc,
};

use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use reforge_discovery::{
    DiscoveryCoordinator,
    generic::GenericExecutableAdapter,
    harnesses::{HarnessKind, HarnessRegistryAdapter},
    providers::{
        AdapterRegistry, ChocolateyAdapter, DockerAdapter, DotnetAdapter, GoAdapter,
        JavaScriptAdapter, NodePackageManager, PowerShellAdapter, PythonAdapter, RustAdapter,
        ScoopAdapter, WinGetAdapter, WindowsRegistrationAdapter, WslAdapter,
    },
};
use reforge_domain::selection::build_selection_closure;
use reforge_domain::{
    ArtifactPolicy, ComponentId, ComponentKind, ErrorEnvelope, Inventory, KnownFolderToken,
    ManualAction, ObjectEntry, ObjectIndex, PackageGraph, PackageManifest, ProgressEvent,
    ReforgeErrorCode, RestoreMode, RestorePlan, RestoreReport, RunId, ScanPhase,
    SecretSelectionPolicy, SelectionInput, SelectionPolicy, TargetFacts, TrustState,
};
use reforge_package::{
    InspectedPackage, ObjectStore, PackageReader, PackageWriteRequest, PackageWriter, canonicalize,
};
use reforge_platform_windows::{
    AtomicWriteSpec, CancellationToken, FileAttributes, KnownFolderMap, ProcessRunner, SafePath,
    atomic_replace, host_preflight,
};
use reforge_restore::{
    BrowserAwareRestoreHandler, CompatibilityEngine, DiffEngine, DockerRestoreHandler,
    EnvironmentRestoreHandler, ExecutionContext, Executor, HarnessRestoreHandler, Journal,
    JournalEvent, JournalManualAction, JournalOperation, JournalRun, ManualActionHandler,
    ManualActionQueue, ObjectSource, ProviderInstallHandler, RestorePlanner, TargetScanner,
    VerificationEngine, VerificationInput, VsCodeRestoreHandler, WslRestoreHandler,
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
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover the current Windows environment.
    Scan,
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
    /// Approve and execute a restore plan.
    Restore {
        #[arg(long)]
        package: PathBuf,
        #[arg(long, value_enum)]
        mode: ModeArg,
        #[arg(long)]
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
    /// Open the numbered human-friendly line-mode wizard.
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
        let inventory = self.inventory()?;
        let preflight = host_preflight()?;
        let (manifest, graph, selection, object_index, store) =
            build_package_inputs(&inventory, selection, &preflight.known_folders, &self.state)?;
        let output = output_file_path(output)?;
        PackageWriter::new(Default::default())?.write(
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
        )
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
        let plan = build_plan(&package, mode, run_id.clone(), &target.facts)?;
        self.journal.create_run(&plan)?;
        let run_state = make_run_state(&package_path, &package, plan.clone())?;
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
        let plan = build_plan(&package, mode, run_id.clone(), &target.facts)?;
        self.journal.create_run(&plan)?;
        self.journal.approve_run(&run_id)?;
        let run_state = make_run_state(&package_path, &package, plan.clone())?;
        write_json_state(&self.state.run_state(&run_id), &run_state)?;
        let (report, _) = execute_to_report(
            self.state.clone(),
            self.journal.clone(),
            package,
            plan,
            target,
            package_path,
            cancellation,
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
        let (report, _) = execute_to_report(
            self.state.clone(),
            self.journal.clone(),
            package,
            run_state.plan,
            target,
            package_path,
            cancellation,
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
    if cli.json && matches!(&cli.command, Command::Interactive) {
        return Err(boxed_error(
            ReforgeErrorCode::SchemaInvalid,
            "Interactive mode cannot emit JSON",
        ));
    }
    match cli.command {
        Command::Scan => scan_command().await,
        Command::Package { command } => match command {
            PackageCommand::Create {
                output,
                selection,
                secret_selection,
            } => package_create_command(output, selection, secret_selection),
            PackageCommand::Inspect { path } => package_inspect_command(path),
        },
        Command::Inventory { command } => match command {
            InventoryCommand::Show => inventory_show_command(),
        },
        Command::Target {
            command: TargetCommand::Scan,
        } => target_scan_command().await,
        Command::Plan { package, mode } => plan_command(package, mode).await,
        Command::Restore {
            package,
            mode,
            yes_safe,
        } => restore_command(package, mode, yes_safe).await,
        Command::Resume { run_id } => resume_command(run_id).await,
        Command::Action { command } => match command {
            ActionCommand::List { run_id } => action_list_command(run_id),
            ActionCommand::Acknowledge { run_id, action_id } => {
                action_acknowledge_command(run_id, action_id)
            }
        },
        Command::Verify { run_id } => verify_command(run_id).await,
        Command::Report { run_id, output } => report_command(run_id, output).await,
        Command::Doctor => doctor_command(),
        Command::Interactive => interactive::run().await,
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
    let state = state_paths()?;
    let inventory: Inventory = read_json_state(&state.inventory)?;
    let preflight = host_preflight()?;
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
    let (manifest, graph, selection, object_index, store) =
        build_package_inputs(&inventory, selection, &preflight.known_folders, &state)?;
    let output = output_file_path(&output)?;
    let writer = PackageWriter::new(Default::default())?;
    let receipt = writer.write(
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
    )?;
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
    let plan = build_plan(&package, mode.into(), run_id.clone(), &target.facts)?;
    let journal = Journal::open(state.journal.clone())?;
    journal.create_run(&plan)?;
    let run_state = make_run_state(&package_path, &package, plan.clone())?;
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
    let plan = build_plan(&package, mode.into(), run_id.clone(), &target.facts)?;
    let journal = Journal::open(state.journal.clone())?;
    journal.create_run(&plan)?;
    journal.approve_run(&run_id)?;
    let run_state = make_run_state(&package_path, &package, plan.clone())?;
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
        "known_folder_count": preflight.known_folders.entries.len(),
        "warning_count": preflight.warnings.len(),
    }))?;
    Ok(CommandResult {
        human: format!(
            "Doctor: ready ({} known folders, {} warnings).\n",
            preflight.known_folders.entries.len(),
            preflight.warnings.len()
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
    let (report, execution_error) = execute_to_report(
        state,
        journal,
        package,
        plan,
        target,
        package_path,
        &CancellationToken::new(),
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

async fn execute_to_report(
    state: StatePaths,
    journal: Journal,
    package: InspectedPackage,
    plan: RestorePlan,
    target: TargetSnapshot,
    package_path: PathBuf,
    cancellation: &CancellationToken,
) -> Result<(RestoreReport, Option<Box<ErrorEnvelope>>), Box<ErrorEnvelope>> {
    let source = PackageObjectSource {
        reader: PackageReader::new(package_path),
    };
    let context =
        ExecutionContext::new(&target.facts, &package.object_index).with_object_source(&source);
    let executor = configured_executor(journal.clone(), target.known_folders);
    let execution_error = executor.execute(&plan, &context, cancellation).await.err();
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
    let report = build_report(&plan, &package, &target.facts, &journal)?;
    write_json_state(&state.report_state(&plan.run_id), &report)?;
    Ok((report, execution_error))
}

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

fn build_plan(
    package: &InspectedPackage,
    mode: RestoreMode,
    run_id: RunId,
    target: &TargetFacts,
) -> Result<RestorePlan, Box<ErrorEnvelope>> {
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
        diff,
        compatibility,
        package.object_index.clone(),
    );
    RestorePlanner::new().plan(input)
}

fn make_run_state(
    package_path: &Path,
    package: &InspectedPackage,
    plan: RestorePlan,
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

fn build_package_inputs(
    inventory: &Inventory,
    selection: SelectionInput,
    known_folders: &KnownFolderMap,
    state: &StatePaths,
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
    let closure = build_selection_closure(&inventory.graph, &selection)?;
    let selected_components: BTreeSet<_> = closure.selected_components.iter().cloned().collect();
    let selected_artifacts: BTreeSet<_> = closure.selected_artifacts.iter().cloned().collect();
    let store = ObjectStore::open(state.root.join("objects"))?;
    let mut graph = inventory.graph.clone();
    let mut objects = BTreeMap::<reforge_domain::ObjectId, ObjectEntry>::new();
    let mut actual_bytes = 0u64;
    for component in &mut graph.components {
        let component_selected = selected_components.contains(&component.id);
        for artifact in &mut component.artifacts {
            if !component_selected || !selected_artifacts.contains(&artifact.id) {
                artifact.object = None;
                continue;
            }
            if artifact.policy == ArtifactPolicy::SecretReference
                || component.kind == ComponentKind::SecretReference
            {
                return Err(boxed_error(
                    ReforgeErrorCode::VaultRequired,
                    "Selected secret content requires an encrypted vault",
                ));
            }
            let path = known_folders.resolve(&artifact.source_path)?;
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                Box::new(ErrorEnvelope::from_io_error(
                    &error,
                    "Read selected artifact",
                ))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(boxed_error(
                    ReforgeErrorCode::ManualActionRequired,
                    "Selected artifact is not a regular file",
                ));
            }
            let file = File::open(&path).map_err(|error| {
                Box::new(ErrorEnvelope::from_io_error(
                    &error,
                    "Open selected artifact",
                ))
            })?;
            let stored = store.store_file(file, artifact.content_type.clone(), 0)?;
            actual_bytes = actual_bytes
                .checked_add(stored.manifest.size_bytes)
                .ok_or_else(|| {
                    boxed_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "Selected artifact size overflow",
                    )
                })?;
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
        warnings: merge_warnings(&inventory.warnings, &closure.warnings),
        object_index_digest: PackageWriter::object_index_digest(&object_index)?,
    };
    Ok((manifest, graph, selection, object_index, store))
}

fn default_selection(graph: &PackageGraph) -> SelectionInput {
    let mut components: Vec<_> = graph
        .components
        .iter()
        .filter(|component| {
            component.selection.selected_by_default
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
mod interactive {
    use std::{
        collections::BTreeSet,
        io::{self, BufRead, Write},
        path::PathBuf,
    };

    use reforge_domain::{
        Component, ComponentId, ComponentKind, Inventory, LargeDataSelectionPolicy, RunId,
        SecretSelectionPolicy, SelectionInput, SelectionPolicy, UnknownBinarySelectionPolicy,
    };
    use serde_json::{Value, json};

    use super::{
        ApplicationService, CommandResult, ErrorEnvelope, ModeArg, action_acknowledge_command,
        action_list_command, doctor_command, package_inspect_command, parse_run_id, plan_command,
        read_json_state, report_command, restore_command, resume_command, scan_command,
        state_paths, target_scan_command, verify_command,
    };

    const PAGE_SIZE: usize = 20;

    pub(super) async fn run() -> Result<CommandResult, Box<ErrorEnvelope>> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut ui = InteractiveUi::new(stdin.lock(), stdout.lock());
        ui.run().await?;
        Ok(CommandResult {
            payload: json!({"status": "exited"}),
            human: String::new(),
            exit_code: 0,
        })
    }

    struct InteractiveUi<R, W> {
        input: R,
        output: W,
        package_path: Option<PathBuf>,
        run_id: Option<RunId>,
    }

    impl<R, W> InteractiveUi<R, W>
    where
        R: BufRead,
        W: Write,
    {
        fn new(input: R, output: W) -> Self {
            Self {
                input,
                output,
                package_path: None,
                run_id: None,
            }
        }

        async fn run(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            self.write_line("Reforge — интерактивный режим командной строки.")?;
            self.write_line(
                "Все операции используют те же проверки, что и обычные команды; restore требует точного YES.",
            )?;
            loop {
                self.write_menu()?;
                let Some(choice) = self.prompt("Выберите пункт: ")? else {
                    self.write_line("Ввод завершён.")?;
                    break;
                };
                match choice.as_str() {
                    "0" => {
                        self.write_line("Выход.")?;
                        break;
                    }
                    "1" => self.show_result(doctor_command())?,
                    "2" => self.scan().await?,
                    "3" => self.show_inventory()?,
                    "4" => self.show_result(target_scan_command().await)?,
                    "5" => self.create_package()?,
                    "6" => self.inspect_package()?,
                    "7" => self.plan().await?,
                    "8" => self.restore().await?,
                    "9" => self.resume().await?,
                    "10" => self.manual_actions()?,
                    "11" => self.verify().await?,
                    "12" => self.report().await?,
                    _ => self.write_line("Неизвестный пункт. Введите число из меню.")?,
                }
            }
            Ok(())
        }

        fn write_menu(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            self.write_line("")?;
            self.write_line("=== Reforge ===")?;
            self.write_line(" 1. Проверить host (doctor)")?;
            self.write_line(" 2. Сканировать окружение")?;
            self.write_line(" 3. Показать найденные компоненты")?;
            self.write_line(" 4. Сканировать target")?;
            self.write_line(" 5. Создать пакет")?;
            self.write_line(" 6. Проверить пакет")?;
            self.write_line(" 7. Построить план восстановления")?;
            self.write_line(" 8. Выполнить восстановление")?;
            self.write_line(" 9. Продолжить interrupted/reboot run")?;
            self.write_line("10. Manual actions")?;
            self.write_line("11. Проверить результат")?;
            self.write_line("12. Показать/сохранить отчёт")?;
            self.write_line(" 0. Выход")?;
            Ok(())
        }

        async fn scan(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            self.show_result(scan_command().await)
        }

        fn show_inventory(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let inventory = match load_inventory() {
                Ok(inventory) => inventory,
                Err(error) => {
                    self.show_error(&error)?;
                    return Ok(());
                }
            };
            self.write_line(&format!(
                "Inventory: {} компонентов, {} предупреждений.",
                inventory.graph.components.len(),
                inventory.warnings.len()
            ))?;
            self.browse_components(&inventory)
        }

        fn create_package(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let inventory = match load_inventory() {
                Ok(inventory) => inventory,
                Err(error) => {
                    self.show_error(&error)?;
                    return Ok(());
                }
            };
            let Some(component_ids) = self.choose_components(&inventory)? else {
                return Ok(());
            };
            let Some(output) = self.prompt_path("Путь выходного .reforge файла (q — отмена): ")?
            else {
                return Ok(());
            };
            let service = match ApplicationService::new() {
                Ok(service) => service,
                Err(error) => {
                    self.show_error(&error)?;
                    return Ok(());
                }
            };
            let selection = SelectionInput {
                components: component_ids.clone(),
                artifacts: Vec::new(),
                policy: SelectionPolicy {
                    secrets: SecretSelectionPolicy::Exclude,
                    large_data: LargeDataSelectionPolicy::Exclude,
                    unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
                    max_bytes: None,
                },
            };
            match service.create_package(&output, selection) {
                Ok(receipt) => {
                    self.package_path = Some(output);
                    self.show_result(Ok(CommandResult {
                        payload: json!({
                            "status": "ok",
                            "package_id": receipt.package_id,
                            "object_count": receipt.object_count,
                            "index_digest": receipt.index_digest,
                        }),
                        human: format!(
                            "Пакет создан: {} (выбрано компонентов: {}, объектов: {}).\n",
                            receipt.package_id,
                            component_ids.len(),
                            receipt.object_count
                        ),
                        exit_code: 0,
                    }))
                }
                Err(error) => {
                    self.show_error(&error)?;
                    Ok(())
                }
            }
        }

        fn inspect_package(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(path) = self.prompt_package_path()? else {
                return Ok(());
            };
            self.show_result(package_inspect_command(path))
        }

        async fn plan(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(path) = self.prompt_package_path()? else {
                return Ok(());
            };
            let Some(mode) = self.prompt_mode()? else {
                return Ok(());
            };
            self.show_result(plan_command(path, mode).await)
        }

        async fn restore(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(path) = self.prompt_package_path()? else {
                return Ok(());
            };
            let Some(mode) = self.prompt_mode()? else {
                return Ok(());
            };
            self.write_line(
                "Восстановление может изменять target; сначала выполните пункт 7 и проверьте план.",
            )?;
            let Some(confirmation) = self.prompt("Для продолжения введите YES: ")?
            else {
                return Ok(());
            };
            if confirmation != "YES" {
                self.write_line("Восстановление отменено.")?;
                return Ok(());
            }
            self.show_result(restore_command(path, mode, true).await)
        }

        async fn resume(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(run_id) = self.prompt_run_id()? else {
                return Ok(());
            };
            self.show_result(resume_command(run_id).await)
        }

        fn manual_actions(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            loop {
                self.write_line("")?;
                self.write_line("Manual actions:")?;
                self.write_line(" 1. Показать очередь")?;
                self.write_line(" 2. Acknowledge action")?;
                self.write_line(" 0. Назад")?;
                let Some(choice) = self.prompt("Выберите пункт: ")? else {
                    return Ok(());
                };
                match choice.as_str() {
                    "0" => return Ok(()),
                    "1" => {
                        let Some(run_id) = self.prompt_run_id()? else {
                            continue;
                        };
                        self.show_result(action_list_command(run_id))?;
                    }
                    "2" => {
                        let Some(run_id) = self.prompt_run_id()? else {
                            continue;
                        };
                        let Some(action_id) =
                            self.prompt_required("Введите action_id (q — назад): ")?
                        else {
                            continue;
                        };
                        self.show_result(action_acknowledge_command(run_id, action_id))?;
                    }
                    _ => self.write_line("Неизвестный пункт.")?,
                }
            }
        }

        async fn verify(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(run_id) = self.prompt_run_id()? else {
                return Ok(());
            };
            self.show_result(verify_command(run_id).await)
        }

        async fn report(&mut self) -> Result<(), Box<ErrorEnvelope>> {
            let Some(run_id) = self.prompt_run_id()? else {
                return Ok(());
            };
            let output = match self
                .prompt("Путь для сохранения отчёта (Enter — только показать, q — назад): ")?
            {
                None => return Ok(()),
                Some(line) if line == "q" => return Ok(()),
                Some(line) if line.is_empty() => None,
                Some(line) => Some(PathBuf::from(line)),
            };
            self.show_result(report_command(run_id, output).await)
        }

        fn prompt_mode(&mut self) -> Result<Option<ModeArg>, Box<ErrorEnvelope>> {
            let Some(choice) = self.prompt("Режим: 1 — rebuild, 2 — migrate, 0 — назад: ")?
            else {
                return Ok(None);
            };
            match choice.as_str() {
                "1" => Ok(Some(ModeArg::Rebuild)),
                "2" => Ok(Some(ModeArg::Migrate)),
                _ => {
                    self.write_line("Режим не выбран.")?;
                    Ok(None)
                }
            }
        }

        fn prompt_package_path(&mut self) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
            let prompt = if self.package_path.is_some() {
                "Путь пакета (Enter — использовать ранее выбранный, q — назад): "
            } else {
                "Путь .reforge пакета (q — назад): "
            };
            let Some(line) = self.prompt(prompt)? else {
                return Ok(None);
            };
            if line == "q" {
                return Ok(None);
            }
            if line.is_empty() {
                return Ok(self.package_path.clone());
            }
            let path = PathBuf::from(line);
            self.package_path = Some(path.clone());
            Ok(Some(path))
        }

        fn prompt_path(&mut self, message: &str) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
            let Some(line) = self.prompt(message)? else {
                return Ok(None);
            };
            if line.is_empty() || line == "q" {
                return Ok(None);
            }
            Ok(Some(PathBuf::from(line)))
        }

        fn prompt_required(&mut self, message: &str) -> Result<Option<String>, Box<ErrorEnvelope>> {
            let Some(line) = self.prompt(message)? else {
                return Ok(None);
            };
            if line.is_empty() || line == "q" {
                return Ok(None);
            }
            Ok(Some(line))
        }

        fn prompt_run_id(&mut self) -> Result<Option<RunId>, Box<ErrorEnvelope>> {
            let message = if self.run_id.is_some() {
                "Run ID (Enter — последний сохранённый, q — назад): "
            } else {
                "Run ID (q — назад): "
            };
            let Some(line) = self.prompt(message)? else {
                return Ok(None);
            };
            if line == "q" {
                return Ok(None);
            }
            if line.is_empty() {
                return Ok(self.run_id.clone());
            }
            match parse_run_id(&line) {
                Ok(run_id) => {
                    self.run_id = Some(run_id.clone());
                    Ok(Some(run_id))
                }
                Err(message) => {
                    self.write_line(&format!("Некорректный run ID: {message}"))?;
                    Ok(None)
                }
            }
        }

        fn choose_components(
            &mut self,
            inventory: &Inventory,
        ) -> Result<Option<Vec<ComponentId>>, Box<ErrorEnvelope>> {
            let candidates = selectable_components(inventory);
            if candidates.is_empty() {
                self.write_line("Нет компонентов, доступных для безопасного выбора.")?;
                return Ok(None);
            }
            self.write_line(
                "Выберите номера компонентов. Можно переходить по страницам; done — завершить, q — отмена.",
            )?;
            let mut selected = Vec::new();
            let mut page = 0usize;
            loop {
                self.write_component_page(&candidates, page, &selected)?;
                let Some(answer) = self.prompt("Номера через запятую / n / p / done: ")?
                else {
                    return Ok(None);
                };
                match answer.to_ascii_lowercase().as_str() {
                    "q" => return Ok(None),
                    "done" => {
                        if selected.is_empty() {
                            self.write_line("Нужно выбрать хотя бы один компонент.")?;
                        } else {
                            return Ok(Some(selected));
                        }
                    }
                    "n" => {
                        if page + 1 < page_count(candidates.len()) {
                            page += 1;
                        }
                    }
                    "p" => page = page.saturating_sub(1),
                    _ => match parse_number_list(&answer, candidates.len()) {
                        Ok(indices) => {
                            for index in indices {
                                let id = candidates[index].id.clone();
                                if !selected.contains(&id) {
                                    selected.push(id);
                                }
                            }
                            self.write_line(&format!("Выбрано компонентов: {}.", selected.len()))?;
                        }
                        Err(message) => self.write_line(&message)?,
                    },
                }
            }
        }

        fn browse_components(&mut self, inventory: &Inventory) -> Result<(), Box<ErrorEnvelope>> {
            let candidates = selectable_components(inventory);
            if candidates.is_empty() {
                self.write_line("Нет компонентов, доступных для отображения.")?;
                return Ok(());
            }
            let mut page = 0usize;
            loop {
                self.write_component_page(&candidates, page, &[])?;
                let Some(answer) = self.prompt("n — следующая, p — предыдущая, q — назад: ")?
                else {
                    return Ok(());
                };
                match answer.to_ascii_lowercase().as_str() {
                    "q" | "" => return Ok(()),
                    "n" if page + 1 < page_count(candidates.len()) => page += 1,
                    "p" => page = page.saturating_sub(1),
                    _ => self.write_line("Команда не распознана.")?,
                }
            }
        }

        fn write_component_page(
            &mut self,
            candidates: &[&Component],
            page: usize,
            selected: &[ComponentId],
        ) -> Result<(), Box<ErrorEnvelope>> {
            let start = page * PAGE_SIZE;
            let end = (start + PAGE_SIZE).min(candidates.len());
            self.write_line(&format!(
                "Компоненты {}–{} из {} (страница {}/{}):",
                start + 1,
                end,
                candidates.len(),
                page + 1,
                page_count(candidates.len())
            ))?;
            for (index, component) in candidates[start..end].iter().enumerate() {
                let global = start + index + 1;
                let marker = if selected.contains(&component.id) {
                    "*"
                } else {
                    " "
                };
                self.write_line(&format!(
                    "[{marker}] {global:>4}. {} ({:?})",
                    safe_component_name(component),
                    component.kind
                ))?;
            }
            Ok(())
        }

        fn show_result(
            &mut self,
            result: Result<CommandResult, Box<ErrorEnvelope>>,
        ) -> Result<(), Box<ErrorEnvelope>> {
            match result {
                Ok(result) => {
                    self.remember_payload(&result.payload);
                    if !result.human.is_empty() {
                        self.write_raw(&result.human)?;
                        if !result.human.ends_with('\n') {
                            self.write_line("")?;
                        }
                    }
                    self.write_line(&format!("Код завершения: {}", result.exit_code))?;
                }
                Err(error) => self.show_error(&error)?,
            }
            Ok(())
        }

        fn show_error(&mut self, error: &ErrorEnvelope) -> Result<(), Box<ErrorEnvelope>> {
            self.write_line(&format!("Ошибка [{:?}]: {}", error.code, error.message))
        }

        fn remember_payload(&mut self, payload: &Value) {
            let run_id = payload.get("run_id").and_then(Value::as_str).or_else(|| {
                payload
                    .get("plan")
                    .and_then(|plan| plan.get("run_id"))
                    .and_then(Value::as_str)
            });
            if let Some(run_id) = run_id
                && let Ok(run_id) = parse_run_id(run_id)
            {
                self.run_id = Some(run_id);
            }
        }

        fn prompt(&mut self, message: &str) -> Result<Option<String>, Box<ErrorEnvelope>> {
            self.output
                .write_all(message.as_bytes())
                .map_err(|error| io_error(error, "Write interactive prompt"))?;
            self.output
                .flush()
                .map_err(|error| io_error(error, "Flush interactive prompt"))?;
            let mut line = String::new();
            let read = self
                .input
                .read_line(&mut line)
                .map_err(|error| io_error(error, "Read interactive input"))?;
            if read == 0 {
                return Ok(None);
            }
            Ok(Some(line.trim().to_owned()))
        }

        fn write_raw(&mut self, value: &str) -> Result<(), Box<ErrorEnvelope>> {
            self.output
                .write_all(value.as_bytes())
                .map_err(|error| io_error(error, "Write interactive output"))
        }

        fn write_line(&mut self, value: &str) -> Result<(), Box<ErrorEnvelope>> {
            writeln!(self.output, "{value}")
                .map_err(|error| io_error(error, "Write interactive output"))
        }
    }

    fn load_inventory() -> Result<Inventory, Box<ErrorEnvelope>> {
        let state = state_paths()?;
        read_json_state(&state.inventory)
    }

    fn selectable_components(inventory: &Inventory) -> Vec<&Component> {
        let mut components = inventory
            .graph
            .components
            .iter()
            .filter(|component| {
                component.kind != ComponentKind::SecretReference && !component.selection.sensitive
            })
            .collect::<Vec<_>>();
        components.sort_by(|left, right| {
            safe_component_name(left)
                .cmp(&safe_component_name(right))
                .then_with(|| left.id.cmp(&right.id))
        });
        components
    }

    fn safe_component_name(component: &Component) -> String {
        let mut name = component
            .display_name
            .chars()
            .filter(|character| !character.is_control())
            .take(80)
            .collect::<String>();
        if name.is_empty() {
            name.push_str("(без названия)");
        }
        name
    }

    fn page_count(item_count: usize) -> usize {
        item_count.div_ceil(PAGE_SIZE)
    }

    fn parse_number_list(input: &str, maximum: usize) -> Result<Vec<usize>, String> {
        let mut seen = BTreeSet::new();
        for token in
            input.split(|character: char| character == ',' || character.is_ascii_whitespace())
        {
            if token.is_empty() {
                continue;
            }
            let number = token
                .parse::<usize>()
                .map_err(|_| format!("Некорректный номер компонента: {token}"))?;
            if number == 0 || number > maximum {
                return Err(format!("Номер компонента должен быть от 1 до {maximum}."));
            }
            seen.insert(number - 1);
        }
        if seen.is_empty() {
            return Err("Введите хотя бы один номер компонента.".to_owned());
        }
        Ok(seen.into_iter().collect())
    }

    fn io_error(error: io::Error, context: &str) -> Box<ErrorEnvelope> {
        Box::new(ErrorEnvelope::from_io_error(&error, context))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Cursor;

        #[test]
        fn menu_exits_cleanly_on_zero() {
            let mut ui = InteractiveUi::new(Cursor::new(b"0\n".to_vec()), Vec::<u8>::new());
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(ui.run()).expect("interactive menu");
            let output = String::from_utf8(ui.output).expect("UTF-8 output");
            assert!(output.contains("1. Проверить host (doctor)"));
            assert!(output.contains("Выход."));
        }
        #[test]
        fn restore_rejects_non_exact_yes_confirmation() {
            let mut ui = InteractiveUi::new(
                Cursor::new(b"unused.reforge\n1\nconfirm\n".to_vec()),
                Vec::<u8>::new(),
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime
                .block_on(ui.restore())
                .expect("restore confirmation");
            let output = String::from_utf8(ui.output).expect("UTF-8 output");
            assert!(output.contains("Восстановление отменено."));
        }

        #[test]
        fn numeric_component_selection_is_deduplicated() {
            assert_eq!(parse_number_list("1, 3 3", 4).expect("numbers"), vec![0, 2]);
        }

        #[test]
        fn numeric_component_selection_rejects_out_of_bounds() {
            let error = parse_number_list("0,2", 4).expect_err("zero must be rejected");
            assert!(error.contains("от 1 до 4"));
        }
    }
}
