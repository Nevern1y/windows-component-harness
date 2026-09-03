//! Declarative, journaled restoration engine for Reforge.
//!
//! Restore planning and execution are introduced after the workspace bootstrap.
//! All future fallible restore boundaries use the domain error envelope so
//! provider/platform details cannot bypass redaction.
pub mod compatibility;
pub mod conflicts;
pub mod diff;
pub mod executor;
pub mod handlers;
pub mod journal;
pub mod manual_actions;
pub mod operations;
pub mod planner;
pub mod target;
pub use verification::{
    REPORT_FORMAT_VERSION, VerificationEngine, VerificationInput, redact_restore_report,
    verify_restore,
};
pub mod verification;

pub use executor::{
    BackupHook, ExecutionContext, ExecutionReport, Executor, ObjectSource, OperationDisposition,
    OperationHandler, OperationOutcome, OperationSatisfaction,
};
pub use journal::{
    Journal, JournalEvent, JournalManualAction, JournalOperation, JournalReader, JournalRun,
};
pub use manual_actions::{
    ManualActionHandler, ManualActionQueue, SecretRestoreAdapter, SecretRestoreGate,
    SecretRestoreReport,
};
pub use planner::{PlannerInput, RestorePlanInput, RestorePlanner, plan_restore};

pub use compatibility::{
    CompatibilityEngine, FREE_SPACE_MARGIN_PERCENT, MINIMUM_FREE_SPACE_MARGIN_BYTES,
    recommended_free_bytes,
};
pub use conflicts::ClassifiedConflict;
pub use diff::{
    BackupRequirement, BackupTarget, ComponentDiff, ComponentDisposition, DiffEngine, TargetDiff,
    merge_path_entries,
};
pub use handlers::{
    BrowserAwareRestoreHandler, BrowserRestoreHandler, ConfigRestoreHandler, DockerRestoreHandler,
    EnvironmentRestoreHandler, FileRestoreHandler, HarnessRestoreHandler, MemoryUserEnvironment,
    ProviderInstallHandler, ProviderProcessBridge, ProviderRestoreHandler, RegistryUserEnvironment,
    UserEnvironmentBackend, VsCodeRestoreHandler, WslRestoreHandler, default_browser_operation,
};
pub use target::TargetScanner;

use reforge_domain::{ComponentId, ErrorEnvelope, OperationId, ReforgeErrorCode, coded_error};

/// Result type for restore planning and execution boundaries.
pub type RestoreResult<T> = Result<T, Box<ErrorEnvelope>>;

/// Construct a restore error while preserving operation correlation and
/// fail-closed technical-detail redaction.
pub fn restore_error(
    code: ReforgeErrorCode,
    message: impl Into<String>,
    technical_detail: Option<&str>,
    component: Option<ComponentId>,
    operation: Option<OperationId>,
    context_id: Option<&str>,
) -> Box<ErrorEnvelope> {
    Box::new(coded_error(
        code,
        message,
        technical_detail,
        component,
        operation,
        context_id,
    ))
}
