//! Evidence-backed discovery orchestration for Reforge.
//!
//! Discovery adapters are introduced after the workspace bootstrap.

mod artifacts;
pub mod browsers;
mod coordinator;
pub mod dedup;
pub mod editors;
mod evidence;
pub mod generic;
pub mod harnesses;
pub mod providers;
pub mod recommend;

pub use artifacts::{
    ArtifactCollection, ArtifactCollector, ArtifactInspection, ArtifactLimits, ArtifactRequest,
    NewlineStyle, collect_artifacts,
};
pub use browsers::{
    BrowserActivity, BrowserAdapter, BrowserDiscovery, BrowserDiscoveryInputs,
    BrowserEvidenceSource, BrowserExtension, BrowserFamily, BrowserInstallation, BrowserProfile,
    BrowserRegistration, ChromiumAdapter, FirefoxAdapter,
};
pub use coordinator::DiscoveryCoordinator;
pub use dedup::deduplicate_graph;
pub use editors::{VSCodeAdapter, VSCodeDiscovery, VSCodeExtension, VSCodeObservations};
pub use generic::{
    ExecutableCandidate, GenericExecutableAdapter, LocalIdentity, PathEvidence,
    SourceCorrelationDecision, correlate_candidates,
};
pub use providers::{
    AdapterRegistry, DetectionResult, Observation, ProviderAdapter, ProviderContext,
    ProviderEnumeration, ProviderResult, WinGetAdapter, WindowsRegistrationAdapter,
};
pub use recommend::recommend;
