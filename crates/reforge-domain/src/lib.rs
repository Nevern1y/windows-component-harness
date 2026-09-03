#![forbid(unsafe_code)]

//! Canonical Reforge domain contracts.
//!
//! The domain crate owns every DTO crossing crate, CLI, Tauri, package, or UI
//! boundaries. Behavior crates build around these types and do not define
//! shadow models.

pub mod error;
pub mod ids;
pub mod model;
pub mod redaction;
pub mod schema;
pub mod selection;

pub use error::{classify_io_error, coded_error, serialize_error};
pub use ids::{
    ArtifactId, CanonicalIdentity, ComponentId, EvidenceId, IdError, ObjectId, OperationId,
    ProviderId, RunId, SnapshotId,
};
pub use model::*;
pub use redaction::{
    RedactedProviderOutput, RedactionPolicy, redact_json, redact_provider_output, redact_text,
    sanitize_context_id,
};
pub use selection::{ExplanationChip, RecommendationScore};
