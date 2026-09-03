//! Reforge package format and vault boundary.
//!
//! Package serialization is deterministic and content-addressed. The package
//! writer and vault layers build on these canonical bytes.

pub mod canonical;
pub mod content_store;
mod reader;
pub mod signature;
pub mod vault;
mod writer;

pub use canonical::{CanonicalJson, canonical_bytes, canonical_object_id, canonicalize};
pub use content_store::{
    BoundedStreamWriter, ContentStoreLimits, FILE_CHUNK_BYTES, ObjectStore, StoredFile,
    StoredObject, StreamDigest,
};
pub use reader::{InspectedPackage, PackageReader};
pub use signature::{
    PackageSignature, PublicKeyFingerprint, SignatureMetadata, SigningKey, TrustDecision,
    apply_trust_decision, require_plan_approval, signature_coverage_bytes,
};
pub use vault::{
    EncryptedVault, ExposeSecret, PendingVault, RecoveryMaterial, SecretDescriptor, SecretKind,
    SecretRecord, SecretSelection, SecretSource, SecretString, SecretTarget, VaultDocument,
    collect_approved_vault,
};
pub use writer::{
    PackageLimits, PackageOperations, PackageSourceRecord, PackageSources, PackageWriteRequest,
    PackageWriter,
};
