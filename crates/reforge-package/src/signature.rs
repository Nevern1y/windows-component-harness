//! Optional Ed25519 package signatures and explicit trust transitions.
//!
//! The embedded public key is an identity hint. Cryptographic validity and
//! out-of-band signer trust are deliberately separate states.

use std::fmt;

pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use reforge_domain::{ErrorEnvelope, ObjectIndex, PackageManifest, ReforgeErrorCode, TrustState};
use serde::{Deserialize, Serialize};

use crate::{canonicalize, writer::normalize_object_index};

const SIGNATURE_FORMAT_VERSION: u16 = 1;
const SIGNATURE_ALGORITHM: &str = "ED25519";
const SIGNATURE_COVERAGE: &str = "REFORGE_PACKAGE_MANIFEST_AND_OBJECT_INDEX_V1";
const SIGNATURE_DOMAIN: &[u8] = b"REFORGE-PACKAGE-SIGNATURE-V1\0";
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const FINGERPRINT_PREFIX: &str = "ed25519_";
const FINGERPRINT_HEX_BYTES: usize = 64;

/// Full BLAKE3 fingerprint of the raw Ed25519 public key.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKeyFingerprint(String);

impl PublicKeyFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, Box<ErrorEnvelope>> {
        let value = value.into();
        let Some(hex) = value.strip_prefix(FINGERPRINT_PREFIX) else {
            return Err(signature_schema_error(
                "signer fingerprint prefix is invalid",
            ));
        };
        if hex.len() != FINGERPRINT_HEX_BYTES
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(signature_schema_error("signer fingerprint is invalid"));
        }
        Ok(Self(value))
    }

    pub fn from_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> Self {
        Self(format!(
            "{FINGERPRINT_PREFIX}{}",
            blake3::hash(public_key).to_hex()
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublicKeyFingerprint {
    type Error = Box<ErrorEnvelope>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PublicKeyFingerprint> for String {
    fn from(value: PublicKeyFingerprint) -> Self {
        value.0
    }
}

impl fmt::Display for PublicKeyFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Canonical, public metadata stored beside the raw signature bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub coverage: String,
    pub format_version: u16,
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub public_key_fingerprint: PublicKeyFingerprint,
}

impl SignatureMetadata {
    fn from_signing_key(signing_key: &SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            coverage: SIGNATURE_COVERAGE.to_owned(),
            format_version: SIGNATURE_FORMAT_VERSION,
            public_key_fingerprint: PublicKeyFingerprint::from_public_key(&public_key),
            public_key,
        }
    }

    fn validate(&self) -> Result<VerifyingKey, Box<ErrorEnvelope>> {
        if self.format_version != SIGNATURE_FORMAT_VERSION {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::UnsupportedVersion,
                "Package signature format version is unsupported",
            )));
        }
        if self.algorithm != SIGNATURE_ALGORITHM || self.coverage != SIGNATURE_COVERAGE {
            return Err(signature_schema_error(
                "package signature algorithm or coverage is unsupported",
            ));
        }
        if self.public_key_fingerprint != PublicKeyFingerprint::from_public_key(&self.public_key) {
            return Err(signature_schema_error(
                "package signer fingerprint does not match its public key",
            ));
        }
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| signature_schema_error("package signer public key is invalid"))
    }
}

/// Validated signature envelope for the two ZIP signature entries.
#[derive(Clone, Eq, PartialEq)]
pub struct PackageSignature {
    metadata: SignatureMetadata,
    metadata_bytes: Vec<u8>,
    signature: [u8; SIGNATURE_BYTES],
}

impl PackageSignature {
    /// Sign the normalized canonical package documents used by the writer.
    pub fn sign_documents(
        signing_key: &SigningKey,
        manifest: &PackageManifest,
        object_index: &ObjectIndex,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let normalized_index = normalize_object_index(object_index)?;
        let manifest = canonicalize(manifest)?.into_bytes();
        let object_index = canonicalize(&normalized_index)?.into_bytes();
        Self::sign_canonical(signing_key, &manifest, &object_index)
    }

    /// Parse canonical metadata and an exact raw 64-byte signature entry.
    pub fn from_entries(
        metadata_bytes: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let metadata: SignatureMetadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| signature_schema_error("package signature metadata is invalid"))?;
        metadata.validate()?;
        let canonical = canonicalize(&metadata)
            .map_err(|_| signature_schema_error("package signature metadata is invalid"))?;
        if canonical.as_bytes() != metadata_bytes {
            return Err(signature_schema_error(
                "package signature metadata is not canonical",
            ));
        }
        let signature = signature_bytes.try_into().map_err(|_| {
            signature_schema_error("package signature must contain exactly 64 bytes")
        })?;
        Ok(Self {
            metadata,
            metadata_bytes,
            signature,
        })
    }

    pub fn metadata(&self) -> &SignatureMetadata {
        &self.metadata
    }

    pub fn metadata_bytes(&self) -> &[u8] {
        &self.metadata_bytes
    }

    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    pub fn verify_documents(
        &self,
        manifest: &PackageManifest,
        object_index: &ObjectIndex,
    ) -> Result<bool, Box<ErrorEnvelope>> {
        let normalized_index = normalize_object_index(object_index)?;
        let manifest = canonicalize(manifest)?.into_bytes();
        let object_index = canonicalize(&normalized_index)?.into_bytes();
        self.verify_canonical(&manifest, &object_index)
    }

    pub(crate) fn verify_canonical(
        &self,
        manifest: &[u8],
        object_index: &[u8],
    ) -> Result<bool, Box<ErrorEnvelope>> {
        let verifying_key = self.metadata.validate()?;
        let coverage = signature_coverage_bytes(manifest, object_index)?;
        let signature = Signature::from_bytes(&self.signature);
        Ok(verifying_key.verify_strict(&coverage, &signature).is_ok())
    }

    pub(crate) fn trust_state_for_canonical(
        &self,
        manifest: &[u8],
        object_index: &[u8],
        trusted_signer: Option<&PublicKeyFingerprint>,
    ) -> Result<TrustState, Box<ErrorEnvelope>> {
        if !self.verify_canonical(manifest, object_index)? {
            return Ok(TrustState::SignatureInvalid);
        }
        if trusted_signer == Some(&self.metadata.public_key_fingerprint) {
            Ok(TrustState::SignatureValidTrusted)
        } else {
            Ok(TrustState::SignatureValidUntrusted)
        }
    }

    fn sign_canonical(
        signing_key: &SigningKey,
        manifest: &[u8],
        object_index: &[u8],
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let metadata = SignatureMetadata::from_signing_key(signing_key);
        let metadata_bytes = canonicalize(&metadata)?.into_bytes();
        let coverage = signature_coverage_bytes(manifest, object_index)?;
        let signature = signing_key.sign(&coverage).to_bytes();
        Ok(Self {
            metadata,
            metadata_bytes,
            signature,
        })
    }
}

impl fmt::Debug for PackageSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageSignature")
            .field("metadata", &self.metadata)
            .field("signature", &"[64 bytes]")
            .finish()
    }
}

/// Build the exact versioned message passed to Ed25519 signing and verification.
pub fn signature_coverage_bytes(
    manifest: &[u8],
    object_index: &[u8],
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let manifest_len = u64::try_from(manifest.len())
        .map_err(|_| signature_security_error("manifest length cannot be represented"))?;
    let object_index_len = u64::try_from(object_index.len())
        .map_err(|_| signature_security_error("object-index length cannot be represented"))?;
    let capacity = SIGNATURE_DOMAIN
        .len()
        .checked_add(size_of::<u64>())
        .and_then(|length| length.checked_add(manifest.len()))
        .and_then(|length| length.checked_add(size_of::<u64>()))
        .and_then(|length| length.checked_add(object_index.len()))
        .ok_or_else(|| signature_security_error("signature coverage length overflow"))?;
    let mut coverage = Vec::with_capacity(capacity);
    coverage.extend_from_slice(SIGNATURE_DOMAIN);
    coverage.extend_from_slice(&manifest_len.to_le_bytes());
    coverage.extend_from_slice(manifest);
    coverage.extend_from_slice(&object_index_len.to_le_bytes());
    coverage.extend_from_slice(object_index);
    Ok(coverage)
}

/// Explicit trust action for the current package load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustDecision {
    Approve,
    Reject,
}

/// Apply a user decision without allowing invalid/unchecked packages to become
/// approved. Signer trust never skips this operation-level approval.
pub fn apply_trust_decision(
    current: TrustState,
    decision: TrustDecision,
) -> Result<TrustState, Box<ErrorEnvelope>> {
    match decision {
        TrustDecision::Reject => Ok(TrustState::Rejected),
        TrustDecision::Approve => match current {
            TrustState::Unsigned
            | TrustState::SignatureValidUntrusted
            | TrustState::SignatureValidTrusted
            | TrustState::UserApproved => Ok(TrustState::UserApproved),
            TrustState::Unchecked | TrustState::IntegrityVerified => Err(package_untrusted(
                "Package signature state must be resolved before approval",
            )),
            TrustState::SignatureInvalid => Err(package_untrusted(
                "A package with an invalid signature cannot be approved",
            )),
            TrustState::Rejected => Err(package_untrusted(
                "A rejected package cannot be approved in the current load",
            )),
        },
    }
}

/// Gate consumed by the restore planner: cryptographic validity or signer trust
/// alone never authorizes operations.
pub fn require_plan_approval(trust: &TrustState) -> Result<(), Box<ErrorEnvelope>> {
    if *trust == TrustState::UserApproved {
        Ok(())
    } else {
        Err(package_untrusted(
            "Package requires explicit trust approval before planning",
        ))
    }
}

fn signature_schema_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::PackageCorrupt,
        message,
    ))
}

fn signature_security_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::SecurityPolicy,
        message,
    ))
}

fn package_untrusted(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::PackageUntrusted,
        message,
    ))
}
