//! Validated opaque identifiers used by the domain wire model.

use std::{error::Error, fmt};

use crate::model::{Identity, IdentityQuality, Publisher};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;
use uuid::Uuid;

/// Error returned when an opaque identifier or UUID does not satisfy its wire grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdError {
    kind: &'static str,
    value: String,
}

impl IdError {
    fn new(kind: &'static str, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} identifier: {}",
            self.kind, self.value
        )
    }
}

impl Error for IdError {}

/// A component identifier together with the identity tier that produced it.
///
/// The tier is part of the result so a local executable fallback cannot be
/// mistaken for a portable product identity by callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalIdentity {
    pub id: ComponentId,
    pub quality: IdentityQuality,
}

/// Stable component identity: `cmp_` followed by lowercase unpadded Base32 BLAKE3-256.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("cmp_") else {
            return Err(IdError::new("component", value));
        };
        if digest.len() != 52
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(IdError::new("component", value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the highest-quality available identity tuple with BLAKE3.
    ///
    /// Provider identities require a stable provider-source identifier.
    /// `publisher` supplies the optional certificate thumbprint used by the
    /// signed-product tier. Paths and display-only fields are intentionally
    /// not accepted, so a path alone can never produce a portable ID.
    pub fn from_identity(
        identity: &Identity,
        publisher: Option<&Publisher>,
    ) -> Result<CanonicalIdentity, IdError> {
        let normalized = NormalizedIdentity::from_parts(identity, publisher)?;
        let (tuple, quality) = normalized.tuple()?;
        let bytes = serde_json::to_vec(&tuple)
            .map_err(|_| IdError::new("component", "identity tuple serialization failed"))?;
        let digest = blake3::hash(&bytes);
        let id = Self::new(format!("cmp_{}", encode_base32_lower(digest.as_slice())))?;
        Ok(CanonicalIdentity { id, quality })
    }
}

impl TryFrom<String> for ComponentId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ComponentId> for String {
    fn from(value: ComponentId) -> Self {
        value.0
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Content-addressed object identity: `obj_` followed by lowercase hexadecimal BLAKE3-256.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct ObjectId(String);

impl ObjectId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix("obj_") else {
            return Err(IdError::new("object", value));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdError::new("object", value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive an object ID from the uncompressed canonical object bytes.
    pub fn from_content(content: &[u8]) -> Self {
        Self(format!("obj_{}", blake3::hash(content).to_hex()))
    }
}

impl TryFrom<String> for ObjectId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ObjectId> for String {
    fn from(value: ObjectId) -> Self {
        value.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// UUIDv7 run identifier used to correlate resumable operations and journal events.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct RunId(Uuid);

impl RunId {
    pub fn new(value: Uuid) -> Result<Self, IdError> {
        if value.get_version_num() != 7 {
            return Err(IdError::new("run", value.to_string()));
        }
        Ok(Self(value))
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl TryFrom<String> for RunId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let original = value.clone();
        let uuid = value
            .parse::<Uuid>()
            .map_err(|_| IdError::new("run", original.clone()))?;
        Self::new(uuid)
    }
}

impl From<RunId> for String {
    fn from(value: RunId) -> Self {
        value.0.to_string()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.to_string())
    }
}

/// Stable operation identity in the form `op_<run-id>_<decimal-ordinal>`.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        let Some(remainder) = value.strip_prefix("op_") else {
            return Err(IdError::new("operation", value));
        };
        let Some((run, ordinal)) = remainder.rsplit_once('_') else {
            return Err(IdError::new("operation", value));
        };
        RunId::try_from(run.to_owned())?;
        if ordinal.is_empty()
            || ordinal.len() > 20
            || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(IdError::new("operation", value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct the stable operation ID for an ordinal within a run.
    pub fn for_run(run_id: &RunId, ordinal: u64) -> Result<Self, IdError> {
        Self::new(format!("op_{run_id}_{ordinal}"))
    }
}

impl TryFrom<String> for OperationId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalIdentityTuple {
    ProviderPackage {
        provider: String,
        provider_source: String,
        package_id: String,
    },
    PackageFamily {
        package_family: String,
        publisher: String,
    },
    SignedProduct {
        product_name: String,
        certificate_thumbprint: String,
    },
    ExecutableProduct {
        product_name: String,
        publisher: String,
        install_role: String,
    },
    LocalExecutable {
        executable_name: String,
        executable_hash: String,
    },
}

struct NormalizedIdentity {
    provider_package: Option<(String, String)>,
    provider_source: Option<String>,
    package_family: Option<String>,
    product_name: Option<String>,
    executable_name: Option<String>,
    publisher: Option<String>,
    certificate_thumbprint: Option<String>,
    executable_hash: Option<String>,
    install_role: Option<String>,
}

impl NormalizedIdentity {
    fn from_parts(identity: &Identity, publisher: Option<&Publisher>) -> Result<Self, IdError> {
        let provider_package = identity
            .provider_package
            .as_ref()
            .map(|(provider, package_id)| {
                Ok((
                    normalize_identity_text("provider", provider.as_str())?,
                    normalize_identity_text("package", package_id)?,
                ))
            })
            .transpose()?;
        let provider_source =
            normalize_optional(identity.provider_source.as_deref(), "provider source")?;
        let publisher_from_identity =
            normalize_optional(identity.publisher.as_deref(), "publisher")?;
        let publisher_from_record = publisher
            .map(|value| normalize_identity_text("publisher", &value.name))
            .transpose()?;
        let certificate_thumbprint = publisher
            .and_then(|value| value.certificate_thumbprint.as_deref())
            .map(normalize_thumbprint)
            .transpose()?;
        let publisher = match (publisher_from_identity, publisher_from_record) {
            (Some(identity), Some(record)) if identity != record => {
                return Err(IdError::new(
                    "component",
                    "conflicting publisher identity facts",
                ));
            }
            (Some(identity), _) => Some(identity),
            (_, Some(record)) => Some(record),
            (None, None) => None,
        };

        Ok(Self {
            provider_package,
            provider_source,
            package_family: normalize_optional(
                identity.package_family.as_deref(),
                "package family",
            )?,
            product_name: normalize_optional(identity.product_name.as_deref(), "product name")?,
            executable_name: identity
                .executable_name
                .as_deref()
                .map(normalize_executable_name)
                .transpose()?,
            publisher,
            certificate_thumbprint,
            executable_hash: normalize_optional(
                identity.executable_hash.as_deref(),
                "executable hash",
            )?,
            install_role: normalize_optional(identity.install_role.as_deref(), "install role")?,
        })
    }
    fn tuple(self) -> Result<(CanonicalIdentityTuple, IdentityQuality), IdError> {
        if let (Some((provider, package_id)), Some(provider_source)) =
            (self.provider_package.clone(), self.provider_source.clone())
        {
            return Ok((
                CanonicalIdentityTuple::ProviderPackage {
                    provider,
                    provider_source,
                    package_id,
                },
                IdentityQuality::Provider,
            ));
        }
        if let (Some(package_family), Some(publisher)) =
            (self.package_family.clone(), self.publisher.clone())
        {
            return Ok((
                CanonicalIdentityTuple::PackageFamily {
                    package_family,
                    publisher,
                },
                IdentityQuality::PackageFamily,
            ));
        }
        if let (Some(product_name), Some(certificate_thumbprint)) = (
            self.product_name.clone(),
            self.certificate_thumbprint.clone(),
        ) {
            return Ok((
                CanonicalIdentityTuple::SignedProduct {
                    product_name,
                    certificate_thumbprint,
                },
                IdentityQuality::SignedProduct,
            ));
        }
        if let (Some(product_name), Some(publisher), Some(install_role)) =
            (self.product_name, self.publisher, self.install_role)
        {
            return Ok((
                CanonicalIdentityTuple::ExecutableProduct {
                    product_name,
                    publisher,
                    install_role,
                },
                IdentityQuality::Product,
            ));
        }
        if let (Some(executable_name), Some(executable_hash)) =
            (self.executable_name, self.executable_hash)
        {
            return Ok((
                CanonicalIdentityTuple::LocalExecutable {
                    executable_name,
                    executable_hash,
                },
                IdentityQuality::Local,
            ));
        }
        Err(IdError::new(
            "component",
            "identity lacks a supported portable or local tuple",
        ))
    }
}

fn normalize_optional(value: Option<&str>, kind: &'static str) -> Result<Option<String>, IdError> {
    value
        .map(|value| normalize_identity_text(kind, value))
        .transpose()
}

fn normalize_identity_text(kind: &'static str, value: &str) -> Result<String, IdError> {
    let value = value.trim().to_lowercase();
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(IdError::new(kind, value));
    }
    Ok(value)
}

fn normalize_thumbprint(value: &str) -> Result<String, IdError> {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            return Err(IdError::new("certificate thumbprint", value));
        }
        if !character.is_whitespace() {
            normalized.push(character.to_ascii_lowercase());
        }
    }
    if normalized.is_empty() {
        return Err(IdError::new("certificate thumbprint", value));
    }
    Ok(normalized)
}

fn normalize_executable_name(value: &str) -> Result<String, IdError> {
    let normalized = normalize_identity_text("executable", value)?;
    let name = normalized.rsplit(['/', '\\']).next().unwrap_or(&normalized);
    if name.is_empty() {
        return Err(IdError::new("executable", normalized));
    }
    Ok(name.to_owned())
}

fn encode_base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u32;
    let mut bits = 0u8;

    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            output.push(ALPHABET[index] as char);
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u32 << bits) - 1;
            }
        }
    }
    if bits != 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

macro_rules! impl_opaque_id {
    ($name:ident) => {
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_opaque(stringify!($name), &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

fn validate_opaque(kind: &'static str, value: &str) -> Result<(), IdError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(IdError::new(kind, value));
    }
    Ok(())
}

/// Opaque evidence identifier. Its value is validated for safe wire transport.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
/// Opaque provider identifier. Its value is validated for safe wire transport.
#[schemars(with = "String")]
pub struct EvidenceId(String);

/// Opaque snapshot identifier. Its value is validated for safe wire transport.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
/// Opaque artifact identifier. Its value is validated for safe wire transport.
#[schemars(with = "String")]
pub struct SnapshotId(String);

/// Opaque provider identifier. Its value is validated for safe wire transport.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct ProviderId(String);

/// Opaque artifact identifier. Its value is validated for safe wire transport.
#[typeshare(serialized_as = "String")]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct ArtifactId(String);

impl_opaque_id!(EvidenceId);
impl_opaque_id!(SnapshotId);
impl_opaque_id!(ProviderId);
impl_opaque_id!(ArtifactId);
