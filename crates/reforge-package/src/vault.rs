//! Age-encrypted, explicitly selected secret vault.
//!
//! Secret values exist only in zeroizing buffers and the encrypted vault. The
//! normal package model carries references and redacted metadata instead.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Cursor, Read, Write},
    iter,
    str::FromStr,
};

pub use age::secrecy::{ExposeSecret, SecretString};
use age::{
    Decryptor, Encryptor,
    armor::{ArmoredReader, ArmoredWriter, Format},
    x25519,
};
use reforge_domain::{ComponentId, ErrorEnvelope, KnownFolderToken, PathToken, ReforgeErrorCode};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::canonicalize;

const VAULT_FORMAT_VERSION: u16 = 1;
const MAX_RECORDS: usize = 10_000;
const MAX_SECRET_VALUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_VAULT_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENCRYPTED_VAULT_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECOVERY_IDENTITY_BYTES: usize = 4 * 1024;
const MAX_PASSPHRASE_BYTES: usize = 4 * 1024;
const MAX_METADATA_TEXT_BYTES: usize = 1_024;
// Keep self-produced vaults within the strict reader resource bound on every host.
const VAULT_SCRYPT_WORK_FACTOR: u8 = 16;
const MAX_SCRYPT_WORK_FACTOR: u8 = 20;
const AGE_ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";

/// Classifies the approved value without exposing it to normal package DTOs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    ApiToken,
    Password,
    PrivateKey,
    Credential,
    Opaque,
}

/// The restore destination requested for a vault record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretTarget {
    WindowsCredentialManager,
    ApplicationKeyring { application: String },
    EnvironmentVariable { name: String },
    ConfigField { destination: PathToken },
    Manual,
}

/// Non-secret metadata shown before an adapter is allowed to read a value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretDescriptor {
    pub id: ComponentId,
    pub kind: SecretKind,
    pub label: String,
    pub risk: String,
    pub source: String,
    pub target: SecretTarget,
}

impl SecretDescriptor {
    pub fn new(
        id: ComponentId,
        label: impl Into<String>,
        kind: SecretKind,
        source: impl Into<String>,
        target: SecretTarget,
        risk: impl Into<String>,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let descriptor = Self {
            id,
            kind,
            label: label.into(),
            risk: risk.into(),
            source: source.into(),
            target,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), Box<ErrorEnvelope>> {
        validate_metadata_text("secret label", &self.label)?;
        validate_metadata_text("secret source", &self.source)?;
        validate_metadata_text("secret risk", &self.risk)?;
        validate_target(&self.target)
    }
}

/// Adapter boundary for a discoverable secret. Metadata is available before
/// `read_secret`; callers must invoke the latter only after explicit approval.
pub trait SecretSource {
    fn descriptor(&self) -> &SecretDescriptor;

    fn read_secret(&mut self) -> Result<Zeroizing<Vec<u8>>, Box<ErrorEnvelope>>;

    /// Defaults to false for plaintext environment/config targets. An adapter
    /// must opt in only when it proves a secure target policy.
    fn secure_target_policy_proven(&self) -> bool {
        false
    }
}

/// Deduplicated set of explicit per-secret approvals.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretSelection {
    approved: BTreeSet<ComponentId>,
}

impl SecretSelection {
    pub fn new(
        approved: impl IntoIterator<Item = ComponentId>,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let mut selected = BTreeSet::new();
        for id in approved {
            if !selected.insert(id) {
                return Err(schema_error("secret selection contains a duplicate ID"));
            }
        }
        Ok(Self { approved: selected })
    }

    pub fn contains(&self, id: &ComponentId) -> bool {
        self.approved.contains(id)
    }

    pub fn is_empty(&self) -> bool {
        self.approved.is_empty()
    }

    pub fn len(&self) -> usize {
        self.approved.len()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ComponentId> {
        self.approved.iter()
    }
}

impl fmt::Debug for SecretSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSelection")
            .field("approved_count", &self.approved.len())
            .finish()
    }
}

/// One plaintext record. `value` is deliberately private and never implements
/// `Serialize` or `Debug` through this public type.
pub struct SecretRecord {
    pub id: ComponentId,
    pub kind: SecretKind,
    pub label: String,
    pub target: SecretTarget,
    value: Zeroizing<Vec<u8>>,
}

impl SecretRecord {
    pub fn new(
        id: ComponentId,
        label: impl Into<String>,
        kind: SecretKind,
        target: SecretTarget,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let record = Self {
            id,
            kind,
            label: label.into(),
            target,
            value,
        };
        record.validate()?;
        Ok(record)
    }

    /// Explicit access for an adapter restoring to a secure target.
    pub fn expose_value(&self) -> &[u8] {
        &self.value
    }

    fn validate(&self) -> Result<(), Box<ErrorEnvelope>> {
        validate_metadata_text("secret label", &self.label)?;
        validate_target(&self.target)?;
        validate_secret_value(&self.value)
    }
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("label", &self.label)
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Canonically ordered plaintext vault. This type is never a normal package DTO.
pub struct VaultDocument {
    pub format_version: u16,
    pub records: Vec<SecretRecord>,
}

impl VaultDocument {
    pub fn new(records: Vec<SecretRecord>) -> Result<Self, Box<ErrorEnvelope>> {
        let mut document = Self {
            format_version: VAULT_FORMAT_VERSION,
            records,
        };
        document.validate_and_normalize()?;
        Ok(document)
    }

    pub fn encrypt(
        mut self,
        passphrase: SecretString,
        request_recovery_identity: bool,
    ) -> Result<PendingVault, Box<ErrorEnvelope>> {
        validate_passphrase(&passphrase)?;
        self.validate_and_normalize()?;
        let plaintext = self.canonical_plaintext()?;
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        let recovery_identity = identity.to_string();

        let vault_payload = encrypt_to_recipient(&recipient, &plaintext)?;
        let passphrase_identity =
            encrypt_with_passphrase(passphrase, recovery_identity.expose_secret().as_bytes())?;
        let envelope = VaultEnvelope {
            format_version: VAULT_FORMAT_VERSION,
            passphrase_identity,
            vault: vault_payload,
        };
        let encrypted = EncryptedVault {
            bytes: canonicalize(&envelope)?.into_bytes(),
        };
        encrypted.validate()?;

        let recovery = request_recovery_identity.then(|| RecoveryMaterial {
            identity: recovery_identity,
            recipient: recipient.to_string(),
        });

        Ok(PendingVault {
            encrypted,
            recovery,
            recovery_acknowledged: false,
            recovery_requested: request_recovery_identity,
            recovery_revealed: false,
        })
    }

    fn validate_and_normalize(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        if self.format_version != VAULT_FORMAT_VERSION {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::UnsupportedVersion,
                "Secret vault format version is unsupported",
            )));
        }
        if self.records.is_empty() {
            return Err(vault_required("At least one approved secret is required"));
        }
        if self.records.len() > MAX_RECORDS {
            return Err(security_error("vault contains too many secret records"));
        }
        for record in &self.records {
            record.validate()?;
        }
        self.records.sort_by(|left, right| left.id.cmp(&right.id));
        if self.records.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(schema_error("vault contains duplicate secret IDs"));
        }
        let total = self.records.iter().try_fold(0usize, |total, record| {
            total
                .checked_add(record.value.len())
                .ok_or_else(|| security_error("vault secret byte total overflow"))
        })?;
        if total > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(security_error(
                "vault secrets exceed the configured plaintext size limit",
            ));
        }
        Ok(())
    }

    fn canonical_plaintext(&self) -> Result<Zeroizing<Vec<u8>>, Box<ErrorEnvelope>> {
        let records = self.records.iter().map(SecretRecordWire::from).collect();
        let wire = VaultDocumentWire {
            format_version: self.format_version,
            records,
        };
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *bytes, &wire)
            .map_err(|_| vault_error("Unable to serialize the secret vault"))?;
        if bytes.len() > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(security_error(
                "vault exceeds the configured plaintext size limit",
            ));
        }
        Ok(bytes)
    }

    fn from_plaintext(plaintext: &[u8]) -> Result<Self, Box<ErrorEnvelope>> {
        let wire: VaultDocumentWireOwned = serde_json::from_slice(plaintext)
            .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
        if wire.format_version != VAULT_FORMAT_VERSION {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::UnsupportedVersion,
                "Secret vault format version is unsupported",
            )));
        }
        if wire.records.len() > MAX_RECORDS {
            return Err(security_error("vault contains too many secret records"));
        }

        let mut records = Vec::with_capacity(wire.records.len());
        for record in wire.records {
            records.push(SecretRecord::new(
                record.id,
                record.label,
                SecretKind::from_wire(record.kind.as_str())?,
                SecretTarget::from_wire(record.target)?,
                record.value,
            )?);
        }
        let document = Self::new(records)?;
        let canonical = document.canonical_plaintext()?;
        if canonical.as_slice() != plaintext {
            return Err(vault_error("Secret vault plaintext is not canonical"));
        }
        Ok(document)
    }
}

impl fmt::Debug for VaultDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultDocument")
            .field("format_version", &self.format_version)
            .field("records", &self.records)
            .finish()
    }
}

/// Read only the explicitly approved sources and build a canonical vault.
pub fn collect_approved_vault(
    selection: &SecretSelection,
    sources: &mut [&mut dyn SecretSource],
) -> Result<VaultDocument, Box<ErrorEnvelope>> {
    if selection.is_empty() {
        return Err(vault_required(
            "At least one secret must be explicitly approved",
        ));
    }
    if selection.len() > MAX_RECORDS {
        return Err(security_error(
            "secret selection exceeds the configured limit",
        ));
    }

    let mut indices = BTreeMap::new();
    for (index, source) in sources.iter().enumerate() {
        source.descriptor().validate()?;
        if indices
            .insert(source.descriptor().id.clone(), index)
            .is_some()
        {
            return Err(schema_error("secret sources contain a duplicate ID"));
        }
    }

    let mut records = Vec::with_capacity(selection.len());
    for id in selection.iter() {
        let Some(index) = indices.get(id).copied() else {
            return Err(vault_required("An approved secret source is unavailable"));
        };
        let source = &mut *sources[index];
        let descriptor = source.descriptor().clone();
        let secure_target_policy = source.secure_target_policy_proven();
        let value = source.read_secret().map_err(discard_source_error)?;
        let target = if matches!(
            descriptor.target,
            SecretTarget::EnvironmentVariable { .. } | SecretTarget::ConfigField { .. }
        ) && !secure_target_policy
        {
            SecretTarget::Manual
        } else {
            descriptor.target
        };
        records.push(SecretRecord::new(
            descriptor.id,
            descriptor.label,
            descriptor.kind,
            target,
            value,
        )?);
    }

    VaultDocument::new(records)
}

/// One-time recovery material. Its custom `Debug` never exposes the identity.
pub struct RecoveryMaterial {
    identity: SecretString,
    recipient: String,
}

impl RecoveryMaterial {
    pub fn identity(&self) -> &SecretString {
        &self.identity
    }

    pub fn recipient(&self) -> &str {
        &self.recipient
    }
}

impl fmt::Debug for RecoveryMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryMaterial")
            .field("identity", &"[REDACTED]")
            .field("recipient", &self.recipient)
            .finish()
    }
}

/// Enforces one-time reveal and acknowledgement before an encrypted vault can
/// be handed to the package writer.
pub struct PendingVault {
    encrypted: EncryptedVault,
    recovery: Option<RecoveryMaterial>,
    recovery_acknowledged: bool,
    recovery_requested: bool,
    recovery_revealed: bool,
}

impl PendingVault {
    pub fn take_recovery_identity(
        &mut self,
    ) -> Result<Option<RecoveryMaterial>, Box<ErrorEnvelope>> {
        if !self.recovery_requested {
            return Ok(None);
        }
        if self.recovery_revealed {
            return Err(user_action_error(
                "Recovery identity can only be displayed once",
            ));
        }
        self.recovery_revealed = true;
        self.recovery.take().map(Some).ok_or_else(|| {
            user_action_error("Recovery identity is no longer available for display")
        })
    }

    pub fn acknowledge_recovery_saved(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        if !self.recovery_requested {
            return Ok(());
        }
        if !self.recovery_revealed {
            return Err(user_action_error(
                "Display the recovery identity before acknowledging it",
            ));
        }
        self.recovery_acknowledged = true;
        Ok(())
    }

    pub fn finish(&self) -> Result<EncryptedVault, Box<ErrorEnvelope>> {
        if self.recovery_requested && !self.recovery_acknowledged {
            return Err(user_action_error(
                "Save and acknowledge the recovery identity before writing the package",
            ));
        }
        Ok(self.encrypted.clone())
    }
}

impl fmt::Debug for PendingVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingVault")
            .field("encrypted", &self.encrypted)
            .field("recovery_acknowledged", &self.recovery_acknowledged)
            .field("recovery_requested", &self.recovery_requested)
            .field("recovery_revealed", &self.recovery_revealed)
            .finish()
    }
}

/// Canonical package entry containing two standard armored age v1 payloads.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedVault {
    bytes: Vec<u8>,
}

impl EncryptedVault {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Box<ErrorEnvelope>> {
        let encrypted = Self { bytes };
        encrypted.validate()?;
        Ok(encrypted)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn decrypt_with_passphrase(
        &self,
        passphrase: SecretString,
    ) -> Result<VaultDocument, Box<ErrorEnvelope>> {
        validate_passphrase(&passphrase)?;
        let envelope = self.envelope()?;
        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(MAX_SCRYPT_WORK_FACTOR);
        let identity_plaintext = decrypt_age(
            envelope.passphrase_identity.as_bytes(),
            &identity,
            true,
            MAX_RECOVERY_IDENTITY_BYTES,
        )?;
        let identity_text = std::str::from_utf8(&identity_plaintext)
            .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
        let recovery_identity = x25519::Identity::from_str(identity_text)
            .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
        let plaintext = decrypt_age(
            envelope.vault.as_bytes(),
            &recovery_identity,
            false,
            MAX_VAULT_PLAINTEXT_BYTES,
        )?;
        VaultDocument::from_plaintext(&plaintext)
    }

    pub fn decrypt_with_recovery_identity(
        &self,
        identity: &SecretString,
    ) -> Result<VaultDocument, Box<ErrorEnvelope>> {
        if identity.expose_secret().len() > MAX_RECOVERY_IDENTITY_BYTES {
            return Err(vault_error("Unable to decrypt the secret vault"));
        }
        let recovery_identity = x25519::Identity::from_str(identity.expose_secret())
            .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
        let envelope = self.envelope()?;
        let plaintext = decrypt_age(
            envelope.vault.as_bytes(),
            &recovery_identity,
            false,
            MAX_VAULT_PLAINTEXT_BYTES,
        )?;
        VaultDocument::from_plaintext(&plaintext)
    }

    fn validate(&self) -> Result<(), Box<ErrorEnvelope>> {
        self.envelope().map(|_| ())
    }

    fn envelope(&self) -> Result<VaultEnvelope, Box<ErrorEnvelope>> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_ENCRYPTED_VAULT_BYTES {
            return Err(vault_error("Encrypted vault size is invalid"));
        }
        let envelope: VaultEnvelope = serde_json::from_slice(&self.bytes)
            .map_err(|_| vault_error("Encrypted vault envelope is invalid"))?;
        if envelope.format_version != VAULT_FORMAT_VERSION {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::UnsupportedVersion,
                "Secret vault format version is unsupported",
            )));
        }
        let canonical = canonicalize(&envelope)
            .map_err(|_| vault_error("Encrypted vault envelope is invalid"))?;
        if canonical.as_bytes() != self.bytes {
            return Err(vault_error("Encrypted vault envelope is not canonical"));
        }
        validate_age_payload(&envelope.passphrase_identity, true)?;
        validate_age_payload(&envelope.vault, false)?;
        Ok(envelope)
    }
}

impl fmt::Debug for EncryptedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedVault")
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope {
    format_version: u16,
    passphrase_identity: String,
    vault: String,
}

#[derive(Serialize)]
struct VaultDocumentWire<'a> {
    format_version: u16,
    records: Vec<SecretRecordWire<'a>>,
}

#[derive(Serialize)]
struct SecretRecordWire<'a> {
    id: &'a ComponentId,
    kind: &'static str,
    label: &'a str,
    target: SecretTargetWire<'a>,
    value: &'a [u8],
}

impl<'a> From<&'a SecretRecord> for SecretRecordWire<'a> {
    fn from(record: &'a SecretRecord) -> Self {
        Self {
            id: &record.id,
            kind: record.kind.as_wire(),
            label: &record.label,
            target: SecretTargetWire::from(&record.target),
            value: &record.value,
        }
    }
}

#[derive(Serialize)]
struct SecretTargetWire<'a> {
    application: Option<&'a str>,
    destination_relative: Option<&'a str>,
    destination_root: Option<KnownFolderWire<'a>>,
    name: Option<&'a str>,
    target_type: &'static str,
}

impl<'a> From<&'a SecretTarget> for SecretTargetWire<'a> {
    fn from(target: &'a SecretTarget) -> Self {
        match target {
            SecretTarget::WindowsCredentialManager => Self::empty("WINDOWS_CREDENTIAL_MANAGER"),
            SecretTarget::ApplicationKeyring { application } => Self {
                application: Some(application),
                ..Self::empty("APPLICATION_KEYRING")
            },
            SecretTarget::EnvironmentVariable { name } => Self {
                name: Some(name),
                ..Self::empty("ENVIRONMENT_VARIABLE")
            },
            SecretTarget::ConfigField { destination } => Self {
                destination_relative: Some(&destination.relative),
                destination_root: Some(KnownFolderWire::from(&destination.root)),
                ..Self::empty("CONFIG_FIELD")
            },
            SecretTarget::Manual => Self::empty("MANUAL"),
        }
    }
}

impl<'a> SecretTargetWire<'a> {
    fn empty(target_type: &'static str) -> Self {
        Self {
            application: None,
            destination_relative: None,
            destination_root: None,
            name: None,
            target_type,
        }
    }
}

#[derive(Serialize)]
struct KnownFolderWire<'a> {
    id: Option<&'a str>,
    root_type: &'static str,
}

impl<'a> From<&'a KnownFolderToken> for KnownFolderWire<'a> {
    fn from(root: &'a KnownFolderToken) -> Self {
        match root {
            KnownFolderToken::UserProfile => Self::plain("USER_PROFILE"),
            KnownFolderToken::RoamingAppData => Self::plain("ROAMING_APP_DATA"),
            KnownFolderToken::LocalAppData => Self::plain("LOCAL_APP_DATA"),
            KnownFolderToken::ProgramData => Self::plain("PROGRAM_DATA"),
            KnownFolderToken::ProgramFiles => Self::plain("PROGRAM_FILES"),
            KnownFolderToken::ProgramFilesX86 => Self::plain("PROGRAM_FILES_X86"),
            KnownFolderToken::StartMenu => Self::plain("START_MENU"),
            KnownFolderToken::Desktop => Self::plain("DESKTOP"),
            KnownFolderToken::Startup => Self::plain("STARTUP"),
            KnownFolderToken::Documents => Self::plain("DOCUMENTS"),
            KnownFolderToken::UserSelected { id } => Self {
                id: Some(id),
                root_type: "USER_SELECTED",
            },
        }
    }
}

impl KnownFolderWire<'_> {
    fn plain(root_type: &'static str) -> Self {
        Self {
            id: None,
            root_type,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultDocumentWireOwned {
    format_version: u16,
    records: Vec<SecretRecordWireOwned>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRecordWireOwned {
    id: ComponentId,
    kind: String,
    label: String,
    target: SecretTargetWireOwned,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretTargetWireOwned {
    application: Option<String>,
    destination_relative: Option<String>,
    destination_root: Option<KnownFolderWireOwned>,
    name: Option<String>,
    target_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownFolderWireOwned {
    id: Option<String>,
    root_type: String,
}

impl SecretKind {
    fn as_wire(self) -> &'static str {
        match self {
            Self::ApiToken => "API_TOKEN",
            Self::Password => "PASSWORD",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::Credential => "CREDENTIAL",
            Self::Opaque => "OPAQUE",
        }
    }

    fn from_wire(value: &str) -> Result<Self, Box<ErrorEnvelope>> {
        match value {
            "API_TOKEN" => Ok(Self::ApiToken),
            "PASSWORD" => Ok(Self::Password),
            "PRIVATE_KEY" => Ok(Self::PrivateKey),
            "CREDENTIAL" => Ok(Self::Credential),
            "OPAQUE" => Ok(Self::Opaque),
            _ => Err(vault_error("Secret vault contains an unknown secret kind")),
        }
    }
}

impl SecretTarget {
    fn from_wire(wire: SecretTargetWireOwned) -> Result<Self, Box<ErrorEnvelope>> {
        let SecretTargetWireOwned {
            application,
            destination_relative,
            destination_root,
            name,
            target_type,
        } = wire;
        match target_type.as_str() {
            "WINDOWS_CREDENTIAL_MANAGER"
                if application.is_none()
                    && destination_relative.is_none()
                    && destination_root.is_none()
                    && name.is_none() =>
            {
                Ok(Self::WindowsCredentialManager)
            }
            "APPLICATION_KEYRING"
                if application.is_some()
                    && destination_relative.is_none()
                    && destination_root.is_none()
                    && name.is_none() =>
            {
                Ok(Self::ApplicationKeyring {
                    application: application.expect("guarded by is_some"),
                })
            }
            "ENVIRONMENT_VARIABLE"
                if application.is_none()
                    && destination_relative.is_none()
                    && destination_root.is_none()
                    && name.is_some() =>
            {
                Ok(Self::EnvironmentVariable {
                    name: name.expect("guarded by is_some"),
                })
            }
            "CONFIG_FIELD"
                if application.is_none()
                    && destination_relative.is_some()
                    && destination_root.is_some()
                    && name.is_none() =>
            {
                let root = known_folder_from_wire(destination_root.expect("guarded by is_some"))?;
                let destination =
                    PathToken::new(root, destination_relative.expect("guarded by is_some"))
                        .map_err(|_| vault_error("Secret vault contains an invalid target path"))?;
                Ok(Self::ConfigField { destination })
            }
            "MANUAL"
                if application.is_none()
                    && destination_relative.is_none()
                    && destination_root.is_none()
                    && name.is_none() =>
            {
                Ok(Self::Manual)
            }
            _ => Err(vault_error("Secret vault contains an invalid target")),
        }
    }
}

fn known_folder_from_wire(
    wire: KnownFolderWireOwned,
) -> Result<KnownFolderToken, Box<ErrorEnvelope>> {
    match (wire.root_type.as_str(), wire.id) {
        ("USER_PROFILE", None) => Ok(KnownFolderToken::UserProfile),
        ("ROAMING_APP_DATA", None) => Ok(KnownFolderToken::RoamingAppData),
        ("LOCAL_APP_DATA", None) => Ok(KnownFolderToken::LocalAppData),
        ("PROGRAM_DATA", None) => Ok(KnownFolderToken::ProgramData),
        ("PROGRAM_FILES", None) => Ok(KnownFolderToken::ProgramFiles),
        ("PROGRAM_FILES_X86", None) => Ok(KnownFolderToken::ProgramFilesX86),
        ("START_MENU", None) => Ok(KnownFolderToken::StartMenu),
        ("DESKTOP", None) => Ok(KnownFolderToken::Desktop),
        ("DOCUMENTS", None) => Ok(KnownFolderToken::Documents),
        ("STARTUP", None) => Ok(KnownFolderToken::Startup),
        ("USER_SELECTED", Some(id)) => {
            validate_metadata_text("user-selected root ID", &id)?;
            Ok(KnownFolderToken::UserSelected { id })
        }
        _ => Err(vault_error("Secret vault contains an invalid target root")),
    }
}

fn encrypt_to_recipient(
    recipient: &x25519::Recipient,
    plaintext: &[u8],
) -> Result<String, Box<ErrorEnvelope>> {
    let encryptor = Encryptor::with_recipients(iter::once(recipient as &dyn age::Recipient))
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    encrypt_armored(encryptor, plaintext)
}

fn encrypt_with_passphrase(
    passphrase: SecretString,
    plaintext: &[u8],
) -> Result<String, Box<ErrorEnvelope>> {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(VAULT_SCRYPT_WORK_FACTOR);
    let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    encrypt_armored(encryptor, plaintext)
}

fn encrypt_armored(encryptor: Encryptor, plaintext: &[u8]) -> Result<String, Box<ErrorEnvelope>> {
    let mut encrypted = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor)
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    writer
        .write_all(plaintext)
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    writer
        .finish()
        .and_then(ArmoredWriter::finish)
        .map_err(|_| vault_error("Unable to encrypt the secret vault"))?;
    String::from_utf8(encrypted).map_err(|_| vault_error("Unable to encrypt the secret vault"))
}

fn decrypt_age(
    ciphertext: &[u8],
    identity: &dyn age::Identity,
    expected_scrypt: bool,
    max_plaintext_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, Box<ErrorEnvelope>> {
    let decryptor = Decryptor::new(ArmoredReader::new(Cursor::new(ciphertext)))
        .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
    if decryptor.is_scrypt() != expected_scrypt {
        return Err(vault_error("Unable to decrypt the secret vault"));
    }
    let reader = decryptor
        .decrypt(iter::once(identity))
        .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
    let limit = u64::try_from(max_plaintext_bytes)
        .expect("vault plaintext limits fit in u64")
        .saturating_add(1);
    let mut bounded = reader.take(limit);
    let mut plaintext = Zeroizing::new(Vec::new());
    bounded
        .read_to_end(&mut plaintext)
        .map_err(|_| vault_error("Unable to decrypt the secret vault"))?;
    if plaintext.len() > max_plaintext_bytes {
        return Err(vault_error("Unable to decrypt the secret vault"));
    }
    Ok(plaintext)
}

fn validate_age_payload(payload: &str, expected_scrypt: bool) -> Result<(), Box<ErrorEnvelope>> {
    let Some(after_begin) = payload.strip_prefix(AGE_ARMOR_BEGIN) else {
        return Err(vault_error(
            "Encrypted vault payload is not armored age data",
        ));
    };
    let has_line_ending = after_begin.starts_with('\n') || after_begin.starts_with("\r\n");
    let trimmed_end = payload.trim_end_matches(['\r', '\n']);
    if !has_line_ending || !trimmed_end.ends_with(AGE_ARMOR_END) {
        return Err(vault_error(
            "Encrypted vault payload is not armored age data",
        ));
    }
    let decryptor = Decryptor::new(ArmoredReader::new(Cursor::new(payload.as_bytes())))
        .map_err(|_| vault_error("Encrypted vault payload is invalid"))?;
    if decryptor.is_scrypt() != expected_scrypt {
        return Err(vault_error(
            "Encrypted vault payload has an invalid recipient type",
        ));
    }
    Ok(())
}

fn validate_secret_value(value: &[u8]) -> Result<(), Box<ErrorEnvelope>> {
    if value.is_empty() {
        return Err(vault_required("Approved secret value is empty"));
    }
    if value.len() > MAX_SECRET_VALUE_BYTES {
        return Err(security_error(
            "secret value exceeds the configured size limit",
        ));
    }
    Ok(())
}

fn validate_passphrase(passphrase: &SecretString) -> Result<(), Box<ErrorEnvelope>> {
    let bytes = passphrase.expose_secret().as_bytes();
    if bytes.is_empty() {
        return Err(vault_required("Vault passphrase must not be empty"));
    }
    if bytes.len() > MAX_PASSPHRASE_BYTES {
        return Err(security_error(
            "vault passphrase exceeds the configured size limit",
        ));
    }
    Ok(())
}

fn validate_target(target: &SecretTarget) -> Result<(), Box<ErrorEnvelope>> {
    match target {
        SecretTarget::ApplicationKeyring { application } => {
            validate_metadata_text("application keyring name", application)
        }
        SecretTarget::EnvironmentVariable { name } => {
            validate_metadata_text("environment variable name", name)?;
            if name.contains('=') {
                return Err(schema_error("environment variable name contains '='"));
            }

            Ok(())
        }
        SecretTarget::ConfigField { destination } => destination
            .validate()
            .map_err(|_| schema_error("secret config target path is invalid")),
        SecretTarget::WindowsCredentialManager | SecretTarget::Manual => Ok(()),
    }
}
fn discard_source_error(mut error: Box<ErrorEnvelope>) -> Box<ErrorEnvelope> {
    error.message.zeroize();
    if let Some(detail) = &mut error.technical_detail {
        detail.zeroize();
    }
    if let Some(context_id) = &mut error.context_id {
        context_id.zeroize();
    }
    drop(error);
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::OperationFailed,
        "Unable to read an approved secret",
    ))
}

fn validate_metadata_text(label: &str, value: &str) -> Result<(), Box<ErrorEnvelope>> {
    if value.is_empty()
        || value.len() > MAX_METADATA_TEXT_BYTES
        || value.chars().any(|character| {
            character == '\0' || character == '\r' || character == '\n' || character.is_control()
        })
    {
        return Err(schema_error(&format!("{label} is invalid")));
    }
    Ok(())
}

fn vault_required(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::VaultRequired, message))
}

fn vault_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::VaultDecryptFailed,
        message,
    ))
}

fn user_action_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::UserActionRequired,
        message,
    ))
}

fn schema_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::SchemaInvalid, message))
}

fn security_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::SecurityPolicy,
        message,
    ))
}
