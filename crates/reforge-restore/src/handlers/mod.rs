//! Safe restore handlers for files, supported configuration, and user env.
//!
//! The handlers receive typed operations only.  Package objects are copied
//! through the verified object-source boundary, destinations are resolved from
//! the current known-folder map, and all durable file changes use the platform
//! atomic replacement primitive.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{ExecutionContext, OperationOutcome, RestoreResult, restore_error};
use reforge_domain::{
    ContentType, ErrorEnvelope, KnownFolderToken, ObjectEntry, ObjectId, ObjectIndex,
    ReforgeErrorCode, TokenizedPath,
};
use reforge_platform_windows::{
    AtomicReplaceResult, AtomicWriteSpec, BoundedFileReader, FileAttributes, KnownFolderMap,
    SafePath, atomic_replace,
};
use serde_json::{Value, json};

static NEXT_SUBSYSTEM_TEMP_ID: AtomicU64 = AtomicU64::new(1);

pub mod browsers;
pub mod config;
pub mod docker;
pub mod environment;
pub mod files;
pub mod harnesses;
pub mod providers;
pub mod vscode;
pub mod wsl;

pub use browsers::{BrowserAwareRestoreHandler, BrowserRestoreHandler, default_browser_operation};
pub use config::ConfigRestoreHandler;
pub use docker::DockerRestoreHandler;
pub use environment::{
    EnvironmentRestoreHandler, MemoryUserEnvironment, RegistryUserEnvironment,
    UserEnvironmentBackend,
};
pub use files::FileRestoreHandler;
pub use harnesses::HarnessRestoreHandler;
pub use providers::{ProviderInstallHandler, ProviderProcessBridge, ProviderRestoreHandler};
pub use vscode::VsCodeRestoreHandler;
pub use wsl::WslRestoreHandler;
/// Maximum object size accepted by a generic file/config handler.
///
/// Larger artifacts must use a dedicated, bounded subsystem handler rather
/// than making one restore operation allocate an unbounded buffer.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum archive size accepted by the WSL and Docker handlers.
///
/// Subsystem exports are streamed to disk, but still need an explicit bound
/// before a provider process is allowed to consume them.
pub(crate) const MAX_SUBSYSTEM_OBJECT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

fn subsystem_error(code: ReforgeErrorCode, message: &'static str) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, Some("subsystem-object"))
}

/// Verified subsystem archive staged in a uniquely-created temporary file.
/// The file is removed when the handler finishes, including error paths.
pub(crate) struct StagedSubsystemObject {
    pub(crate) path: PathBuf,
}
impl Drop for StagedSubsystemObject {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Copy one indexed object through the verified source boundary without
/// buffering the object in memory.
pub(crate) fn stage_subsystem_object(
    context: &ExecutionContext<'_>,
    object: &ObjectId,
    expected_type: ContentType,
) -> RestoreResult<StagedSubsystemObject> {
    let entry = object_entry(context.object_index, object)?;
    if entry.content_type != expected_type {
        return Err(subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The subsystem artifact has an unexpected content type",
        ));
    }
    if entry.uncompressed_bytes == 0 || entry.uncompressed_bytes > MAX_SUBSYSTEM_OBJECT_BYTES {
        return Err(subsystem_error(
            ReforgeErrorCode::SecurityPolicy,
            "The subsystem artifact exceeds the reviewed restore size policy",
        ));
    }
    let source = context.object_source.ok_or_else(|| {
        subsystem_error(
            ReforgeErrorCode::SourceUnavailable,
            "verified package object access is unavailable",
        )
    })?;

    let (path, file) = create_subsystem_temp_file()?;
    let mut writer = HashingFile::new(file, MAX_SUBSYSTEM_OBJECT_BYTES);
    let copied = match source.copy_verified_object(object, &mut writer) {
        Ok(copied) => copied,
        Err(error) => {
            drop(writer);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
    };
    writer.file.sync_all().map_err(|error| {
        let _ = fs::remove_file(&path);
        io_error("sync the staged subsystem artifact", &error)
    })?;
    let (bytes, digest) = writer.finish();
    if copied != entry || bytes != entry.uncompressed_bytes {
        let _ = fs::remove_file(&path);
        return Err(subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The staged subsystem artifact metadata does not match the object index",
        ));
    }
    let actual_id = ObjectId::new(format!("obj_{}", digest.to_hex())).map_err(|_| {
        let _ = fs::remove_file(&path);
        subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The staged subsystem artifact produced an invalid content identity",
        )
    })?;
    if actual_id != *object {
        let _ = fs::remove_file(&path);
        return Err(subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The staged subsystem artifact content does not match its object identity",
        ));
    }

    Ok(StagedSubsystemObject { path })
}

fn create_subsystem_temp_file() -> RestoreResult<(PathBuf, File)> {
    let directory = std::env::temp_dir();
    if !directory.is_absolute() {
        return Err(subsystem_error(
            ReforgeErrorCode::SecurityPolicy,
            "The system temporary directory is not absolute",
        ));
    }
    for _ in 0..32 {
        let id = NEXT_SUBSYSTEM_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("reforge-subsystem-{id}.archive"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(io_error("create the staged subsystem artifact", &error));
            }
        }
    }
    Err(subsystem_error(
        ReforgeErrorCode::TargetConflict,
        "Could not allocate a unique temporary subsystem artifact path",
    ))
}

struct HashingFile {
    file: File,
    hasher: blake3::Hasher,
    bytes: u64,
    max_bytes: u64,
}

impl HashingFile {
    fn new(file: File, max_bytes: u64) -> Self {
        Self {
            file,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn finish(self) -> (u64, blake3::Hash) {
        (self.bytes, self.hasher.finalize())
    }
}

impl Write for HashingFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "write length overflow"))?;
        let next = self
            .bytes
            .checked_add(requested)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact size overflow"))?;
        if next > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "subsystem artifact exceeds the reviewed restore size policy",
            ));
        }
        let written = self.file.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.bytes = self
            .bytes
            .checked_add(
                u64::try_from(written).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "write length overflow")
                })?,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact size overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Return a manual-action outcome when the target cannot prove enough free
/// space for staging, provider writes, and the operational reserve.
pub(crate) fn subsystem_capacity_waiting(
    context: &ExecutionContext<'_>,
    object: &ObjectId,
    subsystem: &str,
) -> Option<OperationOutcome> {
    let required = context
        .object_index
        .objects
        .iter()
        .find(|entry| &entry.id == object)
        .map(|entry| entry.uncompressed_bytes)?;
    let available = context
        .target
        .host
        .free_bytes
        .iter()
        .map(|space| space.bytes)
        .max();
    let Some(recommended) = crate::compatibility::recommended_free_bytes(required) else {
        return Some(OperationOutcome::waiting_for_user(Some(json!({
            "subsystem": subsystem,
            "manual_action_required": true,
            "reason": "target free space reserve could not be calculated safely",
            "required_bytes": required,
            "available_bytes": available,
        }))));
    };
    if available.is_none_or(|available| available < recommended) {
        Some(OperationOutcome::waiting_for_user(Some(json!({
            "subsystem": subsystem,
            "manual_action_required": true,
            "reason": "target free space is unknown or below the restore reserve",
            "required_bytes": required,
            "available_bytes": available,
        }))))
    } else {
        None
    }
}

/// A token resolved against the current target without exposing the absolute
/// path outside the handler implementation.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedDestination {
    pub(crate) root: PathBuf,
    pub(crate) relative: SafePath,
    pub(crate) absolute: PathBuf,
}

pub(crate) fn resolve_destination(
    roots: &KnownFolderMap,
    token: &TokenizedPath,
) -> RestoreResult<ResolvedDestination> {
    let relative = SafePath::from_token(token)?;
    let root = roots.entries.get(&token.root).cloned().ok_or_else(|| {
        restore_error(
            ReforgeErrorCode::PathNotFound,
            "the requested known-folder root is unavailable on this target",
            None,
            None,
            None,
            Some("restore-known-folder"),
        )
    })?;
    let absolute = roots.resolve(token)?;
    Ok(ResolvedDestination {
        root,
        relative,
        absolute,
    })
}

pub(crate) fn reject_protected_root(token: &TokenizedPath) -> RestoreResult<()> {
    if matches!(
        token.root,
        KnownFolderToken::ProgramData
            | KnownFolderToken::ProgramFiles
            | KnownFolderToken::ProgramFilesX86
    ) {
        return Err(restore_error(
            ReforgeErrorCode::SecurityPolicy,
            "generic restore handlers cannot write a protected managed root",
            None,
            None,
            None,
            Some("restore-protected-root"),
        ));
    }
    Ok(())
}

pub(crate) fn object_entry(
    object_index: &ObjectIndex,
    object: &ObjectId,
) -> RestoreResult<ObjectEntry> {
    object_index
        .objects
        .iter()
        .find(|entry| &entry.id == object)
        .cloned()
        .ok_or_else(|| {
            restore_error(
                ReforgeErrorCode::PackageNotFound,
                "the requested restore object is absent from the package index",
                None,
                None,
                None,
                Some("restore-object-index"),
            )
        })
}

/// Copy one indexed object into a bounded buffer and independently verify its
/// content-addressed identity.  A malicious ObjectSource cannot make this
/// helper grow beyond the configured limit or substitute a different object.
pub(crate) fn read_verified_object(
    context: &ExecutionContext<'_>,
    object: &ObjectId,
    max_bytes: u64,
) -> RestoreResult<(ObjectEntry, Vec<u8>)> {
    let expected = object_entry(context.object_index, object)?;
    if expected.uncompressed_bytes > max_bytes {
        return Err(restore_error(
            ReforgeErrorCode::SecurityPolicy,
            "restore object exceeds the handler size limit",
            None,
            None,
            None,
            Some("restore-object-limit"),
        ));
    }
    let source = context.object_source.ok_or_else(|| {
        restore_error(
            ReforgeErrorCode::SourceUnavailable,
            "verified package object access is unavailable",
            None,
            None,
            None,
            Some("restore-object-source"),
        )
    })?;
    let capacity = usize::try_from(expected.uncompressed_bytes).map_err(|_| {
        restore_error(
            ReforgeErrorCode::SecurityPolicy,
            "restore object length cannot be represented locally",
            None,
            None,
            None,
            Some("restore-object-length"),
        )
    })?;
    let mut output = LimitedBuffer::new(capacity, max_bytes);
    let returned = source.copy_verified_object(object, &mut output)?;
    if returned != expected || returned.id != *object {
        return Err(restore_error(
            ReforgeErrorCode::PackageCorrupt,
            "verified package object metadata does not match the plan",
            None,
            None,
            None,
            Some("restore-object-metadata"),
        ));
    }
    let bytes = output.into_inner();
    if bytes.len() as u64 != expected.uncompressed_bytes
        || ObjectId::from_content(&bytes) != *object
    {
        return Err(restore_error(
            ReforgeErrorCode::PackageCorrupt,
            "verified package object bytes do not match the requested identity",
            None,
            None,
            None,
            Some("restore-object-hash"),
        ));
    }
    Ok((expected, bytes))
}

pub(crate) fn read_existing_file(
    destination: &ResolvedDestination,
    max_bytes: u64,
) -> RestoreResult<Option<(Vec<u8>, Metadata)>> {
    let metadata = match fs::symlink_metadata(&destination.absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("inspect restore destination", &error)),
    };
    if !metadata.is_file() {
        return Err(restore_error(
            ReforgeErrorCode::TargetConflict,
            "restore destination is not a regular file",
            None,
            None,
            None,
            Some("restore-destination-type"),
        ));
    }
    let mut reader = BoundedFileReader::open(&destination.root, &destination.relative, max_bytes)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        restore_error(
            ReforgeErrorCode::SecurityPolicy,
            "target file length cannot be represented locally",
            None,
            None,
            None,
            Some("restore-target-length"),
        )
    })?;
    let mut bytes = LimitedBuffer::new(capacity, max_bytes);
    reader.stream_into(&mut bytes)?;
    Ok(Some((bytes.into_inner(), metadata)))
}

pub(crate) fn target_attributes(metadata: Option<&Metadata>) -> FileAttributes {
    metadata
        .map(FileAttributes::from_metadata)
        .unwrap_or_default()
}

pub(crate) fn atomic_write(
    destination: &ResolvedDestination,
    bytes: &[u8],
    attributes: FileAttributes,
    object: &ObjectId,
) -> RestoreResult<AtomicReplaceResult> {
    let digest = *blake3::hash(bytes).as_bytes();
    if ObjectId::from_content(bytes) != *object {
        return Err(restore_error(
            ReforgeErrorCode::PackageCorrupt,
            "restore bytes do not match the requested object identity",
            None,
            None,
            None,
            Some("restore-write-hash"),
        ));
    }
    atomic_replace(
        &destination.root,
        &destination.relative,
        io::Cursor::new(bytes),
        AtomicWriteSpec {
            expected_bytes: bytes.len() as u64,
            expected_blake3: digest,
            attributes,
        },
    )
}

pub(crate) fn verified_evidence(destination: &str, bytes: u64, digest: [u8; 32]) -> Value {
    json!({
        "destination": destination,
        "bytes": bytes,
        "blake3": blake3::Hash::from_bytes(digest).to_hex().to_string(),
    })
}

pub(crate) fn content_type_allowed(
    entry: &ObjectEntry,
    expected: impl IntoIterator<Item = ContentType>,
) -> RestoreResult<()> {
    if expected.into_iter().any(|kind| kind == entry.content_type) {
        Ok(())
    } else {
        Err(restore_error(
            ReforgeErrorCode::SchemaInvalid,
            "restore operation content type does not match its handler",
            None,
            None,
            None,
            Some("restore-content-type"),
        ))
    }
}

pub(crate) fn io_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    let mut envelope = ErrorEnvelope::from_io_error(error, operation);
    envelope.context_id = Some("restore-filesystem".to_owned());
    Box::new(envelope)
}

pub(crate) fn operation_error(
    code: ReforgeErrorCode,
    message: impl Into<String>,
) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, Some("restore-handler"))
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    max_bytes: u64,
}

impl LimitedBuffer {
    fn new(capacity: usize, max_bytes: u64) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            max_bytes,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let current = self.bytes.len() as u64;
        let requested = bytes.len() as u64;
        let end = current
            .checked_add(requested)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "buffer length overflow"))?;
        if end > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "restore buffer limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
