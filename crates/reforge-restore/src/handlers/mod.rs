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
    ContentType, ErrorEnvelope, FileManifest, KnownFolderToken, ObjectEntry, ObjectId, ObjectIndex,
    ReforgeErrorCode, TokenizedPath,
};
use reforge_package::{FILE_CHUNK_BYTES, canonicalize};
use reforge_platform_windows::{
    AtomicReplaceResult, AtomicWriteSpec, BoundedFileReader, CancellationToken, FileAttributes,
    KnownFolderMap, SafePath, atomic_replace,
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

/// Reconstruct one inspected artifact into a temporary file without buffering
/// the complete payload in memory.
pub(crate) fn stage_subsystem_artifact(
    context: &ExecutionContext<'_>,
    object: &ObjectId,
    expected_type: ContentType,
    cancellation: &CancellationToken,
) -> RestoreResult<Option<StagedSubsystemObject>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let artifact = validate_artifact(context, object, MAX_SUBSYSTEM_OBJECT_BYTES)?;
    if artifact.content_type() != &expected_type {
        return Err(subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The subsystem artifact has an unexpected content type",
        ));
    }
    if artifact.size_bytes() == 0 {
        return Err(subsystem_error(
            ReforgeErrorCode::SecurityPolicy,
            "The subsystem artifact exceeds the reviewed restore size policy",
        ));
    }

    let (path, file) = create_subsystem_temp_file()?;
    let mut writer = HashingFile::new(file, MAX_SUBSYSTEM_OBJECT_BYTES);
    let copied = match copy_validated_artifact(context, &artifact, &mut writer, Some(cancellation))
    {
        Ok(Some(copied)) => copied,
        Ok(None) => {
            drop(writer);
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
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
    if copied.bytes != artifact.size_bytes()
        || bytes != artifact.size_bytes()
        || copied.digest != *digest.as_bytes()
    {
        let _ = fs::remove_file(&path);
        return Err(subsystem_error(
            ReforgeErrorCode::PackageCorrupt,
            "The staged subsystem artifact does not match its inspected file metadata",
        ));
    }

    Ok(Some(StagedSubsystemObject { path }))
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
) -> RestoreResult<Option<OperationOutcome>> {
    let required = validate_artifact(context, object, MAX_SUBSYSTEM_OBJECT_BYTES)?.size_bytes();
    let available = context
        .target
        .host
        .free_bytes
        .iter()
        .map(|space| space.bytes)
        .max();
    let Some(recommended) = crate::compatibility::recommended_free_bytes(required) else {
        return Ok(Some(OperationOutcome::waiting_for_user(Some(json!({
            "subsystem": subsystem,
            "manual_action_required": true,
            "reason": "target free space reserve could not be calculated safely",
            "required_bytes": required,
            "available_bytes": available,
        })))));
    };
    if available.is_none_or(|available| available < recommended) {
        Ok(Some(OperationOutcome::waiting_for_user(Some(json!({
            "subsystem": subsystem,
            "manual_action_required": true,
            "reason": "target free space is unknown or below the restore reserve",
            "required_bytes": required,
            "available_bytes": available,
        })))))
    } else {
        Ok(None)
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

fn artifact_error(code: ReforgeErrorCode, message: impl Into<String>) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, Some("restore-artifact"))
}

fn indexed_entry<'a>(
    object_index: &'a ObjectIndex,
    object: &ObjectId,
    missing_code: ReforgeErrorCode,
    missing_message: &'static str,
) -> RestoreResult<&'a ObjectEntry> {
    let mut matching = object_index
        .objects
        .iter()
        .filter(|entry| &entry.id == object);
    let entry = matching
        .next()
        .ok_or_else(|| artifact_error(missing_code, missing_message))?;
    if matching.next().is_some() {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "the package index contains a duplicate object identity",
        ));
    }
    Ok(entry)
}

enum ArtifactLayout<'a> {
    Direct(&'a ObjectEntry),
    Manifest(&'a FileManifest),
}

/// A package artifact reference whose manifest and indexed chunks agree.
pub(crate) struct ValidatedArtifact<'a> {
    layout: ArtifactLayout<'a>,
    size_bytes: u64,
    content_type: ContentType,
}

impl ValidatedArtifact<'_> {
    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub(crate) fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    pub(crate) fn matches_bytes(&self, bytes: &[u8]) -> bool {
        if bytes.len() as u64 != self.size_bytes {
            return false;
        }
        match &self.layout {
            ArtifactLayout::Direct(entry) => ObjectId::from_content(bytes) == entry.id,
            ArtifactLayout::Manifest(manifest) => {
                let mut offset = 0usize;
                for chunk in &manifest.chunks {
                    let Ok(length) = usize::try_from(chunk.uncompressed_bytes) else {
                        return false;
                    };
                    let Some(end) = offset.checked_add(length) else {
                        return false;
                    };
                    let Some(chunk_bytes) = bytes.get(offset..end) else {
                        return false;
                    };
                    if ObjectId::from_content(chunk_bytes) != chunk.id {
                        return false;
                    }
                    offset = end;
                }
                offset == bytes.len()
            }
        }
    }
}

/// Resolve an operation object as either a validated inspected file manifest
/// or the explicit direct-object API used by typed callers.
pub(crate) fn validate_artifact<'a>(
    context: &ExecutionContext<'a>,
    object: &ObjectId,
    max_bytes: u64,
) -> RestoreResult<ValidatedArtifact<'a>> {
    let reference_entry = indexed_entry(
        context.object_index,
        object,
        ReforgeErrorCode::PackageNotFound,
        "the requested restore object is absent from the package index",
    )?;
    let Some(manifest) = context
        .file_manifests
        .and_then(|manifests| manifests.get(object))
    else {
        if reference_entry.uncompressed_bytes > max_bytes {
            return Err(artifact_error(
                ReforgeErrorCode::SecurityPolicy,
                "restore object exceeds the handler size limit",
            ));
        }
        return Ok(ValidatedArtifact {
            layout: ArtifactLayout::Direct(reference_entry),
            size_bytes: reference_entry.uncompressed_bytes,
            content_type: reference_entry.content_type.clone(),
        });
    };

    if manifest.size_bytes > max_bytes {
        return Err(artifact_error(
            ReforgeErrorCode::SecurityPolicy,
            "restore artifact exceeds the handler size limit",
        ));
    }
    let chunk_bytes = FILE_CHUNK_BYTES as u64;
    let expected_chunks = if manifest.size_bytes == 0 {
        0
    } else {
        (manifest.size_bytes - 1) / chunk_bytes + 1
    };
    if manifest.chunks.len() as u64 != expected_chunks {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "file manifest chunk count does not match its declared size",
        ));
    }
    if reference_entry.content_type != ContentType::Json {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "file manifest object is not indexed as canonical JSON",
        ));
    }

    let mut total = 0u64;
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        if chunk.id == *object
            || context
                .file_manifests
                .is_some_and(|manifests| manifests.contains_key(&chunk.id))
        {
            return Err(artifact_error(
                ReforgeErrorCode::PackageCorrupt,
                "file manifest object is also referenced as a file chunk",
            ));
        }
        if chunk.uncompressed_bytes == 0 || chunk.uncompressed_bytes > chunk_bytes {
            return Err(artifact_error(
                ReforgeErrorCode::PackageCorrupt,
                "file manifest contains an invalid chunk length",
            ));
        }
        if index + 1 != manifest.chunks.len() && chunk.uncompressed_bytes != chunk_bytes {
            return Err(artifact_error(
                ReforgeErrorCode::PackageCorrupt,
                "non-final file chunk is not exactly 8 MiB",
            ));
        }
        let entry = indexed_entry(
            context.object_index,
            &chunk.id,
            ReforgeErrorCode::PackageCorrupt,
            "file manifest chunk is absent from the package index",
        )?;
        if entry.uncompressed_bytes != chunk.uncompressed_bytes
            || entry.content_type != manifest.content_type
        {
            return Err(artifact_error(
                ReforgeErrorCode::PackageCorrupt,
                "file manifest chunk metadata disagrees with the package index",
            ));
        }
        total = total.checked_add(chunk.uncompressed_bytes).ok_or_else(|| {
            artifact_error(
                ReforgeErrorCode::PackageCorrupt,
                "file manifest payload size overflow",
            )
        })?;
    }
    if total != manifest.size_bytes {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "file manifest chunks do not reconstruct its declared size",
        ));
    }

    let canonical = canonicalize(manifest).map_err(|_| {
        artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "file manifest cannot be encoded as canonical JSON",
        )
    })?;
    if canonical.object_id() != object
        || canonical.as_bytes().len() as u64 != reference_entry.uncompressed_bytes
    {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "file manifest bytes do not match their indexed identity",
        ));
    }

    Ok(ValidatedArtifact {
        layout: ArtifactLayout::Manifest(manifest),
        size_bytes: manifest.size_bytes,
        content_type: manifest.content_type.clone(),
    })
}

struct CopiedArtifact {
    bytes: u64,
    digest: [u8; 32],
}

fn copy_validated_artifact(
    context: &ExecutionContext<'_>,
    artifact: &ValidatedArtifact<'_>,
    output: &mut dyn Write,
    cancellation: Option<&CancellationToken>,
) -> RestoreResult<Option<CopiedArtifact>> {
    let source = context.object_source.ok_or_else(|| {
        artifact_error(
            ReforgeErrorCode::SourceUnavailable,
            "verified package object access is unavailable",
        )
    })?;
    if cancellation.is_some_and(|token| token.is_cancelled()) {
        return Ok(None);
    }
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    match &artifact.layout {
        ArtifactLayout::Direct(entry) => {
            let Some(copied) =
                copy_verified_indexed_object(source, entry, output, &mut hasher, cancellation)?
            else {
                return Ok(None);
            };
            bytes = copied;
        }
        ArtifactLayout::Manifest(manifest) => {
            for chunk in &manifest.chunks {
                if cancellation.is_some_and(|token| token.is_cancelled()) {
                    return Ok(None);
                }
                let entry = indexed_entry(
                    context.object_index,
                    &chunk.id,
                    ReforgeErrorCode::PackageCorrupt,
                    "file manifest chunk is absent from the package index",
                )?;
                let Some(copied) =
                    copy_verified_indexed_object(source, entry, output, &mut hasher, cancellation)?
                else {
                    return Ok(None);
                };
                bytes = bytes.checked_add(copied).ok_or_else(|| {
                    artifact_error(
                        ReforgeErrorCode::PackageCorrupt,
                        "restored artifact size overflow",
                    )
                })?;
            }
        }
    }
    if bytes != artifact.size_bytes {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "restored artifact bytes do not match the inspected file manifest",
        ));
    }
    Ok(Some(CopiedArtifact {
        bytes,
        digest: *hasher.finalize().as_bytes(),
    }))
}

fn copy_verified_indexed_object(
    source: &dyn crate::ObjectSource,
    expected: &ObjectEntry,
    output: &mut dyn Write,
    artifact_hasher: &mut blake3::Hasher,
    cancellation: Option<&CancellationToken>,
) -> RestoreResult<Option<u64>> {
    let mut writer = VerifyingObjectWriter::new(
        output,
        artifact_hasher,
        expected.uncompressed_bytes,
        cancellation,
    );
    let result = source.copy_verified_object(&expected.id, &mut writer);
    let limit_exceeded = writer.limit_exceeded;
    let cancelled = writer.cancelled;
    let (bytes, digest) = writer.finish();
    if cancelled {
        return Ok(None);
    }
    if limit_exceeded {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "verified package object expanded beyond its indexed length",
        ));
    }
    let returned = result?;
    let encoded = digest.to_hex();
    if returned != *expected
        || bytes != expected.uncompressed_bytes
        || expected.id.as_str().strip_prefix("obj_") != Some(encoded.as_str())
    {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "verified package object bytes or metadata do not match the package index",
        ));
    }
    Ok(Some(bytes))
}

/// Read one resolved artifact into memory while independently verifying every
/// direct object or manifest chunk copied by the package source.
pub(crate) fn read_verified_artifact(
    context: &ExecutionContext<'_>,
    object: &ObjectId,
    max_bytes: u64,
) -> RestoreResult<VerifiedArtifact> {
    let artifact = validate_artifact(context, object, max_bytes)?;
    let capacity = usize::try_from(artifact.size_bytes).map_err(|_| {
        artifact_error(
            ReforgeErrorCode::SecurityPolicy,
            "restore artifact length cannot be represented locally",
        )
    })?;
    let mut output = LimitedBuffer::new(capacity, max_bytes);
    let Some(copied) = copy_validated_artifact(context, &artifact, &mut output, None)? else {
        return Err(artifact_error(
            ReforgeErrorCode::OperationFailed,
            "artifact copy was cancelled without a cancellation boundary",
        ));
    };
    let bytes = output.into_inner();
    if bytes.len() as u64 != copied.bytes || *blake3::hash(&bytes).as_bytes() != copied.digest {
        return Err(artifact_error(
            ReforgeErrorCode::PackageCorrupt,
            "restored artifact payload failed final verification",
        ));
    }
    Ok(VerifiedArtifact {
        bytes,
        content_type: artifact.content_type,
        digest: copied.digest,
    })
}

pub(crate) struct VerifiedArtifact {
    bytes: Vec<u8>,
    content_type: ContentType,
    digest: [u8; 32],
}

impl VerifiedArtifact {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
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
    artifact: &VerifiedArtifact,
    attributes: FileAttributes,
) -> RestoreResult<AtomicReplaceResult> {
    atomic_replace(
        &destination.root,
        &destination.relative,
        io::Cursor::new(artifact.bytes()),
        AtomicWriteSpec {
            expected_bytes: artifact.bytes().len() as u64,
            expected_blake3: artifact.digest(),
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
    actual: &ContentType,
    expected: impl IntoIterator<Item = ContentType>,
) -> RestoreResult<()> {
    if expected.into_iter().any(|kind| &kind == actual) {
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

struct VerifyingObjectWriter<'a, 'c> {
    output: &'a mut dyn Write,
    artifact_hasher: &'a mut blake3::Hasher,
    object_hasher: blake3::Hasher,
    bytes: u64,
    expected_bytes: u64,
    cancellation: Option<&'c CancellationToken>,
    cancelled: bool,
    limit_exceeded: bool,
}

impl<'a, 'c> VerifyingObjectWriter<'a, 'c> {
    fn new(
        output: &'a mut dyn Write,
        artifact_hasher: &'a mut blake3::Hasher,
        expected_bytes: u64,
        cancellation: Option<&'c CancellationToken>,
    ) -> Self {
        Self {
            output,
            artifact_hasher,
            object_hasher: blake3::Hasher::new(),
            bytes: 0,
            expected_bytes,
            cancellation,
            cancelled: false,
            limit_exceeded: false,
        }
    }

    fn finish(self) -> (u64, blake3::Hash) {
        (self.bytes, self.object_hasher.finalize())
    }
}

impl Write for VerifyingObjectWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.cancellation.is_some_and(|token| token.is_cancelled()) {
            self.cancelled = true;
            return Err(io::Error::other("artifact reconstruction was cancelled"));
        }
        let requested = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "write length overflow"))?;
        let Some(end) = self.bytes.checked_add(requested) else {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object length overflow",
            ));
        };
        if end > self.expected_bytes {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object exceeds its indexed length",
            ));
        }
        let written = self.output.write(bytes)?;
        self.object_hasher.update(&bytes[..written]);
        self.artifact_hasher.update(&bytes[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
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
