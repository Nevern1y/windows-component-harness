//! Bounded, content-addressed storage for package objects and file chunks.
//!
//! Object bytes are hashed before they become visible at their final name.
//! Each staged zstd frame is decompressed and verified, then atomically linked
//! into the store. A failed file import may leave complete content-addressed
//! chunks for a later retry, but it never commits a manifest that references an
//! incomplete object.

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use reforge_domain::{
    ChunkRef, ContentType, ErrorEnvelope, FileManifest, ObjectEntry, ObjectId, ReforgeErrorCode,
};

use crate::{
    canonicalize,
    reader::{InspectedPackage, PackageReader},
};

/// Required uncompressed size of every non-final file chunk.
pub const FILE_CHUNK_BYTES: usize = 8 * 1024 * 1024;

const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1_099_511_627_776;
const ZSTD_COMPRESSION_LEVEL: i32 = 3;
const TEMP_NAME_ATTEMPTS: usize = 128;
const WINDOWS_REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

/// Explicit bounds for individual metadata objects and complete files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentStoreLimits {
    pub max_object_bytes: u64,
    pub max_file_bytes: u64,
}

impl ContentStoreLimits {
    /// Construct limits that can hold the mandatory fixed-size chunks.
    pub fn new(max_object_bytes: u64, max_file_bytes: u64) -> Result<Self, Box<ErrorEnvelope>> {
        if max_object_bytes < FILE_CHUNK_BYTES as u64 {
            return Err(security_error(
                "the object limit is smaller than the required file chunk size",
            ));
        }
        Ok(Self {
            max_object_bytes,
            max_file_bytes,
        })
    }
}

impl Default for ContentStoreLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

/// Digest produced while forwarding one bounded uncompressed stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamDigest {
    pub bytes: u64,
    pub blake3: [u8; 32],
}

/// Writer that rejects an over-limit stream while hashing forwarded bytes.
pub struct BoundedStreamWriter<W> {
    inner: W,
    max_bytes: u64,
    bytes: u64,
    hasher: blake3::Hasher,
}

impl<W> BoundedStreamWriter<W> {
    pub fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            bytes: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Return the wrapped writer and digest after the caller has flushed it.
    pub fn finish(self) -> (W, StreamDigest) {
        let digest = StreamDigest {
            bytes: self.bytes,
            blake3: *self.hasher.finalize().as_bytes(),
        };
        (self.inner, digest)
    }
}

impl<W: Write> Write for BoundedStreamWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stream length overflow"))?;
        let end = self
            .bytes
            .checked_add(requested)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stream length overflow"))?;
        if end > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded stream exceeded its configured limit",
            ));
        }

        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// One committed object and whether the bytes were already present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObject {
    pub entry: ObjectEntry,
    pub deduplicated: bool,
}

/// Ordered chunks plus the canonical manifest object for one stored file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredFile {
    pub manifest: FileManifest,
    pub manifest_object: StoredObject,
    pub chunk_objects: Vec<StoredObject>,
}

/// Safe detail for roots that claim one object ID but do not contain identical
/// verified bytes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ObjectConflict {
    pub object_id: ObjectId,
    pub ordered_root_indices: Vec<usize>,
}

impl ObjectConflict {
    pub fn to_error(&self) -> ErrorEnvelope {
        let mut error = ErrorEnvelope::new(
            ReforgeErrorCode::PackageCorrupt,
            "Package roots contain conflicting bytes for one object ID",
        )
        .with_context_id("package-object-conflict");
        if let Ok(detail) = serde_json::to_value(self) {
            error = error.with_json_detail(&detail);
        }
        error
    }
}

/// Receipt for one deterministic, verified object resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedObject {
    pub entry: ObjectEntry,
    pub source_root_index: usize,
    pub verified_root_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct PackageObjectRoot {
    reader: PackageReader,
    inspected: InspectedPackage,
}

/// Resolves content IDs across package files in caller-supplied precedence
/// order. Every duplicate candidate is streamed, verified, and compared before
/// any bytes are emitted to the caller.
#[derive(Clone, Debug)]
pub struct PackageSetResolver {
    roots: Vec<PackageObjectRoot>,
}

impl PackageSetResolver {
    /// Inspect already-configured readers while retaining their exact order.
    pub fn new(
        ordered_roots: impl IntoIterator<Item = PackageReader>,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let roots = ordered_roots
            .into_iter()
            .map(|reader| {
                let inspected = reader.inspect()?;
                Ok(PackageObjectRoot { reader, inspected })
            })
            .collect::<Result<Vec<_>, Box<ErrorEnvelope>>>()?;
        Ok(Self { roots })
    }

    /// Open package paths with default reader limits in their supplied order.
    pub fn open<I, P>(ordered_roots: I) -> Result<Self, Box<ErrorEnvelope>>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self::new(
            ordered_roots
                .into_iter()
                .map(|path| PackageReader::new(path.into())),
        )
    }

    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Write one verified uncompressed object stream. A returned error means
    /// the output must be discarded; conflicts are detected before writing.
    pub fn resolve_object(
        &self,
        object: &ObjectId,
        mut output: impl Write,
    ) -> Result<ResolvedObject, Box<ErrorEnvelope>> {
        let candidate_indices: Vec<_> = self
            .roots
            .iter()
            .enumerate()
            .filter_map(|(index, root)| {
                root.inspected
                    .object_index
                    .objects
                    .binary_search_by(|entry| entry.id.cmp(object))
                    .ok()
                    .map(|_| index)
            })
            .collect();
        let Some((&source_root_index, other_root_indices)) = candidate_indices.split_first() else {
            return Err(Box::new(
                ErrorEnvelope::new(
                    ReforgeErrorCode::PackageNotFound,
                    "Requested object is missing from the ordered package set",
                )
                .with_context_id("package-object-missing"),
            ));
        };

        let source = &self.roots[source_root_index];
        for &other_root_index in other_root_indices {
            let other = &self.roots[other_root_index];
            match source.reader.inspected_objects_equal(
                &source.inspected,
                &other.reader,
                &other.inspected,
                object,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Box::new(
                        ObjectConflict {
                            object_id: object.clone(),
                            ordered_root_indices: candidate_indices,
                        }
                        .to_error(),
                    ));
                }
                Err(error) if error.code == ReforgeErrorCode::PackageCorrupt => {
                    return Err(Box::new(
                        ObjectConflict {
                            object_id: object.clone(),
                            ordered_root_indices: candidate_indices,
                        }
                        .to_error(),
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        let entry = source
            .reader
            .copy_inspected_object(&source.inspected, object, &mut output)?;
        Ok(ResolvedObject {
            entry,
            source_root_index,
            verified_root_indices: candidate_indices,
        })
    }
}

/// Filesystem-backed immutable object store.
#[derive(Clone, Debug)]
pub struct ObjectStore {
    root: PathBuf,
    objects: PathBuf,
    limits: ContentStoreLimits,
}

impl ObjectStore {
    /// Open a store with conservative default size limits.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, Box<ErrorEnvelope>> {
        Self::with_limits(root, ContentStoreLimits::default())
    }

    /// Open a store with caller-supplied, finite size limits.
    pub fn with_limits(
        root: impl AsRef<Path>,
        limits: ContentStoreLimits,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let limits = ContentStoreLimits::new(limits.max_object_bytes, limits.max_file_bytes)?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|error| io_error("create object store", &error))?;
        validate_directory(&root)?;

        let objects = root.join("objects");
        fs::create_dir_all(&objects)
            .map_err(|error| io_error("create object directory", &error))?;
        validate_directory(&objects)?;

        Ok(Self {
            root,
            objects,
            limits,
        })
    }

    /// Local store root. This path never enters portable package metadata.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn limits(&self) -> ContentStoreLimits {
        self.limits
    }

    /// Stream, compress, verify, and atomically commit one metadata object.
    pub fn put_object(
        &self,
        mut reader: impl Read,
        content_type: ContentType,
    ) -> Result<StoredObject, Box<ErrorEnvelope>> {
        let staged = self.stage_object(&mut reader, self.limits.max_object_bytes, None)?;
        self.commit_staged(staged, content_type)
    }

    /// Commit an object only if its exact expected ID and length are observed.
    pub fn put_verified_object(
        &self,
        mut reader: impl Read,
        expected_id: &ObjectId,
        expected_bytes: u64,
        content_type: ContentType,
    ) -> Result<StoredObject, Box<ErrorEnvelope>> {
        if expected_bytes > self.limits.max_object_bytes {
            return Err(security_error("object exceeds the configured size limit"));
        }
        let staged = self.stage_object(
            &mut reader,
            self.limits.max_object_bytes,
            Some((expected_id, expected_bytes)),
        )?;
        self.commit_staged(staged, content_type)
    }

    /// Chunk a complete file, then store its canonical `FileManifest` object.
    pub fn store_file(
        &self,
        mut reader: impl Read,
        content_type: ContentType,
        attributes: u32,
    ) -> Result<StoredFile, Box<ErrorEnvelope>> {
        let mut buffer = vec![0u8; FILE_CHUNK_BYTES];
        let mut total_bytes = 0u64;
        let mut chunks = Vec::new();
        let mut chunk_objects = Vec::new();
        let mut seen = BTreeMap::<ObjectId, ObjectEntry>::new();

        loop {
            if total_bytes == self.limits.max_file_bytes {
                ensure_eof(&mut reader)?;
                break;
            }

            let remaining = self.limits.max_file_bytes - total_bytes;
            let read_limit = if remaining < FILE_CHUNK_BYTES as u64 {
                usize::try_from(remaining + 1)
                    .map_err(|_| security_error("file size limit cannot be represented"))?
            } else {
                FILE_CHUNK_BYTES
            };
            let read = fill_chunk(&mut reader, &mut buffer[..read_limit])?;
            if read == 0 {
                break;
            }

            total_bytes = total_bytes
                .checked_add(read as u64)
                .ok_or_else(|| security_error("file length overflow"))?;
            if total_bytes > self.limits.max_file_bytes {
                return Err(security_error("file exceeds the configured size limit"));
            }

            let bytes = &buffer[..read];
            let id = ObjectId::from_content(bytes);
            let stored = if let Some(entry) = seen.get(&id) {
                StoredObject {
                    entry: entry.clone(),
                    deduplicated: true,
                }
            } else {
                let stored = self.put_known_bytes(bytes, content_type.clone())?;
                seen.insert(id.clone(), stored.entry.clone());
                stored
            };

            chunks.push(ChunkRef {
                id,
                uncompressed_bytes: read as u64,
            });
            chunk_objects.push(stored);

            if read < FILE_CHUNK_BYTES {
                break;
            }
        }

        let manifest = FileManifest {
            size_bytes: total_bytes,
            chunks,
            content_type,
            attributes,
        };
        let canonical = canonicalize(&manifest)?;
        let manifest_object = self.put_known_bytes(canonical.as_bytes(), ContentType::Json)?;

        Ok(StoredFile {
            manifest,
            manifest_object,
            chunk_objects,
        })
    }

    /// Revalidate a stored object's compressed length, uncompressed length,
    /// and BLAKE3 ID without allocating its contents.
    pub fn verify_object(&self, entry: &ObjectEntry) -> Result<(), Box<ErrorEnvelope>> {
        let path = self.object_path(&entry.id);
        let compressed_bytes = verify_compressed_path(
            &path,
            &entry.id,
            entry.uncompressed_bytes,
            Some(entry.compressed_bytes),
        )?;
        if compressed_bytes != entry.compressed_bytes {
            return Err(corrupt_error(
                "stored object compressed length does not match its index",
            ));
        }
        Ok(())
    }

    /// Copy an already-verified zstd frame without materializing it in memory.
    pub fn copy_compressed_object(
        &self,
        entry: &ObjectEntry,
        mut output: impl Write,
    ) -> Result<u64, Box<ErrorEnvelope>> {
        self.verify_object(entry)?;
        let path = self.object_path(&entry.id);
        let mut file = open_regular_file(&path)?;
        let copied = io::copy(&mut file, &mut output)
            .map_err(|error| io_error("copy compressed object", &error))?;
        if copied != entry.compressed_bytes {
            return Err(corrupt_error("stored object changed while it was copied"));
        }
        Ok(copied)
    }

    fn put_known_bytes(
        &self,
        bytes: &[u8],
        content_type: ContentType,
    ) -> Result<StoredObject, Box<ErrorEnvelope>> {
        if bytes.len() as u64 > self.limits.max_object_bytes {
            return Err(security_error("object exceeds the configured size limit"));
        }

        let id = ObjectId::from_content(bytes);
        if let Some(entry) =
            self.verified_existing(&id, bytes.len() as u64, content_type.clone())?
        {
            return Ok(StoredObject {
                entry,
                deduplicated: true,
            });
        }

        let staged = self.stage_object(
            &mut io::Cursor::new(bytes),
            self.limits.max_object_bytes,
            Some((&id, bytes.len() as u64)),
        )?;
        self.commit_staged(staged, content_type)
    }

    fn stage_object(
        &self,
        reader: &mut impl Read,
        max_bytes: u64,
        expected: Option<(&ObjectId, u64)>,
    ) -> Result<StagedObject, Box<ErrorEnvelope>> {
        validate_directory(&self.objects)?;
        let (temp, file) = create_temp_file(&self.objects)?;
        let mut encoder =
            zstd::stream::write::Encoder::new(BufWriter::new(file), ZSTD_COMPRESSION_LEVEL)
                .map_err(|error| io_error("create zstd object encoder", &error))?;
        encoder
            .include_checksum(true)
            .map_err(|error| io_error("configure zstd object checksum", &error))?;
        encoder
            .include_contentsize(true)
            .map_err(|error| io_error("configure zstd object size", &error))?;
        if let Some((_, expected_bytes)) = expected {
            encoder
                .set_pledged_src_size(Some(expected_bytes))
                .map_err(|error| io_error("configure zstd object length", &error))?;
        }

        let mut bounded = BoundedStreamWriter::new(encoder, max_bytes);
        let mut buffer = [0u8; STREAM_BUFFER_BYTES];
        loop {
            let read = read_retry_interrupted(reader, &mut buffer)
                .map_err(|error| io_error("read object stream", &error))?;
            if read == 0 {
                break;
            }
            let end = bounded
                .bytes
                .checked_add(read as u64)
                .ok_or_else(|| security_error("object length overflow"))?;
            if end > max_bytes {
                return Err(security_error("object exceeds the configured size limit"));
            }
            bounded
                .write_all(&buffer[..read])
                .map_err(|error| io_error("compress object stream", &error))?;
        }

        let (encoder, digest) = bounded.finish();
        if let Some((expected_id, expected_bytes)) = expected
            && (digest.bytes != expected_bytes || digest.blake3 != digest_for(expected_id))
        {
            return Err(corrupt_error(
                "object hash or length does not match its expected identity",
            ));
        }

        let mut file = encoder
            .finish()
            .map_err(|error| io_error("finish zstd object frame", &error))?;
        file.flush()
            .map_err(|error| io_error("flush staged object", &error))?;
        file.get_ref()
            .sync_all()
            .map_err(|error| io_error("persist staged object", &error))?;
        drop(file);

        let id = object_id_from_digest(digest.blake3)?;
        let compressed_bytes = verify_compressed_path(&temp.path, &id, digest.bytes, None)?;

        Ok(StagedObject {
            temp,
            id,
            uncompressed_bytes: digest.bytes,
            compressed_bytes,
        })
    }

    fn commit_staged(
        &self,
        mut staged: StagedObject,
        content_type: ContentType,
    ) -> Result<StoredObject, Box<ErrorEnvelope>> {
        if let Some(entry) =
            self.verified_existing(&staged.id, staged.uncompressed_bytes, content_type.clone())?
        {
            return Ok(StoredObject {
                entry,
                deduplicated: true,
            });
        }

        let destination = self.object_path(&staged.id);
        match fs::hard_link(&staged.temp.path, &destination) {
            Ok(()) => {
                staged.temp.remove()?;
                Ok(StoredObject {
                    entry: ObjectEntry {
                        id: staged.id,
                        uncompressed_bytes: staged.uncompressed_bytes,
                        compressed_bytes: staged.compressed_bytes,
                        content_type,
                    },
                    deduplicated: false,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let entry = self
                    .verified_existing(&staged.id, staged.uncompressed_bytes, content_type)?
                    .ok_or_else(|| corrupt_error("object commit destination disappeared"))?;
                Ok(StoredObject {
                    entry,
                    deduplicated: true,
                })
            }
            Err(error) => Err(io_error("atomically commit object", &error)),
        }
    }

    fn verified_existing(
        &self,
        id: &ObjectId,
        uncompressed_bytes: u64,
        content_type: ContentType,
    ) -> Result<Option<ObjectEntry>, Box<ErrorEnvelope>> {
        let path = self.object_path(id);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let compressed_bytes = verify_compressed_path(&path, id, uncompressed_bytes, None)?;
                Ok(Some(ObjectEntry {
                    id: id.clone(),
                    uncompressed_bytes,
                    compressed_bytes,
                    content_type,
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error("inspect stored object", &error)),
        }
    }

    fn object_path(&self, id: &ObjectId) -> PathBuf {
        self.objects.join(format!("{}.zst", id.as_str()))
    }
}

struct StagedObject {
    temp: TempFileGuard,
    id: ObjectId,
    uncompressed_bytes: u64,
    compressed_bytes: u64,
}

struct TempFileGuard {
    path: PathBuf,
    active: bool,
}

impl TempFileGuard {
    fn remove(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        fs::remove_file(&self.path).map_err(|error| io_error("remove staged object", &error))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp_file(directory: &Path) -> Result<(TempFileGuard, File), Box<ErrorEnvelope>> {
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".reforge-object-{}-{id}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                return Ok((TempFileGuard { path, active: true }, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("create staged object", &error)),
        }
    }
    Err(Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::TargetConflict,
        "A unique staged object name could not be allocated",
    )))
}

fn fill_chunk(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Box<ErrorEnvelope>> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = read_retry_interrupted(reader, &mut buffer[filled..])
            .map_err(|error| io_error("read file object", &error))?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

fn ensure_eof(reader: &mut impl Read) -> Result<(), Box<ErrorEnvelope>> {
    let mut probe = [0u8; 1];
    let read = read_retry_interrupted(reader, &mut probe)
        .map_err(|error| io_error("read file size probe", &error))?;
    if read == 0 {
        Ok(())
    } else {
        Err(security_error("file exceeds the configured size limit"))
    }
}

fn read_retry_interrupted(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn verify_compressed_path(
    path: &Path,
    expected_id: &ObjectId,
    expected_bytes: u64,
    expected_compressed_bytes: Option<u64>,
) -> Result<u64, Box<ErrorEnvelope>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect compressed object", &error))?;
    validate_regular_metadata(&metadata)?;
    let compressed_bytes = metadata.len();
    if let Some(expected) = expected_compressed_bytes
        && compressed_bytes != expected
    {
        return Err(corrupt_error(
            "compressed object length does not match its index",
        ));
    }

    let file = File::open(path).map_err(|error| io_error("open compressed object", &error))?;
    let mut decoder = zstd::stream::read::Decoder::new(file)
        .map_err(|_| corrupt_error("object is not a valid zstd frame"))?;
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    let mut bytes = 0u64;
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| corrupt_error("object zstd frame could not be decoded"))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| corrupt_error("object length overflow"))?;
        if bytes > expected_bytes {
            return Err(corrupt_error("object expands beyond its expected length"));
        }
        hasher.update(&buffer[..read]);
    }

    if bytes != expected_bytes || hasher.finalize().as_bytes() != &digest_for(expected_id) {
        return Err(corrupt_error("object hash or length verification failed"));
    }
    Ok(compressed_bytes)
}

fn open_regular_file(path: &Path) -> Result<File, Box<ErrorEnvelope>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect compressed object", &error))?;
    validate_regular_metadata(&metadata)?;
    File::open(path).map_err(|error| io_error("open compressed object", &error))
}

fn validate_directory(path: &Path) -> Result<(), Box<ErrorEnvelope>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect object store directory", &error))?;
    if is_reparse_point(&metadata) {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ReparsePoint,
            "Object store directories must not be reparse points",
        )));
    }
    if !metadata.is_dir() {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::InvalidPath,
            "Object store path must be a directory",
        )));
    }
    Ok(())
}

fn validate_regular_metadata(metadata: &Metadata) -> Result<(), Box<ErrorEnvelope>> {
    if is_reparse_point(metadata) {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ReparsePoint,
            "Stored objects must not be reparse points",
        )));
    }
    if !metadata.is_file() {
        return Err(corrupt_error("stored object is not a regular file"));
    }
    Ok(())
}

fn is_reparse_point(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & WINDOWS_REPARSE_POINT_ATTRIBUTE != 0
    }
    #[cfg(not(windows))]
    {
        let _ = WINDOWS_REPARSE_POINT_ATTRIBUTE;
        false
    }
}

fn object_id_from_digest(digest: [u8; 32]) -> Result<ObjectId, Box<ErrorEnvelope>> {
    ObjectId::new(format!("obj_{}", blake3::Hash::from_bytes(digest).to_hex()))
        .map_err(|_| corrupt_error("computed object identity is invalid"))
}

fn digest_for(id: &ObjectId) -> [u8; 32] {
    let digest = &id.as_str().as_bytes()[4..];
    let mut bytes = [0u8; 32];
    for (output, pair) in bytes.iter_mut().zip(digest.as_chunks::<2>().0) {
        *output = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    bytes
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("ObjectId validation permits lowercase hexadecimal only"),
    }
}

fn io_error(message: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, message))
}

fn security_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::SecurityPolicy,
        message,
    ))
}

fn corrupt_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::PackageCorrupt,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_hashes_only_forwarded_bytes_and_rejects_overflow() {
        let mut writer = BoundedStreamWriter::new(Vec::new(), 4);
        writer.write_all(b"data").unwrap();
        assert!(writer.write_all(b"x").is_err());
        let (bytes, digest) = writer.finish();
        assert_eq!(bytes, b"data");
        assert_eq!(digest.bytes, 4);
        assert_eq!(digest.blake3, *blake3::hash(b"data").as_bytes());
    }

    #[test]
    fn object_digest_round_trips_domain_id_encoding() {
        let id = ObjectId::from_content(b"canonical object");
        assert_eq!(
            digest_for(&id),
            *blake3::hash(b"canonical object").as_bytes()
        );
        assert_eq!(object_id_from_digest(digest_for(&id)).unwrap(), id);
    }
}
