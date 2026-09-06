//! Fail-closed package inspection.
//!
//! Inspection never extracts archive paths. It validates the central directory,
//! canonical metadata, graph/index relationships, and every zstd object frame
//! before returning any package document to a caller.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component as PathComponent, Path, PathBuf},
};

use reforge_domain::{
    ContentType, FileManifest, ObjectEntry, ObjectId, ObjectIndex, PackageGraph, PackageManifest,
    ReforgeErrorCode, SelectionInput, TrustState,
};
use serde::{Serialize, de::DeserializeOwned};
use zip::{CompressionMethod, ZipArchive, read::ZipFile};

use crate::{
    EncryptedVault, PackageSignature, PublicKeyFingerprint, SignatureMetadata, TrustDecision,
    apply_trust_decision, canonicalize, require_plan_approval,
    writer::{
        GRAPH_ENTRY, MANIFEST_ENTRY, OBJECT_INDEX_ENTRY, OPERATIONS_ENTRY, PackageLimits,
        PackageOperations, PackageSources, REQUIRED_FORMAT_ENTRIES, SELECTION_ENTRY,
        SIGNATURE_ENTRY, SIGNATURE_MANIFEST_ENTRY, SOURCES_ENTRY, VAULT_ENTRY, corrupt_error,
        derive_operations, derive_sources, normalize_object_index, object_locations, schema_error,
        security_error, validate_file_manifest, validate_package_documents, validate_vault_policy,
    },
};

const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0606_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const END_OF_CENTRAL_DIRECTORY_BYTES: usize = 22;
const CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const CENTRAL_DIRECTORY_FILE_HEADER_BYTES: usize = 46;
const ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD: u16 = 0x0001;
const MAX_ZIP_COMMENT_BYTES: usize = u16::MAX as usize;
const ZIP64_LOCATOR_BYTES: u64 = 20;
const ZIP64_END_MINIMUM_BYTES: usize = 56;
const ZIP64_END_MINIMUM_RECORD_SIZE: u64 = 44;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;

/// Fully integrity-checked package metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedPackage {
    pub manifest: PackageManifest,
    pub graph: PackageGraph,
    pub selection: SelectionInput,
    pub operations: PackageOperations,
    pub object_index: ObjectIndex,
    /// Validated file-manifest metadata keyed by the artifact object reference.
    pub file_manifests: BTreeMap<ObjectId, FileManifest>,
    pub sources: PackageSources,
    pub trust: TrustState,
    pub warnings: Vec<String>,
    pub has_vault: bool,
    encrypted_vault: Option<EncryptedVault>,
    signature: Option<PackageSignature>,
    object_locations: BTreeMap<ObjectId, String>,
    archive_bytes: u64,
}

impl InspectedPackage {
    pub fn object_location(&self, object: &ObjectId) -> Option<&str> {
        self.object_locations.get(object).map(String::as_str)
    }

    pub fn archive_bytes(&self) -> u64 {
        self.archive_bytes
    }

    pub fn encrypted_vault(&self) -> Option<&EncryptedVault> {
        self.encrypted_vault.as_ref()
    }

    pub fn signature_metadata(&self) -> Option<&SignatureMetadata> {
        self.signature.as_ref().map(PackageSignature::metadata)
    }

    pub fn decide_trust(
        &mut self,
        decision: TrustDecision,
    ) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
        self.trust = apply_trust_decision(self.trust.clone(), decision)?;
        Ok(())
    }

    pub fn require_plan_approval(&self) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
        require_plan_approval(&self.trust)
    }
}

/// Opens a package only through the bounded inspection path.
#[derive(Clone, Debug)]
pub struct PackageReader {
    path: PathBuf,
    limits: PackageLimits,
    trusted_signer: Option<PublicKeyFingerprint>,
}

impl PackageReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            limits: PackageLimits::default(),
            trusted_signer: None,
        }
    }

    pub fn with_limits(
        path: impl Into<PathBuf>,
        limits: PackageLimits,
    ) -> Result<Self, Box<reforge_domain::ErrorEnvelope>> {
        Ok(Self {
            path: path.into(),
            limits: limits.validate()?,
            trusted_signer: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn limits(&self) -> PackageLimits {
        self.limits
    }

    pub fn with_trusted_signer(mut self, fingerprint: PublicKeyFingerprint) -> Self {
        self.trusted_signer = Some(fingerprint);
        self
    }

    pub fn inspect(&self) -> Result<InspectedPackage, Box<reforge_domain::ErrorEnvelope>> {
        let metadata = fs::metadata(&self.path)
            .map_err(|error| io_error("open package for inspection", &error))?;
        if !metadata.is_file() {
            return Err(Box::new(reforge_domain::ErrorEnvelope::new(
                ReforgeErrorCode::InvalidPath,
                "Package path must identify a regular file",
            )));
        }
        let archive_bytes = metadata.len();
        if archive_bytes == 0 || archive_bytes > self.limits.max_archive_bytes {
            return Err(security_error(
                "package file exceeds the configured archive size limit",
            ));
        }

        let mut file = File::open(&self.path)
            .map_err(|error| io_error("open package for inspection", &error))?;
        let central = preflight_central_directory(&mut file, archive_bytes, self.limits)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind package", &error))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|_| corrupt_error("package central directory is corrupt"))?;
        if archive.len() as u64 != central.entry_count {
            return Err(corrupt_error(
                "package central-directory entry count is inconsistent",
            ));
        }

        let summaries = inspect_entries(&mut archive, self.limits)?;
        for required in REQUIRED_FORMAT_ENTRIES {
            if !summaries.contains_key(required) {
                return Err(corrupt_error("package is missing a required format entry"));
            }
        }

        let manifest: PackageManifest = read_canonical_json(
            &mut archive,
            MANIFEST_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let graph: PackageGraph = read_canonical_json(
            &mut archive,
            GRAPH_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let selection: SelectionInput = read_canonical_json(
            &mut archive,
            SELECTION_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let operations: PackageOperations = read_canonical_json(
            &mut archive,
            OPERATIONS_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let object_index: ObjectIndex = read_canonical_json(
            &mut archive,
            OBJECT_INDEX_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let sources: PackageSources = read_canonical_json(
            &mut archive,
            SOURCES_ENTRY,
            self.limits.max_metadata_entry_bytes,
        )?;
        let encrypted_vault = if summaries.contains_key(VAULT_ENTRY) {
            let bytes = read_entry_bytes(
                &mut archive,
                VAULT_ENTRY,
                self.limits.max_metadata_entry_bytes,
            )?;
            Some(EncryptedVault::from_bytes(bytes)?)
        } else {
            None
        };
        validate_vault_policy(&selection, encrypted_vault.is_some())?;

        let normalized_index = normalize_object_index(&object_index)?;
        if normalized_index != object_index {
            return Err(schema_error(
                "object index is not in canonical object-ID order",
            ));
        }
        validate_package_documents(&manifest, &graph, &selection, &object_index)?;
        if operations != derive_operations(&graph)? {
            return Err(schema_error(
                "operations document does not match component restore descriptors",
            ));
        }
        if sources != derive_sources(&graph)? {
            return Err(schema_error(
                "sources document does not match component provenance",
            ));
        }
        let canonical_index = canonicalize(&object_index)?;
        let index_digest = canonical_index.object_id().as_str().to_owned();
        let object_index_signature_bytes = canonical_index.into_bytes();
        if manifest.object_index_digest != index_digest {
            return Err(corrupt_error(
                "object-index digest does not match the package manifest",
            ));
        }

        let total_object_bytes = object_index.objects.iter().try_fold(0u64, |total, entry| {
            total
                .checked_add(entry.uncompressed_bytes)
                .ok_or_else(|| security_error("package object size total overflow"))
        })?;
        if total_object_bytes > self.limits.max_total_object_bytes {
            return Err(security_error(
                "package objects exceed the configured size limit",
            ));
        }

        let indexed: BTreeMap<_, _> = object_index
            .objects
            .iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        let file_manifests = read_file_manifests(
            &mut archive,
            &summaries,
            &graph,
            &indexed,
            self.limits.max_metadata_entry_bytes,
        )?;
        let locations = object_locations(&object_index, &file_manifests)?;
        validate_object_entry_set(&summaries, &locations)?;

        for entry in &object_index.objects {
            let name = locations
                .get(&entry.id)
                .expect("every indexed object has one validated location");
            verify_object_entry(&mut archive, &summaries, name, entry)?;
        }

        let has_signature_manifest = summaries.contains_key(SIGNATURE_MANIFEST_ENTRY);
        let has_signature = summaries.contains_key(SIGNATURE_ENTRY);
        if has_signature_manifest != has_signature {
            return Err(corrupt_error(
                "package contains an incomplete signature envelope",
            ));
        }
        let signature = if has_signature_manifest {
            let metadata = read_entry_bytes(
                &mut archive,
                SIGNATURE_MANIFEST_ENTRY,
                self.limits.max_metadata_entry_bytes,
            )?;
            let signature = read_entry_bytes(
                &mut archive,
                SIGNATURE_ENTRY,
                self.limits.max_metadata_entry_bytes,
            )?;
            Some(PackageSignature::from_entries(metadata, signature)?)
        } else {
            None
        };
        let manifest_signature_bytes = canonicalize(&manifest)?.into_bytes();
        let trust = if let Some(signature) = &signature {
            signature.trust_state_for_canonical(
                &manifest_signature_bytes,
                &object_index_signature_bytes,
                self.trusted_signer.as_ref(),
            )?
        } else {
            TrustState::Unsigned
        };

        let mut warnings = manifest.warnings.clone();
        let trust_warning = match &trust {
            TrustState::Unsigned => Some("Package is unsigned"),
            TrustState::SignatureInvalid => Some("Package signature is invalid"),
            TrustState::SignatureValidUntrusted => {
                Some("Package signature is valid, but its signer is not trusted")
            }
            _ => None,
        };
        if let Some(warning) = trust_warning
            && !warnings.iter().any(|existing| existing == warning)
        {
            warnings.push(warning.to_owned());
        }

        Ok(InspectedPackage {
            manifest,
            graph,
            selection,
            operations,
            object_index,
            file_manifests,
            sources,
            trust,
            warnings,
            has_vault: encrypted_vault.is_some(),
            encrypted_vault,
            signature,
            object_locations: locations,
            archive_bytes,
        })
    }

    /// Copy one object as a bounded, decompressed stream after revalidating its
    /// package and content identity. Bytes written before an error must be
    /// discarded by the caller.
    pub fn copy_verified_object(
        &self,
        object: &ObjectId,
        mut output: impl Write,
    ) -> Result<ObjectEntry, Box<reforge_domain::ErrorEnvelope>> {
        let inspected = self.inspect()?;
        self.copy_inspected_object(&inspected, object, &mut output)
    }

    pub(crate) fn copy_inspected_object(
        &self,
        inspected: &InspectedPackage,
        object: &ObjectId,
        output: &mut dyn Write,
    ) -> Result<ObjectEntry, Box<reforge_domain::ErrorEnvelope>> {
        let mut stream = self.open_inspected_object(inspected, object)?;
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let read = stream.read_chunk(&mut buffer)?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| io_error("write verified package object", &error))?;
        }
        Ok(stream.entry)
    }

    pub(crate) fn inspected_objects_equal(
        &self,
        inspected: &InspectedPackage,
        other_reader: &Self,
        other_inspected: &InspectedPackage,
        object: &ObjectId,
    ) -> Result<bool, Box<reforge_domain::ErrorEnvelope>> {
        let mut left = self.open_inspected_object(inspected, object)?;
        let mut right = other_reader.open_inspected_object(other_inspected, object)?;
        let mut left_buffer = [0u8; 128 * 1024];
        let mut right_buffer = [0u8; 128 * 1024];
        let mut equal = true;
        loop {
            let left_read = left.read_chunk(&mut left_buffer)?;
            let right_read = right.read_chunk(&mut right_buffer)?;
            if left_read == 0 && right_read == 0 {
                return Ok(equal);
            }
            if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
                equal = false;
            }
        }
    }

    fn open_inspected_object(
        &self,
        inspected: &InspectedPackage,
        object: &ObjectId,
    ) -> Result<VerifiedObjectStream, Box<reforge_domain::ErrorEnvelope>> {
        let entry = inspected
            .object_index
            .objects
            .binary_search_by(|entry| entry.id.cmp(object))
            .ok()
            .map(|index| inspected.object_index.objects[index].clone())
            .ok_or_else(missing_object_error)?;
        let name = inspected
            .object_location(object)
            .ok_or_else(missing_object_error)?;

        let metadata = fs::metadata(&self.path)
            .map_err(|error| io_error("open package object stream", &error))?;
        if !metadata.is_file() || metadata.len() != inspected.archive_bytes {
            return Err(corrupt_error(
                "package changed after its object index was inspected",
            ));
        }
        let mut file = File::open(&self.path)
            .map_err(|error| io_error("open package object stream", &error))?;
        let central = preflight_central_directory(&mut file, metadata.len(), self.limits)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind package object stream", &error))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|_| corrupt_error("package central directory is corrupt"))?;
        if archive.len() as u64 != central.entry_count {
            return Err(corrupt_error(
                "package central-directory entry count is inconsistent",
            ));
        }
        let summaries = inspect_entries(&mut archive, self.limits)?;
        validate_object_summary(&summaries, name, &entry)?;
        let (data_start, compressed_bytes) = {
            let file = archive
                .by_name(name)
                .map_err(|_| corrupt_error("indexed package object is missing"))?;
            (
                file.data_start()
                    .ok_or_else(|| corrupt_error("package object data offset is unavailable"))?,
                file.compressed_size(),
            )
        };
        let data_end = data_start
            .checked_add(compressed_bytes)
            .ok_or_else(|| corrupt_error("package object data range overflow"))?;
        if data_end > inspected.archive_bytes {
            return Err(corrupt_error(
                "package object data range exceeds the package file",
            ));
        }
        drop(archive);

        let mut raw = File::open(&self.path)
            .map_err(|error| io_error("reopen package object stream", &error))?;
        raw.seek(SeekFrom::Start(data_start))
            .map_err(|error| io_error("seek to package object stream", &error))?;
        let decoder = zstd_decoder(raw.take(compressed_bytes))?;
        Ok(VerifiedObjectStream {
            decoder: Some(decoder),
            entry,
            total: 0,
            hasher: blake3::Hasher::new(),
            finished: false,
        })
    }
}

type PackageObjectDecoder = zstd::stream::read::Decoder<'static, io::BufReader<io::Take<File>>>;

struct VerifiedObjectStream {
    decoder: Option<PackageObjectDecoder>,
    entry: ObjectEntry,
    total: u64,
    hasher: blake3::Hasher,
    finished: bool,
}

impl VerifiedObjectStream {
    fn read_chunk(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<usize, Box<reforge_domain::ErrorEnvelope>> {
        if self.finished {
            return Ok(0);
        }
        let mut filled = 0;
        while filled < buffer.len() {
            let read = self
                .decoder
                .as_mut()
                .expect("unfinished object stream retains its decoder")
                .read(&mut buffer[filled..])
                .map_err(|_| corrupt_error("package object is not a valid zstd frame"))?;
            if read == 0 {
                self.finish()?;
                break;
            }
            filled += read;
            self.total = self
                .total
                .checked_add(read as u64)
                .ok_or_else(|| corrupt_error("package object length overflow"))?;
            if self.total > self.entry.uncompressed_bytes {
                return Err(corrupt_error(
                    "package object expands beyond its indexed length",
                ));
            }
            self.hasher.update(&buffer[filled - read..filled]);
        }
        Ok(filled)
    }

    fn finish(&mut self) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
        let decoder = self
            .decoder
            .take()
            .expect("object stream is finalized exactly once");
        ensure_zstd_frame_consumed(decoder)?;
        let actual = format!("obj_{}", self.hasher.finalize().to_hex());
        if self.total != self.entry.uncompressed_bytes || actual != self.entry.id.as_str() {
            return Err(corrupt_error(
                "package object failed hash or length verification",
            ));
        }
        self.finished = true;
        Ok(())
    }
}

fn missing_object_error() -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(
        reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::PackageNotFound,
            "Requested object is missing from the package",
        )
        .with_context_id("package-object-missing"),
    )
}

#[derive(Clone, Debug)]
struct EntrySummary {
    size: u64,
    compressed_size: u64,
}

#[derive(Clone, Copy, Debug)]
struct CentralDirectoryInfo {
    entry_count: u64,
}

fn inspect_entries<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    limits: PackageLimits,
) -> Result<BTreeMap<String, EntrySummary>, Box<reforge_domain::ErrorEnvelope>> {
    let mut entries = BTreeMap::new();
    let mut case_folded_names = BTreeSet::new();
    let mut total_metadata_bytes = 0u64;

    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| corrupt_error("package central-directory entry is unreadable"))?;
        validate_entry(&file, limits)?;
        let name = file.name().to_owned();
        if entries.contains_key(&name) || !case_folded_names.insert(name.to_lowercase()) {
            return Err(security_error(
                "package contains duplicate or case-colliding entry names",
            ));
        }
        if !is_object_entry_name(&name) {
            if !is_allowed_non_object_entry(&name) {
                return Err(security_error("package contains an unexpected entry"));
            }
            if file.size() > limits.max_metadata_entry_bytes {
                return Err(security_error(
                    "package metadata entry exceeds its configured limit",
                ));
            }
            total_metadata_bytes = total_metadata_bytes
                .checked_add(file.size())
                .ok_or_else(|| security_error("package metadata size total overflow"))?;
        }
        entries.insert(
            name,
            EntrySummary {
                size: file.size(),
                compressed_size: file.compressed_size(),
            },
        );
    }

    if total_metadata_bytes > limits.max_total_metadata_bytes {
        return Err(security_error(
            "package metadata exceeds its configured total limit",
        ));
    }
    Ok(entries)
}

fn validate_entry<R: Read>(
    file: &ZipFile<'_, R>,
    limits: PackageLimits,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let raw_name = file.name_raw();
    if raw_name.len() > limits.max_entry_name_bytes {
        return Err(security_error(
            "package entry name exceeds its configured limit",
        ));
    }
    let utf8_name = std::str::from_utf8(raw_name)
        .map_err(|_| security_error("package entry name is not UTF-8"))?;
    if utf8_name != file.name() {
        return Err(security_error("package entry name is not canonical UTF-8"));
    }
    validate_entry_name(utf8_name)?;
    if file.enclosed_name().is_none() || !file.is_file() || file.is_symlink() {
        return Err(security_error(
            "package contains a directory, symlink, or unsafe path",
        ));
    }
    if file.encrypted() {
        return Err(security_error(
            "encrypted outer ZIP entries are not supported",
        ));
    }
    if !file.comment().is_empty() {
        return Err(security_error(
            "package entries must not contain ZIP comments",
        ));
    }
    if file.compressed_size() == 0 && file.size() != 0 {
        return Err(security_error(
            "package entry has an invalid compressed length",
        ));
    }
    if file.compressed_size() != 0
        && exceeds_ratio(
            file.size(),
            file.compressed_size(),
            limits.max_outer_compression_ratio,
        )
    {
        return Err(security_error(
            "package entry exceeds the outer compression-ratio limit",
        ));
    }
    if file.compression() != CompressionMethod::Stored {
        return Err(security_error(
            "package outer entries must use stored ZIP compression",
        ));
    }
    Ok(())
}

fn validate_entry_name(name: &str) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    if name.is_empty()
        || name.contains('\0')
        || name.contains('\\')
        || name.starts_with('/')
        || name.starts_with("//")
        || name.ends_with('/')
    {
        return Err(security_error("package entry path is unsafe"));
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, PathComponent::Normal(_)))
        || name.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.contains(':')
        })
    {
        return Err(security_error(
            "package entry path contains an unsafe component",
        ));
    }
    Ok(())
}

fn is_allowed_non_object_entry(name: &str) -> bool {
    REQUIRED_FORMAT_ENTRIES.contains(&name)
        || matches!(
            name,
            VAULT_ENTRY | SIGNATURE_MANIFEST_ENTRY | SIGNATURE_ENTRY
        )
}

fn is_object_entry_name(name: &str) -> bool {
    parse_object_entry_name(name).is_some()
}

fn parse_object_entry_name(name: &str) -> Option<()> {
    let body = name.strip_prefix("objects/")?;
    if !body.contains(".chunks/") {
        let id = body.strip_suffix(".zst")?;
        ObjectId::new(id).ok()?;
        return Some(());
    }

    let (manifest_id, tail) = body.split_once(".chunks/")?;
    ObjectId::new(manifest_id).ok()?;
    let index = tail.strip_suffix(".zst")?;
    if index.is_empty()
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
        || index.parse::<usize>().is_err()
    {
        return None;
    }
    Some(())
}

fn validate_object_entry_set(
    summaries: &BTreeMap<String, EntrySummary>,
    locations: &BTreeMap<ObjectId, String>,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let actual: BTreeSet<_> = summaries
        .keys()
        .filter(|name| is_object_entry_name(name))
        .cloned()
        .collect();
    let expected: BTreeSet<_> = locations.values().cloned().collect();
    if actual != expected {
        return Err(corrupt_error(
            "package object entries do not match the object index",
        ));
    }
    Ok(())
}

fn read_file_manifests<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    summaries: &BTreeMap<String, EntrySummary>,
    graph: &PackageGraph,
    indexed: &BTreeMap<ObjectId, &ObjectEntry>,
    max_metadata_bytes: u64,
) -> Result<BTreeMap<ObjectId, FileManifest>, Box<reforge_domain::ErrorEnvelope>> {
    let mut manifests = BTreeMap::new();
    for component in &graph.components {
        for artifact in &component.artifacts {
            let Some(object_id) = &artifact.object else {
                continue;
            };
            if manifests.contains_key(object_id) {
                continue;
            }
            let entry = indexed
                .get(object_id)
                .ok_or_else(|| schema_error("artifact object is missing from the object index"))?;
            if entry.content_type != ContentType::Json {
                return Err(schema_error(
                    "file manifest object must have JSON content type",
                ));
            }
            let name = format!("objects/{}.zst", object_id.as_str());
            let bytes =
                read_verified_object_bytes(archive, summaries, &name, entry, max_metadata_bytes)?;
            let manifest: FileManifest = serde_json::from_slice(&bytes)
                .map_err(|_| schema_error("artifact object is not a file manifest"))?;
            if canonicalize(&manifest)?.as_bytes() != bytes {
                return Err(schema_error("file manifest object is not canonical JSON"));
            }
            validate_file_manifest(
                &manifest,
                artifact.size_bytes,
                &artifact.content_type,
                indexed,
            )?;
            manifests.insert(object_id.clone(), manifest);
        }
    }
    Ok(manifests)
}

fn verify_object_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    summaries: &BTreeMap<String, EntrySummary>,
    name: &str,
    expected: &ObjectEntry,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    validate_object_summary(summaries, name, expected)?;
    let file = archive
        .by_name(name)
        .map_err(|_| corrupt_error("indexed package object is missing"))?;
    let mut decoder = zstd_decoder(file)?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| corrupt_error("package object is not a valid zstd frame"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| corrupt_error("package object length overflow"))?;
        if total > expected.uncompressed_bytes {
            return Err(corrupt_error(
                "package object expands beyond its indexed length",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    ensure_zstd_frame_consumed(decoder)?;
    let actual = format!("obj_{}", hasher.finalize().to_hex());
    if total != expected.uncompressed_bytes || actual != expected.id.as_str() {
        return Err(corrupt_error(
            "package object failed hash or length verification",
        ));
    }
    Ok(())
}

fn read_verified_object_bytes<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    summaries: &BTreeMap<String, EntrySummary>,
    name: &str,
    expected: &ObjectEntry,
    max_bytes: u64,
) -> Result<Vec<u8>, Box<reforge_domain::ErrorEnvelope>> {
    if expected.uncompressed_bytes > max_bytes {
        return Err(security_error(
            "file manifest object exceeds the metadata size limit",
        ));
    }
    validate_object_summary(summaries, name, expected)?;
    let file = archive
        .by_name(name)
        .map_err(|_| corrupt_error("indexed package object is missing"))?;
    let mut decoder = zstd_decoder(file)?;
    let capacity = usize::try_from(expected.uncompressed_bytes)
        .map_err(|_| security_error("metadata size cannot be represented"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|_| corrupt_error("package object is not a valid zstd frame"))?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > capacity {
            return Err(corrupt_error(
                "package object expands beyond its indexed length",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    ensure_zstd_frame_consumed(decoder)?;
    if bytes.len() as u64 != expected.uncompressed_bytes
        || ObjectId::from_content(&bytes) != expected.id
    {
        return Err(corrupt_error(
            "package object failed hash or length verification",
        ));
    }
    Ok(bytes)
}

fn validate_object_summary(
    summaries: &BTreeMap<String, EntrySummary>,
    name: &str,
    expected: &ObjectEntry,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let summary = summaries
        .get(name)
        .ok_or_else(|| corrupt_error("indexed package object is missing"))?;
    if summary.size != expected.compressed_bytes
        || summary.compressed_size != expected.compressed_bytes
    {
        return Err(corrupt_error(
            "package object frame length disagrees with the object index",
        ));
    }
    Ok(())
}

fn zstd_decoder<R: Read>(
    reader: R,
) -> Result<
    zstd::stream::read::Decoder<'static, io::BufReader<R>>,
    Box<reforge_domain::ErrorEnvelope>,
> {
    let mut decoder = zstd::stream::read::Decoder::new(reader)
        .map_err(|_| corrupt_error("package object is not a valid zstd frame"))?
        .single_frame();
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .map_err(|_| corrupt_error("package object zstd window exceeds the safety limit"))?;
    Ok(decoder)
}

fn ensure_zstd_frame_consumed<R: Read>(
    decoder: zstd::stream::read::Decoder<'static, io::BufReader<R>>,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let mut reader = decoder.finish();
    if !reader.buffer().is_empty() {
        return Err(corrupt_error(
            "package object contains trailing data after its zstd frame",
        ));
    }
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(corrupt_error(
            "package object contains trailing data after its zstd frame",
        )),
        Err(_) => Err(corrupt_error("package object failed ZIP CRC verification")),
    }
}

fn read_canonical_json<T: DeserializeOwned + Serialize, R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<T, Box<reforge_domain::ErrorEnvelope>> {
    let bytes = read_entry_bytes(archive, name, max_bytes)?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|_| schema_error("package metadata does not match its domain schema"))?;
    if canonicalize(&value)?.as_bytes() != bytes {
        return Err(schema_error("package metadata is not canonical JSON"));
    }
    Ok(value)
}

fn read_entry_bytes<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, Box<reforge_domain::ErrorEnvelope>> {
    let mut file = archive
        .by_name(name)
        .map_err(|_| corrupt_error("package is missing a required entry"))?;
    if file.size() > max_bytes {
        return Err(security_error(
            "package metadata entry exceeds its configured limit",
        ));
    }
    let capacity = usize::try_from(file.size())
        .map_err(|_| security_error("metadata size cannot be represented"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| corrupt_error("package metadata entry failed ZIP CRC verification"))?;
    if bytes.len() != capacity {
        return Err(corrupt_error(
            "package metadata entry length is inconsistent",
        ));
    }
    Ok(bytes)
}

fn preflight_central_directory(
    file: &mut File,
    archive_bytes: u64,
    limits: PackageLimits,
) -> Result<CentralDirectoryInfo, Box<reforge_domain::ErrorEnvelope>> {
    if archive_bytes < END_OF_CENTRAL_DIRECTORY_BYTES as u64 {
        return Err(corrupt_error(
            "package is too short to contain a ZIP central directory",
        ));
    }
    let tail_len =
        archive_bytes.min((END_OF_CENTRAL_DIRECTORY_BYTES + MAX_ZIP_COMMENT_BYTES) as u64);
    let tail_start = archive_bytes - tail_len;
    file.seek(SeekFrom::Start(tail_start))
        .map_err(|error| io_error("seek package central directory", &error))?;
    let mut tail = vec![0u8; tail_len as usize];
    file.read_exact(&mut tail)
        .map_err(|error| io_error("read package central directory", &error))?;

    let eocd_index = (0..=tail.len() - END_OF_CENTRAL_DIRECTORY_BYTES)
        .rev()
        .find(|index| {
            read_u32(&tail[*index..]) == Some(END_OF_CENTRAL_DIRECTORY_SIGNATURE)
                && read_u16(&tail[*index + 20..]).is_some_and(|comment| {
                    *index + END_OF_CENTRAL_DIRECTORY_BYTES + comment as usize == tail.len()
                })
        })
        .ok_or_else(|| corrupt_error("package ZIP end-of-central-directory record is missing"))?;
    let eocd = &tail[eocd_index..];
    if read_u16(&eocd[20..]) != Some(0) {
        return Err(security_error("package ZIP comments are not supported"));
    }
    let eocd_offset = tail_start + eocd_index as u64;
    let disk = read_u16(&eocd[4..]).expect("bounded EOCD disk field");
    let central_disk = read_u16(&eocd[6..]).expect("bounded EOCD central disk field");
    let entries_on_disk = read_u16(&eocd[8..]).expect("bounded EOCD entry field");
    let entries = read_u16(&eocd[10..]).expect("bounded EOCD entry field");
    let central_size_32 = read_u32(&eocd[12..]).expect("bounded EOCD size field");
    let central_offset_32 = read_u32(&eocd[16..]).expect("bounded EOCD offset field");
    if disk != 0 || central_disk != 0 {
        return Err(security_error("multi-disk ZIP packages are not supported"));
    }

    let needs_zip64 = entries == u16::MAX
        || entries_on_disk == u16::MAX
        || central_size_32 == u32::MAX
        || central_offset_32 == u32::MAX;
    let (entry_count, central_size, central_offset, central_boundary) = if needs_zip64 {
        if eocd_offset < ZIP64_LOCATOR_BYTES {
            return Err(corrupt_error("package ZIP64 locator is missing"));
        }
        let locator_offset = eocd_offset - ZIP64_LOCATOR_BYTES;
        file.seek(SeekFrom::Start(locator_offset))
            .map_err(|error| io_error("seek ZIP64 locator", &error))?;
        let mut locator = [0u8; ZIP64_LOCATOR_BYTES as usize];
        file.read_exact(&mut locator)
            .map_err(|_| corrupt_error("package ZIP64 locator is truncated"))?;
        if read_u32(&locator) != Some(ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE)
            || read_u32(&locator[4..]) != Some(0)
            || read_u32(&locator[16..]) != Some(1)
        {
            return Err(security_error(
                "package ZIP64 locator uses unsupported multi-disk fields",
            ));
        }
        let zip64_offset = read_u64(&locator[8..]).expect("bounded ZIP64 locator offset");
        if zip64_offset >= locator_offset {
            return Err(corrupt_error("package ZIP64 end record offset is invalid"));
        }
        file.seek(SeekFrom::Start(zip64_offset))
            .map_err(|error| io_error("seek ZIP64 end record", &error))?;
        let mut zip64 = [0u8; ZIP64_END_MINIMUM_BYTES];
        file.read_exact(&mut zip64)
            .map_err(|_| corrupt_error("package ZIP64 end record is truncated"))?;
        let zip64_record_size = read_u64(&zip64[4..])
            .ok_or_else(|| corrupt_error("package ZIP64 end record size is missing"))?;
        if read_u32(&zip64) != Some(ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE)
            || zip64_record_size < ZIP64_END_MINIMUM_RECORD_SIZE
            || zip64_offset
                .checked_add(12)
                .and_then(|offset| offset.checked_add(zip64_record_size))
                != Some(locator_offset)
            || read_u32(&zip64[16..]) != Some(0)
            || read_u32(&zip64[20..]) != Some(0)
        {
            return Err(corrupt_error("package ZIP64 end record is invalid"));
        }
        let entries_on_disk_64 = read_u64(&zip64[24..]).expect("bounded ZIP64 entry field");
        let entries_64 = read_u64(&zip64[32..]).expect("bounded ZIP64 entry field");
        if entries_on_disk_64 != entries_64 {
            return Err(security_error(
                "multi-disk ZIP64 packages are not supported",
            ));
        }
        (
            entries_64,
            read_u64(&zip64[40..]).expect("bounded ZIP64 central size"),
            read_u64(&zip64[48..]).expect("bounded ZIP64 central offset"),
            zip64_offset,
        )
    } else {
        if entries_on_disk != entries {
            return Err(security_error("multi-disk ZIP packages are not supported"));
        }
        (
            entries as u64,
            central_size_32 as u64,
            central_offset_32 as u64,
            eocd_offset,
        )
    };

    if entry_count == 0 || entry_count > limits.max_entries as u64 {
        return Err(security_error(
            "package exceeds the configured entry-count limit",
        ));
    }
    if central_size > limits.max_central_directory_bytes {
        return Err(security_error(
            "package central directory exceeds its configured limit",
        ));
    }
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| corrupt_error("package central-directory offset overflow"))?;
    if central_end != central_boundary || central_boundary > archive_bytes {
        return Err(corrupt_error(
            "package central-directory bounds are invalid",
        ));
    }
    validate_central_directory_entries(file, central_offset, central_size, entry_count, limits)?;

    Ok(CentralDirectoryInfo { entry_count })
}

fn validate_central_directory_entries(
    file: &mut File,
    central_offset: u64,
    central_size: u64,
    entry_count: u64,
    limits: PackageLimits,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    file.seek(SeekFrom::Start(central_offset))
        .map_err(|error| io_error("seek package central-directory entries", &error))?;
    let mut consumed = 0u64;
    let mut names = BTreeSet::new();

    for _ in 0..entry_count {
        let mut header = [0u8; CENTRAL_DIRECTORY_FILE_HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|_| corrupt_error("package central-directory entry is truncated"))?;
        consumed = consumed
            .checked_add(CENTRAL_DIRECTORY_FILE_HEADER_BYTES as u64)
            .ok_or_else(|| corrupt_error("package central-directory size overflow"))?;
        if read_u32(&header) != Some(CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE) {
            return Err(corrupt_error(
                "package central-directory entry signature is invalid",
            ));
        }

        let flags = read_u16(&header[8..]).expect("bounded central flags");
        let method = read_u16(&header[10..]).expect("bounded central method");
        let compressed_32 = read_u32(&header[20..]).expect("bounded central compressed size");
        let uncompressed_32 = read_u32(&header[24..]).expect("bounded central size");
        let name_len = read_u16(&header[28..]).expect("bounded central name length") as usize;
        let extra_len = read_u16(&header[30..]).expect("bounded central extra length") as usize;
        let comment_len = read_u16(&header[32..]).expect("bounded central comment length") as usize;
        let disk = read_u16(&header[34..]).expect("bounded central disk field");
        let variable_len = name_len
            .checked_add(extra_len)
            .and_then(|size| size.checked_add(comment_len))
            .ok_or_else(|| corrupt_error("package central-directory entry size overflow"))?;
        consumed = consumed
            .checked_add(variable_len as u64)
            .ok_or_else(|| corrupt_error("package central-directory size overflow"))?;
        if consumed > central_size || name_len > limits.max_entry_name_bytes {
            return Err(security_error(
                "package central-directory entry exceeds its configured limit",
            ));
        }

        let mut variable = vec![0u8; variable_len];
        file.read_exact(&mut variable)
            .map_err(|_| corrupt_error("package central-directory entry is truncated"))?;
        let raw_name = &variable[..name_len];
        let extra = &variable[name_len..name_len + extra_len];
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| security_error("package entry name is not UTF-8"))?;
        if !name.is_ascii() && flags & (1 << 11) == 0 {
            return Err(security_error(
                "non-ASCII package entry name lacks the UTF-8 flag",
            ));
        }
        validate_entry_name(name)?;
        if !names.insert(name.to_lowercase()) {
            return Err(security_error(
                "package contains duplicate or case-colliding entry names",
            ));
        }
        if comment_len != 0 {
            return Err(security_error(
                "package entries must not contain ZIP comments",
            ));
        }
        if flags & 1 != 0 || flags & (1 << 6) != 0 {
            return Err(security_error(
                "encrypted outer ZIP entries are not supported",
            ));
        }
        if disk != 0 {
            return Err(security_error("multi-disk ZIP entries are not supported"));
        }

        let (compressed, uncompressed) =
            central_entry_sizes(compressed_32, uncompressed_32, extra)?;
        if compressed == 0 && uncompressed != 0 {
            return Err(security_error(
                "package entry has an invalid compressed length",
            ));
        }
        if compressed != 0
            && exceeds_ratio(uncompressed, compressed, limits.max_outer_compression_ratio)
        {
            return Err(security_error(
                "package entry exceeds the outer compression-ratio limit",
            ));
        }
        if method != 0 || compressed != uncompressed {
            return Err(security_error(
                "package outer entries must use stored ZIP compression",
            ));
        }
    }

    if consumed != central_size {
        return Err(corrupt_error(
            "package central-directory size is inconsistent",
        ));
    }
    Ok(())
}

fn exceeds_ratio(uncompressed: u64, compressed: u64, maximum: u64) -> bool {
    (uncompressed as u128) > (compressed as u128) * (maximum as u128)
}

fn central_entry_sizes(
    compressed_32: u32,
    uncompressed_32: u32,
    extra: &[u8],
) -> Result<(u64, u64), Box<reforge_domain::ErrorEnvelope>> {
    let needs_uncompressed = uncompressed_32 == u32::MAX;
    let needs_compressed = compressed_32 == u32::MAX;
    if !needs_uncompressed && !needs_compressed {
        return Ok((compressed_32 as u64, uncompressed_32 as u64));
    }

    let mut offset = 0usize;
    while offset + 4 <= extra.len() {
        let field_id = read_u16(&extra[offset..]).expect("bounded extra-field ID");
        let field_len =
            read_u16(&extra[offset + 2..]).expect("bounded extra-field length") as usize;
        offset += 4;
        let end = offset
            .checked_add(field_len)
            .ok_or_else(|| corrupt_error("package ZIP extra-field size overflow"))?;
        if end > extra.len() {
            return Err(corrupt_error("package ZIP extra field is truncated"));
        }
        if field_id == ZIP64_EXTENDED_INFORMATION_EXTRA_FIELD {
            let field = &extra[offset..end];
            let mut cursor = 0usize;
            let uncompressed = if needs_uncompressed {
                let value = read_u64(&field[cursor..])
                    .ok_or_else(|| corrupt_error("package ZIP64 size field is truncated"))?;
                cursor += 8;
                value
            } else {
                uncompressed_32 as u64
            };
            let compressed = if needs_compressed {
                read_u64(&field[cursor..])
                    .ok_or_else(|| corrupt_error("package ZIP64 size field is truncated"))?
            } else {
                compressed_32 as u64
            };
            return Ok((compressed, uncompressed));
        }
        offset = end;
    }
    Err(corrupt_error("package ZIP64 size extra field is missing"))
}

fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

fn io_error(message: &str, error: &io::Error) -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(reforge_domain::ErrorEnvelope::from_io_error(error, message))
}
