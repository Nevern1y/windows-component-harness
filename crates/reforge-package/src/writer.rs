//! Deterministic ZIP64 package writer.
//!
//! The outer archive stores canonical metadata and already-compressed zstd
//! object frames. Every object is revalidated in the content store before the
//! package becomes visible at its destination.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use reforge_domain::{
    ComponentId, EvidenceId, FileManifest, ObjectEntry, ObjectId, ObjectIndex, PackageGraph,
    PackageManifest, Provenance, ReforgeErrorCode, RestoreDescriptor, SecretSelectionPolicy,
    SelectionInput, TransportReceipt,
};
use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{EncryptedVault, ObjectStore, PackageSignature, canonicalize};

pub const MANIFEST_ENTRY: &str = "format/manifest.json";
pub const GRAPH_ENTRY: &str = "format/graph.json";
pub const SELECTION_ENTRY: &str = "format/selection.json";
pub const OPERATIONS_ENTRY: &str = "format/operations.json";
pub const OBJECT_INDEX_ENTRY: &str = "format/object-index.json";
pub const SOURCES_ENTRY: &str = "format/sources.json";
pub const VAULT_ENTRY: &str = "vault/age-v1.txt";
pub const SIGNATURE_MANIFEST_ENTRY: &str = "signatures/manifest.json";
pub const SIGNATURE_ENTRY: &str = "signatures/manifest.sig";

pub const REQUIRED_FORMAT_ENTRIES: [&str; 6] = [
    MANIFEST_ENTRY,
    GRAPH_ENTRY,
    SELECTION_ENTRY,
    OPERATIONS_ENTRY,
    OBJECT_INDEX_ENTRY,
    SOURCES_ENTRY,
];

const SUPPORTED_FORMAT_VERSION: u16 = 1;
const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 4 * 1_099_511_627_776;
const DEFAULT_MAX_ENTRIES: usize = 1_000_000;
const DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_METADATA_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_METADATA_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_OBJECT_BYTES: u64 = 4 * 1_099_511_627_776;
const DEFAULT_MAX_ENTRY_NAME_BYTES: usize = 1_024;
const DEFAULT_MAX_OUTER_COMPRESSION_RATIO: u64 = 100;
const TEMP_NAME_ATTEMPTS: usize = 128;
const FILE_CHUNK_BYTES_U64: u64 = crate::FILE_CHUNK_BYTES as u64;
const WINDOWS_REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

static NEXT_PACKAGE_TEMP_ID: AtomicU64 = AtomicU64::new(1);

/// Security and resource limits applied before archive content is trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageLimits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_central_directory_bytes: u64,
    pub max_metadata_entry_bytes: u64,
    pub max_total_metadata_bytes: u64,
    pub max_total_object_bytes: u64,
    pub max_entry_name_bytes: usize,
    pub max_outer_compression_ratio: u64,
}

impl PackageLimits {
    pub fn validate(self) -> Result<Self, Box<reforge_domain::ErrorEnvelope>> {
        if self.max_archive_bytes == 0
            || self.max_entries < REQUIRED_FORMAT_ENTRIES.len()
            || self.max_central_directory_bytes == 0
            || self.max_metadata_entry_bytes == 0
            || self.max_total_metadata_bytes < self.max_metadata_entry_bytes
            || self.max_total_object_bytes == 0
            || self.max_entry_name_bytes == 0
            || self.max_outer_compression_ratio == 0
        {
            return Err(security_error(
                "package limits are invalid or internally inconsistent",
            ));
        }
        Ok(self)
    }
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_central_directory_bytes: DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
            max_metadata_entry_bytes: DEFAULT_MAX_METADATA_ENTRY_BYTES,
            max_total_metadata_bytes: DEFAULT_MAX_TOTAL_METADATA_BYTES,
            max_total_object_bytes: DEFAULT_MAX_TOTAL_OBJECT_BYTES,
            max_entry_name_bytes: DEFAULT_MAX_ENTRY_NAME_BYTES,
            max_outer_compression_ratio: DEFAULT_MAX_OUTER_COMPRESSION_RATIO,
        }
    }
}

/// Required immutable inputs for one standalone package.
pub struct PackageWriteRequest<'a> {
    pub manifest: &'a PackageManifest,
    pub graph: &'a PackageGraph,
    pub selection: &'a SelectionInput,
    pub object_index: &'a ObjectIndex,
    pub signature: Option<&'a PackageSignature>,
    pub vault: Option<&'a EncryptedVault>,
}

pub type PackageOperations = BTreeMap<ComponentId, RestoreDescriptor>;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageSourceRecord {
    pub provenance: Option<Provenance>,
    pub claim_ids: Vec<EvidenceId>,
}

pub type PackageSources = BTreeMap<ComponentId, PackageSourceRecord>;

/// Writes validated packages with deterministic entry ordering.
#[derive(Clone, Copy, Debug, Default)]
pub struct PackageWriter {
    limits: PackageLimits,
}

impl PackageWriter {
    pub fn new(limits: PackageLimits) -> Result<Self, Box<reforge_domain::ErrorEnvelope>> {
        Ok(Self {
            limits: limits.validate()?,
        })
    }

    pub fn limits(&self) -> PackageLimits {
        self.limits
    }

    /// Compute the exact digest stored in `PackageManifest::object_index_digest`.
    pub fn object_index_digest(
        object_index: &ObjectIndex,
    ) -> Result<String, Box<reforge_domain::ErrorEnvelope>> {
        let normalized = normalize_object_index(object_index)?;
        Ok(canonicalize(&normalized)?.object_id().as_str().to_owned())
    }

    /// Validate every input and atomically publish one `.reforge` file.
    pub fn write(
        &self,
        destination: impl AsRef<Path>,
        request: PackageWriteRequest<'_>,
        store: &ObjectStore,
    ) -> Result<TransportReceipt, Box<reforge_domain::ErrorEnvelope>> {
        let prepared = self.prepare(request, store)?;
        let destination = destination.as_ref();
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| io_error("create package output directory", &error))?;
        validate_directory(parent)?;
        reject_existing_destination(destination)?;

        let (mut temp, file) = create_temp_file(parent)?;
        let mut archive = ZipWriter::new(file);
        let options = package_file_options();

        for (name, bytes) in &prepared.metadata_entries {
            archive
                .start_file(*name, options)
                .map_err(|error| zip_write_error("start package metadata entry", &error))?;
            archive
                .write_all(bytes)
                .map_err(|error| io_error("write package metadata entry", &error))?;
        }

        if let Some(vault) = prepared.vault {
            archive
                .start_file(VAULT_ENTRY, options)
                .map_err(|error| zip_write_error("start package vault entry", &error))?;
            archive
                .write_all(vault.as_bytes())
                .map_err(|error| io_error("write package vault entry", &error))?;
        }

        if let Some(signature) = prepared.signature {
            archive
                .start_file(SIGNATURE_MANIFEST_ENTRY, options)
                .map_err(|error| zip_write_error("start signature metadata entry", &error))?;
            archive
                .write_all(signature.metadata_bytes())
                .map_err(|error| io_error("write signature metadata entry", &error))?;
            archive
                .start_file(SIGNATURE_ENTRY, options)
                .map_err(|error| zip_write_error("start package signature entry", &error))?;
            archive
                .write_all(signature.signature_bytes())
                .map_err(|error| io_error("write package signature entry", &error))?;
        }

        for (name, entry) in &prepared.object_entries {
            archive
                .start_file(name, options)
                .map_err(|error| zip_write_error("start package object entry", &error))?;
            let copied = store.copy_compressed_object(entry, &mut archive)?;
            if copied != entry.compressed_bytes {
                return Err(corrupt_error(
                    "content store object length changed during package write",
                ));
            }
        }

        let file = archive
            .finish()
            .map_err(|error| zip_write_error("finish package central directory", &error))?;
        file.sync_all()
            .map_err(|error| io_error("persist package file", &error))?;
        drop(file);

        let package_bytes = fs::metadata(&temp.path)
            .map_err(|error| io_error("inspect staged package", &error))?
            .len();
        if package_bytes > self.limits.max_archive_bytes {
            return Err(security_error(
                "package exceeds the configured archive size limit",
            ));
        }

        fs::rename(&temp.path, destination)
            .map_err(|error| io_error("publish package file", &error))?;
        temp.active = false;

        Ok(TransportReceipt {
            package_id: prepared.package_id,
            object_count: prepared.object_count,
            index_digest: prepared.index_digest,
        })
    }

    fn prepare<'a>(
        &self,
        request: PackageWriteRequest<'a>,
        store: &ObjectStore,
    ) -> Result<PreparedPackage<'a>, Box<reforge_domain::ErrorEnvelope>> {
        let normalized_index = normalize_object_index(request.object_index)?;
        validate_package_documents(
            request.manifest,
            request.graph,
            request.selection,
            &normalized_index,
        )?;
        validate_vault_policy(request.selection, request.vault.is_some())?;

        let canonical_index = canonicalize(&normalized_index)?;
        let index_digest = canonical_index.object_id().as_str().to_owned();
        let object_index_bytes = canonical_index.into_bytes();
        if request.manifest.object_index_digest != index_digest {
            return Err(schema_error(
                "package manifest object-index digest is stale",
            ));
        }

        let total_object_bytes =
            normalized_index
                .objects
                .iter()
                .try_fold(0u64, |total, entry| {
                    total
                        .checked_add(entry.uncompressed_bytes)
                        .ok_or_else(|| security_error("package object size total overflow"))
                })?;
        if total_object_bytes > self.limits.max_total_object_bytes {
            return Err(security_error(
                "package objects exceed the configured size limit",
            ));
        }

        let indexed: BTreeMap<_, _> = normalized_index
            .objects
            .iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        for entry in &normalized_index.objects {
            store.verify_object(entry)?;
        }

        let file_manifests = load_file_manifests(
            request.graph,
            &indexed,
            store,
            self.limits.max_metadata_entry_bytes,
        )?;
        let locations = object_locations(&normalized_index, &file_manifests)?;

        let operations = derive_operations(request.graph)?;
        let sources = derive_sources(request.graph)?;
        let manifest_bytes = canonicalize(request.manifest)?.into_bytes();
        if let Some(signature) = request.signature
            && !signature.verify_canonical(&manifest_bytes, &object_index_bytes)?
        {
            return Err(Box::new(reforge_domain::ErrorEnvelope::new(
                ReforgeErrorCode::PackageUntrusted,
                "Provided package signature does not cover the package documents",
            )));
        }
        let metadata_entries = vec![
            (MANIFEST_ENTRY, manifest_bytes),
            (GRAPH_ENTRY, canonicalize(request.graph)?.into_bytes()),
            (
                SELECTION_ENTRY,
                canonicalize(request.selection)?.into_bytes(),
            ),
            (OPERATIONS_ENTRY, canonicalize(&operations)?.into_bytes()),
            (OBJECT_INDEX_ENTRY, object_index_bytes),
            (SOURCES_ENTRY, canonicalize(&sources)?.into_bytes()),
        ];
        validate_metadata_sizes(
            &metadata_entries,
            request.vault,
            request.signature,
            self.limits,
        )?;

        let mut object_entries: Vec<_> = normalized_index
            .objects
            .iter()
            .map(|entry| {
                let name = locations
                    .get(&entry.id)
                    .expect("every normalized object has one package location")
                    .clone();
                (name, entry.clone())
            })
            .collect();
        object_entries.sort_by(|left, right| left.0.cmp(&right.0));

        let optional_entries = usize::from(request.vault.is_some())
            .checked_add(usize::from(request.signature.is_some()) * 2)
            .ok_or_else(|| security_error("package entry count overflow"))?;
        let entry_count = metadata_entries
            .len()
            .checked_add(optional_entries)
            .and_then(|count| count.checked_add(object_entries.len()))
            .ok_or_else(|| security_error("package entry count overflow"))?;
        if entry_count > self.limits.max_entries {
            return Err(security_error(
                "package exceeds the configured entry-count limit",
            ));
        }

        Ok(PreparedPackage {
            package_id: request.manifest.package_id.clone(),
            object_count: normalized_index.objects.len() as u64,
            index_digest,
            metadata_entries,
            vault: request.vault,
            signature: request.signature,
            object_entries,
        })
    }
}

struct PreparedPackage<'a> {
    package_id: String,
    object_count: u64,
    index_digest: String,
    metadata_entries: Vec<(&'static str, Vec<u8>)>,
    object_entries: Vec<(String, ObjectEntry)>,
    vault: Option<&'a EncryptedVault>,
    signature: Option<&'a PackageSignature>,
}

pub(crate) fn normalize_object_index(
    object_index: &ObjectIndex,
) -> Result<ObjectIndex, Box<reforge_domain::ErrorEnvelope>> {
    let mut objects = object_index.objects.clone();
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    for pair in objects.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(schema_error("object index contains duplicate object IDs"));
        }
    }
    Ok(ObjectIndex { objects })
}

pub(crate) fn validate_vault_policy(
    selection: &SelectionInput,
    has_vault: bool,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    match (&selection.policy.secrets, has_vault) {
        (SecretSelectionPolicy::Exclude, false) | (SecretSelectionPolicy::VaultExplicit, true) => {
            Ok(())
        }
        (SecretSelectionPolicy::VaultExplicit, false) => {
            Err(Box::new(reforge_domain::ErrorEnvelope::new(
                ReforgeErrorCode::VaultRequired,
                "Explicit secret selection requires an encrypted vault",
            )))
        }
        (SecretSelectionPolicy::Exclude, true) => Err(security_error(
            "an encrypted vault requires explicit secret selection",
        )),
    }
}

pub(crate) fn validate_package_documents(
    manifest: &PackageManifest,
    graph: &PackageGraph,
    selection: &SelectionInput,
    object_index: &ObjectIndex,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    if manifest.format_version != SUPPORTED_FORMAT_VERSION {
        return Err(Box::new(reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::UnsupportedVersion,
            "Package format version is not supported",
        )));
    }
    if manifest.package_id.is_empty() || manifest.package_id.len() > 256 {
        return Err(schema_error("package ID is empty or too long"));
    }

    let mut components = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    for component in &graph.components {
        if components.insert(component.id.clone(), component).is_some() {
            return Err(schema_error(
                "package graph contains duplicate component IDs",
            ));
        }
        for artifact in &component.artifacts {
            if artifacts.insert(artifact.id.clone(), artifact).is_some() {
                return Err(schema_error(
                    "package graph contains duplicate artifact IDs",
                ));
            }
        }
    }
    for edge in &graph.edges {
        if !components.contains_key(&edge.from) || !components.contains_key(&edge.to) {
            return Err(schema_error(
                "package graph edge references a missing component",
            ));
        }
    }

    let manifest_components: BTreeSet<_> = manifest.component_ids.iter().cloned().collect();
    if manifest_components.len() != manifest.component_ids.len()
        || manifest_components != components.keys().cloned().collect()
    {
        return Err(schema_error(
            "manifest component IDs do not match the package graph",
        ));
    }

    let mut selected_components = BTreeSet::new();
    for component in &selection.components {
        if !selected_components.insert(component.clone()) || !components.contains_key(component) {
            return Err(schema_error(
                "package selection contains an invalid component",
            ));
        }
    }
    let mut selected_artifacts = BTreeSet::new();
    for decision in &selection.artifacts {
        let Some(artifact) = artifacts.get(&decision.artifact) else {
            return Err(schema_error(
                "package selection contains an invalid artifact",
            ));
        };
        if !selected_artifacts.insert(decision.artifact.clone()) {
            return Err(schema_error(
                "package selection contains an invalid artifact",
            ));
        }
        let content_optional = matches!(
            artifact.policy,
            reforge_domain::ArtifactPolicy::Manual
                | reforge_domain::ArtifactPolicy::SecretReference
        );
        if decision.include && artifact.object.is_none() && !content_optional {
            return Err(schema_error(
                "selected package artifact is missing its content object",
            ));
        }
        if !decision.include && artifact.object.is_some() {
            return Err(schema_error(
                "excluded package artifact must not retain a content object",
            ));
        }
    }

    let indexed: BTreeSet<_> = object_index
        .objects
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    if indexed.len() != object_index.objects.len() {
        return Err(schema_error("object index contains duplicate object IDs"));
    }
    for component in &graph.components {
        for artifact in &component.artifacts {
            if let Some(object) = &artifact.object
                && !indexed.contains(object)
            {
                return Err(schema_error(
                    "artifact references an object missing from the index",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn derive_operations(
    graph: &PackageGraph,
) -> Result<PackageOperations, Box<reforge_domain::ErrorEnvelope>> {
    let mut operations = BTreeMap::new();
    for component in &graph.components {
        if operations
            .insert(component.id.clone(), component.restore.clone())
            .is_some()
        {
            return Err(schema_error(
                "package operations contain a duplicate component",
            ));
        }
    }
    Ok(operations)
}

pub(crate) fn derive_sources(
    graph: &PackageGraph,
) -> Result<PackageSources, Box<reforge_domain::ErrorEnvelope>> {
    let mut sources = BTreeMap::new();
    for component in &graph.components {
        let mut claim_ids: Vec<_> = component
            .evidence
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect();
        claim_ids.sort();
        if claim_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(schema_error("package source contains a duplicate claim ID"));
        }
        if component.provenance.is_none() && claim_ids.is_empty() {
            continue;
        }
        let record = PackageSourceRecord {
            provenance: component.provenance.clone(),
            claim_ids,
        };
        if sources.insert(component.id.clone(), record).is_some() {
            return Err(schema_error(
                "package sources contain a duplicate component",
            ));
        }
    }
    Ok(sources)
}

pub(crate) fn object_locations(
    object_index: &ObjectIndex,
    file_manifests: &BTreeMap<ObjectId, FileManifest>,
) -> Result<BTreeMap<ObjectId, String>, Box<reforge_domain::ErrorEnvelope>> {
    let indexed: BTreeSet<_> = object_index
        .objects
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    let mut chunk_locations = BTreeMap::<ObjectId, String>::new();
    let mut reachable: BTreeSet<_> = file_manifests.keys().cloned().collect();

    for (manifest_id, manifest) in file_manifests {
        for (index, chunk) in manifest.chunks.iter().enumerate() {
            if chunk.id == *manifest_id || file_manifests.contains_key(&chunk.id) {
                return Err(schema_error(
                    "file manifest object must not also be used as a file chunk",
                ));
            }
            if !indexed.contains(&chunk.id) {
                return Err(schema_error(
                    "file manifest chunk is missing from the object index",
                ));
            }
            reachable.insert(chunk.id.clone());
            let candidate = format!("objects/{}.chunks/{index}.zst", manifest_id.as_str());
            chunk_locations
                .entry(chunk.id.clone())
                .and_modify(|existing| {
                    if candidate < *existing {
                        *existing = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }
    if reachable != indexed {
        return Err(schema_error(
            "object index contains missing or unreachable package objects",
        ));
    }

    Ok(object_index
        .objects
        .iter()
        .map(|entry| {
            let location = chunk_locations
                .get(&entry.id)
                .cloned()
                .unwrap_or_else(|| format!("objects/{}.zst", entry.id.as_str()));
            (entry.id.clone(), location)
        })
        .collect())
}

fn load_file_manifests(
    graph: &PackageGraph,
    indexed: &BTreeMap<ObjectId, &ObjectEntry>,
    store: &ObjectStore,
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
            if entry.content_type != reforge_domain::ContentType::Json {
                return Err(schema_error(
                    "file manifest object must have JSON content type",
                ));
            }
            let bytes = read_store_object(store, entry, max_metadata_bytes)?;
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

pub(crate) fn validate_file_manifest(
    manifest: &FileManifest,
    expected_file_bytes: u64,
    expected_content_type: &reforge_domain::ContentType,
    indexed: &BTreeMap<ObjectId, &ObjectEntry>,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    if manifest.size_bytes != expected_file_bytes || &manifest.content_type != expected_content_type
    {
        return Err(schema_error(
            "file manifest metadata does not match its artifact",
        ));
    }
    let mut total = 0u64;
    for (index, chunk) in manifest.chunks.iter().enumerate() {
        if chunk.uncompressed_bytes == 0 || chunk.uncompressed_bytes > FILE_CHUNK_BYTES_U64 {
            return Err(schema_error(
                "file manifest contains an invalid chunk length",
            ));
        }
        if index + 1 != manifest.chunks.len() && chunk.uncompressed_bytes != FILE_CHUNK_BYTES_U64 {
            return Err(schema_error("non-final file chunk is not exactly 8 MiB"));
        }
        let entry = indexed
            .get(&chunk.id)
            .ok_or_else(|| schema_error("file manifest chunk is missing from the object index"))?;
        if entry.uncompressed_bytes != chunk.uncompressed_bytes {
            return Err(schema_error(
                "file manifest chunk length disagrees with the object index",
            ));
        }
        if entry.content_type != manifest.content_type {
            return Err(schema_error(
                "file chunk content type disagrees with its manifest",
            ));
        }
        total = total
            .checked_add(chunk.uncompressed_bytes)
            .ok_or_else(|| schema_error("file manifest size overflow"))?;
    }
    if total != manifest.size_bytes
        || (manifest.size_bytes == 0 && !manifest.chunks.is_empty())
        || (manifest.size_bytes != 0 && manifest.chunks.is_empty())
    {
        return Err(schema_error(
            "file manifest chunks do not reconstruct the declared file size",
        ));
    }
    Ok(())
}

fn read_store_object(
    store: &ObjectStore,
    entry: &ObjectEntry,
    max_bytes: u64,
) -> Result<Vec<u8>, Box<reforge_domain::ErrorEnvelope>> {
    if entry.uncompressed_bytes > max_bytes || entry.compressed_bytes > max_bytes {
        return Err(security_error(
            "file manifest object exceeds the metadata size limit",
        ));
    }
    let capacity = usize::try_from(entry.compressed_bytes)
        .map_err(|_| security_error("compressed metadata size cannot be represented"))?;
    let mut compressed = Vec::with_capacity(capacity);
    store.copy_compressed_object(entry, &mut compressed)?;

    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .map_err(|_| corrupt_error("file manifest object is not a valid zstd frame"))?;
    decoder
        .window_log_max(27)
        .map_err(|_| corrupt_error("file manifest zstd window is unsafe"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(entry.uncompressed_bytes)
            .map_err(|_| security_error("metadata size cannot be represented"))?,
    );
    decoder
        .read_to_end(&mut bytes)
        .map_err(|_| corrupt_error("file manifest object could not be decoded"))?;
    if bytes.len() as u64 != entry.uncompressed_bytes || ObjectId::from_content(&bytes) != entry.id
    {
        return Err(corrupt_error(
            "file manifest object failed hash or length verification",
        ));
    }
    Ok(bytes)
}

fn validate_metadata_sizes(
    entries: &[(&str, Vec<u8>)],
    vault: Option<&EncryptedVault>,
    signature: Option<&PackageSignature>,
    limits: PackageLimits,
) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let mut total = 0u64;
    let entries = entries
        .iter()
        .map(|(name, bytes)| (*name, bytes.as_slice()))
        .chain(
            vault
                .into_iter()
                .map(|vault| (VAULT_ENTRY, vault.as_bytes())),
        )
        .chain(signature.into_iter().flat_map(|signature| {
            [
                (SIGNATURE_MANIFEST_ENTRY, signature.metadata_bytes()),
                (SIGNATURE_ENTRY, &signature.signature_bytes()[..]),
            ]
        }));
    for (name, bytes) in entries {
        if name.len() > limits.max_entry_name_bytes
            || bytes.len() as u64 > limits.max_metadata_entry_bytes
        {
            return Err(security_error(
                "package metadata entry exceeds its configured limit",
            ));
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| security_error("package metadata size total overflow"))?;
    }
    if total > limits.max_total_metadata_bytes {
        return Err(security_error(
            "package metadata exceeds its configured total limit",
        ));
    }
    Ok(())
}

fn package_file_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o600)
}
struct TempPackageGuard {
    path: PathBuf,
    active: bool,
}

impl Drop for TempPackageGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp_file(
    parent: &Path,
) -> Result<(TempPackageGuard, File), Box<reforge_domain::ErrorEnvelope>> {
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let id = NEXT_PACKAGE_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".reforge-package-{}-{id}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                return Ok((TempPackageGuard { path, active: true }, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("create staged package", &error)),
        }
    }
    Err(Box::new(reforge_domain::ErrorEnvelope::new(
        ReforgeErrorCode::TargetConflict,
        "A unique staged package name could not be allocated",
    )))
}

fn reject_existing_destination(path: &Path) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Box::new(reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::TargetConflict,
            "Package output already exists",
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect package output", &error)),
    }
}

fn validate_directory(path: &Path) -> Result<(), Box<reforge_domain::ErrorEnvelope>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect package output directory", &error))?;
    if is_reparse_point(&metadata) {
        return Err(Box::new(reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::ReparsePoint,
            "Package output directory must not be a reparse point",
        )));
    }
    if !metadata.is_dir() {
        return Err(Box::new(reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::InvalidPath,
            "Package output parent must be a directory",
        )));
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

fn zip_write_error(
    message: &str,
    error: &zip::result::ZipError,
) -> Box<reforge_domain::ErrorEnvelope> {
    match error {
        zip::result::ZipError::Io(error) => io_error(message, error),
        _ => Box::new(reforge_domain::ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            message,
        )),
    }
}

fn io_error(message: &str, error: &io::Error) -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(reforge_domain::ErrorEnvelope::from_io_error(error, message))
}

pub(crate) fn schema_error(message: &str) -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(reforge_domain::ErrorEnvelope::new(
        ReforgeErrorCode::SchemaInvalid,
        message,
    ))
}

pub(crate) fn security_error(message: &str) -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(reforge_domain::ErrorEnvelope::new(
        ReforgeErrorCode::SecurityPolicy,
        message,
    ))
}

pub(crate) fn corrupt_error(message: &str) -> Box<reforge_domain::ErrorEnvelope> {
    Box::new(reforge_domain::ErrorEnvelope::new(
        ReforgeErrorCode::PackageCorrupt,
        message,
    ))
}
