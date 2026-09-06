#[allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use fixtures::FixtureRoot;
use reforge_domain::{
    Architecture, ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId,
    ComponentKind, Confidence, ConfigScope, ContentType, Identity, IdentityQuality,
    KnownFolderToken, LargeDataSelectionPolicy, ObjectEntry, ObjectId, ObjectIndex, PackageGraph,
    PackageManifest, PathToken, Portability, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy,
    SecretSelectionPolicy, SelectionInput, SelectionMetadata, SelectionPolicy, SourceHostSummary,
    TrustState, UnknownBinarySelectionPolicy,
};
use reforge_package::{
    ObjectStore, PackageLimits, PackageReader, PackageWriteRequest, PackageWriter,
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};
const END_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP64_END_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";

const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
const LOCAL_SIGNATURE: &[u8; 4] = b"PK\x03\x04";

struct PackageCase {
    temp: FixtureRoot,
    store: ObjectStore,
    manifest: PackageManifest,
    graph: PackageGraph,
    selection: SelectionInput,
    object_index: ObjectIndex,
    chunk_entry: ObjectEntry,
    chunk_frame: Vec<u8>,
}

impl PackageCase {
    fn new() -> Self {
        let temp = FixtureRoot::new("package-case").expect("temporary package root");
        let store = ObjectStore::open(temp.root().join("store")).expect("object store");
        let payload = b"reforge package round-trip payload".repeat(4_096);
        let stored = store
            .store_file(Cursor::new(&payload), ContentType::Binary, 0)
            .expect("stored file");
        let chunk_entry = stored.chunk_objects[0].entry.clone();
        let mut chunk_frame = Vec::new();
        store
            .copy_compressed_object(&chunk_entry, &mut chunk_frame)
            .expect("compressed chunk");

        let component_id =
            ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID");
        let artifact_id = ArtifactId::new("settings").expect("artifact ID");
        let component = Component {
            id: component_id.clone(),
            kind: ComponentKind::Application,
            identity: Identity {
                provider_package: None,
                provider_source: None,
                package_family: None,
                product_name: Some("Package fixture".to_owned()),
                executable_name: Some("fixture.exe".to_owned()),
                publisher: None,
                executable_hash: None,
                install_role: Some("application".to_owned()),
                identity_quality: IdentityQuality::Product,
            },
            display_name: "Package fixture".to_owned(),
            version: None,
            architecture: Some(Architecture::X64),
            publisher: None,
            provenance: None,
            evidence: Vec::new(),
            confidence: Confidence::High,
            dependencies: Vec::new(),
            artifacts: vec![ArtifactRef {
                id: artifact_id.clone(),
                source_path: PathToken::new(KnownFolderToken::Documents, "fixture/settings.bin")
                    .expect("tokenized path"),
                scope: ConfigScope::User,
                size_bytes: payload.len() as u64,
                content_type: ContentType::Binary,
                policy: ArtifactPolicy::Config,
                object: Some(stored.manifest_object.entry.id.clone()),
            }],
            restore: RestoreDescriptor {
                primary: RestoreStrategy::ConfigPortable,
                alternatives: Vec::new(),
                portability: Portability::Portable,
                requires_elevation: false,
                requires_user_action: false,
                rationale: vec!["fixture".to_owned()],
            },
            compatibility: Compatibility {
                required_os: Some("windows".to_owned()),
                required_architecture: Some(Architecture::X64),
                requires_provider: None,
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: Vec::new(),
            selection: SelectionMetadata {
                recommended: true,
                score: 100,
                selected_by_default: true,
                sensitive: false,
                size_bytes: payload.len() as u64,
            },
            extensions: BTreeMap::new(),
        };
        let graph = PackageGraph {
            components: vec![component],
            edges: Vec::new(),
        };
        let selection = SelectionInput {
            components: vec![component_id.clone()],
            artifacts: vec![reforge_domain::ArtifactSelection {
                artifact: artifact_id,
                include: true,
            }],
            policy: SelectionPolicy {
                secrets: SecretSelectionPolicy::Exclude,
                large_data: LargeDataSelectionPolicy::RequireConfirmation,
                unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
                max_bytes: None,
            },
        };
        let object_index = ObjectIndex {
            // Intentionally not ID-sorted. The writer must canonicalize the index.
            objects: vec![chunk_entry.clone(), stored.manifest_object.entry],
        };
        let manifest = PackageManifest {
            package_id: "pkg_fixture".to_owned(),
            format_version: 1,
            created_at: "2026-08-30T12:00:00Z".parse().expect("timestamp"),
            source_host: SourceHostSummary {
                os_version: "Windows 11".to_owned(),
                os_build: "26200".to_owned(),
                architecture: Architecture::X64,
                known_folder_tokens: vec![KnownFolderToken::Documents],
            },
            required_os: Some("windows".to_owned()),
            required_architecture: Some(Architecture::X64),
            component_ids: vec![component_id],
            warnings: Vec::new(),
            object_index_digest: PackageWriter::object_index_digest(&object_index)
                .expect("object-index digest"),
        };

        Self {
            temp,
            store,
            manifest,
            graph,
            selection,
            object_index,
            chunk_entry,
            chunk_frame,
        }
    }

    fn write(&self, name: &str) -> PathBuf {
        let path = self.temp.root().join(name);
        PackageWriter::default()
            .write(
                &path,
                PackageWriteRequest {
                    manifest: &self.manifest,
                    graph: &self.graph,
                    selection: &self.selection,
                    object_index: &self.object_index,
                    signature: None,
                    vault: None,
                },
                &self.store,
            )
            .expect("valid package write");
        path
    }
}

#[test]
fn round_trip_is_deterministic_and_uses_zip64_object_layout() {
    let case = PackageCase::new();
    let first = case.write("first.reforge");
    let second = case.write("second.reforge");
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let inspected = PackageReader::new(&first).inspect().expect("valid package");
    assert_eq!(inspected.manifest, case.manifest);
    assert_eq!(inspected.graph, case.graph);
    assert_eq!(inspected.selection, case.selection);
    assert_eq!(inspected.trust, TrustState::Unsigned);
    assert!(
        inspected
            .warnings
            .iter()
            .any(|warning| warning == "Package is unsigned")
    );
    assert_eq!(inspected.file_manifests.len(), 1);
    let file_manifest = inspected
        .file_manifests
        .values()
        .next()
        .expect("inspected file manifest");
    assert_eq!(
        file_manifest.size_bytes,
        case.graph.components[0].artifacts[0].size_bytes
    );
    assert_eq!(file_manifest.chunks[0].id, case.chunk_entry.id);
    let chunk_location = inspected
        .object_location(&case.chunk_entry.id)
        .expect("chunk location");
    assert!(chunk_location.contains(".chunks/0.zst"));

    let bytes = fs::read(&first).unwrap();
    let first_local = find_subslice(&bytes, LOCAL_SIGNATURE).expect("local ZIP header");
    let version_needed =
        u16::from_le_bytes(bytes[first_local + 4..first_local + 6].try_into().unwrap());
    assert!(
        version_needed >= 45,
        "writer must opt each entry into ZIP64"
    );

    let file = File::open(&first).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    for index in 0..archive.len() {
        assert_eq!(
            archive.by_index(index).unwrap().compression(),
            CompressionMethod::Stored
        );
    }
}

#[test]
fn reader_rejects_zip_slip_entry_name() {
    let temp = FixtureRoot::new("zip-slip").unwrap();
    let path = temp.root().join("zip-slip.reforge");
    create_raw_zip(&path, &[("../evil", b"x")]);

    assert_error_code(&path, ReforgeErrorCode::SecurityPolicy);
    assert!(!temp.root().join("evil").exists());
}

#[test]
fn reader_rejects_duplicate_entry_names() {
    let temp = FixtureRoot::new("duplicate-entry").unwrap();
    let path = temp.root().join("duplicate.reforge");
    create_raw_zip(
        &path,
        &[("one/entry.json", b"one"), ("two/entry.json", b"two")],
    );
    patch_all_equal(&path, b"two/entry.json", b"one/entry.json");

    assert_error_code(&path, ReforgeErrorCode::SecurityPolicy);
}

#[test]
fn reader_rejects_outer_compression_bomb_before_decompression() {
    let temp = FixtureRoot::new("compression-bomb").unwrap();
    let path = temp.root().join("bomb.reforge");
    create_raw_zip(&path, &[("bomb.dat", b"x")]);
    patch_declared_zip_size(&path, 1_000_000);

    assert_error_code(&path, ReforgeErrorCode::SecurityPolicy);
}

#[test]
fn reader_rejects_corrupt_central_directory() {
    let temp = FixtureRoot::new("corrupt-central-directory").unwrap();
    let path = temp.root().join("central.reforge");
    create_raw_zip(&path, &[("safe.dat", b"safe")]);
    let mut bytes = fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 8);
    fs::write(&path, bytes).unwrap();

    assert_error_code(&path, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn reader_parses_zip64_central_directory_before_schema_validation() {
    let temp = FixtureRoot::new("zip64-central-directory").unwrap();
    let path = temp.root().join("zip64.reforge");
    create_raw_zip(&path, &[("format/manifest.json", b"safe")]);
    promote_to_zip64(&path);

    let error = PackageReader::new(&path)
        .inspect()
        .expect_err("raw ZIP still lacks Reforge metadata");
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
    assert_eq!(error.message, "package is missing a required format entry");
}

#[test]
fn reader_rejects_missing_indexed_object() {
    let case = PackageCase::new();
    let path = case.write("missing-object.reforge");
    let inspected = PackageReader::new(&path).inspect().unwrap();
    let original = inspected
        .object_location(&case.chunk_entry.id)
        .unwrap()
        .as_bytes()
        .to_vec();
    let other_parent = ObjectId::from_content(b"unrelated parent object");
    let replacement = format!("objects/{}.chunks/0.zst", other_parent.as_str()).into_bytes();
    assert_eq!(original.len(), replacement.len());
    patch_all_equal(&path, &original, &replacement);

    assert_error_code(&path, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn reader_rejects_corrupt_object_frame() {
    let case = PackageCase::new();
    let path = case.write("corrupt-object.reforge");
    let mut bytes = fs::read(&path).unwrap();
    let offset = find_subslice(&bytes, &case.chunk_frame).expect("stored zstd frame in package");
    bytes[offset + case.chunk_frame.len() / 2] ^= 0x5a;
    fs::write(&path, bytes).unwrap();

    assert_error_code(&path, ReforgeErrorCode::PackageCorrupt);
}

#[test]
fn reader_enforces_entry_count_before_opening_archive_entries() {
    let case = PackageCase::new();
    let path = case.write("entry-limit.reforge");
    let limits = PackageLimits {
        max_entries: 6,
        ..PackageLimits::default()
    };
    let error = PackageReader::with_limits(&path, limits)
        .unwrap()
        .inspect()
        .expect_err("entry count must be bounded");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
}

fn assert_error_code(path: &Path, expected: ReforgeErrorCode) {
    let error = PackageReader::new(path)
        .inspect()
        .expect_err("malicious package must be rejected");
    assert_eq!(error.code, expected, "unexpected error: {error:?}");
}

fn create_raw_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        archive.start_file(*name, options).unwrap();
        archive.write_all(bytes).unwrap();
    }
    archive.finish().unwrap();
}

fn patch_all_equal(path: &Path, from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut bytes = fs::read(path).unwrap();
    let mut offset = 0;
    let mut replacements = 0;
    while let Some(relative) = find_subslice(&bytes[offset..], from) {
        let start = offset + relative;
        bytes[start..start + from.len()].copy_from_slice(to);
        offset = start + to.len();
        replacements += 1;
    }
    assert!(
        replacements >= 2,
        "local and central names must both be patched"
    );
    fs::write(path, bytes).unwrap();
}

fn patch_declared_zip_size(path: &Path, declared_size: u32) {
    let mut bytes = fs::read(path).unwrap();
    let local = find_subslice(&bytes, LOCAL_SIGNATURE).unwrap();
    bytes[local + 8..local + 10].copy_from_slice(&8u16.to_le_bytes());
    bytes[local + 22..local + 26].copy_from_slice(&declared_size.to_le_bytes());

    let central = find_subslice(&bytes, CENTRAL_SIGNATURE).unwrap();
    bytes[central + 10..central + 12].copy_from_slice(&8u16.to_le_bytes());
    bytes[central + 24..central + 28].copy_from_slice(&declared_size.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn promote_to_zip64(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let eocd = bytes
        .windows(END_SIGNATURE.len())
        .rposition(|candidate| candidate == END_SIGNATURE)
        .expect("end-of-central-directory record");
    let entries = u16::from_le_bytes(bytes[eocd + 10..eocd + 12].try_into().unwrap()) as u64;
    let central_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
    let central_offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as u64;

    let mut zip64_end = Vec::with_capacity(56);
    zip64_end.extend_from_slice(ZIP64_END_SIGNATURE);
    zip64_end.extend_from_slice(&44u64.to_le_bytes());
    zip64_end.extend_from_slice(&45u16.to_le_bytes());
    zip64_end.extend_from_slice(&45u16.to_le_bytes());
    zip64_end.extend_from_slice(&0u32.to_le_bytes());
    zip64_end.extend_from_slice(&0u32.to_le_bytes());
    zip64_end.extend_from_slice(&entries.to_le_bytes());
    zip64_end.extend_from_slice(&entries.to_le_bytes());
    zip64_end.extend_from_slice(&central_size.to_le_bytes());
    zip64_end.extend_from_slice(&central_offset.to_le_bytes());
    assert_eq!(zip64_end.len(), 56);

    let mut locator = Vec::with_capacity(20);
    locator.extend_from_slice(ZIP64_LOCATOR_SIGNATURE);
    locator.extend_from_slice(&0u32.to_le_bytes());
    locator.extend_from_slice(&(eocd as u64).to_le_bytes());
    locator.extend_from_slice(&1u32.to_le_bytes());

    let mut standard_end = bytes[eocd..].to_vec();
    standard_end[8..12].fill(0xff);
    standard_end[12..20].fill(0xff);
    let mut promoted = bytes[..eocd].to_vec();
    promoted.extend_from_slice(&zip64_end);
    promoted.extend_from_slice(&locator);
    promoted.extend_from_slice(&standard_end);
    fs::write(path, promoted).unwrap();
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}
