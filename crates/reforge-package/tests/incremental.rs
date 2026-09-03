#[allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use fixtures::FixtureRoot;
use reforge_domain::{
    Architecture, ArtifactId, ArtifactPolicy, ArtifactRef, ArtifactSelection, Compatibility,
    Component, ComponentId, ComponentKind, Confidence, ConfigScope, ContentType, Identity,
    IdentityQuality, KnownFolderToken, LargeDataSelectionPolicy, ObjectEntry, ObjectId,
    ObjectIndex, PackageGraph, PackageManifest, PathToken, Portability, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, SecretSelectionPolicy, SelectionInput, SelectionMetadata,
    SelectionPolicy, SourceHostSummary, UnknownBinarySelectionPolicy,
};
use reforge_package::{
    ObjectStore, PackageWriteRequest, PackageWriter,
    content_store::{PackageSetResolver, ResolvedObject},
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

struct IncrementalFixture {
    temp: FixtureRoot,
}

struct PackageFile {
    path: PathBuf,
    entries: Vec<ObjectEntry>,
    object_location: String,
}

impl IncrementalFixture {
    fn new() -> Self {
        Self {
            temp: FixtureRoot::new("incremental-resolver").expect("temporary resolver root"),
        }
    }

    fn write_package(&self, label: &str, bytes: &[u8], content_type: ContentType) -> PackageFile {
        let store = ObjectStore::open(self.temp.root().join(format!("{label}-store")))
            .expect("object store");
        let stored = store
            .store_file(Cursor::new(bytes), content_type.clone(), 0)
            .expect("stored package file");
        let entry = stored.chunk_objects[0].entry.clone();
        let object_location = format!(
            "objects/{}.chunks/0.zst",
            stored.manifest_object.entry.id.as_str()
        );
        let object_index = ObjectIndex {
            objects: stored
                .chunk_objects
                .iter()
                .map(|chunk| chunk.entry.clone())
                .chain(std::iter::once(stored.manifest_object.entry.clone()))
                .collect(),
        };
        let component_id =
            ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID");
        let artifact_id = ArtifactId::new("payload").expect("artifact ID");
        let component = Component {
            id: component_id.clone(),
            kind: ComponentKind::Application,
            identity: Identity {
                provider_package: None,
                provider_source: None,
                package_family: None,
                product_name: Some("Incremental fixture".to_owned()),
                executable_name: None,
                publisher: None,
                executable_hash: None,
                install_role: Some("fixture".to_owned()),
                identity_quality: IdentityQuality::Product,
            },
            display_name: "Incremental fixture".to_owned(),
            version: None,
            architecture: Some(Architecture::X64),
            publisher: None,
            provenance: None,
            evidence: Vec::new(),
            confidence: Confidence::High,
            dependencies: Vec::new(),
            artifacts: vec![ArtifactRef {
                id: artifact_id.clone(),
                source_path: PathToken::new(
                    KnownFolderToken::Documents,
                    format!("{label}/payload.bin"),
                )
                .expect("artifact path"),
                scope: ConfigScope::User,
                size_bytes: bytes.len() as u64,
                content_type,
                policy: ArtifactPolicy::Config,
                object: Some(stored.manifest_object.entry.id.clone()),
            }],
            restore: RestoreDescriptor {
                primary: RestoreStrategy::ConfigPortable,
                alternatives: Vec::new(),
                portability: Portability::Portable,
                requires_elevation: false,
                requires_user_action: false,
                rationale: vec!["incremental fixture".to_owned()],
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
                size_bytes: bytes.len() as u64,
            },
            extensions: BTreeMap::new(),
        };
        let graph = PackageGraph {
            components: vec![component],
            edges: Vec::new(),
        };
        let selection = SelectionInput {
            components: vec![component_id.clone()],
            artifacts: vec![ArtifactSelection {
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
        let manifest = PackageManifest {
            package_id: format!("pkg_{label}"),
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
        let path = self.temp.root().join(format!("{label}.reforge"));
        PackageWriter::default()
            .write(
                &path,
                PackageWriteRequest {
                    manifest: &manifest,
                    graph: &graph,
                    selection: &selection,
                    object_index: &object_index,
                    signature: None,
                    vault: None,
                },
                &store,
            )
            .expect("package write");
        PackageFile {
            path,
            entries: vec![entry],
            object_location,
        }
    }
}

#[test]
fn base_and_delta_roots_reuse_objects_without_a_second_format() {
    let fixture = IncrementalFixture::new();
    let base_bytes = b"object retained from the base snapshot";
    let delta_bytes = b"object introduced by the delta snapshot";
    let base = fixture.write_package("base", base_bytes, ContentType::Binary);
    let delta = fixture.write_package("delta", delta_bytes, ContentType::Utf8Text);
    let resolver = PackageSetResolver::open([delta.path.clone(), base.path.clone()])
        .expect("ordered package resolver");

    assert_eq!(resolver.root_count(), 2);
    assert!(!resolver.is_empty());

    let mut base_output = Vec::new();
    let base_resolution = resolver
        .resolve_object(&base.entries[0].id, &mut base_output)
        .expect("base object resolution");
    assert_eq!(base_output, base_bytes);
    assert_eq!(base_resolution.source_root_index, 1);
    assert_eq!(base_resolution.verified_root_indices, vec![1]);

    let mut delta_output = Vec::new();
    let delta_resolution = resolver
        .resolve_object(&delta.entries[0].id, &mut delta_output)
        .expect("delta object resolution");
    assert_eq!(delta_output, delta_bytes);
    assert_eq!(delta_resolution.source_root_index, 0);
    assert_eq!(delta_resolution.verified_root_indices, vec![0]);
}

#[test]
fn standalone_package_resolves_without_a_base() {
    let fixture = IncrementalFixture::new();
    let bytes = b"standalone package object";
    let package = fixture.write_package("standalone", bytes, ContentType::Binary);
    let resolver = PackageSetResolver::open([package.path]).expect("standalone resolver");

    let mut output = Vec::new();
    let resolution = resolver
        .resolve_object(&package.entries[0].id, &mut output)
        .expect("standalone object resolution");
    assert_eq!(output, bytes);
    assert_eq!(
        resolution,
        ResolvedObject {
            entry: package.entries[0].clone(),
            source_root_index: 0,
            verified_root_indices: vec![0],
        }
    );
}

#[test]
fn missing_base_object_is_a_typed_error_and_writes_nothing() {
    let fixture = IncrementalFixture::new();
    let delta = fixture.write_package("missing-base-delta", b"delta", ContentType::Binary);
    let resolver = PackageSetResolver::open([delta.path]).expect("delta resolver");
    let missing = ObjectId::from_content(b"required base object");
    let mut output = Vec::new();

    let error = resolver.resolve_object(&missing, &mut output).unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::PackageNotFound);
    assert_eq!(error.context_id.as_deref(), Some("package-object-missing"));
    assert!(output.is_empty());
}

#[test]
fn conflicting_same_id_bytes_block_resolution_before_output() {
    let fixture = IncrementalFixture::new();
    let original = vec![b'a'; 4_096];
    let conflicting = vec![b'b'; original.len()];
    let first = fixture.write_package("conflict-first", &original, ContentType::Binary);
    let second = fixture.write_package("conflict-second", &original, ContentType::Binary);
    let resolver = PackageSetResolver::open([first.path.clone(), second.path.clone()])
        .expect("resolver before mutation");

    let replacement_frame = encode_object_frame(&conflicting);
    assert_eq!(
        replacement_frame.len() as u64,
        second.entries[0].compressed_bytes,
        "fixture mutation must preserve the indexed frame length"
    );
    rewrite_entry(&second.path, &second.object_location, &replacement_frame);

    let mut output = Vec::new();
    let error = resolver
        .resolve_object(&first.entries[0].id, &mut output)
        .unwrap_err();
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
    assert_eq!(error.context_id.as_deref(), Some("package-object-conflict"));
    assert!(
        error
            .technical_detail
            .as_deref()
            .is_some_and(|detail| detail.contains(first.entries[0].id.as_str()))
    );
    assert!(output.is_empty());
}

#[test]
fn duplicate_candidates_resolve_from_the_first_root_deterministically() {
    let fixture = IncrementalFixture::new();
    let bytes = b"identical object in two package roots";
    let first = fixture.write_package("deterministic-first", bytes, ContentType::Binary);
    let second = fixture.write_package("deterministic-second", bytes, ContentType::Binary);
    let resolver = PackageSetResolver::open([second.path, first.path]).expect("ordered resolver");

    for _ in 0..2 {
        let mut output = Vec::new();
        let resolution = resolver
            .resolve_object(&first.entries[0].id, &mut output)
            .expect("duplicate object resolution");
        assert_eq!(output, bytes);
        assert_eq!(resolution.source_root_index, 0);
        assert_eq!(resolution.verified_root_indices, vec![0, 1]);
    }
}

fn encode_object_frame(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).expect("zstd encoder");
    encoder.include_checksum(true).expect("zstd checksum");
    encoder
        .include_contentsize(true)
        .expect("zstd content size");
    encoder
        .set_pledged_src_size(Some(bytes.len() as u64))
        .expect("zstd pledged size");
    encoder.write_all(bytes).expect("zstd object bytes");
    encoder.finish().expect("zstd object frame")
}

fn rewrite_entry(package: &Path, entry_name: &str, replacement: &[u8]) {
    let original_bytes = fs::metadata(package).expect("original metadata").len();
    let source = File::open(package).expect("source package");
    let mut source = ZipArchive::new(source).expect("source ZIP");
    let replacement_path = package.with_extension("replacement");
    let destination = File::create(&replacement_path).expect("replacement package");
    let mut destination = ZipWriter::new(destination);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o600);

    for index in 0..source.len() {
        let mut entry = source.by_index(index).expect("source entry");
        let name = entry.name().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("source entry bytes");
        if name == entry_name {
            bytes.clear();
            bytes.extend_from_slice(replacement);
        }
        destination
            .start_file(name, options)
            .expect("replacement entry");
        destination
            .write_all(&bytes)
            .expect("replacement entry bytes");
    }
    destination.finish().expect("finish replacement package");
    drop(source);
    fs::remove_file(package).expect("remove original package");
    fs::rename(replacement_path, package).expect("publish replacement package");
    assert_eq!(
        fs::metadata(package).expect("replacement metadata").len(),
        original_bytes,
        "fixture rewrite must preserve archive length"
    );
}
