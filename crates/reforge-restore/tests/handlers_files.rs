#![allow(clippy::too_many_arguments)]
#![allow(dead_code)]

mod support;

use std::{collections::BTreeMap, io::Write};

use async_trait::async_trait;
use reforge_domain::{
    ChunkRef, ContentType, FileManifest, FileMode, KnownFolderToken, ObjectEntry, ObjectId,
    ObjectIndex, Operation, OperationId, OperationKind, Precondition, ReforgeErrorCode, RunId,
};
use reforge_package::{FILE_CHUNK_BYTES, canonicalize};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use reforge_restore::{
    ExecutionContext, FileRestoreHandler, ObjectSource, OperationHandler, OperationSatisfaction,
    RestoreResult,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", "f".repeat(52))).expect("component ID")
}

fn roots(fixture: &FixtureRoot) -> KnownFolderMap {
    KnownFolderMap::from_entries(BTreeMap::from([(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    )]))
}

fn operation(
    destination: reforge_domain::PathToken,
    object: ObjectId,
    mode: FileMode,
) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind: OperationKind::WriteFile {
            destination,
            object,
            mode,
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:file-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn target_object(bytes: &[u8]) -> (ObjectId, ObjectIndex, ObjectEntry) {
    let object = ObjectId::from_content(bytes);
    let entry = ObjectEntry {
        id: object.clone(),
        uncompressed_bytes: bytes.len() as u64,
        compressed_bytes: bytes.len() as u64,
        content_type: ContentType::Binary,
    };
    (
        object,
        ObjectIndex {
            objects: vec![entry.clone()],
        },
        entry,
    )
}

struct MemoryObjectSource {
    bytes: Vec<u8>,
    entry: ObjectEntry,
}

#[async_trait]
impl ObjectSource for MemoryObjectSource {
    fn copy_verified_object(
        &self,
        _object: &ObjectId,
        output: &mut dyn Write,
    ) -> RestoreResult<ObjectEntry> {
        output.write_all(&self.bytes).map_err(|error| {
            Box::new(reforge_domain::ErrorEnvelope::from_io_error(
                &error,
                "write fixture object",
            ))
        })?;
        Ok(self.entry.clone())
    }
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    index: &'a ObjectIndex,
    source: &'a dyn ObjectSource,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, index).with_object_source(source)
}

struct MappedObjectSource {
    objects: BTreeMap<ObjectId, (ObjectEntry, Vec<u8>)>,
}

impl ObjectSource for MappedObjectSource {
    fn copy_verified_object(
        &self,
        object: &ObjectId,
        output: &mut dyn Write,
    ) -> RestoreResult<ObjectEntry> {
        let (entry, bytes) = self.objects.get(object).ok_or_else(|| {
            reforge_restore::restore_error(
                ReforgeErrorCode::PackageNotFound,
                "fixture object is missing",
                None,
                None,
                None,
                Some("manifest-file-test"),
            )
        })?;
        output.write_all(bytes).map_err(|error| {
            reforge_restore::restore_error(
                ReforgeErrorCode::OperationFailed,
                "fixture object write failed",
                Some(&error.to_string()),
                None,
                None,
                Some("manifest-file-test"),
            )
        })?;
        Ok(entry.clone())
    }
}

fn manifest_artifact(
    chunks: Vec<Vec<u8>>,
) -> (
    ObjectId,
    ObjectIndex,
    BTreeMap<ObjectId, FileManifest>,
    MappedObjectSource,
    Vec<u8>,
) {
    let mut payload = Vec::new();
    let mut chunk_refs = Vec::new();
    let mut entries = Vec::new();
    let mut objects = BTreeMap::new();
    for bytes in chunks {
        payload.extend_from_slice(&bytes);
        let id = ObjectId::from_content(&bytes);
        let entry = ObjectEntry {
            id: id.clone(),
            uncompressed_bytes: bytes.len() as u64,
            compressed_bytes: bytes.len() as u64,
            content_type: ContentType::Binary,
        };
        chunk_refs.push(ChunkRef {
            id: id.clone(),
            uncompressed_bytes: bytes.len() as u64,
        });
        entries.push(entry.clone());
        objects.insert(id, (entry, bytes));
    }
    let manifest = FileManifest {
        size_bytes: payload.len() as u64,
        chunks: chunk_refs,
        content_type: ContentType::Binary,
        attributes: 0,
    };
    let canonical = canonicalize(&manifest).expect("canonical file manifest");
    let object = canonical.object_id().clone();
    let manifest_bytes = canonical.into_bytes();
    let manifest_entry = ObjectEntry {
        id: object.clone(),
        uncompressed_bytes: manifest_bytes.len() as u64,
        compressed_bytes: manifest_bytes.len() as u64,
        content_type: ContentType::Json,
    };
    entries.push(manifest_entry.clone());
    objects.insert(object.clone(), (manifest_entry, manifest_bytes));
    (
        object.clone(),
        ObjectIndex { objects: entries },
        BTreeMap::from([(object, manifest)]),
        MappedObjectSource { objects },
        payload,
    )
}

#[tokio::test]
async fn replaces_existing_file_and_returns_safe_backup() {
    let fixture = FixtureRoot::new("handlers-files-backup").expect("fixture root");
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "state.bin")
        .expect("destination token");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "state.bin", b"old")
        .expect("old file");
    let new_bytes = b"new file bytes";
    let (object, index, entry) = target_object(new_bytes);
    let source = MemoryObjectSource {
        bytes: new_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(destination, object, FileMode::Replace);
    let handler = FileRestoreHandler::new(roots(&fixture));
    let outcome = handler
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("file replacement");

    assert_eq!(
        outcome.disposition,
        reforge_restore::OperationDisposition::Completed
    );
    let backup = outcome.backup.expect("existing target backup");
    let backup_path = backup
        .get("path")
        .and_then(serde_json::Value::as_str)
        .expect("safe backup path");
    assert!(!backup_path.contains(':'));
    let installed = std::fs::read(
        fixture
            .resolve_token(KnownFolderToken::UserProfile, "state.bin")
            .expect("installed file path"),
    )
    .expect("installed file");
    assert_eq!(installed, new_bytes);
    let backup_bytes =
        std::fs::read(fixture.tokens().user_profile.join(backup_path)).expect("backup file");
    assert_eq!(backup_bytes, b"old");
}

#[tokio::test]
async fn create_only_rejects_a_racing_target() {
    let fixture = FixtureRoot::new("handlers-files-create-only").expect("fixture root");
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "state.bin")
        .expect("destination token");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "state.bin", b"target")
        .expect("target file");
    let bytes = b"package";
    let (object, index, entry) = target_object(bytes);
    let source = MemoryObjectSource {
        bytes: bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(destination, object, FileMode::CreateOnly);
    let error = FileRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("create-only collision");
    assert_eq!(error.code, reforge_domain::ReforgeErrorCode::TargetConflict);
}

#[tokio::test]
async fn protected_program_files_root_is_rejected() {
    let fixture = FixtureRoot::new("handlers-files-protected-root").expect("fixture root");
    let destination = reforge_domain::PathToken::new(KnownFolderToken::ProgramFiles, "managed.exe")
        .expect("destination token");
    let bytes = b"package";
    let (object, index, entry) = target_object(bytes);
    let source = MemoryObjectSource {
        bytes: bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(destination, object, FileMode::Replace);
    let error = FileRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("protected root");
    assert_eq!(error.code, reforge_domain::ReforgeErrorCode::SecurityPolicy);
}

#[tokio::test]
async fn already_matching_file_is_reported_as_satisfied() {
    let fixture = FixtureRoot::new("handlers-files-satisfied").expect("fixture root");
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "state.bin")
        .expect("destination token");
    let bytes = b"already installed";
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "state.bin", bytes)
        .expect("target file");
    let (object, index, entry) = target_object(bytes);
    let source = MemoryObjectSource {
        bytes: bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(destination, object, FileMode::Replace);
    let satisfaction = FileRestoreHandler::new(roots(&fixture))
        .is_satisfied(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("satisfaction check");
    assert!(matches!(
        satisfaction,
        OperationSatisfaction::Satisfied { .. }
    ));
}

#[tokio::test]
async fn manifest_backed_file_reconstructs_chunks_in_order_and_is_idempotent() {
    let fixture = FixtureRoot::new("handlers-files-manifest").expect("fixture root");
    let destination =
        reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "manifest-backed.bin")
            .expect("destination token");
    let first = vec![b'a'; FILE_CHUNK_BYTES];
    let second = b"ordered-tail".to_vec();
    let (object, index, manifests, source, payload) = manifest_artifact(vec![first, second]);
    let target = support::fixtures::target_facts();
    let operation = operation(destination.clone(), object.clone(), FileMode::Replace);
    let context = ExecutionContext::new(&target, &index)
        .with_object_source(&source)
        .with_file_manifests(&manifests);
    let handler = FileRestoreHandler::new(roots(&fixture));

    let outcome = handler
        .execute(&operation, &context, &CancellationToken::new())
        .await
        .expect("manifest-backed file restore");
    assert_eq!(outcome.evidence[0]["object_id"], object.as_str());

    let installed = std::fs::read(
        fixture
            .resolve_token(KnownFolderToken::UserProfile, "manifest-backed.bin")
            .expect("installed file path"),
    )
    .expect("installed file");
    assert_eq!(installed, payload);
    let satisfaction = handler
        .is_satisfied(&operation, &context, &CancellationToken::new())
        .await
        .expect("manifest-backed satisfaction check");
    assert!(matches!(
        satisfaction,
        OperationSatisfaction::Satisfied { .. }
    ));
}

#[tokio::test]
async fn manifest_backed_file_rejects_a_missing_indexed_chunk() {
    let fixture = FixtureRoot::new("handlers-files-missing-chunk").expect("fixture root");
    let destination =
        reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "missing-chunk.bin")
            .expect("destination token");
    let (object, mut index, manifests, source, _) =
        manifest_artifact(vec![b"package payload".to_vec()]);
    let missing = manifests[&object].chunks[0].id.clone();
    index.objects.retain(|entry| entry.id != missing);
    let target = support::fixtures::target_facts();
    let context = ExecutionContext::new(&target, &index)
        .with_object_source(&source)
        .with_file_manifests(&manifests);

    let error = FileRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(destination, object, FileMode::Replace),
            &context,
            &CancellationToken::new(),
        )
        .await
        .expect_err("missing manifest chunk must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::PackageCorrupt);
}

#[tokio::test]
async fn manifest_backed_file_rejects_corrupt_chunk_bytes_and_payload_bounds() {
    let fixture = FixtureRoot::new("handlers-files-corrupt-chunk").expect("fixture root");
    let destination =
        reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "corrupt-chunk.bin")
            .expect("destination token");
    let (object, index, manifests, mut source, payload) =
        manifest_artifact(vec![b"package payload".to_vec()]);
    let chunk = manifests[&object].chunks[0].id.clone();
    source.objects.get_mut(&chunk).expect("chunk object").1[0] ^= 0xff;
    let target = support::fixtures::target_facts();
    let context = ExecutionContext::new(&target, &index)
        .with_object_source(&source)
        .with_file_manifests(&manifests);
    let operation = operation(destination, object.clone(), FileMode::Replace);

    let corrupt = FileRestoreHandler::new(roots(&fixture))
        .execute(&operation, &context, &CancellationToken::new())
        .await
        .expect_err("corrupt manifest chunk must fail closed");
    assert_eq!(corrupt.code, ReforgeErrorCode::PackageCorrupt);

    let bounded = FileRestoreHandler::new(roots(&fixture))
        .with_max_object_bytes(payload.len() as u64 - 1)
        .expect("nonzero handler bound")
        .execute(&operation, &context, &CancellationToken::new())
        .await
        .expect_err("manifest payload over the handler bound must fail closed");
    assert_eq!(bounded.code, ReforgeErrorCode::SecurityPolicy);
}
