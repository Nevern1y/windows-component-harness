#![allow(dead_code)]

mod support;

use std::{collections::BTreeMap, io::Write};

use async_trait::async_trait;
use reforge_domain::{
    ContentType, FileMode, KnownFolderToken, MergePolicy, ObjectEntry, ObjectId, ObjectIndex,
    Operation, OperationId, OperationKind, Precondition, RunId,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use reforge_restore::{
    ConfigRestoreHandler, ExecutionContext, ObjectSource, OperationDisposition, OperationHandler,
    OperationSatisfaction, RestoreResult,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", "c".repeat(52))).expect("component ID")
}

fn roots(fixture: &FixtureRoot) -> KnownFolderMap {
    KnownFolderMap::from_entries(BTreeMap::from([(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    )]))
}

fn object(bytes: &[u8], content_type: ContentType) -> (ObjectId, ObjectIndex, ObjectEntry) {
    let id = ObjectId::from_content(bytes);
    let entry = ObjectEntry {
        id: id.clone(),
        uncompressed_bytes: bytes.len() as u64,
        compressed_bytes: bytes.len() as u64,
        content_type,
    };
    (
        id,
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

fn operation(
    destination: reforge_domain::PathToken,
    object: ObjectId,
    kind: ConfigKind,
    policy: MergePolicy,
) -> Operation {
    let operation_kind = match kind {
        ConfigKind::Json => OperationKind::MergeJson {
            destination,
            object,
            policy,
        },
        ConfigKind::Toml => OperationKind::MergeToml {
            destination,
            object,
            policy,
        },
    };
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind: operation_kind,
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:config-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

#[derive(Clone, Copy)]
enum ConfigKind {
    Json,
    Toml,
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    index: &'a ObjectIndex,
    source: &'a MemoryObjectSource,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, index).with_object_source(source)
}

#[tokio::test]
async fn json_preserve_unknown_merges_nested_values_and_keeps_target_data() {
    let fixture = FixtureRoot::new("handlers-config-json").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "config.json",
            br#"{"known":{"target":true},"keep":"target"}"#,
        )
        .expect("target config");
    let source_bytes = br#"{"known":{"source":true},"new":1}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.json")
        .expect("destination token");
    let operation = operation(
        destination,
        object_id,
        ConfigKind::Json,
        MergePolicy::PreserveUnknown,
    );
    let target = support::fixtures::target_facts();
    let outcome = ConfigRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("JSON merge");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let merged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::UserProfile, "config.json")
                .expect("merged config path"),
        )
        .expect("merged config"),
    )
    .expect("valid merged JSON");
    assert_eq!(merged["known"]["target"], true);
    assert_eq!(merged["known"]["source"], true);
    assert_eq!(merged["keep"], "target");
    assert_eq!(merged["new"], 1);
}

#[tokio::test]
async fn migration_merge_records_backup_and_verification_facts() {
    let fixture = FixtureRoot::new("handlers-config-migration-evidence").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "config.json",
            br#"{"target":true,"shared":"old"}"#,
        )
        .expect("target config");
    let source_bytes = br#"{"package":true,"shared":"new"}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let operation = operation(
        reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.json")
            .expect("destination token"),
        object_id,
        ConfigKind::Json,
        MergePolicy::ReplaceKnownKeys,
    );
    let target = support::fixtures::target_facts();
    let outcome = ConfigRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("migration merge");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    assert!(
        outcome.backup.is_some(),
        "target state is backed up before merge"
    );
    assert_eq!(
        outcome.evidence.len(),
        1,
        "merge records verification facts"
    );
    assert_eq!(outcome.evidence[0]["destination"], "config.json");
    let merged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::UserProfile, "config.json")
                .expect("merged config path"),
        )
        .expect("merged config"),
    )
    .expect("valid merged JSON");
    assert_eq!(merged["target"], true, "unrelated target data remains");
    assert_eq!(merged["package"], true);
    assert_eq!(merged["shared"], "new");
}

#[tokio::test]
async fn manual_on_conflict_preserves_the_target_and_pauses() {
    let fixture = FixtureRoot::new("handlers-config-conflict").expect("fixture root");
    let original = br#"{"setting":"target"}"#;
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "config.json", original)
        .expect("target config");
    let source_bytes = br#"{"setting":"package"}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.json")
        .expect("destination token");
    let operation = operation(
        destination,
        object_id,
        ConfigKind::Json,
        MergePolicy::ManualOnConflict,
    );
    let target = support::fixtures::target_facts();
    let outcome = ConfigRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("manual conflict outcome");
    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert_eq!(
        std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::UserProfile, "config.json")
                .expect("target config path"),
        )
        .expect("target config"),
        original,
    );
}

#[tokio::test]
async fn malformed_target_config_is_rejected_without_replacement() {
    let fixture = FixtureRoot::new("handlers-config-malformed").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "config.json",
            br#"{"setting": }"#,
        )
        .expect("malformed target config");
    let source_bytes = br#"{"setting":true}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.json")
        .expect("destination token");
    let operation = operation(
        destination,
        object_id,
        ConfigKind::Json,
        MergePolicy::ReplaceKnownKeys,
    );
    let target = support::fixtures::target_facts();
    let error = ConfigRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect_err("malformed target must fail");
    assert_eq!(error.code, reforge_domain::ReforgeErrorCode::SchemaInvalid);
}

#[tokio::test]
async fn toml_append_unique_keeps_existing_order() {
    let fixture = FixtureRoot::new("handlers-config-toml").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "config.toml",
            "paths = [\"target\", \"shared\"]\nkeep = true\n",
        )
        .expect("target TOML");
    let source_bytes = b"paths = [\"shared\", \"package\"]\nnew = 3\n";
    let (object_id, index, entry) = object(source_bytes, ContentType::Toml);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.toml")
        .expect("destination token");
    let operation = operation(
        destination,
        object_id,
        ConfigKind::Toml,
        MergePolicy::AppendUnique,
    );
    let target = support::fixtures::target_facts();
    let outcome = ConfigRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("TOML merge");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let merged: toml::Table = toml::from_str(
        std::str::from_utf8(
            &std::fs::read(
                fixture
                    .resolve_token(KnownFolderToken::UserProfile, "config.toml")
                    .expect("merged TOML path"),
            )
            .expect("merged TOML"),
        )
        .expect("UTF-8 TOML"),
    )
    .expect("valid merged TOML");
    assert_eq!(
        merged["paths"].as_array().expect("paths"),
        &vec![
            toml::Value::String("target".to_owned()),
            toml::Value::String("shared".to_owned()),
            toml::Value::String("package".to_owned()),
        ],
    );
    assert_eq!(merged["keep"].as_bool(), Some(true));
    assert_eq!(merged["new"].as_integer(), Some(3));
}

#[tokio::test]
async fn parseable_config_is_not_claimed_satisfied_without_merge_evidence() {
    let fixture = FixtureRoot::new("handlers-config-satisfaction").expect("fixture root");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "config.json", br#"{}"#)
        .expect("target config");
    let source_bytes = br#"{"new":true}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let destination = reforge_domain::PathToken::new(KnownFolderToken::UserProfile, "config.json")
        .expect("destination token");
    let operation = operation(
        destination,
        object_id,
        ConfigKind::Json,
        MergePolicy::PreserveUnknown,
    );
    let target = support::fixtures::target_facts();
    let satisfaction = ConfigRestoreHandler::new(roots(&fixture))
        .is_satisfied(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("satisfaction check");
    assert!(matches!(satisfaction, OperationSatisfaction::NotSatisfied));
}

#[allow(dead_code)]
fn _keep_file_mode_linked(_mode: FileMode) {}
