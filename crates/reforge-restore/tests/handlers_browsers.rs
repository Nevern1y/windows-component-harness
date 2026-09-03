#![allow(dead_code)]

mod support;

use std::{collections::BTreeMap, io::Write};

use async_trait::async_trait;
use reforge_domain::{
    ComponentId, ContentType, FileMode, KnownFolderToken, ManualActionState, MergePolicy,
    ObjectEntry, ObjectId, ObjectIndex, Operation, OperationId, OperationKind, PathToken,
    Precondition, RunId,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use reforge_restore::{
    BrowserAwareRestoreHandler, BrowserRestoreHandler, ExecutionContext, ObjectSource,
    OperationDisposition, OperationHandler, RestoreResult,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "b".repeat(52))).expect("component ID")
}

fn roots(fixture: &FixtureRoot) -> KnownFolderMap {
    KnownFolderMap::from_entries(BTreeMap::from([
        (
            KnownFolderToken::LocalAppData,
            fixture.tokens().local_app_data.clone(),
        ),
        (
            KnownFolderToken::RoamingAppData,
            fixture.tokens().roaming_app_data.clone(),
        ),
    ]))
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
                "write browser fixture object",
            ))
        })?;
        Ok(self.entry.clone())
    }
}

fn operation(kind: OperationKind) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id(),
        kind,
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:browser-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn context<'a>(
    target: &'a reforge_domain::TargetFacts,
    index: &'a ObjectIndex,
    source: &'a MemoryObjectSource,
) -> ExecutionContext<'a> {
    ExecutionContext::new(target, index).with_object_source(source)
}

fn chromium_path(file: &str) -> PathToken {
    PathToken::new(
        KnownFolderToken::LocalAppData,
        format!("Google/Chrome/User Data/Default/{file}"),
    )
    .expect("browser artifact path")
}

#[tokio::test]
async fn locked_browser_profile_pauses_without_touching_the_target() {
    let fixture = FixtureRoot::new("handlers-browser-locked").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/LOCK",
            b"active",
        )
        .expect("browser lock marker");
    let source_bytes = br#"{"homepage":"https://example.invalid"}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(OperationKind::MergeJson {
        destination: chromium_path("Preferences"),
        object: object_id,
        policy: MergePolicy::PreserveUnknown,
    });

    let outcome = BrowserAwareRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("locked profile decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(
        outcome
            .result
            .as_ref()
            .and_then(|value| value["reason"].as_str())
            .is_some_and(|reason| reason.contains("close the browser"))
    );
    assert!(
        !fixture
            .resolve_token(
                KnownFolderToken::LocalAppData,
                "Google/Chrome/User Data/Default/Preferences",
            )
            .expect("preferences path")
            .exists()
    );
}

#[tokio::test]
async fn unsupported_profile_item_becomes_manual_and_is_never_written() {
    let fixture = FixtureRoot::new("handlers-browser-unsupported").expect("fixture root");
    let source_bytes = b"cookie database bytes";
    let (object_id, index, entry) = object(source_bytes, ContentType::Binary);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let destination = chromium_path("Cookies");
    let operation = operation(OperationKind::WriteFile {
        destination: destination.clone(),
        object: object_id,
        mode: FileMode::CreateOnly,
    });

    let outcome = BrowserAwareRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("unsupported item decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(
        outcome
            .result
            .as_ref()
            .and_then(|value| value["reason"].as_str())
            .is_some_and(|reason| reason.contains("portable subset"))
    );
    assert!(
        !fixture
            .resolve_token(destination.root, destination.relative.as_str())
            .expect("cookies path")
            .exists()
    );
}

#[tokio::test]
async fn portable_preferences_use_policy_driven_json_merge() {
    let fixture = FixtureRoot::new("handlers-browser-preferences").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Preferences",
            br#"{"target_only":true,"nested":{"target":1}}"#,
        )
        .expect("target preferences");
    let source_bytes = br#"{"nested":{"source":2},"source_only":true}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(OperationKind::MergeJson {
        destination: chromium_path("Preferences"),
        object: object_id,
        policy: MergePolicy::PreserveUnknown,
    });

    let outcome = BrowserAwareRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("portable preference merge");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let merged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(
                    KnownFolderToken::LocalAppData,
                    "Google/Chrome/User Data/Default/Preferences",
                )
                .expect("preferences path"),
        )
        .expect("merged preferences"),
    )
    .expect("valid preferences JSON");
    assert_eq!(merged["target_only"], true);
    assert_eq!(merged["nested"]["target"], 1);
    assert_eq!(merged["nested"]["source"], 2);
    assert_eq!(merged["source_only"], true);
}

#[tokio::test]
async fn generic_config_operations_continue_through_the_browser_aware_handler() {
    let fixture = FixtureRoot::new("handlers-browser-aware-generic").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Example/settings.json",
            br#"{"target_only":true}"#,
        )
        .expect("target settings");
    let source_bytes = br#"{"source_only":true}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();
    let operation = operation(OperationKind::MergeJson {
        destination: PathToken::new(KnownFolderToken::LocalAppData, "Example/settings.json")
            .expect("generic config path"),
        object: object_id,
        policy: MergePolicy::PreserveUnknown,
    });

    let outcome = BrowserAwareRestoreHandler::new(roots(&fixture))
        .execute(
            &operation,
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("generic config restore");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let merged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::LocalAppData, "Example/settings.json")
                .expect("generic settings path"),
        )
        .expect("merged generic settings"),
    )
    .expect("valid generic settings JSON");
    assert_eq!(merged["target_only"], true);
    assert_eq!(merged["source_only"], true);
}

#[test]
fn default_browser_choice_is_an_explicit_pending_windows_action() {
    let action = BrowserRestoreHandler::default_browser_action(component_id());

    assert_eq!(action.state, ManualActionState::Pending);
    assert!(action.title.contains("default browser"));
    assert!(action.reason.contains("UserChoice"));
    assert!(
        action
            .instructions
            .iter()
            .any(|instruction| instruction.contains("Windows Settings"))
    );
    assert!(action.independent_operations_may_continue);
}
