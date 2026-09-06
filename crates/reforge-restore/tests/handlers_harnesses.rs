#![allow(dead_code)]

mod support;

use std::{collections::BTreeMap, io::Write};

use async_trait::async_trait;
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, ChunkRef, ComponentId, ConfigScope, ContentType,
    EnvBinding, ExecutableRef, FileManifest, KnownFolderToken, McpServerSpec, McpTransport,
    ObjectEntry, ObjectId, ObjectIndex, Operation, OperationId, OperationKind, PathToken,
    Precondition, ReforgeErrorCode, RunId, RuntimeFact, SafeValueRef,
};
use reforge_package::canonicalize;
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use reforge_restore::{
    ExecutionContext, HarnessRestoreHandler, ObjectSource, OperationDisposition, OperationHandler,
    RestoreResult,
};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id(seed: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", seed.to_string().repeat(52))).expect("component ID")
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
                "write MCP fixture object",
            ))
        })?;
        Ok(self.entry.clone())
    }
}

fn source_config(object: ObjectId, content_type: ContentType) -> ArtifactRef {
    ArtifactRef {
        id: ArtifactId::new("mcp-restore-config").expect("artifact ID"),
        source_path: PathToken::new(KnownFolderToken::UserProfile, ".codex/config.json")
            .expect("source path"),
        scope: ConfigScope::User,
        size_bytes: 512,
        content_type,
        policy: ArtifactPolicy::Config,
        object: Some(object),
    }
}

fn server(object: ObjectId, content_type: ContentType) -> McpServerSpec {
    McpServerSpec {
        name: "context7".to_owned(),
        scope: ConfigScope::User,
        transport: McpTransport::Stdio,
        command: Some(ExecutableRef {
            name: "npx.cmd".to_owned(),
            component: None,
            observed_path: None,
        }),
        args: vec![
            SafeValueRef::LiteralNonSecret("-y".to_owned()),
            SafeValueRef::LiteralNonSecret("@upstash/context7-mcp@1.0.0".to_owned()),
        ],
        cwd: None,
        endpoint: None,
        environment: vec![EnvBinding {
            name: "LOG_LEVEL".to_owned(),
            value: SafeValueRef::LiteralNonSecret("info".to_owned()),
        }],
        required_runtime: None,
        required_package: None,
        source_config: source_config(object, content_type),
    }
}

fn operation(server: McpServerSpec) -> Operation {
    Operation {
        id: OperationId::for_run(&run_id(), 0).expect("operation ID"),
        component: component_id('m'),
        kind: OperationKind::RegisterMcp { server },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: "restore-v1:mcp-handler-test".to_owned(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
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
                Some("manifest-mcp-test"),
            )
        })?;
        output.write_all(bytes).map_err(|error| {
            reforge_restore::restore_error(
                ReforgeErrorCode::OperationFailed,
                "fixture object write failed",
                Some(&error.to_string()),
                None,
                None,
                Some("manifest-mcp-test"),
            )
        })?;
        Ok(entry.clone())
    }
}

#[tokio::test]
async fn merges_normalized_mcp_server_and_preserves_unrelated_target_config() {
    let fixture = FixtureRoot::new("handlers-mcp-merge").expect("fixture root");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/config.json",
            br#"{"theme":"dark","mcpServers":{"existing":{"type":"stdio","command":"tool"}}}"#,
        )
        .expect("target config");
    let source_bytes = br#"{"mcpServers":{"context7":{"type":"stdio","command":"npx.cmd","args":["-y","@upstash/context7-mcp@1.0.0"],"env":{"LOG_LEVEL":"info"}}}}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let target = support::fixtures::target_facts();

    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(server(object_id, ContentType::Json)),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("MCP registration");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let merged: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::UserProfile, ".codex/config.json")
                .expect("target config path"),
        )
        .expect("merged target config"),
    )
    .expect("valid merged JSON");
    assert_eq!(merged["theme"], "dark");
    assert_eq!(merged["mcpServers"]["existing"]["command"], "tool");
    assert_eq!(merged["mcpServers"]["context7"]["command"], "npx.cmd");
    assert_eq!(merged["mcpServers"]["context7"]["env"]["LOG_LEVEL"], "info");
}

#[tokio::test]
async fn secret_reference_never_enters_config_bytes_and_requires_reauthentication() {
    let fixture = FixtureRoot::new("handlers-mcp-secret").expect("fixture root");
    let source_bytes = br#"{"mcpServers":{"context7":{"type":"stdio","command":"npx.cmd","env":{"CONTEXT7_API_KEY":"fixture-secret"}}}}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let mut spec = server(object_id, ContentType::Json);
    spec.environment = vec![EnvBinding {
        name: "CONTEXT7_API_KEY".to_owned(),
        value: SafeValueRef::SecretReference {
            id: component_id('s'),
            label: "Context7 API key".to_owned(),
        },
    }];
    let target = support::fixtures::target_facts();

    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(spec),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("secret-bound MCP decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    let restored = std::fs::read_to_string(
        fixture
            .resolve_token(KnownFolderToken::UserProfile, ".codex/config.json")
            .expect("target path"),
    )
    .expect("safe partial MCP config");
    assert!(!restored.contains("fixture-secret"));
    assert!(!restored.contains("CONTEXT7_API_KEY"));
    assert!(restored.contains("npx.cmd"));
    let result = outcome.result.expect("manual result").to_string();
    assert!(!result.contains("fixture-secret"));
    assert!(result.contains("reauth"));
}

#[tokio::test]
async fn secret_like_literal_is_dropped_instead_of_written_as_safe_config() {
    let fixture = FixtureRoot::new("handlers-mcp-secret-literal").expect("fixture root");
    let source_bytes = br#"{"mcpServers":{"context7":{"type":"stdio","command":"npx.cmd","env":{"LOG_LEVEL":"api_key=do-not-copy"}}}}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let mut spec = server(object_id, ContentType::Json);
    spec.environment[0].value = SafeValueRef::LiteralNonSecret("api_key=do-not-copy".to_owned());
    let target = support::fixtures::target_facts();

    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(spec),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("secret-like literal decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    let bytes = std::fs::read(
        fixture
            .resolve_token(KnownFolderToken::UserProfile, ".codex/config.json")
            .expect("target path"),
    )
    .expect("normalized config");
    assert!(
        !String::from_utf8(bytes)
            .expect("UTF-8 config")
            .contains("do-not-copy")
    );
}

#[tokio::test]
async fn missing_required_runtime_pauses_before_config_mutation() {
    let fixture = FixtureRoot::new("handlers-mcp-runtime").expect("fixture root");
    let source_bytes = br#"{"mcpServers":{"context7":{"type":"stdio","command":"npx.cmd"}}}"#;
    let (object_id, index, entry) = object(source_bytes, ContentType::Json);
    let source = MemoryObjectSource {
        bytes: source_bytes.to_vec(),
        entry,
    };
    let mut spec = server(object_id, ContentType::Json);
    let required_runtime = component_id('r');
    spec.required_runtime = Some(required_runtime.clone());
    let target = support::fixtures::target_facts();

    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(spec),
            &context(&target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("missing runtime decision");

    assert_eq!(outcome.disposition, OperationDisposition::WaitingForUser);
    assert!(
        !fixture
            .resolve_token(KnownFolderToken::UserProfile, ".codex/config.json")
            .expect("target path")
            .exists()
    );

    let mut complete_target = target;
    complete_target.runtimes.push(RuntimeFact {
        id: required_runtime,
        version: None,
        architecture: None,
    });
    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(server(
                ObjectId::from_content(source_bytes),
                ContentType::Json,
            )),
            &context(&complete_target, &index, &source),
            &CancellationToken::new(),
        )
        .await
        .expect("present runtime registration");
    assert_eq!(outcome.disposition, OperationDisposition::Completed);
}

#[tokio::test]
async fn mcp_registration_reads_the_manifest_payload_instead_of_manifest_json() {
    let fixture = FixtureRoot::new("handlers-mcp-manifest").expect("fixture root");
    let payload = br#"{"mcpServers":{"context7":{"type":"stdio","command":"npx.cmd","args":["-y","@upstash/context7-mcp@1.0.0"],"env":{"LOG_LEVEL":"info"}}}}"#.to_vec();
    let chunk_id = ObjectId::from_content(&payload);
    let chunk_entry = ObjectEntry {
        id: chunk_id.clone(),
        uncompressed_bytes: payload.len() as u64,
        compressed_bytes: payload.len() as u64,
        content_type: ContentType::Json,
    };
    let manifest = FileManifest {
        size_bytes: payload.len() as u64,
        chunks: vec![ChunkRef {
            id: chunk_id.clone(),
            uncompressed_bytes: payload.len() as u64,
        }],
        content_type: ContentType::Json,
        attributes: 0,
    };
    let canonical = canonicalize(&manifest).expect("canonical file manifest");
    let object_id = canonical.object_id().clone();
    let manifest_bytes = canonical.into_bytes();
    let manifest_entry = ObjectEntry {
        id: object_id.clone(),
        uncompressed_bytes: manifest_bytes.len() as u64,
        compressed_bytes: manifest_bytes.len() as u64,
        content_type: ContentType::Json,
    };
    let index = ObjectIndex {
        objects: vec![manifest_entry.clone(), chunk_entry.clone()],
    };
    let manifests = BTreeMap::from([(object_id.clone(), manifest)]);
    let source = MappedObjectSource {
        objects: BTreeMap::from([
            (object_id.clone(), (manifest_entry, manifest_bytes)),
            (chunk_id, (chunk_entry, payload)),
        ]),
    };
    let target = support::fixtures::target_facts();
    let context = ExecutionContext::new(&target, &index)
        .with_object_source(&source)
        .with_file_manifests(&manifests);

    let outcome = HarnessRestoreHandler::new(roots(&fixture))
        .execute(
            &operation(server(object_id, ContentType::Json)),
            &context,
            &CancellationToken::new(),
        )
        .await
        .expect("manifest-backed MCP registration");

    assert_eq!(outcome.disposition, OperationDisposition::Completed);
    let restored: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            fixture
                .resolve_token(KnownFolderToken::UserProfile, ".codex/config.json")
                .expect("restored config path"),
        )
        .expect("restored config"),
    )
    .expect("valid restored JSON");
    assert_eq!(restored["mcpServers"]["context7"]["command"], "npx.cmd");
    assert!(restored.get("chunks").is_none());
}
