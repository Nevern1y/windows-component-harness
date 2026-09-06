#![allow(dead_code)]

#[path = "../support.rs"]
mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::harnesses::{
    McpReferenceCatalog, OpenCodeAdapter, OpenCodeConfigOwner, OpenCodeConfigSource,
    OpenCodeDiscoveryOptions, OpenCodeTrustScope,
};
use reforge_domain::{
    ComponentKind, ConfigScope, ExecutableRef, KnownFolderToken, PathToken, ReforgeErrorCode,
    RestoreStrategy,
};
use reforge_platform_windows::KnownFolderMap;

use crate::support::FixtureRoot;

const GLOBAL_CONFIG: &[u8] =
    include_bytes!("../../../../tests/fixtures/harnesses/opencode/config.jsonc");
const MANAGED_CONFIG: &[u8] =
    include_bytes!("../../../../tests/fixtures/harnesses/opencode/managed.jsonc");
const INVALID_CONFIG: &[u8] =
    include_bytes!("../../../../tests/fixtures/harnesses/opencode/invalid.jsonc");

fn observed_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn fixture_context(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let mut entries = BTreeMap::new();
    entries.insert(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    );
    entries.insert(
        KnownFolderToken::ProgramData,
        fixture.tokens().program_data.clone(),
    );
    (fixture, KnownFolderMap::from_entries(entries))
}

fn references() -> McpReferenceCatalog {
    let mut references = McpReferenceCatalog::default();
    references.register_executable(ExecutableRef {
        name: "node".to_owned(),
        component: None,
        observed_path: None,
    });
    references
}

#[test]
fn discovers_precedence_managed_state_metadata_and_symbolic_mcp() {
    let (fixture, known_folders) = fixture_context("opencode-discovery");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".config/opencode/opencode.jsonc",
            GLOBAL_CONFIG,
        )
        .expect("global OpenCode config fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".config/opencode/tui.json",
            br#"{"theme":"dark"}"#,
        )
        .expect("global TUI config fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".opencode/commands/user-review.md",
            b"User review command metadata.\n",
        )
        .expect("user command fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".opencode/agents/user-reviewer.md",
            b"User reviewer metadata.\n",
        )
        .expect("user agent fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".opencode/instructions/user.md",
            b"User instructions metadata.\n",
        )
        .expect("user instruction fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".opencode/plugins/user-plugin.ts",
            b"export default {};\n",
        )
        .expect("user plugin fixture");

    let project_root =
        PathToken::new(KnownFolderToken::UserProfile, "project").expect("project token");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/opencode.json",
            br#"{"model":"project-model","mcp":{"project-server":{"type":"local","command":"node","args":["project-server.js"]}}}"#,
        )
        .expect("project OpenCode config fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.opencode/commands/project-review.md",
            b"Project command metadata.\n",
        )
        .expect("project command fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.opencode/agents/project-reviewer.md",
            b"Project agent metadata.\n",
        )
        .expect("project agent fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.opencode/instructions/project.md",
            b"Project instructions metadata.\n",
        )
        .expect("project instruction fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.opencode/plugins/project-plugin.ts",
            b"export default {};\n",
        )
        .expect("project plugin fixture");

    fixture
        .write_tokenized(
            KnownFolderToken::ProgramData,
            "opencode/opencode.jsonc",
            MANAGED_CONFIG,
        )
        .expect("managed OpenCode config fixture");

    let custom_path = fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "custom/opencode.jsonc",
            br#"{"model":"${CUSTOM_MODEL}","plugin":["custom-plugin"]}"#,
        )
        .expect("custom OpenCode config fixture");
    let _custom_dir_file = fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "custom-dir/opencode.json",
            br#"{"model":"custom-directory-model"}"#,
        )
        .expect("custom OpenCode config directory fixture");
    let custom_dir = fixture
        .resolve_token(KnownFolderToken::UserProfile, "custom-dir")
        .expect("custom OpenCode config directory path");
    let mut environment = BTreeMap::new();
    environment.insert(
        "OPENCODE_CONFIG".to_owned(),
        custom_path.display().to_string(),
    );
    environment.insert(
        "OPENCODE_CONFIG_DIR".to_owned(),
        custom_dir.display().to_string(),
    );

    let options = OpenCodeDiscoveryOptions {
        project_roots: vec![project_root.clone()],
        project_trust: BTreeMap::from([(
            format!("UserProfile/{}", project_root.relative),
            OpenCodeTrustScope::Untrusted,
        )]),
        environment,
        references: references(),
        observed_at: Some(observed_at()),
    };
    let discovery = OpenCodeAdapter::new()
        .discover_with_options(&known_folders, &options)
        .expect("OpenCode fixture discovery");

    assert!(
        discovery
            .configs
            .iter()
            .any(|config| config.source == OpenCodeConfigSource::Global)
    );
    assert!(
        discovery
            .configs
            .iter()
            .any(|config| config.source == OpenCodeConfigSource::GlobalTui)
    );
    assert!(discovery.configs.iter().any(|config| {
        config.source == OpenCodeConfigSource::Project
            && config.scope == ConfigScope::Project
            && config.trust == OpenCodeTrustScope::Untrusted
    }));
    assert!(
        discovery
            .configs
            .iter()
            .any(|config| config.source == OpenCodeConfigSource::Custom)
    );
    assert!(
        discovery
            .configs
            .iter()
            .filter(|config| config.source == OpenCodeConfigSource::Custom)
            .count()
            >= 2
    );
    let managed = discovery
        .configs
        .iter()
        .find(|config| config.managed)
        .expect("managed OpenCode config");
    assert_eq!(managed.owner, OpenCodeConfigOwner::Managed);
    assert_eq!(managed.scope, ConfigScope::Managed);
    let managed_component = discovery
        .components
        .iter()
        .find(|component| {
            component
                .artifacts
                .iter()
                .any(|artifact| artifact.source_path == managed.artifact.source_path)
        })
        .expect("managed config component");
    assert_eq!(managed_component.restore.primary, RestoreStrategy::Manual);

    assert!(
        discovery
            .instructions
            .iter()
            .any(|instruction| instruction.namespace == "user")
    );
    assert!(discovery.instructions.iter().any(|instruction| {
        instruction.scope == ConfigScope::Project && instruction.namespace.starts_with("project:")
    }));
    assert!(
        discovery
            .agents
            .iter()
            .any(|agent| agent.name == "project-reviewer")
    );
    assert!(
        discovery
            .commands
            .iter()
            .any(|command| command.name == "user-review")
    );
    assert!(
        discovery
            .plugins
            .iter()
            .any(|plugin| plugin.name == "user-plugin")
    );
    assert!(
        discovery
            .plugins
            .iter()
            .any(|plugin| plugin.name == "custom-plugin")
    );

    let global = discovery
        .configs
        .iter()
        .find(|config| config.source == OpenCodeConfigSource::Global)
        .expect("global config");
    assert_eq!(global.safe_config["model"], "${OPENCODE_MODEL}");
    let safe_global =
        serde_json::to_string(&global.safe_config).expect("safe config serialization");
    assert!(!safe_global.contains("fixture-context7-secret"));
    assert!(!safe_global.contains("fixture-context7-env-secret"));
    assert!(
        discovery
            .secret_references
            .iter()
            .any(|secret| secret.server == "context7")
    );
    assert!(
        discovery
            .mcp_servers
            .iter()
            .any(|server| server.name == "context7")
    );
    assert!(
        discovery
            .mcp_servers
            .iter()
            .any(|server| server.name == "project-server")
    );
    assert!(discovery.components.iter().all(|component| {
        !component
            .extensions
            .get("executed")
            .and_then(|value| value.as_bool())
            .unwrap_or(true)
            || component.kind != ComponentKind::Plugin
    }));
    let harness = discovery
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Harness)
        .expect("OpenCode harness component");
    assert!(matches!(
        harness.verification.first(),
        Some(reforge_domain::VerificationRule::ConfigParses { .. })
    ));
}

#[test]
fn malformed_opencode_jsonc_fails_closed() {
    let (fixture, known_folders) = fixture_context("opencode-invalid");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".config/opencode/opencode.jsonc",
            INVALID_CONFIG,
        )
        .expect("invalid OpenCode config fixture");

    let error = OpenCodeAdapter::new()
        .discover_with_options(
            &known_folders,
            &OpenCodeDiscoveryOptions {
                observed_at: Some(observed_at()),
                ..OpenCodeDiscoveryOptions::default()
            },
        )
        .expect_err("malformed OpenCode JSONC must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
