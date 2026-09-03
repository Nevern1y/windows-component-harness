#![allow(dead_code)]

#[path = "../support.rs"]
mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::harnesses::{
    CodexAdapter, CodexAuthMode, CodexDiscoveryOptions, CodexTrustScope, McpReferenceCatalog,
};
use reforge_domain::{
    ComponentKind, ConfigScope, ExecutableRef, KnownFolderToken, PathToken, ReforgeErrorCode,
};
use reforge_platform_windows::KnownFolderMap;

use crate::support::FixtureRoot;

const CONFIG: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/codex/config.toml");
const CONFIG_MCP: &[u8] =
    include_bytes!("../../../../tests/fixtures/harnesses/codex/config-mcp.toml");
const INVALID: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/codex/invalid.toml");

fn observed_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn component_id(seed: char) -> reforge_domain::ComponentId {
    reforge_domain::ComponentId::new(format!("cmp_{}", seed.to_string().repeat(52)))
        .expect("fixture component ID")
}

fn fixture_context(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let mut entries = BTreeMap::new();
    entries.insert(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    );
    (fixture, KnownFolderMap::from_entries(entries))
}

fn references() -> McpReferenceCatalog {
    let mut references = McpReferenceCatalog::default();
    references.register_executable(ExecutableRef {
        name: "node".to_owned(),
        component: Some(component_id('n')),
        observed_path: None,
    });
    references
}

#[test]
fn discovers_home_profile_project_auth_and_mcp_without_secret_bytes() {
    let (fixture, known_folders) = fixture_context("codex-discovery");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, ".codex/config.toml", CONFIG)
        .expect("user config fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/default.config.toml",
            CONFIG_MCP,
        )
        .expect("profile fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/instructions.md",
            b"Keep generated changes reviewable.\n",
        )
        .expect("instruction fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/AGENTS.md",
            b"Review agent output before restore.\n",
        )
        .expect("user instruction fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/auth.json",
            br#"{"access_token":"fixture-auth-secret"}"#,
        )
        .expect("auth fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/hooks.json",
            br#"{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo from-file"}]}]}"#,
        )
        .expect("hook fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/skills/review/SKILL.md",
            b"# Review\n",
        )
        .expect("skill fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".codex/agents/reviewer.md",
            b"Review agent metadata\n",
        )
        .expect("agent fixture");

    let project_root =
        PathToken::new(KnownFolderToken::UserProfile, "project").expect("project token");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.codex/config.toml",
            br#"cli_auth_credentials_store = "keyring"
openai_base_url = "https://api.example.invalid"
model = "gpt-fixture"
"#,
        )
        .expect("project config fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/AGENTS.md",
            b"Project instructions require review.\n",
        )
        .expect("project instruction fixture");

    let codex_home = fixture.tokens().user_profile.join(".codex");
    let mut environment = BTreeMap::new();
    environment.insert(
        "CODEX_HOME".to_owned(),
        codex_home.to_string_lossy().into_owned(),
    );
    let options = CodexDiscoveryOptions {
        project_roots: vec![project_root.clone()],
        project_trust: CodexDiscoveryOptions::default()
            .with_project_trust(project_root.clone(), CodexTrustScope::Untrusted)
            .project_trust,
        environment,
        references: references(),
        observed_at: Some(observed_at()),
    };

    let discovery = CodexAdapter::new()
        .discover_with_options(&known_folders, &options)
        .expect("Codex fixture discovery");

    assert_eq!(discovery.auth_mode, Some(CodexAuthMode::File));
    assert_eq!(discovery.configs.len(), 2);
    assert_eq!(discovery.profiles.len(), 1);
    assert!(discovery.instructions.iter().any(|item| {
        item.path.relative == "project/AGENTS.md"
            && item.scope == ConfigScope::Project
            && item.trust == CodexTrustScope::Untrusted
    }));
    assert!(!discovery.skills.is_empty());
    assert!(!discovery.agents.is_empty());
    assert!(!discovery.hooks.is_empty());
    assert_eq!(discovery.mcp_servers.len(), 1);
    assert!(
        discovery
            .secret_references
            .iter()
            .any(|secret| secret.server == "context7")
    );
    assert!(discovery.configs.iter().any(|config| {
        config.scope == ConfigScope::Project
            && config.trust == CodexTrustScope::Untrusted
            && config
                .ignored_project_keys
                .iter()
                .any(|key| key == "openai_base_url")
    }));

    let auth = discovery.auth_reference.as_ref().expect("auth reference");
    assert_eq!(auth.mode, CodexAuthMode::File);
    let auth_artifact = auth.artifact.as_ref().expect("auth artifact metadata");
    assert_eq!(
        auth_artifact.policy,
        reforge_domain::ArtifactPolicy::SecretReference
    );
    assert!(auth_artifact.object.is_none());
    assert!(discovery.artifacts.iter().all(|artifact| {
        !artifact
            .source_path
            .relative
            .contains("fixture-auth-secret")
    }));

    let safe_config = serde_json::to_string(
        &discovery
            .configs
            .iter()
            .find(|config| config.scope == ConfigScope::User)
            .expect("user config")
            .safe_config,
    )
    .expect("safe config serialization");
    assert!(!safe_config.contains("fixture-argument-secret"));
    assert!(!safe_config.contains("fixture-context7-secret"));
    assert!(
        discovery
            .components
            .iter()
            .any(|component| { component.kind == ComponentKind::Harness })
    );
    assert!(
        discovery
            .components
            .iter()
            .any(|component| { component.kind == ComponentKind::SecretReference })
    );
}

#[test]
fn malformed_codex_toml_fails_with_provider_parse_error() {
    let (fixture, known_folders) = fixture_context("codex-invalid");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, ".codex/config.toml", INVALID)
        .expect("invalid config fixture");
    let codex_home = fixture.tokens().user_profile.join(".codex");
    let mut environment = BTreeMap::new();
    environment.insert(
        "CODEX_HOME".to_owned(),
        codex_home.to_string_lossy().into_owned(),
    );
    let options = CodexDiscoveryOptions {
        environment,
        observed_at: Some(observed_at()),
        ..CodexDiscoveryOptions::default()
    };

    let error = CodexAdapter::new()
        .discover_with_options(&known_folders, &options)
        .expect_err("malformed Codex config must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
