#![allow(dead_code)]

#[path = "../support.rs"]
mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::harnesses::{
    ClaudeCodeAdapter, ClaudeDiscoveryOptions, ClaudeTrustScope, McpReferenceCatalog,
};
use reforge_domain::{
    ComponentKind, ConfigScope, ExecutableRef, KnownFolderToken, PathToken, ReforgeErrorCode,
};
use reforge_platform_windows::KnownFolderMap;

use crate::support::FixtureRoot;

const SETTINGS: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/claude/settings.json");
const MCP: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/claude/mcp.json");
const INVALID: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/claude/invalid.json");

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

fn write_common_user_state(fixture: &FixtureRoot) {
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/settings.json",
            SETTINGS,
        )
        .expect("settings fixture");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, ".claude.json", MCP)
        .expect("user MCP fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/CLAUDE.md",
            b"Review instructions before restore.\n",
        )
        .expect("user instruction fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/skills/standalone/SKILL.md",
            b"# Standalone skill\n",
        )
        .expect("standalone skill fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/commands/review.md",
            b"Review the current change.\n",
        )
        .expect("standalone command fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/agents/reviewer.md",
            b"Review agent metadata.\n",
        )
        .expect("standalone agent fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/hooks/hooks.json",
            br#"{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo standalone-hook"}]}]}"#,
        )
        .expect("standalone hooks fixture");

    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/.claude-plugin/plugin.json",
            br#"{"name":"review-tools","description":"Review helpers","version":"1.2.3"}"#,
        )
        .expect("plugin manifest fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/.mcp.json",
            br#"{"mcpServers":{"plugin-server":{"type":"stdio","command":"node","args":["plugin-server.js"]}}}"#,
        )
        .expect("plugin MCP fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/settings.json",
            br#"{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"echo plugin-hook"}]}]}}"#,
        )
        .expect("plugin settings fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/skills/plugin-skill/SKILL.md",
            b"# Plugin skill\n",
        )
        .expect("plugin skill fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/commands/plugin-command.md",
            b"Plugin command metadata.\n",
        )
        .expect("plugin command fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/agents/plugin-agent.md",
            b"Plugin agent metadata.\n",
        )
        .expect("plugin agent fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/hooks/hooks.json",
            br#"{"Notification":[{"hooks":[{"type":"command","command":"echo plugin-file-hook"}]}]}"#,
        )
        .expect("plugin hooks fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/plugins/review/bin/review.cmd",
            b"@echo off\necho plugin-binary\n",
        )
        .expect("plugin binary fixture");
}

#[test]
fn discovers_scoped_claude_state_plugins_and_redacted_mcp() {
    let (fixture, known_folders) = fixture_context("claude-discovery");
    write_common_user_state(&fixture);

    let project_root =
        PathToken::new(KnownFolderToken::UserProfile, "project").expect("project token");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.claude/settings.json",
            br#"{"model":"fixture-model","permissions":{"allow":["Read"]}}"#,
        )
        .expect("project settings fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/.claude/settings.local.json",
            br#"{"env":{"CLAUDE_API_KEY":"fixture-project-secret"}}"#,
        )
        .expect("project local settings fixture");
    fixture
        .write_tokenized(KnownFolderToken::UserProfile, "project/.mcp.json", MCP)
        .expect("project MCP fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "project/CLAUDE.md",
            b"Project instructions require review.\n",
        )
        .expect("project instruction fixture");

    let mut options = ClaudeDiscoveryOptions::current(vec![project_root.clone()], references())
        .with_project_trust(project_root, ClaudeTrustScope::Untrusted)
        .with_observed_at(observed_at());
    options.environment.clear();

    let discovery = ClaudeCodeAdapter::new()
        .discover_with_options(&known_folders, &options)
        .expect("Claude fixture discovery");

    assert!(discovery.settings.iter().any(|settings| {
        settings.scope == ConfigScope::User && !settings.local && settings.namespace == "user"
    }));
    assert!(
        discovery
            .settings
            .iter()
            .any(|settings| { settings.scope == ConfigScope::Project && settings.local })
    );
    assert!(discovery.instructions.iter().any(|instruction| {
        instruction.scope == ConfigScope::Project
            && instruction.trust == ClaudeTrustScope::Untrusted
    }));
    assert!(
        discovery
            .skills
            .iter()
            .any(|skill| skill.namespace == "user")
    );
    assert!(
        discovery
            .skills
            .iter()
            .any(|skill| skill.namespace == "plugin:review-tools")
    );
    assert!(
        discovery
            .commands
            .iter()
            .any(|command| command.namespace == "plugin:review-tools")
    );
    assert!(
        discovery
            .agents
            .iter()
            .any(|agent| agent.namespace == "plugin:review-tools")
    );
    assert!(
        discovery
            .plugins
            .iter()
            .any(|plugin| plugin.namespace == "plugin:review-tools")
    );
    assert!(
        discovery
            .plugins
            .iter()
            .flat_map(|plugin| plugin.binaries.iter())
            .any(|path| path.relative.ends_with("bin/review.cmd"))
    );
    assert!(
        discovery
            .hooks
            .iter()
            .any(|hook| { hook.command.as_deref() == Some("echo standalone-hook") })
    );
    assert!(discovery.mcp_servers.len() >= 2);
    assert!(
        discovery
            .secret_references
            .iter()
            .any(|secret| secret.server == "context7")
    );

    let safe_settings = serde_json::to_string(
        &discovery
            .settings
            .iter()
            .find(|settings| settings.scope == ConfigScope::User && !settings.local)
            .expect("user settings")
            .safe_config,
    )
    .expect("safe settings serialization");
    assert!(!safe_settings.contains("fixture-settings-secret"));
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
            .any(|component| { component.kind == ComponentKind::Plugin })
    );
    assert!(
        discovery
            .manual_actions
            .iter()
            .any(|action| { action.title.contains("plugin") || action.title.contains("Plugin") })
    );
}

#[test]
fn malformed_claude_settings_fail_with_provider_parse_error() {
    let (fixture, known_folders) = fixture_context("claude-invalid");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            ".claude/settings.json",
            INVALID,
        )
        .expect("invalid settings fixture");

    let error = ClaudeCodeAdapter::new()
        .discover_with_options(
            &known_folders,
            &ClaudeDiscoveryOptions {
                observed_at: Some(observed_at()),
                ..ClaudeDiscoveryOptions::default()
            },
        )
        .expect_err("malformed Claude settings must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
