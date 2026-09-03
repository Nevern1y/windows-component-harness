#![allow(dead_code)]

#[path = "support.rs"]
mod support;

use std::collections::BTreeMap;

use reforge_discovery::editors::{VSCodeAdapter, VSCodeObservations};
use reforge_domain::{ComponentKind, KnownFolderToken, PathToken};
use reforge_platform_windows::KnownFolderMap;

use crate::support::fixtures::FixtureRoot;

const EXTENSIONS: &[u8] = include_bytes!("../../../tests/fixtures/editors/vscode/extensions.json");

fn fixture_context(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let entries = BTreeMap::from([(
        KnownFolderToken::RoamingAppData,
        fixture.tokens().roaming_app_data.clone(),
    )]);
    (fixture, KnownFolderMap::from_entries(entries))
}

#[test]
fn discovers_settings_extensions_and_explicit_settings_sync_reauth() {
    let (fixture, known_folders) = fixture_context("vscode-discovery");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Code/User/settings.json",
            br#"{"editor.formatOnSave":true}"#,
        )
        .expect("settings fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Code/User/keybindings.json",
            br#"[]"#,
        )
        .expect("keybindings fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Code/User/snippets/rust.code-snippets",
            br#"{"log":{"prefix":"log","body":["println!($1)"]}}"#,
        )
        .expect("snippet fixture");

    let discovery = VSCodeAdapter::new()
        .discover_with_observations(
            &known_folders,
            VSCodeObservations {
                version_output: Some("1.99.0\ncommit fixture\nx64\n".to_owned()),
                extensions_output: Some(
                    std::str::from_utf8(EXTENSIONS)
                        .expect("UTF-8 extension fixture")
                        .to_owned(),
                ),
                cli_available: true,
            },
        )
        .expect("VS Code discovery");

    let editor = discovery.component.expect("editor component");
    assert_eq!(editor.kind, ComponentKind::Editor);
    assert_eq!(
        editor.version.as_ref().map(|version| version.raw.as_str()),
        Some("1.99.0")
    );
    assert_eq!(discovery.extensions.len(), 2);
    assert!(
        discovery
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path.relative.ends_with("settings.json"))
    );
    assert!(
        discovery
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path.relative.contains("snippets"))
    );
    assert!(
        discovery
            .manual_actions
            .iter()
            .any(|action| action.title.contains("Settings Sync"))
    );
    assert!(discovery.extensions.iter().all(|component| {
        component
            .extensions
            .get("protected_state_copied")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    }));
}

#[test]
fn discovers_only_allowlisted_workspace_configuration() {
    let fixture = FixtureRoot::new("vscode-workspace").expect("fixture root");
    let entries = BTreeMap::from([
        (
            KnownFolderToken::UserProfile,
            fixture.tokens().user_profile.clone(),
        ),
        (
            KnownFolderToken::RoamingAppData,
            fixture.tokens().roaming_app_data.clone(),
        ),
    ]);
    let known_folders = KnownFolderMap::from_entries(entries);
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "workspace/.vscode/settings.json",
            br#"{"editor.tabSize":2}"#,
        )
        .expect("workspace settings fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "workspace/project.code-workspace",
            br#"{"folders":[{"path":"."}]}"#,
        )
        .expect("workspace file fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::UserProfile,
            "workspace/.git/config",
            b"[remote]\nurl = https://example.invalid/repository.git\n",
        )
        .expect("non-allowlisted fixture");
    let workspace_root =
        PathToken::new(KnownFolderToken::UserProfile, "workspace").expect("workspace token");

    let discovery = VSCodeAdapter::new()
        .discover_with_observations_and_workspace_roots(
            &known_folders,
            VSCodeObservations {
                cli_available: true,
                ..VSCodeObservations::default()
            },
            &[workspace_root],
        )
        .expect("workspace discovery");

    assert!(discovery.artifacts.iter().any(|artifact| {
        artifact
            .source_path
            .relative
            .ends_with(".vscode/settings.json")
    }));
    assert!(discovery.artifacts.iter().any(|artifact| {
        artifact
            .source_path
            .relative
            .ends_with("project.code-workspace")
    }));
    assert!(
        !discovery
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path.relative.contains(".git"))
    );
}

#[test]
fn unavailable_cli_remains_observable_without_inventing_extensions() {
    let (fixture, known_folders) = fixture_context("vscode-no-cli");
    let discovery = VSCodeAdapter::new()
        .discover_with_observations(
            &known_folders,
            VSCodeObservations {
                cli_available: false,
                ..VSCodeObservations::default()
            },
        )
        .expect("unavailable CLI is non-fatal");
    assert!(discovery.extensions.is_empty());
    assert!(discovery.component.is_none());
    assert!(
        discovery
            .warnings
            .iter()
            .any(|warning| warning.code == reforge_domain::ReforgeErrorCode::ManualActionRequired)
    );
    drop(fixture);
}
