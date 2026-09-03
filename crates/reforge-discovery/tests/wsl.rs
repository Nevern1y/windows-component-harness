#![allow(dead_code)]
mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::{WslAdapter, WslCaptures, WslExportEligibility, WslState};
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, ComponentKind, ConfigScope, KnownFolderToken,
    ObjectId, OperationKind, ProviderFact, ProviderId, ReforgeErrorCode, RunId,
};
use reforge_platform_windows::{KnownFolderMap, ProcessResult};

use crate::support::fixtures::FixtureRoot;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/wsl/list.txt");
const STATUS: &[u8] = include_bytes!("../../../tests/fixtures/providers/wsl/status.txt");
const WSL_CONFIG: &[u8] = include_bytes!("../../../tests/fixtures/providers/wsl/.wslconfig");
const WSL_CONF: &[u8] = include_bytes!("../../../tests/fixtures/providers/wsl/wsl.conf");

fn captured_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid fixture timestamp")
}

fn success(stdout: &[u8]) -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: String::from_utf8(stdout.to_vec()).expect("fixture is UTF-8"),
        stderr: String::new(),
        timed_out: false,
        cancelled: false,
    }
}

fn failure(exit_code: i32, stderr: &str) -> ProcessResult {
    ProcessResult {
        exit_code: Some(exit_code),
        stdout: String::new(),
        stderr: stderr.to_owned(),
        timed_out: false,
        cancelled: false,
    }
}

fn known_folders(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let entries = BTreeMap::from([(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    )]);
    (fixture, KnownFolderMap::from_entries(entries))
}

fn target_with_wsl() -> reforge_domain::TargetFacts {
    let mut target = crate::support::fixtures::target_facts();
    target.providers = vec![ProviderFact {
        id: ProviderId::new("wsl").expect("provider ID"),
        version: None,
        available: true,
    }];
    target
}

fn captures() -> WslCaptures {
    WslCaptures::new(success(LIST), success(STATUS)).with_feature_output(
        r#"[{"FeatureName":"Microsoft-Windows-Subsystem-Linux","State":"Enabled","RestartNeeded":false},{"FeatureName":"VirtualMachinePlatform","State":"Enabled","RestartNeeded":false}]"#,
    )
}

#[test]
fn absent_wsl_is_a_typed_provider_failure() {
    let adapter = WslAdapter::new();
    let error = adapter
        .discover_from_captures(
            &KnownFolderMap::default(),
            WslCaptures::new(
                failure(1, "The requested operation requires elevation"),
                success(STATUS),
            ),
            captured_at(),
        )
        .expect_err("missing WSL must not become an empty successful inventory");
    assert_eq!(error.code, ReforgeErrorCode::ProviderUnavailable);
}

#[test]
fn multiple_distros_preserve_version_default_and_running_state() {
    let adapter = WslAdapter::new();
    let discovery = adapter
        .discover_from_captures(&KnownFolderMap::default(), captures(), captured_at())
        .expect("WSL fixture parses");
    assert_eq!(discovery.distributions.len(), 3);
    let ubuntu = discovery
        .distributions
        .iter()
        .find(|distribution| distribution.name == "Ubuntu-22.04")
        .expect("Ubuntu distribution");
    assert_eq!(ubuntu.wsl_version, Some(2));
    assert_eq!(ubuntu.state, WslState::Running);
    assert!(ubuntu.running);
    assert!(ubuntu.default);
    assert_eq!(discovery.status.default_version, Some(2));
    assert!(
        discovery
            .edges
            .iter()
            .any(|edge| edge.kind == reforge_domain::DependencyKind::RestoresBefore)
    );
}

#[test]
fn stopped_and_running_configs_remain_distinct_and_linux_config_is_manual() {
    let (_fixture, known) = known_folders("wsl-config");
    let adapter = WslAdapter::new();
    let discovery = adapter
        .discover_from_captures(
            &known,
            captures()
                .with_wslconfig(WSL_CONFIG)
                .with_distro_config("Ubuntu-22.04", WSL_CONF),
            captured_at(),
        )
        .expect("WSL configs parse");
    let windows = discovery
        .config_artifacts
        .iter()
        .find(|artifact| artifact.distribution.is_none())
        .expect("Windows-side config");
    assert_eq!(windows.path, ".wslconfig");
    assert_eq!(
        windows.token.as_ref().map(|token| &token.root),
        Some(&KnownFolderToken::UserProfile)
    );
    assert!(windows.artifact.is_some());
    let linux = discovery
        .config_artifacts
        .iter()
        .find(|artifact| artifact.distribution.as_deref() == Some("Ubuntu-22.04"))
        .expect("Linux-side config");
    assert_eq!(linux.path, "/etc/wsl.conf");
    assert!(linux.token.is_none());
    assert_eq!(linux.policy, ArtifactPolicy::Manual);
    assert!(discovery.warnings.iter().any(|warning| {
        warning.code == ReforgeErrorCode::ManualActionRequired
            && warning.message.contains("wsl.conf")
    }));
}

#[test]
fn failed_export_is_partial_and_manual() {
    let adapter = WslAdapter::new();
    let discovery = adapter
        .discover_from_captures(
            &KnownFolderMap::default(),
            captures().with_export("Ubuntu-22.04", failure(1, "export failed")),
            captured_at(),
        )
        .expect("failed optional export remains a discovery result");
    let ubuntu = discovery
        .distributions
        .iter()
        .find(|distribution| distribution.name == "Ubuntu-22.04")
        .expect("Ubuntu distribution");
    assert_eq!(ubuntu.export_eligibility, WslExportEligibility::Failed);
    assert!(!ubuntu.export_eligible);
    let component = discovery
        .distribution_component("Ubuntu-22.04")
        .expect("Ubuntu component");
    assert_eq!(
        component.restore.primary,
        reforge_domain::RestoreStrategy::Partial
    );
    assert!(discovery.warnings.iter().any(|warning| {
        warning.code == ReforgeErrorCode::ManualActionRequired
            && warning.message.contains("export failed")
    }));
}

#[test]
fn selected_export_gets_typed_import_after_prerequisites() {
    let adapter = WslAdapter::new();
    let export = ArtifactRef {
        id: ArtifactId::new("wsl-export-fixture").expect("artifact ID"),
        source_path: reforge_domain::PathToken::new(
            KnownFolderToken::UserSelected {
                id: "wsl-export".to_owned(),
            },
            "ubuntu.tar",
        )
        .expect("export token"),
        scope: ConfigScope::User,
        size_bytes: 32 * 1024 * 1024,
        content_type: reforge_domain::ContentType::Archive,
        policy: ArtifactPolicy::LargeOptIn,
        object: Some(ObjectId::from_content(b"ubuntu export")),
    };
    let discovery = adapter
        .discover_from_captures(
            &KnownFolderMap::default(),
            captures().with_export_artifact("Ubuntu-22.04", export),
            captured_at(),
        )
        .expect("selected export parses");
    let run_id = RunId::new(uuid::Uuid::now_v7()).expect("UUIDv7 run ID");
    let operations = adapter
        .plan_restore(&discovery, &target_with_wsl(), &run_id, 7)
        .expect("WSL restore plan");
    let import_index = operations
        .iter()
        .position(|operation| matches!(operation.kind, OperationKind::ImportWsl { .. }))
        .expect("selected export has an import operation");
    assert!(import_index > 0);
    assert!(operations[..import_index].iter().all(|operation| {
        operation.component
            != discovery
                .distribution_component("Ubuntu-22.04")
                .expect("component")
                .id
    }));
    assert!(!operations[import_index].prerequisites.is_empty());
    assert!(operations[..import_index].iter().any(|operation| {
        operation.component.as_str()
            == discovery
                .components
                .iter()
                .find(|component| component.kind == ComponentKind::SystemFeature)
                .expect("prerequisite operation")
                .id
                .as_str()
    }));
}
