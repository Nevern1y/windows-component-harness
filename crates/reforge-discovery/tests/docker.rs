#![allow(dead_code)]
mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::{
    ProviderAdapter,
    providers::{DockerAdapter, DockerCaptures},
};
use reforge_domain::{
    KnownFolderToken, OperationKind, ProviderFact, ProviderId, ReforgeErrorCode, RunId,
};
use reforge_platform_windows::{KnownFolderMap, ProcessResult};

use crate::support::fixtures::FixtureRoot;

const CONTEXTS: &[u8] = include_bytes!("../../../tests/fixtures/providers/docker/contexts.json");
const IMAGES: &[u8] = include_bytes!("../../../tests/fixtures/providers/docker/images.json");
const VOLUMES: &[u8] = include_bytes!("../../../tests/fixtures/providers/docker/volumes.json");

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

fn known_folders(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let entries = BTreeMap::from([(
        KnownFolderToken::UserProfile,
        fixture.tokens().user_profile.clone(),
    )]);
    (fixture, KnownFolderMap::from_entries(entries))
}

fn target_with_docker() -> reforge_domain::TargetFacts {
    let mut target = crate::support::fixtures::target_facts();
    target.providers = vec![ProviderFact {
        id: ProviderId::new("docker").expect("provider ID"),
        version: None,
        available: true,
    }];
    target
}

#[test]
fn absent_daemon_is_a_typed_provider_failure() {
    let adapter = DockerAdapter::new();
    let failed = ProcessResult {
        exit_code: Some(125),
        stdout: String::new(),
        stderr: "Cannot connect to the Docker daemon".to_owned(),
        timed_out: false,
        cancelled: false,
    };
    let error = adapter
        .parse_capture(&failed, &success(b"[]"), &success(b"[]"), captured_at())
        .expect_err("daemon failure must not become an empty inventory");
    assert_eq!(error.code, ReforgeErrorCode::ProviderUnavailable);
}

#[test]
fn contexts_preserve_export_metadata_and_redact_endpoint_credentials() {
    let adapter = DockerAdapter::new();
    let discovery = adapter
        .parse_capture(
            &success(CONTEXTS),
            &success(b"[]"),
            &success(b"[]"),
            captured_at(),
        )
        .expect("context fixture parses");
    assert_eq!(discovery.contexts.len(), 2);
    assert!(discovery.contexts[0].export_eligible);
    assert!(discovery.contexts.iter().any(|context| context.current));
    let remote = discovery
        .contexts
        .iter()
        .find(|context| context.name == "remote")
        .expect("remote context");
    assert_eq!(
        remote.endpoint.as_deref(),
        Some("tcp://docker.example:2376")
    );
    assert!(remote.endpoint_redacted);
    assert!(
        discovery
            .components
            .iter()
            .any(|component| component.kind == reforge_domain::ComponentKind::DockerContext)
    );
}

#[test]
fn image_and_volume_sizes_are_estimates_and_large_objects_are_opt_in() {
    let adapter = DockerAdapter::new();
    let discovery = adapter
        .parse_capture(
            &success(CONTEXTS),
            &success(IMAGES),
            &success(VOLUMES),
            captured_at(),
        )
        .expect("Docker fixtures parse");
    let small_image = discovery
        .images
        .iter()
        .find(|image| image.repository == "alpine")
        .expect("small image");
    assert_eq!(small_image.size_bytes, 1_572_864);
    assert!(!small_image.large_data);
    let large_image = discovery
        .images
        .iter()
        .find(|image| image.repository == "example/app")
        .expect("large image");
    assert_eq!(large_image.size_bytes, 33_554_432);
    assert!(large_image.large_data);
    let volume = discovery
        .volumes
        .iter()
        .find(|volume| volume.name == "build-cache")
        .expect("volume");
    assert_eq!(volume.size_bytes, 33_554_432);
    assert!(volume.large_data);
    assert_eq!(discovery.estimated_bytes, 69_206_016);
}

#[test]
fn credential_helpers_are_references_and_running_volume_is_manual() {
    let (_fixture, known_folders) = known_folders("docker-config");
    let adapter = DockerAdapter::new();
    let containers = success(
        br#"[{"Names":"builder","ID":"container-id","Image":"example/app:latest","State":"Up 2 minutes","Mounts":[{"Type":"volume","Name":"build-cache"}]}]"#,
    );
    let config = br#"{
        "currentContext":"default",
        "credsStore":"desktop",
        "credHelpers":{"ghcr.io":"pass"},
        "auths":{"https://registry.example":"TOP_SECRET"}
    }"#;
    let captures = DockerCaptures::new(success(CONTEXTS), success(IMAGES), success(VOLUMES))
        .with_containers(containers)
        .with_config(config);
    let discovery = adapter
        .discover_from_captures(&known_folders, captures, captured_at())
        .expect("Docker capture parses");
    assert_eq!(discovery.current_context.as_deref(), Some("default"));
    assert_eq!(discovery.credential_helpers.len(), 2);
    assert_eq!(discovery.auth_registries, vec!["registry.example"]);
    assert!(!format!("{discovery:?}").contains("TOP_SECRET"));
    let volume = discovery
        .volumes
        .iter()
        .find(|volume| volume.name == "build-cache")
        .expect("running volume");
    assert!(volume.running);
    assert!(volume.requires_quiescence);
    assert!(discovery.warnings.iter().any(|warning| {
        warning.code == ReforgeErrorCode::ManualActionRequired
            && warning.message.contains("running container")
    }));
    assert!(
        discovery
            .warnings
            .iter()
            .any(|warning| warning.code == ReforgeErrorCode::ManualSecretRequired)
    );
}

#[test]
fn image_planning_stays_manual_until_an_explicit_save_object_exists() {
    let adapter = DockerAdapter::new();
    let discovery = adapter
        .parse_capture(
            &success(CONTEXTS),
            &success(IMAGES),
            &success(VOLUMES),
            captured_at(),
        )
        .expect("Docker fixtures parse");
    let image = discovery
        .components
        .iter()
        .find(|component| component.kind == reforge_domain::ComponentKind::DockerImage)
        .expect("image component");
    let run_id = RunId::new(uuid::Uuid::now_v7()).expect("UUIDv7 run ID");
    let operations = adapter
        .plan_install(image, &target_with_docker(), &run_id, 4)
        .expect("manual Docker operation");
    assert_eq!(operations.len(), 1);
    assert!(matches!(
        operations[0].kind,
        OperationKind::OpenManualAction { .. }
    ));
}
