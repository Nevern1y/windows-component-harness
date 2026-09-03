#![allow(dead_code)]
mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::ScoopAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::{
    Component, OperationKind, PackageInstallPolicy, Portability, ProviderFact, ProviderId,
    ReforgeErrorCode, RestoreStrategy, RunId,
};
use reforge_platform_windows::ProcessResult;

use crate::support::target_facts;

const EXPORT: &[u8] = include_bytes!("../../../tests/fixtures/providers/scoop/list.json");

fn captured_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid fixture timestamp")
}

fn run_id() -> RunId {
    RunId::new(uuid::Uuid::now_v7()).expect("fixture UUIDv7 run ID")
}

fn success(stderr: &str) -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: String::new(),
        stderr: stderr.to_owned(),
        timed_out: false,
        cancelled: false,
    }
}

fn target_with_scoop(available: bool) -> reforge_domain::TargetFacts {
    let mut target = target_facts();
    target.providers = vec![ProviderFact {
        id: ProviderId::new("scoop").expect("provider ID"),
        version: None,
        available,
    }];
    target
}

fn normalized_component(bytes: &[u8]) -> Component {
    let adapter = ScoopAdapter::new();
    let enumeration = adapter
        .parse_capture(&success(""), bytes, captured_at())
        .expect("fixture export parses");
    adapter
        .normalize(
            enumeration
                .observations
                .into_iter()
                .next()
                .expect("fixture package observation"),
        )
        .expect("fixture package normalizes")
        .into_iter()
        .next()
        .expect("fixture component")
}

#[test]
fn versioned_export_preserves_bucket_metadata_and_script_warning() {
    let adapter = ScoopAdapter::new();
    let enumeration = adapter
        .parse_capture(&success(""), EXPORT, captured_at())
        .expect("Scoop fixture parses");
    assert_eq!(enumeration.observations.len(), 2);
    assert!(
        enumeration
            .warnings
            .iter()
            .any(|warning| warning.contains("installer scripts"))
    );
    match &enumeration.observations[0] {
        Observation::Package { spec, version, .. } => {
            assert_eq!(spec.provider.as_str(), "scoop");
            assert_eq!(spec.source_name.as_deref(), Some("main"));
            assert_eq!(spec.source_identifier.as_deref(), Some("bucket:main"));
            assert_eq!(
                spec.source.as_ref().map(url::Url::as_str),
                Some("https://github.com/ScoopInstaller/Main")
            );
            assert_eq!(
                version.as_ref().map(|value| value.raw.as_str()),
                Some("2.47.1")
            );
        }
        other => panic!("unexpected observation: {other:?}"),
    }
}

#[test]
fn reviewed_bucket_and_version_create_opt_in_typed_install() {
    let adapter = ScoopAdapter::new();
    let component = normalized_component(EXPORT);
    assert_eq!(component.restore.primary, RestoreStrategy::Reinstall);
    assert_eq!(component.restore.portability, Portability::SupportedExport);
    let operations = adapter
        .plan_install(&component, &target_with_scoop(true), &run_id(), 9)
        .expect("typed Scoop operation");
    assert_eq!(operations.len(), 1);
    match &operations[0].kind {
        OperationKind::InstallPackage {
            provider,
            package,
            policy,
        } => {
            assert_eq!(provider.as_str(), "scoop");
            assert_eq!(package.id, "git");
            assert_eq!(package.version.as_deref(), Some("2.47.1"));
            assert_eq!(
                policy,
                &PackageInstallPolicy {
                    accept_source_agreements: false,
                    accept_package_agreements: false,
                    silent: false,
                    allow_reboot: false,
                }
            );
        }
        other => panic!("unexpected operation kind: {other:?}"),
    }
}

#[test]
fn malformed_json_and_custom_bucket_are_safe() {
    let adapter = ScoopAdapter::new();
    let malformed = adapter
        .parse_capture(&success(""), b"{", captured_at())
        .expect_err("malformed JSON rejects");
    assert_eq!(malformed.code, ReforgeErrorCode::ProviderParseFailed);

    let custom = br#"{"apps":[{"Name":"private-tool","Version":"1.0","Source":"private"}],"buckets":[{"Name":"private","Source":"https://packages.example.invalid/bucket"}]}"#;
    let enumeration = adapter
        .parse_capture(&success(""), custom, captured_at())
        .expect("custom bucket remains discoverable");
    let component = adapter
        .normalize(
            enumeration
                .observations
                .into_iter()
                .next()
                .expect("observation"),
        )
        .expect("custom bucket normalizes")
        .into_iter()
        .next()
        .expect("component");
    assert_eq!(component.restore.primary, RestoreStrategy::Manual);
    assert!(
        component
            .restore
            .rationale
            .iter()
            .any(|reason| reason.contains("installer scripts"))
    );
}

#[test]
fn unavailable_provider_becomes_manual_action() {
    let adapter = ScoopAdapter::new();
    let component = normalized_component(EXPORT);
    let operations = adapter
        .plan_install(&component, &target_with_scoop(false), &run_id(), 0)
        .expect("provider absence creates a manual action");
    assert!(matches!(
        operations[0].kind,
        OperationKind::OpenManualAction { .. }
    ));
}
