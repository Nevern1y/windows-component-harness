#![allow(dead_code)]
mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::ChocolateyAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::{
    Component, OperationKind, PackageInstallPolicy, Portability, ProviderFact, ProviderId,
    ReforgeErrorCode, RestoreStrategy, RunId,
};
use reforge_platform_windows::ProcessResult;

use crate::support::target_facts;

const EXPORT: &[u8] = include_bytes!("../../../tests/fixtures/providers/chocolatey/list.json");

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

fn target_with_chocolatey(available: bool) -> reforge_domain::TargetFacts {
    let mut target = target_facts();
    target.providers = vec![ProviderFact {
        id: ProviderId::new("chocolatey").expect("provider ID"),
        version: None,
        available,
    }];
    target
}

fn normalized_component(bytes: &[u8]) -> Component {
    let adapter = ChocolateyAdapter::new();
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
fn versioned_export_preserves_package_source_and_script_warning() {
    let adapter = ChocolateyAdapter::new();
    let enumeration = adapter
        .parse_capture(&success(""), EXPORT, captured_at())
        .expect("Chocolatey fixture parses");
    assert_eq!(enumeration.observations.len(), 2);
    assert!(
        enumeration
            .warnings
            .iter()
            .any(|warning| warning.contains("install scripts"))
    );
    match &enumeration.observations[0] {
        Observation::Package { spec, version, .. } => {
            assert_eq!(spec.provider.as_str(), "chocolatey");
            assert_eq!(spec.id, "7zip");
            assert!(spec.source_name.is_none());
            assert!(spec.source_identifier.is_none());
            assert!(spec.source.is_none());
            assert_eq!(
                version.as_ref().map(|value| value.raw.as_str()),
                Some("24.09")
            );
        }
        other => panic!("unexpected observation: {other:?}"),
    }
}

#[test]
fn exact_source_and_version_create_opt_in_typed_install() {
    let adapter = ChocolateyAdapter::new();
    let component = normalized_component(EXPORT);
    assert_eq!(component.restore.primary, RestoreStrategy::Reinstall);
    assert_eq!(
        component.restore.portability,
        Portability::PartiallyPortable
    );
    let operations = adapter
        .plan_install(&component, &target_with_chocolatey(true), &run_id(), 7)
        .expect("typed Chocolatey operation");
    assert_eq!(operations.len(), 1);
    match &operations[0].kind {
        OperationKind::InstallPackage {
            provider,
            package,
            policy,
        } => {
            assert_eq!(provider.as_str(), "chocolatey");
            assert_eq!(package.id, "7zip");
            assert_eq!(package.version.as_deref(), Some("24.09"));
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
fn malformed_xml_and_custom_source_are_safe() {
    let adapter = ChocolateyAdapter::new();
    let malformed = adapter
        .parse_capture(&success(""), b"<packages><package", captured_at())
        .expect_err("malformed XML rejects");
    assert_eq!(malformed.code, ReforgeErrorCode::ProviderParseFailed);

    let custom = br#"<packages><package id="private-tool" version="1.0" source="https://packages.example.invalid/api/v2" /></packages>"#;
    let enumeration = adapter
        .parse_capture(&success(""), custom, captured_at())
        .expect("custom source remains discoverable");
    let component = adapter
        .normalize(
            enumeration
                .observations
                .into_iter()
                .next()
                .expect("observation"),
        )
        .expect("custom source normalizes")
        .into_iter()
        .next()
        .expect("component");
    assert_eq!(component.restore.primary, RestoreStrategy::Manual);
    assert!(
        component
            .restore
            .rationale
            .iter()
            .any(|reason| reason.contains("install scripts"))
    );
}

#[test]
fn unavailable_provider_becomes_manual_action() {
    let adapter = ChocolateyAdapter::new();
    let component = normalized_component(EXPORT);
    let operations = adapter
        .plan_install(&component, &target_with_chocolatey(false), &run_id(), 0)
        .expect("provider absence creates a manual action");
    assert!(matches!(
        operations[0].kind,
        OperationKind::OpenManualAction { .. }
    ));
}
