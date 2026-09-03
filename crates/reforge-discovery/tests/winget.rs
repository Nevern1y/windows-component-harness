#![allow(dead_code)]
mod support;

use std::ffi::OsString;

use chrono::{TimeZone, Utc};
use reforge_discovery::{Observation, ProviderAdapter, WinGetAdapter};
use reforge_domain::{
    Component, IdentityQuality, OperationKind, PackageInstallPolicy, Portability, ProviderId,
    ReforgeErrorCode, RestoreStrategy, RunId, VerificationRule,
};
use reforge_platform_windows::{BuiltinExecutable, ProcessResult, TrustedExecutable};

use crate::support::target_facts;

const EXPORT_V2: &[u8] = include_bytes!("../../../tests/fixtures/providers/winget/export.json");
const EXPORT_V1: &[u8] = include_bytes!("../../../tests/fixtures/providers/winget/export-v1.json");
const EXPORT_MISSING_VERSION: &[u8] =
    include_bytes!("../../../tests/fixtures/providers/winget/export-missing-version.json");
const WARNINGS: &str = include_str!("../../../tests/fixtures/providers/winget/warnings.txt");
const INVALID: &[u8] = include_bytes!("../../../tests/fixtures/providers/winget/invalid.json");
const LIST_TABLE: &str = include_str!("../../../tests/fixtures/providers/winget/list.txt");

fn captured_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid fixture timestamp")
}

fn run_id() -> RunId {
    RunId::new(uuid::Uuid::now_v7()).expect("fixture UUIDv7 run ID")
}

fn success(stdout: &str, stderr: &str) -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        timed_out: false,
        cancelled: false,
    }
}

fn normalized_component(bytes: &[u8]) -> Component {
    let adapter = WinGetAdapter::new();
    let enumeration = adapter
        .parse_capture(&success("", ""), bytes, captured_at())
        .expect("fixture export parses");
    let observation = enumeration
        .observations
        .into_iter()
        .next()
        .expect("fixture package observation");
    adapter
        .normalize(observation)
        .expect("fixture package normalizes")
        .into_iter()
        .next()
        .expect("fixture component")
}

#[test]
fn parses_versioned_v1_and_v2_exports_without_localized_tables() {
    let adapter = WinGetAdapter::new();
    let v1 = adapter
        .parse_capture(&success("", ""), EXPORT_V1, captured_at())
        .expect("legacy fixture parses");
    let v2 = adapter
        .parse_capture(&success(LIST_TABLE, ""), EXPORT_V2, captured_at())
        .expect("current fixture parses");

    assert_eq!(v1.observations.len(), 1);
    assert_eq!(v2.observations.len(), 2);
    match &v1.observations[0] {
        Observation::Package { spec, version, .. } => {
            assert_eq!(spec.id, "Contoso.Editor");
            assert_eq!(spec.version.as_deref(), Some("4.2.0"));
            assert_eq!(
                spec.source_identifier.as_deref(),
                Some("Contoso.Private.Source")
            );
            assert_eq!(
                spec.source.as_ref().map(url::Url::as_str),
                Some("https://packages.example.test/index")
            );
            assert_eq!(
                version.as_ref().map(|value| value.raw.as_str()),
                Some("4.2.0")
            );
        }
        other => panic!("unexpected observation: {other:?}"),
    }
}

#[test]
fn duplicate_sources_merge_only_identical_records() {
    let adapter = WinGetAdapter::new();
    let duplicate = br#"{
        "$schema":"https://aka.ms/winget-packages.schema.2.0.json",
        "Sources":[
            {
                "SourceDetails":{"Name":"winget","Argument":"https://example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
                "Packages":[{"PackageIdentifier":"Contoso.Editor","Version":"1.0.0"}]
            },
            {
                "SourceDetails":{"Name":"winget","Argument":"https://example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
                "Packages":[{"PackageIdentifier":"Contoso.Editor","Version":"1.0.0"}]
            }
        ]
    }"#;
    let enumeration = adapter
        .parse_capture(&success("", ""), duplicate, captured_at())
        .expect("identical duplicate source records merge");
    assert_eq!(enumeration.observations.len(), 1);
    assert!(
        enumeration
            .warnings
            .iter()
            .any(|warning| warning.contains("repeated source"))
    );

    let conflicting = br#"{
        "$schema":"https://aka.ms/winget-packages.schema.2.0.json",
        "Sources":[
            {
                "SourceDetails":{"Name":"winget","Argument":"https://example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
                "Packages":[{"PackageIdentifier":"Contoso.Editor","Version":"1.0.0"}]
            },
            {
                "SourceDetails":{"Name":"winget","Argument":"https://other.example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
                "Packages":[{"PackageIdentifier":"Contoso.Editor","Version":"1.0.0"}]
            }
        ]
    }"#;
    let error = adapter
        .parse_capture(&success("", ""), conflicting, captured_at())
        .expect_err("conflicting duplicate source records reject");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}

#[test]
fn malformed_or_unreviewed_exports_fail_closed() {
    let adapter = WinGetAdapter::new();
    let malformed = adapter
        .parse_capture(&success("", ""), INVALID, captured_at())
        .expect_err("missing source type is invalid");
    assert_eq!(malformed.code, ReforgeErrorCode::ProviderParseFailed);

    let unsupported = br#"{
        "$schema":"https://aka.ms/winget-packages.schema.3.0.json",
        "Sources":[],
        "WinGetVersion":"2.0.0"
    }"#;
    let unsupported = adapter
        .parse_capture(&success("", ""), unsupported, captured_at())
        .expect_err("unknown schema version is rejected");
    assert_eq!(unsupported.code, ReforgeErrorCode::UnsupportedVersion);
}

#[test]
fn process_failures_and_export_bounds_are_typed() {
    let adapter = WinGetAdapter::new();
    let failed = ProcessResult {
        exit_code: Some(7),
        stdout: String::new(),
        stderr: "provider failed".to_owned(),
        timed_out: false,
        cancelled: false,
    };
    let failed = adapter
        .parse_capture(&failed, EXPORT_V2, captured_at())
        .expect_err("non-zero provider exit is rejected");
    assert_eq!(failed.code, ReforgeErrorCode::OperationFailed);

    let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
    let oversized = adapter
        .parse_capture(&success("", ""), &oversized, captured_at())
        .expect_err("oversized export is rejected before parsing");
    assert_eq!(oversized.code, ReforgeErrorCode::SecurityPolicy);
}

#[test]
fn provider_warnings_are_bounded_and_secret_redacted() {
    let adapter = WinGetAdapter::new();
    let enumeration = adapter
        .parse_capture(&success(WARNINGS, ""), EXPORT_V2, captured_at())
        .expect("fixture export parses");
    let joined = enumeration.warnings.join("\n");
    assert!(joined.contains("unmatched installed package"));
    assert!(joined.contains("<REDACTED>"));
    assert!(!joined.contains("fixture-secret-token"));
}

#[test]
fn normalization_preserves_exact_provider_source_and_version_identity() {
    let component = normalized_component(EXPORT_V2);
    assert_eq!(
        component.identity.identity_quality,
        IdentityQuality::Provider
    );
    assert_eq!(
        component.identity.provider_package.as_ref(),
        Some(&(
            ProviderId::new("winget").expect("provider ID"),
            "Git.Git".to_owned()
        ))
    );
    assert_eq!(
        component.identity.provider_source.as_deref(),
        Some("Microsoft.Winget.Source_8wekyb3d8bbwe")
    );
    assert_eq!(
        component.version.as_ref().map(|value| value.raw.as_str()),
        Some("2.47.1")
    );
    assert_eq!(component.restore.primary, RestoreStrategy::Reinstall);
    assert_eq!(component.restore.portability, Portability::SupportedExport);
}

#[test]
fn exact_plan_is_opt_in_for_agreements_and_has_stable_run_identity() {
    let adapter = WinGetAdapter::new();
    let component = normalized_component(EXPORT_V2);
    let run_id = run_id();
    let operations = adapter
        .plan_install(&component, &target_facts(), &run_id, 17)
        .expect("exact package plans");
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].id.as_str(), format!("op_{}_17", run_id));
    match &operations[0].kind {
        OperationKind::InstallPackage {
            provider,
            package,
            policy,
        } => {
            assert_eq!(provider.as_str(), "winget");
            assert_eq!(package.id, "Git.Git");
            assert_eq!(package.version.as_deref(), Some("2.47.1"));
            assert_eq!(package.source_name.as_deref(), Some("winget"));
            assert_eq!(
                package.source_identifier.as_deref(),
                Some("Microsoft.Winget.Source_8wekyb3d8bbwe")
            );
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
fn missing_version_or_provider_becomes_a_manual_action_not_latest() {
    let adapter = WinGetAdapter::new();
    let component = normalized_component(EXPORT_MISSING_VERSION);
    assert_eq!(component.restore.primary, RestoreStrategy::Manual);
    assert_eq!(
        component.restore.portability,
        Portability::PartiallyPortable
    );

    let operations = adapter
        .plan_install(&component, &target_facts(), &run_id(), 0)
        .expect("partial package creates manual plan");
    assert!(matches!(
        operations[0].kind,
        OperationKind::OpenManualAction { .. }
    ));

    let mut unavailable_target = target_facts();
    unavailable_target.providers[0].available = false;
    let exact_component = normalized_component(EXPORT_V2);
    let operations = adapter
        .plan_install(&exact_component, &unavailable_target, &run_id(), 0)
        .expect("missing target provider creates manual plan");
    assert!(matches!(
        operations[0].kind,
        OperationKind::OpenManualAction { .. }
    ));
}

#[test]
fn verification_query_uses_argument_vector_and_exact_source_identity() {
    let adapter = WinGetAdapter::new();
    let component = normalized_component(EXPORT_V2);
    let rules = adapter
        .verify(&component, &target_facts())
        .expect("verification descriptor exists");
    let package = match &rules[0] {
        VerificationRule::ProviderIdentity { provider, package } => {
            assert_eq!(provider.as_str(), "winget");
            package
        }
        other => panic!("unexpected verification rule: {other:?}"),
    };
    let command = adapter
        .verification_command(package)
        .expect("verification command is valid");
    assert_eq!(
        command.executable,
        TrustedExecutable::Builtin(BuiltinExecutable::WinGet)
    );
    assert_eq!(
        command.args,
        [
            "list",
            "--id",
            "Git.Git",
            "--exact",
            "--source",
            "winget",
            "--disable-interactivity"
        ]
        .map(OsString::from)
    );
    assert!(
        !command
            .args
            .iter()
            .any(|argument| argument == "--accept-source-agreements")
    );
}

#[test]
fn full_fixture_lifecycle_survives_domain_serialization() {
    let adapter = WinGetAdapter::new();
    let component = normalized_component(EXPORT_V1);
    let bytes = serde_json::to_vec(&component).expect("component serializes");
    let component: Component = serde_json::from_slice(&bytes).expect("component deserializes");
    let run_id = run_id();
    let operations = adapter
        .plan_install(&component, &target_facts(), &run_id, 5)
        .expect("component plans");
    let rules = adapter
        .verify(&component, &target_facts())
        .expect("component verifies");

    assert_eq!(operations.len(), 1);
    assert_eq!(rules.len(), 1);
    assert_eq!(operations[0].verification, rules);
}

#[test]
fn package_and_source_injection_shapes_are_rejected() {
    let adapter = WinGetAdapter::new();
    let malicious_id = br#"{
        "$schema":"https://aka.ms/winget-packages.schema.2.0.json",
        "Sources":[{
            "SourceDetails":{"Name":"winget","Argument":"https://example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
            "Packages":[{"PackageIdentifier":"Contoso.Editor --exact","Version":"1.0.0"}]
        }]
    }"#;
    let error = adapter
        .parse_capture(&success("", ""), malicious_id, captured_at())
        .expect_err("whitespace cannot enter package identity arguments");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);

    let credential_url = br#"{
        "$schema":"https://aka.ms/winget-packages.schema.2.0.json",
        "Sources":[{
            "SourceDetails":{"Name":"private","Argument":"https://user:secret@example.test/index","Identifier":"source-id","Type":"Microsoft.PreIndexed.Package"},
            "Packages":[{"PackageIdentifier":"Contoso.Editor","Version":"1.0.0"}]
        }]
    }"#;
    let enumeration = adapter
        .parse_capture(&success("", ""), credential_url, captured_at())
        .expect("package remains discoverable without unsafe source URL");
    match &enumeration.observations[0] {
        Observation::Package { spec, .. } => assert!(spec.source.is_none()),
        other => panic!("unexpected observation: {other:?}"),
    }
}
