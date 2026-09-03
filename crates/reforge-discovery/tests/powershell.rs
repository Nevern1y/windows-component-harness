#![allow(dead_code)]

mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::PowerShellAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::ReforgeErrorCode;
use reforge_platform_windows::ProcessResult;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/powershell/list.json");

fn captured_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid fixture timestamp")
}

fn success() -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        cancelled: false,
    }
}

fn package(observation: &Observation) -> &reforge_domain::PackageSpec {
    match observation {
        Observation::Package { spec, .. } => spec,
        other => panic!("expected package observation, got {other:?}"),
    }
}

#[test]
fn powershell_fixture_preserves_module_repository_and_prerelease_version() {
    let adapter = PowerShellAdapter::new();
    let result = adapter
        .parse_capture(&success(), LIST, captured_at())
        .expect("PowerShell fixture parses");
    assert_eq!(result.observations.len(), 3);
    let prerelease = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "PreviewModule")
        })
        .expect("PowerShell prerelease module");
    assert_eq!(package(prerelease).version.as_deref(), Some("2.0.0-beta.1"));
    assert_eq!(
        package(prerelease).source_name.as_deref(),
        Some("PSGallery")
    );
    let runtime = result
        .observations
        .iter()
        .find(|observation| matches!(observation, Observation::Runtime { .. }))
        .expect("PowerShell runtime observation");
    assert_eq!(
        adapter
            .normalize(runtime.clone())
            .expect("PowerShell runtime normalizes")[0]
            .provenance
            .as_ref()
            .expect("PowerShell runtime provenance")
            .adapter_id,
        "powershell"
    );
}

#[test]
fn powershell_provider_rejects_malformed_module_collection() {
    let error = PowerShellAdapter::new()
        .parse_capture(&success(), br#"{"modules":{}}"#, captured_at())
        .expect_err("malformed module collection rejects");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
