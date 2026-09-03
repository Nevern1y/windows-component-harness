#![allow(dead_code)]

mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::DotnetAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::{ReforgeErrorCode, RestoreStrategy};
use reforge_platform_windows::ProcessResult;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/dotnet/list.json");

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
fn dotnet_fixture_preserves_nuget_and_unknown_sources() {
    let adapter = DotnetAdapter::new();
    let result = adapter
        .parse_capture(&success(), LIST, captured_at())
        .expect("dotnet fixture parses");
    assert_eq!(result.observations.len(), 3);

    let nuget = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "dotnet-ef")
        })
        .expect("NuGet tool");
    assert_eq!(package(nuget).source_name.as_deref(), Some("nuget"));
    assert_eq!(package(nuget).version.as_deref(), Some("9.0.1"));
    let component = adapter
        .normalize(nuget.clone())
        .expect("NuGet package normalizes")
        .pop()
        .expect("NuGet component");
    assert_eq!(component.restore.primary, RestoreStrategy::Reinstall);

    let local = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "local-tool")
        })
        .expect("unknown-source tool");
    assert!(package(local).source_name.is_none());
}

#[test]
fn dotnet_provider_rejects_malformed_collection() {
    let error = DotnetAdapter::new()
        .parse_capture(&success(), br#"{"tools":{}}"#, captured_at())
        .expect_err("malformed package collection rejects");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
