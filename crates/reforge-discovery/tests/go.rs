#![allow(dead_code)]

mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::GoAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_platform_windows::ProcessResult;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/go/list.json");

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
fn go_env_fixture_preserves_git_and_path_sources_without_fabricating_missing_source() {
    let adapter = GoAdapter::new();
    let result = adapter
        .parse_capture(&success(), LIST, captured_at())
        .expect("Go fixture parses");
    assert_eq!(result.observations.len(), 3);

    let git = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "github.com/acme/tool")
        })
        .expect("git module");
    assert_eq!(package(git).source_name.as_deref(), Some("git"));
    assert_eq!(
        package(git).source_identifier.as_deref(),
        Some("github.com/acme/tool")
    );
    assert_eq!(
        package(git).source.as_ref().map(|source| source.as_str()),
        Some("https://github.com/acme/tool")
    );

    let path = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "example.com/local")
        })
        .expect("path module");
    assert_eq!(package(path).source_name.as_deref(), Some("path"));
    assert!(package(path).source.is_none());

    let runtime = result
        .observations
        .iter()
        .find(|observation| matches!(observation, Observation::Runtime { .. }))
        .expect("Go runtime observation");
    assert_eq!(
        adapter
            .normalize(runtime.clone())
            .expect("Go runtime normalizes")[0]
            .provenance
            .as_ref()
            .expect("Go runtime provenance")
            .adapter_id,
        "go"
    );
}

#[test]
fn go_provider_rejects_malformed_json() {
    let error = GoAdapter::new()
        .parse_capture(&success(), b"not-json", captured_at())
        .expect_err("malformed Go output rejects");
    assert_eq!(
        error.code,
        reforge_domain::ReforgeErrorCode::ProviderParseFailed
    );
}
