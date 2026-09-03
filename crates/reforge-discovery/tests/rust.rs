#![allow(dead_code)]

mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::RustAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::Architecture;
use reforge_platform_windows::ProcessResult;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/rust/list.json");

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
fn cargo_fixture_keeps_registry_and_path_provenance_distinct() {
    let adapter = RustAdapter::new();
    let result = adapter
        .parse_capture(&success(), LIST, captured_at())
        .expect("Cargo fixture parses");
    assert_eq!(result.observations.len(), 3);
    let runtime = result
        .observations
        .iter()
        .find(|observation| matches!(observation, Observation::Runtime { .. }))
        .expect("Rust runtime observation");
    let runtime_component = adapter
        .normalize(runtime.clone())
        .expect("Rust runtime normalizes")
        .pop()
        .expect("Rust runtime component");
    assert_eq!(runtime_component.architecture, Some(Architecture::X64));

    let registry = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "ripgrep")
        })
        .expect("registry crate");
    assert_eq!(package(registry).source_name.as_deref(), Some("crates.io"));
    assert_eq!(
        package(registry)
            .source
            .as_ref()
            .map(|source| source.as_str()),
        Some("https://crates.io/crates/ripgrep")
    );
    let path = result
        .observations
        .iter()
        .find(|observation| {
            matches!(observation, Observation::Package { spec, .. } if spec.id == "local-tool")
        })
        .expect("path crate");
    assert_eq!(package(path).source_name.as_deref(), Some("path"));
    assert_eq!(
        package(path).source_identifier.as_deref(),
        Some("local-workspace")
    );
}

#[test]
fn rustup_line_output_is_bounded_and_versioned() {
    let adapter = RustAdapter::new();
    let output = b"stable-x86_64-pc-windows-msvc (active, default)\nripgrep v14.1.0:\n  rg.exe\n";
    let result = adapter
        .parse_capture(&success(), output, captured_at())
        .expect("rustup line fixture parses");
    assert_eq!(result.observations.len(), 2);
    assert!(result.observations.iter().any(|observation| {
        matches!(observation, Observation::Runtime { spec, .. } if spec.version.as_deref() == Some("stable-x86_64-pc-windows-msvc"))
    }));
    assert!(result.observations.iter().any(|observation| {
        matches!(observation, Observation::Package { spec, .. } if spec.version.as_deref() == Some("v14.1.0"))
    }));
}
