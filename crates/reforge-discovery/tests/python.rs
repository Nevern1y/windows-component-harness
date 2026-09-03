#![allow(dead_code)]

mod support;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::PythonAdapter;
use reforge_discovery::{Observation, ProviderAdapter};
use reforge_domain::{ComponentKind, DependencyKind, ReforgeErrorCode};
use reforge_platform_windows::ProcessResult;

const LIST: &[u8] = include_bytes!("../../../tests/fixtures/providers/python/list.json");

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

fn package_id(observation: &Observation) -> Option<&str> {
    match observation {
        Observation::Package { spec, .. } => Some(spec.id.as_str()),
        _ => None,
    }
}

#[test]
fn pip_inspect_preserves_interpreter_abi_and_install_provenance() {
    let adapter = PythonAdapter::new();
    let result = adapter
        .parse_capture(&success(), LIST, captured_at())
        .expect("pip inspect fixture parses");
    assert_eq!(result.observations.len(), 4);

    let runtime = result
        .observations
        .iter()
        .find(|observation| matches!(observation, Observation::Runtime { .. }))
        .expect("Python runtime observation");
    let runtime_component = adapter
        .normalize(runtime.clone())
        .expect("runtime normalizes")
        .pop()
        .expect("runtime component");
    assert_eq!(runtime_component.kind, ComponentKind::Runtime);
    assert_eq!(runtime_component.extensions["abi"], "cp313");
    assert_eq!(
        runtime_component
            .provenance
            .as_ref()
            .expect("runtime provenance")
            .adapter_id,
        "python"
    );

    let editable = result
        .observations
        .iter()
        .find(|observation| package_id(observation) == Some("editable-tool"))
        .expect("editable package");
    assert_eq!(package(editable).source_name.as_deref(), Some("editable"));
    assert!(package(editable).source.is_none());

    let abi_mismatch = result
        .observations
        .iter()
        .find(|observation| package_id(observation) == Some("native-tool"))
        .expect("ABI-mismatched package");
    assert_eq!(
        package(abi_mismatch).source_name.as_deref(),
        Some("abi-mismatch")
    );
    let package_component = adapter
        .normalize(abi_mismatch.clone())
        .expect("package normalizes")
        .pop()
        .expect("package component");
    assert!(matches!(
        package_component.dependencies.as_slice(),
        [dependency] if dependency.kind == DependencyKind::RequiredRuntime
    ));
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("ABI"))
    );
}

#[test]
fn pipx_and_uv_outputs_remain_manual_when_source_is_not_reported() {
    let adapter = PythonAdapter::new();
    let pipx = br#"{
        "venvs": {
            "black": {
                "metadata": {
                    "main_package": {
                        "package_or_url": "black",
                        "package_version": "24.10.0"
                    }
                }
            }
        }
    }"#;
    let pipx_result = adapter
        .parse_capture(&success(), pipx, captured_at())
        .expect("pipx fixture parses");
    assert_eq!(pipx_result.observations.len(), 1);
    assert_eq!(package(&pipx_result.observations[0]).id, "black");
    assert!(package(&pipx_result.observations[0]).source_name.is_none());

    let uv = b"Package   Version   Executable\nblack     24.10.0   black.exe\nruff      0.9.2     ruff.exe\n";
    let uv_result = adapter
        .parse_capture(&success(), uv, captured_at())
        .expect("uv fixture parses");
    assert_eq!(uv_result.observations.len(), 2);
    assert!(
        uv_result
            .observations
            .iter()
            .all(|observation| package(observation).source_name.is_none())
    );
}

#[test]
fn python_provider_rejects_failed_process_and_unsafe_package_name() {
    let failed = ProcessResult {
        exit_code: Some(1),
        stdout: String::new(),
        stderr: "secret=do-not-copy".to_owned(),
        timed_out: false,
        cancelled: false,
    };
    let adapter = PythonAdapter::new();
    let error = adapter
        .parse_capture(&failed, b"{}", captured_at())
        .expect_err("failed process rejects");
    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert!(
        !error
            .technical_detail
            .as_deref()
            .unwrap_or_default()
            .contains("do-not-copy")
    );

    let unsafe_python = br#"[{"name":"bad package","version":"1.0.0"}]"#;
    let error = adapter
        .parse_capture(&success(), unsafe_python, captured_at())
        .expect_err("unsafe package name rejects");
    assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
}
