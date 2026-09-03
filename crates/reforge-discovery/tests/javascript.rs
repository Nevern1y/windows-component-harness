#![allow(dead_code)]

mod support;

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::providers::{JavaScriptAdapter, NodePackageManager};
use reforge_discovery::{Observation, ProviderAdapter, ProviderContext};
use reforge_domain::{
    Component, ComponentKind, ContentType, KnownFolderToken, PathToken, ReforgeErrorCode,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap, ProcessResult, ProcessRunner};

use crate::support::{FixtureRoot, host_facts};

const NPM_GLOBAL: &[u8] =
    include_bytes!("../../../tests/fixtures/providers/javascript/npm-global.json");
const PNPM_GLOBAL: &[u8] =
    include_bytes!("../../../tests/fixtures/providers/javascript/pnpm-global.json");
const YARN_GLOBAL: &[u8] =
    include_bytes!("../../../tests/fixtures/providers/javascript/yarn-global.json");
const BUN_GLOBAL: &[u8] =
    include_bytes!("../../../tests/fixtures/providers/javascript/bun-global.json");

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

fn component_from_observation(adapter: &JavaScriptAdapter, observation: Observation) -> Component {
    adapter
        .normalize(observation)
        .expect("JavaScript observation normalizes")
        .into_iter()
        .next()
        .expect("one normalized JavaScript component")
}

fn package_observations(adapter: &JavaScriptAdapter, output: &[u8]) -> Vec<Observation> {
    adapter
        .parse_capture(&success(), output, captured_at())
        .expect("JavaScript fixture parses")
        .observations
}

#[test]
fn npm_preserves_scoped_source_and_nested_dependency_closure() {
    let adapter = JavaScriptAdapter::npm();
    let observations = package_observations(&adapter, NPM_GLOBAL);
    assert_eq!(observations.len(), 3);

    let specs: Vec<_> = observations
        .iter()
        .map(|observation| match observation {
            Observation::Package { spec, .. } => spec.clone(),
            other => panic!("unexpected observation: {other:?}"),
        })
        .collect();
    let scoped = specs
        .iter()
        .find(|spec| spec.id == "@acme/cli")
        .expect("scoped package");
    assert_eq!(scoped.version.as_deref(), Some("2.4.0"));
    assert_eq!(
        scoped.source.as_ref().map(|source| source.as_str()),
        Some("https://registry.npmjs.org/@acme/cli/-/cli-2.4.0.tgz")
    );
    assert_eq!(scoped.installer_hash.as_deref(), Some("sha512-acmefixture"));

    let components: Vec<_> = observations
        .into_iter()
        .map(|observation| component_from_observation(&adapter, observation))
        .collect();
    let scoped_component = components
        .iter()
        .find(|component| component.display_name == "@acme/cli")
        .expect("scoped component");
    let nested_component = components
        .iter()
        .find(|component| component.display_name == "shared-dep")
        .expect("nested component");
    assert_eq!(scoped_component.kind, ComponentKind::Package);
    assert_eq!(scoped_component.dependencies.len(), 1);
    assert_eq!(scoped_component.dependencies[0].to, nested_component.id);
    assert_eq!(
        scoped_component.extensions["lifecycle_risk"]["install_scripts_may_execute"],
        true
    );
    assert!(
        scoped_component
            .restore
            .rationale
            .iter()
            .any(|reason| reason.contains("lifecycle scripts"))
    );
}

#[test]
fn pnpm_preserves_nested_scoped_package_and_global_scope() {
    let adapter = JavaScriptAdapter::pnpm();
    let observations = package_observations(&adapter, PNPM_GLOBAL);
    assert_eq!(observations.len(), 2);
    let components: Vec<_> = observations
        .into_iter()
        .map(|observation| component_from_observation(&adapter, observation))
        .collect();
    let scoped = components
        .iter()
        .find(|component| component.display_name == "@scope/shared")
        .expect("nested scoped package");
    assert_eq!(scoped.extensions["scope"].as_str(), Some("global"));
    assert_eq!(scoped.extensions["top_level"].as_bool(), Some(false));
    let tool = components
        .iter()
        .find(|component| component.display_name == "pnpm-tool")
        .expect("pnpm top-level tool");
    assert_eq!(tool.extensions["top_level"].as_bool(), Some(true));
    assert_eq!(tool.dependencies.len(), 1);
}

#[test]
fn yarn_classic_fixture_is_parsed_but_modern_uncertainty_is_visible() {
    let adapter = JavaScriptAdapter::yarn();
    let result = adapter
        .parse_capture(&success(), YARN_GLOBAL, captured_at())
        .expect("Yarn Classic fixture parses");
    assert_eq!(result.observations.len(), 2);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("Classic"))
    );
    assert!(result.observations.iter().any(|observation| {
        matches!(
            observation,
            Observation::Package { spec, .. } if spec.id == "@acme/yarn-tool"
        )
    }));

    let modern =
        br#"{"type":"error","data":"Unknown Syntax Error: global is not a supported command"}"#;
    let modern_result = adapter
        .parse_capture(&success(), modern, captured_at())
        .expect("modern Yarn uncertainty is non-fatal");
    assert!(modern_result.observations.is_empty());
    assert!(
        modern_result
            .warnings
            .iter()
            .any(|warning| warning.contains("modern"))
    );
}

#[test]
fn bun_parses_structured_global_listing_and_nested_dependency() {
    let adapter = JavaScriptAdapter::bun();
    let observations = package_observations(&adapter, BUN_GLOBAL);
    assert_eq!(observations.len(), 2);
    let tool_observation = observations
        .into_iter()
        .find(|observation| {
            matches!(
                observation,
                Observation::Package { spec, .. } if spec.id == "bun-tool"
            )
        })
        .expect("Bun global tool");
    let spec = match &tool_observation {
        Observation::Package { spec, .. } => spec,
        other => panic!("unexpected observation: {other:?}"),
    };
    assert_eq!(spec.version.as_deref(), Some("0.8.0"));
    assert!(spec.source.is_none(), "unreported source remains unknown");
    let tool = component_from_observation(&adapter, tool_observation);
    assert_eq!(tool.dependencies.len(), 1);
}

#[test]
fn unsafe_source_and_failed_process_fail_closed() {
    let adapter = JavaScriptAdapter::npm();
    let unsafe_source = br#"{"dependencies":{"tool":{"version":"1.0.0","resolved":"https://user:secret@example.invalid/tool.tgz"}}}"#;
    let result = adapter
        .parse_capture(&success(), unsafe_source, captured_at())
        .expect("unsafe source is still discoverable");
    let spec = match &result.observations[0] {
        Observation::Package { spec, .. } => spec,
        other => panic!("unexpected observation: {other:?}"),
    };
    assert!(spec.source.is_none());
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("omitted"))
    );

    let failed = ProcessResult {
        exit_code: Some(1),
        stdout: String::new(),
        stderr: "secret=do-not-copy".to_owned(),
        timed_out: false,
        cancelled: false,
    };
    let error = adapter
        .parse_capture(&failed, b"{}", captured_at())
        .expect_err("failed package-manager process is rejected");
    assert_eq!(error.code, ReforgeErrorCode::OperationFailed);
    assert!(
        !error
            .technical_detail
            .as_deref()
            .unwrap_or_default()
            .contains("do-not-copy")
    );
}

#[tokio::test]
async fn project_manifests_and_lockfiles_are_tokenized_artifacts() {
    let fixture = FixtureRoot::new("javascript-project").expect("fixture root");
    fixture
        .create_dir("projects/demo")
        .expect("project directory");
    fixture
        .write_file(
            "projects/demo/package.json",
            br#"{"name":"demo","dependencies":{"x":"1.0.0"}}"#,
        )
        .expect("package manifest");
    fixture
        .write_file("projects/demo/pnpm-lock.yaml", b"lockfileVersion: '9.0'\n")
        .expect("lockfile");

    let root_id = "workspace".to_owned();
    let mut entries = BTreeMap::new();
    entries.insert(
        KnownFolderToken::UserSelected {
            id: root_id.clone(),
        },
        fixture.root().to_path_buf(),
    );
    let known_folders = KnownFolderMap::from_entries(entries);
    let root_token = PathToken::new(
        KnownFolderToken::UserSelected { id: root_id },
        "projects/demo",
    )
    .expect("project token");
    let adapter = JavaScriptAdapter::with_project_roots(NodePackageManager::Pnpm, [root_token]);
    let host = host_facts();
    let runner = ProcessRunner::new();
    let cancellation = CancellationToken::new();
    let context = ProviderContext {
        host: &host,
        known_folders: &known_folders,
        runner: &runner,
        cancellation: &cancellation,
    };

    let result = adapter
        .project_artifacts(&context)
        .expect("project artifacts enumerate");
    assert_eq!(result.observations.len(), 2);
    let components: Vec<_> = result
        .observations
        .into_iter()
        .map(|observation| component_from_observation(&adapter, observation))
        .collect();
    assert!(components.iter().all(|component| {
        component.kind == ComponentKind::DataArtifact
            && component.artifacts.len() == 1
            && component.artifacts[0]
                .source_path
                .relative
                .starts_with("projects/demo/")
            && component.artifacts[0].object.is_some()
    }));
    assert!(
        components
            .iter()
            .any(|component| { component.artifacts[0].content_type == ContentType::Json })
    );
    assert!(
        components
            .iter()
            .any(|component| { component.artifacts[0].content_type == ContentType::Utf8Text })
    );
}
