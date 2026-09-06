use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn run_cli_with_input<I, S>(state: &Path, args: I, input: &[u8]) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(env!("CARGO_BIN_EXE_reforge"))
        .args(args)
        .env("REFORGE_STATE_DIR", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch interactive reforge CLI");
    child
        .stdin
        .take()
        .expect("interactive stdin")
        .write_all(input)
        .expect("write interactive input");
    child.wait_with_output().expect("wait for interactive CLI")
}

use chrono::Utc;
use reforge_domain::{
    Architecture, Compatibility, Component, ComponentId, ComponentKind, Confidence, Identity,
    IdentityQuality, KnownFolderToken, ObjectIndex, PackageGraph, PackageManifest, PathToken,
    Portability, RestoreDescriptor, RestoreStrategy, SelectionInput, SelectionMetadata,
    SelectionPolicy, SourceHostSummary, VerificationRule,
};
use reforge_package::{ObjectStore, PackageWriteRequest, PackageWriter};
use serde_json::Value;

fn cli_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn run_cli<I, S>(state: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_reforge"))
        .args(args)
        .env("REFORGE_STATE_DIR", state)
        .output()
        .expect("launch reforge CLI")
}

fn json_stdout(output: &Output) -> Value {
    assert!(
        !output.stdout.is_empty(),
        "CLI emitted no JSON stdout; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI stdout was not exactly one JSON document: {error}; stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn temp_state_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "reforge-cli-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create CLI state directory");
    path
}

fn write_manual_package(path: &Path) {
    let component_id = ComponentId::new(format!("cmp_{}", "m".repeat(52))).expect("component ID");
    let verification_path = PathToken::new(
        KnownFolderToken::UserProfile,
        "ReforgeCliSmoke/manual-fixture.exe",
    )
    .expect("verification path token");
    let component = Component {
        id: component_id.clone(),
        kind: ComponentKind::Tool,
        identity: Identity {
            provider_package: None,
            provider_source: None,
            package_family: None,
            product_name: Some("Reforge CLI manual fixture".to_owned()),
            executable_name: Some("manual-fixture.exe".to_owned()),
            publisher: None,
            executable_hash: None,
            install_role: Some("tool".to_owned()),
            identity_quality: IdentityQuality::Product,
        },
        display_name: "Reforge CLI manual fixture".to_owned(),
        version: None,
        architecture: Some(Architecture::X64),
        publisher: None,
        provenance: None,
        evidence: Vec::new(),
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: Vec::new(),
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "The fixture intentionally requires a documented manual restore".to_owned(),
            ],
        },
        compatibility: Compatibility {
            required_os: Some("windows".to_owned()),
            required_architecture: Some(Architecture::X64),
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
        verification: vec![VerificationRule::FileVersion {
            destination: verification_path,
            version: None,
            publisher: None,
        }],
        selection: SelectionMetadata {
            recommended: true,
            score: 100,
            selected_by_default: true,
            sensitive: false,
            size_bytes: 0,
        },
        extensions: BTreeMap::new(),
    };
    let graph = PackageGraph {
        components: vec![component],
        edges: Vec::new(),
    };
    let selection = SelectionInput {
        components: vec![component_id.clone()],
        artifacts: Vec::new(),
        policy: SelectionPolicy {
            secrets: reforge_domain::SecretSelectionPolicy::Exclude,
            large_data: reforge_domain::LargeDataSelectionPolicy::Exclude,
            unknown_binaries: reforge_domain::UnknownBinarySelectionPolicy::Exclude,
            max_bytes: None,
        },
    };
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let manifest = PackageManifest {
        package_id: "pkg_cli_smoke_manual".to_owned(),
        format_version: 1,
        created_at: Utc::now(),
        source_host: SourceHostSummary {
            os_version: "Windows".to_owned(),
            os_build: "fixture".to_owned(),
            architecture: Architecture::X64,
            known_folder_tokens: vec![KnownFolderToken::UserProfile],
        },
        required_os: Some("windows".to_owned()),
        required_architecture: Some(Architecture::X64),
        component_ids: vec![component_id],
        warnings: Vec::new(),
        object_index_digest: PackageWriter::object_index_digest(&object_index)
            .expect("empty object-index digest"),
    };
    let store = ObjectStore::open(
        path.parent()
            .expect("manual package parent")
            .join("manual-objects"),
    )
    .expect("manual package object store");
    PackageWriter::default()
        .write(
            path,
            PackageWriteRequest {
                manifest: &manifest,
                graph: &graph,
                selection: &selection,
                object_index: &object_index,
                signature: None,
                vault: None,
            },
            &store,
        )
        .expect("write manual fixture package");
}

#[test]
fn cli_fixture_workflow_is_json_safe_and_resumable() {
    let state = temp_state_dir("workflow");
    let invalid_package = state.join("invalid.reforge");
    fs::write(&invalid_package, b"not a reforge package").expect("write invalid package");

    let version = run_cli(&state, cli_args(&["--version"]));
    assert!(version.status.success(), "--version failed: {version:?}");

    let help = run_cli(&state, cli_args(&["--help"]));
    assert!(help.status.success(), "--help failed: {help:?}");
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("scan"));
    assert!(help_text.contains("restore"));
    assert!(help_text.contains("interactive"));
    assert!(help_text.contains("backup"));
    assert!(
        !help_text.contains("--scope"),
        "scan scope selector must not be advertised: {help_text}"
    );

    let interactive_json = run_cli(&state, cli_args(&["interactive", "--json"]));
    assert_eq!(
        interactive_json.status.code(),
        Some(2),
        "interactive JSON mode must be rejected: {interactive_json:?}"
    );
    let interactive_json_value = json_stdout(&interactive_json);
    assert_eq!(interactive_json_value["payload"]["status"], "error");
    assert_eq!(
        interactive_json_value["payload"]["error"]["code"],
        "SCHEMA_INVALID"
    );

    for command in ["backup", "restore"] {
        let output = run_cli(&state, cli_args(&[command, "--json"]));
        assert_eq!(
            output.status.code(),
            Some(2),
            "guided {command} JSON mode must be rejected: {output:?}"
        );
        let value = json_stdout(&output);
        assert_eq!(value["payload"]["status"], "error");
        assert_eq!(value["payload"]["error"]["code"], "SCHEMA_INVALID");
    }

    let interactive = run_cli_with_input(&state, cli_args(&["interactive"]), b"0\n");
    assert!(
        interactive.status.success(),
        "interactive menu failed: {interactive:?}"
    );
    let interactive_stdout = String::from_utf8_lossy(&interactive.stdout);
    assert!(interactive_stdout.contains("[1] Quick Backup"));

    let no_argument = run_cli_with_input(&state, Vec::<OsString>::new(), b"0\n");
    assert!(
        no_argument.status.success(),
        "no-argument launch failed: {no_argument:?}"
    );
    let no_argument_stdout = String::from_utf8_lossy(&no_argument.stdout);
    assert!(no_argument_stdout.contains("[1] Quick Backup"));

    let unsupported_scope = run_cli(&state, cli_args(&["scan", "--scope", "user", "--json"]));
    assert_eq!(
        unsupported_scope.status.code(),
        Some(2),
        "unsupported scan scope exit: {unsupported_scope:?}"
    );
    let unsupported_scope_json = json_stdout(&unsupported_scope);
    assert_eq!(unsupported_scope_json["payload"]["status"], "error");
    assert_eq!(
        unsupported_scope_json["payload"]["error"]["code"],
        "SCHEMA_INVALID"
    );

    let invalid = run_cli(
        &state,
        [
            OsString::from("package"),
            OsString::from("inspect"),
            invalid_package.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    );
    assert_eq!(
        invalid.status.code(),
        Some(2),
        "invalid package exit: {invalid:?}"
    );
    let invalid_json = json_stdout(&invalid);
    assert_eq!(invalid_json["payload"]["status"], "error");
    assert_eq!(invalid_json["payload"]["error"]["code"], "PACKAGE_CORRUPT");

    let scan = run_cli(&state, cli_args(&["scan", "--json"]));
    assert!(scan.status.success(), "scan failed: {scan:?}");
    let scan_json = json_stdout(&scan);
    assert_eq!(scan_json["payload"]["status"], "ok");
    assert!(scan_json["payload"]["component_count"].is_number());
    let scan_stderr = String::from_utf8_lossy(&scan.stderr);
    assert!(
        scan_stderr.contains("progress phase="),
        "scan progress missing: {scan_stderr}"
    );
    assert!(!String::from_utf8_lossy(&scan.stdout).contains("progress phase="));

    let inventory = run_cli(&state, cli_args(&["inventory", "show", "--json"]));
    assert!(
        inventory.status.success(),
        "inventory show failed: {inventory:?}"
    );
    let inventory_json = json_stdout(&inventory);
    assert_eq!(inventory_json["payload"]["status"], "ok");
    assert!(inventory_json["payload"]["inventory"].is_object());

    let empty_selection = state.join("empty-selection.json");
    fs::write(
        &empty_selection,
        br#"{"components":[],"artifacts":[],"policy":{"secrets":"EXCLUDE","large_data":"EXCLUDE","unknown_binaries":"EXCLUDE","max_bytes":null}}"#,
    )
    .expect("write empty selection");
    let created_package = state.join("created.reforge");
    let create = run_cli(
        &state,
        [
            OsString::from("package"),
            OsString::from("create"),
            OsString::from("--output"),
            created_package.as_os_str().to_owned(),
            OsString::from("--selection"),
            empty_selection.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    );
    assert!(create.status.success(), "package create failed: {create:?}");
    let create_json = json_stdout(&create);
    assert_eq!(create_json["payload"]["status"], "ok");
    assert!(created_package.is_file());

    let inspect = run_cli(
        &state,
        [
            OsString::from("package"),
            OsString::from("inspect"),
            created_package.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    );
    assert!(
        inspect.status.success(),
        "package inspect failed: {inspect:?}"
    );
    let inspect_json = json_stdout(&inspect);
    assert_eq!(inspect_json["payload"]["status"], "ok");
    assert_eq!(inspect_json["payload"]["selected_component_count"], 0);
    assert_eq!(inspect_json["payload"]["object_count"], 0);

    let manual_package = state.join("manual.reforge");
    write_manual_package(&manual_package);
    let plan_state = temp_state_dir("plan");
    let plan = run_cli(
        &plan_state,
        [
            OsString::from("plan"),
            OsString::from("--package"),
            manual_package.as_os_str().to_owned(),
            OsString::from("--mode"),
            OsString::from("rebuild"),
            OsString::from("--json"),
        ],
    );
    assert!(plan.status.success(), "plan failed: {plan:?}");
    let plan_json = json_stdout(&plan);
    assert_eq!(plan_json["payload"]["status"], "planned");
    let planned_operations = plan_json["payload"]["plan"]["operations"]
        .as_array()
        .expect("planned operations array");
    assert!(!planned_operations.is_empty());
    assert!(planned_operations.iter().all(|operation| {
        operation["operation"]["kind"]["type"] != "WRITE_FILE"
            && operation["operation"]["kind"]["type"] != "INSTALL_PACKAGE"
    }));
    let planned_run_id = plan_json["payload"]["plan"]["run_id"]
        .as_str()
        .expect("planned run ID");
    assert!(
        plan_state
            .join("runs")
            .join(format!("{planned_run_id}.json"))
            .is_file()
    );

    let approval_required = run_cli(
        &state,
        [
            OsString::from("restore"),
            OsString::from("--package"),
            manual_package.as_os_str().to_owned(),
            OsString::from("--mode"),
            OsString::from("rebuild"),
            OsString::from("--json"),
        ],
    );
    assert_eq!(approval_required.status.code(), Some(5));
    let approval_json = json_stdout(&approval_required);
    assert_eq!(approval_json["payload"]["status"], "error");
    assert_eq!(
        approval_json["payload"]["error"]["code"],
        "PACKAGE_UNTRUSTED"
    );

    let restore = run_cli(
        &state,
        [
            OsString::from("restore"),
            OsString::from("--package"),
            manual_package.as_os_str().to_owned(),
            OsString::from("--mode"),
            OsString::from("rebuild"),
            OsString::from("--yes-safe"),
            OsString::from("--json"),
        ],
    );
    assert_eq!(
        restore.status.code(),
        Some(3),
        "manual restore exit: {restore:?}"
    );
    let restore_json = json_stdout(&restore);
    assert_eq!(restore_json["payload"]["status"], "WAITING_FOR_USER");
    let run_id = restore_json["payload"]["run_id"]
        .as_str()
        .expect("restore run ID")
        .to_owned();
    assert!(
        state
            .join("reports")
            .join(format!("{run_id}.json"))
            .is_file()
    );
    let verify = run_cli(
        &state,
        [
            OsString::from("verify"),
            OsString::from(&run_id),
            OsString::from("--json"),
        ],
    );
    assert_eq!(verify.status.code(), Some(3), "verify exit: {verify:?}");
    let verify_json = json_stdout(&verify);
    assert_eq!(verify_json["payload"]["status"], "WAITING_FOR_USER");

    let report_path = state.join("saved-report.json");
    let report = run_cli(
        &state,
        [
            OsString::from("report"),
            OsString::from(&run_id),
            OsString::from("--output"),
            report_path.as_os_str().to_owned(),
            OsString::from("--json"),
        ],
    );
    assert_eq!(report.status.code(), Some(3), "report exit: {report:?}");
    let report_json = json_stdout(&report);
    assert_eq!(report_json["payload"]["status"], "WAITING_FOR_USER");
    let saved_report: Value =
        serde_json::from_slice(&fs::read(&report_path).expect("saved report"))
            .expect("saved report JSON");
    assert_eq!(saved_report["status"], "WAITING_FOR_USER");
    let saved_report_bytes = fs::read(&report_path).expect("saved report bytes");
    assert!(!String::from_utf8_lossy(&saved_report_bytes).contains("C:\\Users\\"));

    let resume = run_cli(
        &state,
        [
            OsString::from("resume"),
            OsString::from(&run_id),
            OsString::from("--json"),
        ],
    );
    assert_eq!(resume.status.code(), Some(3), "resume exit: {resume:?}");
    let resume_json = json_stdout(&resume);
    assert_eq!(resume_json["payload"]["status"], "WAITING_FOR_USER");

    let actions = run_cli(
        &state,
        [
            OsString::from("action"),
            OsString::from("list"),
            OsString::from(&run_id),
            OsString::from("--json"),
        ],
    );
    assert!(actions.status.success(), "action list failed: {actions:?}");
    let actions_json = json_stdout(&actions);
    assert_eq!(actions_json["payload"]["status"], "ok");
    let action_id = actions_json["payload"]["manual_actions"]
        .as_array()
        .expect("manual action list")
        .first()
        .expect("manual action")
        .get("id")
        .and_then(Value::as_str)
        .expect("manual action ID")
        .to_owned();
    assert_eq!(
        actions_json["payload"]["manual_actions"][0]["state"],
        "PENDING"
    );
    let acknowledgement = run_cli(
        &state,
        [
            OsString::from("action"),
            OsString::from("acknowledge"),
            OsString::from(&run_id),
            OsString::from(&action_id),
            OsString::from("--json"),
        ],
    );
    assert!(
        acknowledgement.status.success(),
        "action acknowledgement failed: {acknowledgement:?}"
    );
    let acknowledgement_json = json_stdout(&acknowledgement);
    assert_eq!(acknowledgement_json["payload"]["status"], "acknowledged");
    assert_eq!(
        acknowledgement_json["payload"]["action"]["state"],
        "ACKNOWLEDGED"
    );
    let refreshed_verification = run_cli(
        &state,
        [
            OsString::from("verify"),
            OsString::from(&run_id),
            OsString::from("--json"),
        ],
    );
    assert_eq!(
        refreshed_verification.status.code(),
        Some(3),
        "verification after acknowledgement: {refreshed_verification:?}"
    );
    let refreshed_verification_json = json_stdout(&refreshed_verification);
    assert_eq!(
        refreshed_verification_json["payload"]["manual_actions"][0]["state"],
        "ACKNOWLEDGED"
    );

    let _ = fs::remove_dir_all(state);
    let _ = fs::remove_dir_all(plan_state);
}
