#![allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by other suites"
)]

mod support;

use std::{collections::BTreeMap, ffi::OsString, time::Duration};

use reforge_domain::{
    ComponentId, ComponentReport, ContentType, ErrorEnvelope, FileMode, KnownFolderToken,
    ObjectEntry, ObjectId, ObjectIndex, Operation, OperationId, OperationKind, Precondition,
    ProviderId, ReforgeErrorCode, ReportCounts, ReportStatus, RestoreMode, RestorePlan,
    RestoreReport, RunId, validate_restore_plan,
};
use reforge_platform_windows::{BuiltinExecutable, CommandSpec, KnownFolderMap, TrustedExecutable};
use reforge_restore::{Journal, redact_restore_report};
use serde_json::{Value, json};
use support::FixtureRoot;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("component ID")
}

fn operation_id(ordinal: u64) -> OperationId {
    OperationId::for_run(&run_id(), ordinal).expect("operation ID")
}

fn operation(
    ordinal: u64,
    kind: OperationKind,
    prerequisites: Vec<OperationId>,
    key: impl Into<String>,
) -> Operation {
    Operation {
        id: operation_id(ordinal),
        component: component_id(),
        kind,
        prerequisites,
        precondition: Precondition::Always,
        idempotency_key: key.into(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

fn plan(operations: Vec<Operation>) -> RestorePlan {
    RestorePlan {
        format_version: 1,
        run_id: run_id(),
        package_id: "pkg_security_fixture".to_owned(),
        mode: RestoreMode::Rebuild,
        target_fingerprint: "target-fingerprint".to_owned(),
        selected_components: vec![component_id()],
        operations,
        conflicts: Vec::new(),
        manual_actions: Vec::new(),
        warnings: Vec::new(),
    }
}

fn provider_operation(ordinal: u64, prerequisites: Vec<OperationId>) -> Operation {
    operation(
        ordinal,
        OperationKind::EnsureProvider {
            provider: ProviderId::new("winget").expect("provider ID"),
        },
        prerequisites,
        format!("security-operation-{ordinal}"),
    )
}

#[test]
fn generated_acyclic_operation_plans_validate_and_round_trip() {
    let object = ObjectId::from_content(b"security object");
    let index = ObjectIndex {
        objects: vec![ObjectEntry {
            id: object.clone(),
            uncompressed_bytes: b"security object".len() as u64,
            compressed_bytes: 17,
            content_type: ContentType::Binary,
        }],
    };

    for seed in 0..512u64 {
        let count = 1 + (seed as usize % 24);
        let mut operations = Vec::with_capacity(count);
        for ordinal in 0..count {
            let prerequisites = if ordinal != 0 && (seed.rotate_left(ordinal as u32) & 1) == 1 {
                vec![operation_id((seed as usize % ordinal) as u64)]
            } else {
                Vec::new()
            };
            let kind = if ordinal % 3 == 0 {
                OperationKind::WriteFile {
                    destination: reforge_domain::PathToken::new(
                        KnownFolderToken::Documents,
                        format!("generated/{seed:04x}/{ordinal:02}.bin"),
                    )
                    .expect("safe generated destination"),
                    object: object.clone(),
                    mode: FileMode::Replace,
                }
            } else {
                OperationKind::EnsureProvider {
                    provider: ProviderId::new("winget").expect("provider ID"),
                }
            };
            operations.push(operation(
                ordinal as u64,
                kind,
                prerequisites,
                format!("generated-{seed}-{ordinal}"),
            ));
        }

        let generated = plan(operations);
        validate_restore_plan(&generated, &index).expect("generated DAG must validate");
        let encoded = serde_json::to_vec(&generated).expect("plan JSON");
        let decoded: RestorePlan = serde_json::from_slice(&encoded).expect("plan round trip");
        validate_restore_plan(&decoded, &index).expect("round-tripped DAG must validate");
    }
}

#[test]
fn dependency_cycles_duplicate_ids_and_missing_objects_fail_closed() {
    let first = operation_id(0);
    let second = operation_id(1);
    let cycle = plan(vec![
        provider_operation(0, vec![second.clone()]),
        provider_operation(1, vec![first]),
    ]);
    assert_eq!(
        validate_restore_plan(
            &cycle,
            &ObjectIndex {
                objects: Vec::new()
            }
        )
        .expect_err("cycle must fail")
        .code,
        ReforgeErrorCode::DependencyCycle
    );

    let duplicate = plan(vec![
        provider_operation(0, Vec::new()),
        provider_operation(0, Vec::new()),
    ]);
    assert_eq!(
        validate_restore_plan(
            &duplicate,
            &ObjectIndex {
                objects: Vec::new()
            }
        )
        .expect_err("duplicate operation ID must fail")
        .code,
        ReforgeErrorCode::SchemaInvalid
    );

    let missing = ObjectId::from_content(b"missing object");
    let missing_object = plan(vec![operation(
        0,
        OperationKind::WriteFile {
            destination: reforge_domain::PathToken::new(KnownFolderToken::Documents, "missing.bin")
                .expect("safe destination"),
            object: missing,
            mode: FileMode::Replace,
        },
        Vec::new(),
        "missing-object",
    )]);
    assert_eq!(
        validate_restore_plan(
            &missing_object,
            &ObjectIndex {
                objects: Vec::new()
            }
        )
        .expect_err("absent object reference must fail")
        .code,
        ReforgeErrorCode::SchemaInvalid
    );
}

#[test]
fn malformed_plan_schemas_paths_and_imperative_operation_kinds_are_rejected() {
    let object = ObjectId::from_content(b"object");
    let valid = plan(vec![operation(
        0,
        OperationKind::WriteFile {
            destination: reforge_domain::PathToken::new(
                KnownFolderToken::Documents,
                "safe/file.bin",
            )
            .expect("safe destination"),
            object,
            mode: FileMode::Replace,
        },
        Vec::new(),
        "schema-operation",
    )]);

    let mut unknown_field = serde_json::to_value(&valid).expect("plan value");
    unknown_field["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<RestorePlan>(unknown_field).is_err());

    let mut traversal = serde_json::to_value(&valid).expect("plan value");
    traversal["operations"][0]["kind"]["content"]["destination"]["relative"] =
        Value::String("../escape.bin".to_owned());
    assert!(serde_json::from_value::<RestorePlan>(traversal).is_err());

    let mut run_command = serde_json::to_value(&valid).expect("plan value");
    run_command["operations"][0]["kind"]["type"] = Value::String("RUN_COMMAND".to_owned());
    run_command["operations"][0]["kind"]["content"] = json!({
        "command": "cmd.exe /c whoami"
    });
    assert!(serde_json::from_value::<RestorePlan>(run_command).is_err());

    for malformed in [
        b"".as_slice(),
        b"null",
        b"[]",
        b"{",
        b"{\"format_version\":1}",
    ] {
        assert!(serde_json::from_slice::<RestorePlan>(malformed).is_err());
    }
}

#[cfg(windows)]
#[test]
fn known_folder_resolution_rejects_junction_traversal() {
    use std::{os::windows::fs::symlink_dir, process::Command};

    let fixture = FixtureRoot::new("security-reparse").expect("fixture root");
    let target = fixture
        .create_dir("junction-target")
        .expect("junction target");
    let link = fixture.tokens().documents.join("linked");
    if symlink_dir(&target, &link).is_err() {
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/j"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("cmd.exe test fixture helper");
        assert!(
            output.status.success(),
            "junction fixture creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let roots = KnownFolderMap::from_entries(BTreeMap::from([(
        KnownFolderToken::Documents,
        fixture.tokens().documents.clone(),
    )]));
    let token = reforge_domain::PathToken::new(KnownFolderToken::Documents, "linked/escape.bin")
        .expect("lexically safe path");
    let error = roots
        .resolve(&token)
        .expect_err("reparse point must fail closed");
    assert_eq!(error.code, ReforgeErrorCode::ReparsePoint);
}

#[test]
fn shell_metacharacters_remain_literal_arguments_and_nul_is_rejected() {
    let metacharacters = [
        OsString::from("package&whoami"),
        OsString::from("$(whoami)"),
        OsString::from("value|more"),
        OsString::from("quoted value; Remove-Item C:\\*"),
    ];
    let spec = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
        metacharacters.clone(),
        Duration::from_secs(30),
        64 * 1024,
    )
    .expect("literal argument vector");
    assert_eq!(spec.args, metacharacters);

    let error = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
        [OsString::from("unsafe\0argument")],
        Duration::from_secs(30),
        64 * 1024,
    )
    .expect_err("NUL argument must fail before process creation");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
}

#[test]
fn journal_errors_provider_output_and_reports_never_emit_raw_secrets() {
    let secret = "super-secret-journal-value-927451";
    let fixture = FixtureRoot::new("security-secret-leakage").expect("fixture root");
    let database = fixture.path("journal.sqlite").expect("journal path");
    let journal = Journal::open(database).expect("journal opens");
    let restore_plan = plan(vec![provider_operation(0, Vec::new())]);
    journal.create_run(&restore_plan).expect("run created");
    journal
        .append_event(
            &restore_plan.run_id,
            "ERROR",
            &json!({
                "authorization": format!("Bearer {secret}"),
                "message": format!("token={secret}"),
                "source_path": r"C:\Users\Alice\secret.txt"
            }),
        )
        .expect("redacted event");
    let events = journal
        .list_events(&restore_plan.run_id)
        .expect("persisted events");
    let persisted =
        serde_json::to_string(&events.last().expect("appended event").event).expect("event JSON");
    assert!(!persisted.contains(secret));
    assert!(!persisted.contains(r"C:\Users\Alice"));
    assert!(persisted.contains("<REDACTED>"));
    assert!(persisted.contains("<PATH>"));

    let envelope = ErrorEnvelope::new(ReforgeErrorCode::OperationFailed, "safe failure")
        .with_technical_detail(format!("password={secret}"));
    assert!(!envelope.to_json().contains(secret));

    let provider = reforge_domain::redact_provider_output(
        format!("Authorization: Bearer {secret}").as_bytes(),
        format!("token={secret}").as_bytes(),
    );
    let provider_text = format!("{provider:?}");
    assert!(!provider_text.contains(secret));
    assert!(provider_text.contains("<REDACTED>"));

    let report = RestoreReport {
        format_version: 1,
        run_id: restore_plan.run_id,
        package_id: "pkg_security_fixture".to_owned(),
        status: ReportStatus::Failed,
        counts: ReportCounts {
            verified: 0,
            partial: 0,
            already_present: 0,
            waiting_for_user: 0,
            reauth_required: 0,
            reboot_required: 0,
            unsupported: 0,
            failed: 1,
        },
        components: vec![ComponentReport {
            component: component_id(),
            status: ReportStatus::Failed,
            evidence: Vec::new(),
            manual_actions: vec![format!("token={secret}")],
            warnings: vec![format!("password={secret}")],
        }],
        manual_actions: Vec::new(),
        warnings: vec![format!("authorization=Bearer {secret}")],
        elapsed_ms: 1,
        bytes_written: 0,
    };
    let report_json = serde_json::to_string(&redact_restore_report(report)).expect("report JSON");
    assert!(!report_json.contains(secret));
    assert!(report_json.contains("<REDACTED>"));
}
