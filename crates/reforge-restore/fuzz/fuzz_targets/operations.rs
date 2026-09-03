#![no_main]

use std::{ffi::OsString, time::Duration};

use libfuzzer_sys::fuzz_target;
use reforge_domain::{
    ComponentId, ContentType, FileMode, KnownFolderToken, MergePolicy, ObjectEntry, ObjectId,
    ObjectIndex, Operation, OperationId, OperationKind, PathToken, Precondition, ProviderId,
    RestoreMode, RestorePlan, RunId, validate_restore_plan,
};
use reforge_platform_windows::{BuiltinExecutable, CommandSpec, TrustedExecutable};

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;

fn run_id() -> RunId {
    RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned()).expect("fixed run ID")
}

fn component_id() -> ComponentId {
    ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("fixed component ID")
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(candidate) = serde_json::from_slice::<RestorePlan>(data) {
        let _ = validate_restore_plan(
            &candidate,
            &ObjectIndex {
                objects: Vec::new(),
            },
        );
    }

    let redacted = reforge_domain::redact_provider_output(data, data);
    if let Ok(text) = std::str::from_utf8(data) {
        let args = [OsString::from(text)];
        if let Ok(spec) = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
            args.clone(),
            Duration::from_secs(1),
            64 * 1024,
        ) {
            assert_eq!(spec.args, args);
        }
        if text.contains('\0') {
            assert!(
                CommandSpec::new(
                    TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
                    args,
                    Duration::from_secs(1),
                    64 * 1024,
                )
                .is_err()
            );
        }
    }
    for value in [&redacted.stdout, &redacted.stderr].into_iter().flatten() {
        assert!(value.len() <= reforge_domain::redaction::DEFAULT_MAX_REDACTED_BYTES);
        assert!(!value.chars().any(|character| {
            character.is_control() && !matches!(character, '\n' | '\r' | '\t')
        }));
    }

    let count = 1 + data.first().copied().unwrap_or_default() as usize % 32;
    let object = ObjectId::from_content(data);
    let ids: Vec<_> = (0..count)
        .map(|ordinal| OperationId::for_run(&run_id(), ordinal as u64).expect("operation ID"))
        .collect();
    let mut operations = Vec::with_capacity(count);
    for ordinal in 0..count {
        let selector = data.get(ordinal + 1).copied().unwrap_or(ordinal as u8);
        let prerequisites = if selector & 1 == 0 {
            Vec::new()
        } else if selector == u8::MAX {
            vec![OperationId::for_run(&run_id(), count as u64 + 1).expect("missing ID")]
        } else {
            vec![ids[selector as usize % count].clone()]
        };
        let destination = PathToken::new(
            KnownFolderToken::Documents,
            format!("fuzz/{:02x}/{ordinal}.json", selector),
        )
        .expect("generated path");
        let kind = match selector % 3 {
            0 => OperationKind::WriteFile {
                destination,
                object: object.clone(),
                mode: FileMode::Replace,
            },
            1 => OperationKind::MergeJson {
                destination,
                object: object.clone(),
                policy: MergePolicy::PreserveUnknown,
            },
            _ => OperationKind::EnsureProvider {
                provider: ProviderId::new("winget").expect("provider ID"),
            },
        };
        operations.push(Operation {
            id: ids[ordinal].clone(),
            component: component_id(),
            kind,
            prerequisites,
            precondition: Precondition::Always,
            idempotency_key: format!("fuzz-{}-{ordinal}", selector % 7),
            verification: Vec::new(),
            requires_elevation: false,
            non_idempotent: false,
        });
    }
    let plan = RestorePlan {
        format_version: 1,
        run_id: run_id(),
        package_id: "pkg_fuzz".to_owned(),
        mode: RestoreMode::Rebuild,
        target_fingerprint: "fuzz-target".to_owned(),
        selected_components: vec![component_id()],
        operations,
        conflicts: Vec::new(),
        manual_actions: Vec::new(),
        warnings: Vec::new(),
    };
    let object_index = ObjectIndex {
        objects: vec![ObjectEntry {
            id: object,
            uncompressed_bytes: data.len() as u64,
            compressed_bytes: data.len() as u64,
            content_type: ContentType::Binary,
        }],
    };
    if validate_restore_plan(&plan, &object_index).is_ok() {
        let encoded = serde_json::to_vec(&plan).expect("validated plan JSON");
        let decoded: RestorePlan = serde_json::from_slice(&encoded).expect("validated plan parse");
        validate_restore_plan(&decoded, &object_index)
            .expect("round-tripped plan must remain valid");
    }
});
