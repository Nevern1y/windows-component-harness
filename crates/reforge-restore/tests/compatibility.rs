#![allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by later restore suites"
)]

mod support;

use std::collections::BTreeMap;

use reforge_domain::{
    Architecture, Compatibility, CompatibilityStatus, Component, ComponentId, ComponentKind,
    Confidence, Identity, IdentityQuality, PackageGraph, PackageManifest, Portability,
    ProviderFact, ProviderId, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy,
    SelectionMetadata, SourceHostSummary, TargetFacts,
};
use reforge_restore::{CompatibilityEngine, recommended_free_bytes};
use support::target_facts;

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn ready_target_keeps_non_blocking_warnings_separate() {
    let runtime_id = component_id('r');
    let mut target = target_facts();
    target.providers = vec![provider("winget", true, false)];
    target.runtimes = vec![reforge_domain::RuntimeFact {
        id: runtime_id.clone(),
        version: None,
        architecture: Some(Architecture::X64),
    }];
    let component = component(
        'a',
        Compatibility {
            required_os: Some("windows".to_owned()),
            required_architecture: Some(Architecture::X64),
            requires_provider: Some(ProviderId::new("winget").unwrap()),
            requires_runtime: Some(runtime_id),
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
    );

    let result = evaluate(&[component], 1, &target);

    assert_eq!(result.status, CompatibilityStatus::Ready);
    assert!(result.blockers.is_empty());
    assert!(result.confirmations.is_empty());
    assert_eq!(result.warnings.len(), 2);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("provider"))
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("runtime"))
    );
}

#[test]
fn operating_system_conflict_is_blocked() {
    let mut target = target_facts();
    target.host.os_version = "Linux".to_owned();
    let result = evaluate(&[], 0, &target);

    assert_eq!(result.status, CompatibilityStatus::Blocked);
    assert_eq!(result.blockers[0].code, ReforgeErrorCode::OsConflict);
    assert!(result.blockers[0].required_action.is_some());
}

#[test]
fn architecture_conflict_and_unknown_privileged_architecture_are_blocked() {
    let mut target = target_facts();
    target.host.architecture = Architecture::Arm64;
    let component = component(
        'a',
        Compatibility {
            required_os: None,
            required_architecture: Some(Architecture::X64),
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
    );
    let result = evaluate(std::slice::from_ref(&component), 0, &target);
    assert_eq!(result.status, CompatibilityStatus::Blocked);
    assert!(
        result
            .blockers
            .iter()
            .any(|blocker| blocker.code == ReforgeErrorCode::ArchitectureConflict)
    );

    target.host.architecture = Architecture::Unknown;
    let unknown = evaluate(&[component], 0, &target);
    assert_eq!(unknown.status, CompatibilityStatus::Blocked);
    assert!(
        unknown
            .warnings
            .iter()
            .any(|warning| warning == "Target architecture is unknown")
    );
}

#[test]
fn insufficient_and_unknown_disk_are_blocked() {
    let mut target = target_facts();
    target.host.free_bytes[0].bytes = 99;
    let insufficient = evaluate(&[], 100, &target);
    assert_eq!(insufficient.status, CompatibilityStatus::Blocked);
    assert_eq!(
        insufficient.blockers[0].code,
        ReforgeErrorCode::InsufficientDisk
    );

    target.host.free_bytes.clear();
    let unknown = evaluate(&[], 100, &target);
    assert_eq!(unknown.status, CompatibilityStatus::Blocked);
    assert_eq!(unknown.blockers[0].code, ReforgeErrorCode::InsufficientDisk);
    assert!(unknown.blockers[0].required_action.is_some());
}

#[test]
fn free_space_without_the_backup_margin_requires_confirmation() {
    let required = GIB;
    let recommended = recommended_free_bytes(required).expect("bounded recommendation");
    let mut target = target_facts();
    target.host.free_bytes[0].bytes = recommended - 1;

    let result = evaluate(&[], required, &target);

    assert_eq!(result.status, CompatibilityStatus::RequiresConfirmation);
    assert!(result.blockers.is_empty());
    assert_eq!(result.confirmations.len(), 1);
    assert_eq!(result.confirmations[0].id, "confirm_low_disk_margin");
}

#[test]
fn unavailable_provider_produces_a_manual_blocker() {
    let mut target = target_facts();
    target.providers = vec![provider("winget", false, true)];
    let component = component(
        'a',
        Compatibility {
            required_os: None,
            required_architecture: None,
            requires_provider: Some(ProviderId::new("winget").unwrap()),
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
    );

    let result = evaluate(&[component], 0, &target);

    assert_eq!(result.status, CompatibilityStatus::Blocked);
    assert_eq!(
        result.blockers[0].code,
        ReforgeErrorCode::ProviderUnavailable
    );
    let action = result.blockers[0]
        .required_action
        .as_ref()
        .expect("manual provider action");
    assert!(!action.independent_operations_may_continue);
    assert!(!action.instructions.is_empty());
}

#[test]
fn absent_runtime_and_wrong_runtime_architecture_block() {
    let runtime_id = component_id('r');
    let component = component(
        'a',
        Compatibility {
            required_os: None,
            required_architecture: None,
            requires_provider: None,
            requires_runtime: Some(runtime_id.clone()),
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
    );
    let mut target = target_facts();
    let absent = evaluate(std::slice::from_ref(&component), 0, &target);
    assert!(
        absent
            .blockers
            .iter()
            .any(|blocker| blocker.code == ReforgeErrorCode::TargetConflict)
    );

    target.runtimes = vec![reforge_domain::RuntimeFact {
        id: runtime_id,
        version: Some(reforge_domain::VersionValue {
            raw: "1".to_owned(),
            normalized: Some("1".to_owned()),
        }),
        architecture: Some(Architecture::Arm64),
    }];
    let mismatch = evaluate(&[component], 0, &target);
    assert!(
        mismatch
            .blockers
            .iter()
            .any(|blocker| blocker.code == ReforgeErrorCode::ArchitectureConflict)
    );
}

#[test]
fn non_elevated_target_blocks_privileged_component() {
    let component = component(
        'a',
        Compatibility {
            required_os: None,
            required_architecture: None,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: true,
            requires_wsl: false,
            requires_docker: false,
        },
    );
    let result = evaluate(&[component], 0, &target_facts());

    assert_eq!(result.status, CompatibilityStatus::Blocked);
    assert!(
        result
            .blockers
            .iter()
            .any(|blocker| blocker.code == ReforgeErrorCode::AccessDenied)
    );
}

#[test]
fn missing_wsl_and_docker_support_each_block() {
    let component = component(
        'a',
        Compatibility {
            required_os: None,
            required_architecture: None,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: true,
            requires_docker: true,
        },
    );
    let mut target = target_facts();
    target.providers.clear();

    let result = evaluate(&[component], 0, &target);

    assert_eq!(result.status, CompatibilityStatus::Blocked);
    assert_eq!(
        result
            .blockers
            .iter()
            .filter(|blocker| blocker.code == ReforgeErrorCode::ProviderUnavailable)
            .count(),
        2
    );
}

fn evaluate(
    components: &[Component],
    required_disk_bytes: u64,
    target: &TargetFacts,
) -> reforge_domain::CompatibilityResult {
    CompatibilityEngine::new().evaluate(
        &manifest(),
        &PackageGraph {
            components: components.to_vec(),
            edges: Vec::new(),
        },
        required_disk_bytes,
        target,
    )
}

fn manifest() -> PackageManifest {
    PackageManifest {
        package_id: "pkg_compatibility".to_owned(),
        format_version: 1,
        created_at: "2026-08-30T12:00:00Z".parse().expect("timestamp"),
        source_host: SourceHostSummary {
            os_version: "Windows 11".to_owned(),
            os_build: "fixture".to_owned(),
            architecture: Architecture::X64,
            known_folder_tokens: Vec::new(),
        },
        required_os: Some("windows".to_owned()),
        required_architecture: Some(Architecture::X64),
        component_ids: Vec::new(),
        warnings: Vec::new(),
        object_index_digest: "obj_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
    }
}

fn component(id_character: char, compatibility: Compatibility) -> Component {
    Component {
        id: component_id(id_character),
        kind: ComponentKind::Application,
        identity: Identity {
            provider_package: None,
            provider_source: None,
            package_family: None,
            product_name: Some("Compatibility fixture".to_owned()),
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: Some("fixture".to_owned()),
            identity_quality: IdentityQuality::Product,
        },
        display_name: "Compatibility fixture".to_owned(),
        version: None,
        architecture: compatibility.required_architecture.clone(),
        publisher: None,
        provenance: None,
        evidence: Vec::new(),
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Reinstall,
            alternatives: Vec::new(),
            portability: Portability::Portable,
            requires_elevation: compatibility.requires_elevation,
            requires_user_action: false,
            rationale: vec!["fixture".to_owned()],
        },
        compatibility,
        verification: Vec::new(),
        selection: SelectionMetadata {
            recommended: true,
            score: 100,
            selected_by_default: true,
            sensitive: false,
            size_bytes: 0,
        },
        extensions: BTreeMap::new(),
    }
}

fn component_id(character: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", character.to_string().repeat(52))).expect("component ID")
}

fn provider(id: &str, available: bool, with_version: bool) -> ProviderFact {
    ProviderFact {
        id: ProviderId::new(id).expect("provider ID"),
        version: with_version.then(|| reforge_domain::VersionValue {
            raw: "1.0".to_owned(),
            normalized: Some("1.0".to_owned()),
        }),
        available,
    }
}
