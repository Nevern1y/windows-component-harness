#![allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by later restore suites"
)]

mod support;

use std::collections::BTreeMap;

use reforge_domain::{
    Architecture, Compatibility, Component, ComponentId, ComponentKind, Confidence, ConfigScope,
    EnvironmentFact, Identity, IdentityQuality, Inventory, ObjectId, PackageGraph, Portability,
    Provenance, ProviderFact, ProviderId, Publisher, RestoreDescriptor, RestoreStrategy, RunId,
    SelectionMetadata, VersionValue,
};
use reforge_restore::TargetScanner;
use support::host_facts;

#[test]
fn same_source_package_is_present_with_normalized_identity() {
    let component = package_component('a', "Contoso.Editor", "1.2.3");
    let expected_identity = component.identity.clone();
    let facts = TargetScanner::new()
        .scan(inventory(vec![component], false))
        .expect("target scan");

    assert_eq!(facts.installed.len(), 1);
    assert_eq!(facts.installed[0].identity, expected_identity);
    assert_eq!(
        facts.installed[0]
            .version
            .as_ref()
            .map(|value| value.raw.as_str()),
        Some("1.2.3")
    );
    assert_eq!(facts.providers.len(), 1);
    assert_eq!(facts.providers[0].id.as_str(), "winget");
    assert!(facts.providers[0].available);
}

#[test]
fn absent_package_produces_no_installed_fact() {
    let facts = TargetScanner::new()
        .scan(inventory(Vec::new(), false))
        .expect("empty target scan");

    assert!(facts.installed.is_empty());
    assert!(facts.runtimes.is_empty());
    assert!(facts.providers.is_empty());
}

#[test]
fn newer_target_version_is_preserved_for_source_comparison() {
    let old = TargetScanner::new()
        .scan(inventory(
            vec![package_component('a', "Contoso.Editor", "1.2.3")],
            false,
        ))
        .expect("old target scan");
    let newer = TargetScanner::new()
        .scan(inventory(
            vec![package_component('a', "Contoso.Editor", "2.0.0")],
            false,
        ))
        .expect("new target scan");

    assert_eq!(
        newer.installed[0]
            .version
            .as_ref()
            .and_then(|value| value.normalized.as_deref()),
        Some("2.0.0")
    );
    assert_ne!(old.fingerprint, newer.fingerprint);
}

#[test]
fn target_architecture_and_runtime_architecture_remain_explicit() {
    let mut arm_host = host_facts();
    arm_host.architecture = Architecture::Arm64;
    let runtime = runtime_component('r', "3.12.1", Architecture::X64);
    let mut target = inventory(vec![runtime], false);
    target.host = arm_host;

    let facts = TargetScanner::new().scan(target).expect("target scan");

    assert_eq!(facts.host.architecture, Architecture::Arm64);
    assert_eq!(facts.runtimes.len(), 1);
    assert_eq!(facts.runtimes[0].architecture, Some(Architecture::X64));
    assert!(facts.installed.is_empty());
}

#[test]
fn fingerprint_is_order_stable_and_excludes_local_identity_and_secret_hashes() {
    let package = package_component('a', "Contoso.Editor", "1.2.3");
    let runtime = runtime_component('r', "3.12.1", Architecture::X64);
    let first_secret = secret_component('s', b"first secret value");
    let second_secret = secret_component('s', b"different secret value");

    let first_providers = vec![provider("winget", true), provider("scoop", false)];
    let second_providers = vec![provider("scoop", false), provider("winget", true)];
    let first_environment = vec![EnvironmentFact {
        scope: ConfigScope::User,
        name: "reforge_test_value".to_owned(),
        value_hash: Some(
            ObjectId::from_content(b"first secret value")
                .as_str()
                .to_owned(),
        ),
    }];
    let second_environment = vec![EnvironmentFact {
        scope: ConfigScope::User,
        name: "REFORGE_TEST_VALUE".to_owned(),
        value_hash: Some(
            ObjectId::from_content(b"different secret value")
                .as_str()
                .to_owned(),
        ),
    }];

    let first = TargetScanner::new()
        .scan_with_current_facts(
            inventory(vec![package.clone(), runtime.clone(), first_secret], false),
            first_providers,
            first_environment,
        )
        .expect("first target scan");

    let mut reordered = inventory(vec![second_secret, runtime, package], true);
    reordered.host.sid_fingerprint = Some("another-local-sid".to_owned());
    reordered.host.drives[0].filesystem = Some("different-hardware".to_owned());
    reordered.host.free_bytes[0].bytes = 1;
    reordered.host.known_folders.reverse();
    let second = TargetScanner::new()
        .scan_with_current_facts(reordered, second_providers, second_environment)
        .expect("second target scan");

    assert_eq!(first.fingerprint, second.fingerprint);
    assert!(first.fingerprint.starts_with("target_"));
    assert_eq!(first.fingerprint.len(), "target_".len() + 64);
    assert_eq!(first.environment[0].name, "REFORGE_TEST_VALUE");
    assert_ne!(
        first.environment[0].value_hash,
        second.environment[0].value_hash
    );
    assert!(
        first
            .installed
            .iter()
            .all(|fact| fact.kind != ComponentKind::SecretReference)
    );
}

fn inventory(components: Vec<Component>, alternate_scan: bool) -> Inventory {
    Inventory {
        format_version: 1,
        scan_id: run_id(alternate_scan),
        captured_at: if alternate_scan {
            "2026-08-30T13:00:00Z".parse().expect("timestamp")
        } else {
            "2026-08-30T12:00:00Z".parse().expect("timestamp")
        },
        host: host_facts(),
        graph: PackageGraph {
            components,
            edges: Vec::new(),
        },
        evidence: Vec::new(),
        warnings: if alternate_scan {
            vec!["scan-local warning".to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn run_id(alternate: bool) -> RunId {
    let value = if alternate {
        "01890f3e-7b6c-7cc0-98c4-dc0c0c0c0c0d"
    } else {
        "01890f3e-7b6c-7cc0-98c4-dc0c0c0c0c0c"
    };
    RunId::new(value.parse().expect("UUIDv7")).expect("run ID")
}

fn package_component(id_character: char, package_id: &str, version: &str) -> Component {
    component(
        id_character,
        ComponentKind::Application,
        Some((
            ProviderId::new("winget").expect("provider ID"),
            package_id.to_owned(),
        )),
        version,
        Some(Architecture::X64),
        Some(Provenance {
            provider: Some(ProviderId::new("winget").expect("provider ID")),
            package_id: Some(package_id.to_owned()),
            source_url: None,
            observed_version: Some(version.to_owned()),
            adapter_id: "winget".to_owned(),
            adapter_version: "fixture".to_owned(),
        }),
    )
}

fn runtime_component(id_character: char, version: &str, architecture: Architecture) -> Component {
    component(
        id_character,
        ComponentKind::Runtime,
        None,
        version,
        Some(architecture),
        None,
    )
}

fn secret_component(id_character: char, value: &[u8]) -> Component {
    let mut component = component(
        id_character,
        ComponentKind::SecretReference,
        None,
        "1",
        None,
        None,
    );
    component.identity.executable_hash = Some(ObjectId::from_content(value).as_str().to_owned());
    component
}

fn component(
    id_character: char,
    kind: ComponentKind,
    provider_package: Option<(ProviderId, String)>,
    version: &str,
    architecture: Option<Architecture>,
    provenance: Option<Provenance>,
) -> Component {
    Component {
        id: ComponentId::new(format!("cmp_{}", id_character.to_string().repeat(52)))
            .expect("component ID"),
        kind,
        identity: Identity {
            provider_package,
            provider_source: None,
            package_family: None,
            product_name: Some("Target fixture".to_owned()),
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: Some("fixture".to_owned()),
            identity_quality: IdentityQuality::Provider,
        },
        display_name: "Target fixture".to_owned(),
        version: Some(VersionValue {
            raw: version.to_owned(),
            normalized: Some(version.to_owned()),
        }),
        architecture: architecture.clone(),
        publisher: Some(Publisher {
            name: "Contoso".to_owned(),
            certificate_thumbprint: None,
        }),
        provenance,
        evidence: Vec::new(),
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Reinstall,
            alternatives: Vec::new(),
            portability: Portability::Portable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec!["fixture".to_owned()],
        },
        compatibility: Compatibility {
            required_os: Some("windows".to_owned()),
            required_architecture: architecture,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
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

fn provider(id: &str, available: bool) -> ProviderFact {
    ProviderFact {
        id: ProviderId::new(id).expect("provider ID"),
        version: None,
        available,
    }
}
