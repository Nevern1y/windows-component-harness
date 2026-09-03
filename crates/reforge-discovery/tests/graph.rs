use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use reforge_discovery::deduplicate_graph;
use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, DependencyEdge,
    DependencyKind, Evidence, EvidenceId, EvidenceSource, Identity, IdentityQuality, Portability,
    Publisher, RestoreDescriptor, RestoreStrategy, SelectionMetadata,
};

#[test]
fn package_registry_and_executable_observations_merge_by_shared_product_identity() {
    let evidence = vec![
        evidence("package", 55, "package-export"),
        evidence("registry", 30, "registry"),
        evidence("executable", 25, "executable"),
    ];
    let package = component(
        ComponentKind::Package,
        provider_identity("Git.Git"),
        "Git.Git",
        &evidence[0],
    );
    let registry = component(
        ComponentKind::Application,
        product_identity(None, None),
        "Git",
        &evidence[1],
    );
    let executable = component(
        ComponentKind::PortableBinary,
        product_identity(Some("git.exe"), Some("hash-git")),
        "Git executable",
        &evidence[2],
    );
    let graph = deduplicate_graph(
        vec![package.clone(), registry.clone(), executable.clone()],
        Vec::new(),
        &evidence,
    )
    .expect("graph deduplicates");

    assert_eq!(graph.components.len(), 1);
    let merged = &graph.components[0];
    assert_eq!(
        merged.identity.provider_package.as_ref().map(|(_, id)| id),
        Some(&"Git.Git".to_owned())
    );
    assert_eq!(merged.confidence, Confidence::Confirmed);
    let metadata = merged
        .extensions
        .get("reforge_dedup")
        .and_then(|value| value.get("member_component_ids"))
        .and_then(|value| value.as_array())
        .expect("merge membership metadata");
    assert_eq!(metadata.len(), 3);
}

#[test]
fn conflicting_publishers_are_preserved_and_reduce_confidence() {
    let first_evidence = evidence("publisher-a", 60, "registry");
    let second_evidence = evidence("publisher-b", 60, "authenticode");
    let first = component(
        ComponentKind::PortableBinary,
        local_identity_with_publisher("tool.exe", "same-hash", "Publisher A"),
        "Tool",
        &first_evidence,
    );
    let second = component(
        ComponentKind::PortableBinary,
        local_identity_with_publisher("tool.exe", "same-hash", "Publisher B"),
        "Tool",
        &second_evidence,
    );
    let graph = deduplicate_graph(
        vec![first, second],
        Vec::new(),
        &[first_evidence, second_evidence],
    )
    .expect("graph deduplicates conflicting facts");

    assert_eq!(graph.components.len(), 1);
    assert_eq!(graph.components[0].confidence, Confidence::High);
    let conflicts = graph.components[0]
        .extensions
        .get("reforge_dedup")
        .and_then(|value| value.get("conflicts"))
        .and_then(|value| value.get("publisher"))
        .and_then(|value| value.as_array())
        .expect("publisher conflict metadata");
    assert_eq!(conflicts.len(), 2);
    assert!(conflicts.iter().all(|value| value.is_string()));
}

#[test]
fn required_cycles_and_optional_edges_are_retained_deterministically() {
    let first_evidence = evidence("a", 70, "package");
    let second_evidence = evidence("b", 70, "registry");
    let first = component(
        ComponentKind::Package,
        product_identity_with_publisher("a.exe", "hash-a", "Publisher A"),
        "A",
        &first_evidence,
    );
    let second = component(
        ComponentKind::Package,
        product_identity_with_publisher("b.exe", "hash-b", "Publisher B"),
        "B",
        &second_evidence,
    );
    let required_ab = edge(&first, &second, true, first_evidence.id.clone());
    let required_ba = edge(&second, &first, true, second_evidence.id.clone());
    let optional_ab = DependencyEdge {
        kind: DependencyKind::RelatedOnly,
        required: false,
        ..required_ab.clone()
    };
    let graph = deduplicate_graph(
        vec![first.clone(), second.clone()],
        vec![required_ab, required_ba, optional_ab],
        &[first_evidence, second_evidence],
    )
    .expect("graph retains cycle");

    assert_eq!(graph.components.len(), 2);
    assert_eq!(graph.edges.len(), 3);
    assert!(graph.edges.iter().any(|edge| edge.required));
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| !edge.required && edge.kind == DependencyKind::RelatedOnly)
    );
    for component in &graph.components {
        assert_eq!(
            component.dependencies,
            graph
                .edges
                .iter()
                .filter(|edge| edge.from == component.id)
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn repeated_input_order_produces_the_same_graph() {
    let first_evidence = evidence("first", 45, "one");
    let second_evidence = evidence("second", 45, "two");
    let first = component(
        ComponentKind::Application,
        product_identity_with_publisher("first.exe", "hash-first", "Publisher First"),
        "First",
        &first_evidence,
    );
    let second = component(
        ComponentKind::Application,
        product_identity_with_publisher("second.exe", "hash-second", "Publisher Second"),
        "Second",
        &second_evidence,
    );
    let first_edge = edge(&first, &second, true, first_evidence.id.clone());
    let second_edge = edge(&second, &first, false, second_evidence.id.clone());
    let evidence = vec![first_evidence, second_evidence];
    let forward = deduplicate_graph(
        vec![first.clone(), second.clone()],
        vec![first_edge.clone(), second_edge.clone()],
        &evidence,
    )
    .expect("forward graph");
    let reversed = deduplicate_graph(
        vec![second, first],
        vec![second_edge, first_edge],
        &evidence,
    )
    .expect("reversed graph");

    assert_eq!(forward, reversed);
}

fn provider_identity(package_id: &str) -> Identity {
    let publisher = "Git".to_owned();
    Identity {
        provider_package: Some((
            reforge_domain::ProviderId::new("winget").expect("provider"),
            package_id.to_owned(),
        )),
        provider_source: Some("winget-source".to_owned()),
        package_family: None,
        product_name: Some("Git".to_owned()),
        executable_name: Some("git.exe".to_owned()),
        publisher: Some(publisher),
        executable_hash: None,
        install_role: Some("application".to_owned()),
        identity_quality: IdentityQuality::Provider,
    }
}

fn local_identity_with_publisher(executable: &str, hash: &str, publisher: &str) -> Identity {
    Identity {
        provider_package: None,
        provider_source: None,
        package_family: None,
        product_name: None,
        executable_name: Some(executable.to_owned()),
        publisher: Some(publisher.to_owned()),
        executable_hash: Some(hash.to_owned()),
        install_role: Some("application".to_owned()),
        identity_quality: IdentityQuality::Local,
    }
}

fn product_identity(executable: Option<&str>, hash: Option<&str>) -> Identity {
    product_identity_with_publisher(
        executable.unwrap_or("tool.exe"),
        hash.unwrap_or("hash"),
        "Git",
    )
}

fn product_identity_with_publisher(executable: &str, hash: &str, publisher: &str) -> Identity {
    Identity {
        provider_package: None,
        provider_source: None,
        package_family: None,
        product_name: Some("Git".to_owned()),
        executable_name: Some(executable.to_owned()),
        publisher: Some(publisher.to_owned()),
        executable_hash: Some(hash.to_owned()),
        install_role: Some("application".to_owned()),
        identity_quality: IdentityQuality::Product,
    }
}

fn component(
    kind: ComponentKind,
    identity: Identity,
    name: &str,
    evidence: &Evidence,
) -> Component {
    let publisher = identity.publisher.clone().map(|name| Publisher {
        name,
        certificate_thumbprint: None,
    });
    let canonical = ComponentId::from_identity(&identity, publisher.as_ref())
        .expect("component identity")
        .id;
    Component {
        id: canonical,
        kind,
        identity,
        display_name: name.to_owned(),
        version: None,
        architecture: None,
        publisher,
        provenance: None,
        evidence: vec![reforge_domain::EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        }],
        confidence: Confidence::Low,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: Vec::new(),
            portability: Portability::Unknown,
            requires_elevation: false,
            requires_user_action: false,
            rationale: Vec::new(),
        },
        compatibility: Compatibility {
            required_os: None,
            required_architecture: None,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
        verification: Vec::new(),
        selection: SelectionMetadata {
            recommended: false,
            score: 0,
            selected_by_default: false,
            sensitive: false,
            size_bytes: 0,
        },
        extensions: BTreeMap::new(),
    }
}

fn evidence(label: &str, strength: u8, group: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!("evidence-{label}")).expect("evidence ID"),
        source: EvidenceSource::Unknown,
        locator: format!("fixture:{label}"),
        observed_at: Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5).unwrap(),
        summary: format!("{label} evidence"),
        strength,
        independent_group: group.to_owned(),
    }
}

fn edge(from: &Component, to: &Component, required: bool, evidence: EvidenceId) -> DependencyEdge {
    DependencyEdge {
        from: from.id.clone(),
        to: to.id.clone(),
        kind: DependencyKind::RequiredPackage,
        required,
        evidence: vec![evidence],
        confidence: Confidence::Unknown,
    }
}
