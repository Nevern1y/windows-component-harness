use reforge_domain::selection::build_selection_closure;
use reforge_domain::{
    Architecture, ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, Component,
    ComponentGraph, ComponentId, ComponentKind, Confidence, ConfigScope, DependencyEdge,
    DependencyKind, Identity, IdentityQuality, LargeDataSelectionPolicy, PathToken, Portability,
    ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, SecretSelectionPolicy, SelectionInput,
    SelectionMetadata, SelectionPolicy, UnknownBinarySelectionPolicy,
};

fn component_id(suffix: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", suffix.to_string().repeat(52))).expect("component ID")
}

fn identity(hash: Option<&str>) -> Identity {
    Identity {
        provider_package: None,
        provider_source: None,
        package_family: None,
        product_name: None,
        executable_name: hash.map(|_| "tool.exe".to_owned()),
        publisher: None,
        executable_hash: hash.map(str::to_owned),
        install_role: None,
        identity_quality: IdentityQuality::Local,
    }
}

fn component(id: ComponentId, kind: ComponentKind, hash: Option<&str>) -> Component {
    Component {
        id,
        kind,
        identity: identity(hash),
        display_name: "test component".to_owned(),
        version: None,
        architecture: Some(Architecture::X64),
        publisher: None,
        provenance: None,
        evidence: Vec::new(),
        confidence: Confidence::Unknown,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: Vec::new(),
            portability: Portability::Unknown,
            requires_elevation: false,
            requires_user_action: true,
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
        extensions: Default::default(),
    }
}

fn policy() -> SelectionPolicy {
    SelectionPolicy {
        secrets: SecretSelectionPolicy::Exclude,
        large_data: LargeDataSelectionPolicy::Exclude,
        unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
        max_bytes: None,
    }
}

fn artifact(id: &str, size_bytes: u64, artifact_policy: ArtifactPolicy) -> ArtifactRef {
    ArtifactRef {
        id: ArtifactId::new(id).expect("artifact ID"),
        source_path: PathToken::new(
            reforge_domain::KnownFolderToken::Documents,
            format!("{id}.dat"),
        )
        .expect("path token"),
        scope: ConfigScope::User,
        size_bytes,
        content_type: reforge_domain::ContentType::Binary,
        policy: artifact_policy,
        object: None,
    }
}

fn input(components: Vec<ComponentId>) -> SelectionInput {
    SelectionInput {
        components,
        artifacts: Vec::new(),
        policy: policy(),
    }
}

#[test]
fn required_dependencies_are_added_transitively_and_optional_edges_are_visible() {
    let root = component(component_id('a'), ComponentKind::Application, None);
    let runtime = component(component_id('b'), ComponentKind::Runtime, None);
    let optional = component(component_id('c'), ComponentKind::Tool, None);
    let graph = ComponentGraph {
        components: vec![root.clone(), runtime.clone(), optional],
        edges: vec![
            DependencyEdge {
                from: root.id.clone(),
                to: runtime.id.clone(),
                kind: DependencyKind::RequiredRuntime,
                required: true,
                evidence: Vec::new(),
                confidence: Confidence::Unknown,
            },
            DependencyEdge {
                from: root.id.clone(),
                to: component_id('c'),
                kind: DependencyKind::OptionalFeature,
                required: false,
                evidence: Vec::new(),
                confidence: Confidence::Unknown,
            },
        ],
    };

    let closure = build_selection_closure(&graph, &input(vec![root.id.clone()]))
        .expect("required dependency closure");
    assert_eq!(closure.selected_components, vec![root.id, runtime.id]);
    assert_eq!(closure.auto_added_dependencies, vec![component_id('b')]);
    assert!(
        closure
            .warnings
            .iter()
            .any(|warning| warning.contains("Optional dependency"))
    );
}

#[test]
fn required_dependency_cannot_be_removed_by_an_artifact_decision() {
    let root = component(component_id('a'), ComponentKind::Application, None);
    let runtime_id = component_id('b');
    let mut runtime = component(runtime_id.clone(), ComponentKind::Runtime, None);
    runtime
        .artifacts
        .push(artifact("runtime-config", 4, ArtifactPolicy::Config));
    let graph = ComponentGraph {
        components: vec![root.clone(), runtime],
        edges: vec![DependencyEdge {
            from: root.id.clone(),
            to: runtime_id.clone(),
            kind: DependencyKind::RequiredRuntime,
            required: true,
            evidence: Vec::new(),
            confidence: Confidence::Unknown,
        }],
    };
    let mut selection = input(vec![root.id.clone()]);
    selection.artifacts.push(reforge_domain::ArtifactSelection {
        artifact: ArtifactId::new("runtime-config").expect("artifact ID"),
        include: false,
    });

    let closure = build_selection_closure(&graph, &selection).expect("dependency remains selected");
    assert!(closure.selected_components.contains(&runtime_id));
    assert!(closure.selected_artifacts.is_empty());
}

#[test]
fn unknown_binary_requires_hash_and_explicit_portable_policy() {
    let id = component_id('u');
    let mut binary = component(id.clone(), ComponentKind::PortableBinary, Some("blake3"));
    binary.restore.primary = RestoreStrategy::PortableBinary;
    let graph = ComponentGraph {
        components: vec![binary],
        edges: Vec::new(),
    };

    let error = build_selection_closure(&graph, &input(vec![id.clone()]))
        .expect_err("default unknown-binary policy blocks selection");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);

    let mut explicit = input(vec![id.clone()]);
    explicit.policy.unknown_binaries = UnknownBinarySelectionPolicy::PortableBinaryExplicit;
    let closure = build_selection_closure(&graph, &explicit).expect("portable binary opt-in");
    assert_eq!(closure.selected_components, vec![id]);
    assert!(
        closure
            .warnings
            .iter()
            .any(|warning| warning.contains("signature"))
    );

    let mut missing_hash = component(component_id('v'), ComponentKind::PortableBinary, None);
    missing_hash.restore.primary = RestoreStrategy::PortableBinary;
    let graph = ComponentGraph {
        components: vec![missing_hash.clone()],
        edges: Vec::new(),
    };
    let mut explicit_missing = input(vec![missing_hash.id]);
    explicit_missing.policy.unknown_binaries = UnknownBinarySelectionPolicy::PortableBinaryExplicit;
    let error = build_selection_closure(&graph, &explicit_missing)
        .expect_err("portable binary without hash blocks selection");
    assert_eq!(error.code, ReforgeErrorCode::SelectionIncomplete);
}

#[test]
fn large_artifacts_need_explicit_confirmation_and_count_toward_limit() {
    let id = component_id('l');
    let mut large = component(id.clone(), ComponentKind::DataArtifact, None);
    let size = 16 * 1024 * 1024 + 1;
    large
        .artifacts
        .push(artifact("large", size, ArtifactPolicy::Data));
    let graph = ComponentGraph {
        components: vec![large],
        edges: Vec::new(),
    };

    let closure = build_selection_closure(&graph, &input(vec![id.clone()]))
        .expect("large data is excluded by default");
    assert!(closure.selected_artifacts.is_empty());

    let mut confirmed = input(vec![id.clone()]);
    confirmed.policy.large_data = LargeDataSelectionPolicy::RequireConfirmation;
    confirmed.artifacts.push(reforge_domain::ArtifactSelection {
        artifact: ArtifactId::new("large").expect("artifact ID"),
        include: true,
    });
    let closure = build_selection_closure(&graph, &confirmed).expect("large data confirmation");
    assert_eq!(closure.total_bytes, size);
    assert_eq!(
        closure.selected_artifacts,
        vec![ArtifactId::new("large").unwrap()]
    );

    confirmed.policy.max_bytes = Some(size - 1);
    let error = build_selection_closure(&graph, &confirmed).expect_err("size limit blocks package");
    assert_eq!(error.code, ReforgeErrorCode::SecurityPolicy);
}

#[test]
fn secret_artifacts_are_excluded_by_default_and_require_vault_opt_in() {
    let id = component_id('s');
    let mut secret_owner = component(id.clone(), ComponentKind::Configuration, None);
    secret_owner.artifacts.push(artifact(
        "secret-config",
        12,
        ArtifactPolicy::SecretReference,
    ));
    let graph = ComponentGraph {
        components: vec![secret_owner],
        edges: Vec::new(),
    };

    let closure = build_selection_closure(&graph, &input(vec![id.clone()]))
        .expect("secret is excluded by default");
    assert!(closure.selected_artifacts.is_empty());

    let mut selected = input(vec![id]);
    selected.policy.secrets = SecretSelectionPolicy::VaultExplicit;
    selected.artifacts.push(reforge_domain::ArtifactSelection {
        artifact: ArtifactId::new("secret-config").expect("artifact ID"),
        include: true,
    });
    let closure = build_selection_closure(&graph, &selected).expect("secret vault opt-in");
    assert_eq!(closure.total_bytes, 12);
    assert!(
        closure
            .warnings
            .iter()
            .any(|warning| warning.contains("vault"))
    );
}
