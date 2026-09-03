#![allow(
    dead_code,
    reason = "shared fixture harness exposes scenarios used by later restore suites"
)]

mod support;

use std::collections::BTreeMap;

use reforge_domain::{
    Architecture, ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId,
    ComponentKind, Confidence, ConfigScope, ConflictKind, ConflictResolution, ContentType,
    DependencyEdge, DependencyKind, EnvironmentFact, Identity, IdentityQuality, InstalledFact,
    KnownFolderToken, ObjectId, PackageGraph, PathToken, Portability, Provenance, ProviderId,
    Publisher, RestoreDescriptor, RestoreStrategy, SafeValueRef, SelectionMetadata, TargetFacts,
    VerificationRule, VersionValue,
};
use reforge_restore::{BackupTarget, ComponentDisposition, DiffEngine, merge_path_entries};

use support::target_facts;

#[test]
fn newer_target_is_kept_without_confirmation() {
    let source = package_component('a', "Contoso.Editor", "2.1.0");
    let mut target = target_facts();
    target.installed.push(installed_from(&source, "3.0.0"));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::VersionDifference);

    assert_eq!(conflict.resolution, ConflictResolution::Skip);
    assert!(!conflict.requires_confirmation);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Skip
    );
}

#[test]
fn older_target_requires_confirmation_before_upgrade() {
    let source = package_component('a', "Contoso.Editor", "3.0.0");
    let mut target = target_facts();
    target.installed.push(installed_from(&source, "2.1.0"));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::VersionDifference);

    assert_eq!(conflict.resolution, ConflictResolution::Install);
    assert!(conflict.requires_confirmation);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Install
    );
}

#[test]
fn config_collision_requires_merge_and_backup() {
    let mut source = package_component('a', "Contoso.Editor", "3.0.0");
    source.artifacts.push(artifact('a', ArtifactPolicy::Config));
    let mut target = target_facts();
    target.installed.push(installed_from(&source, "3.0.0"));

    let diff = compare(&[source.clone()], Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::ConfigDifference);

    assert_eq!(conflict.resolution, ConflictResolution::Merge);
    assert!(conflict.requires_confirmation);
    assert!(diff.backup_requirements.iter().any(|requirement| {
        requirement.component == source.id
            && matches!(requirement.target, BackupTarget::Artifact { .. })
    }));
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Merge
    );
}
#[test]
fn data_collision_requires_backup_and_manual_decision() {
    let mut source = package_component('a', "Contoso.Editor", "3.0.0");
    source.artifacts.push(artifact('a', ArtifactPolicy::Data));
    let mut target = target_facts();
    target.installed.push(installed_from(&source, "3.0.0"));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::DataCollision);

    assert_eq!(conflict.resolution, ConflictResolution::Manual);
    assert!(conflict.requires_confirmation);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Manual
    );
    assert!(diff.backup_requirements.iter().any(|requirement| {
        requirement.component == source.id
            && matches!(requirement.target, BackupTarget::Artifact { .. })
    }));
}

#[test]
fn differing_package_source_is_reported_and_blocks_automatic_restore() {
    let source = package_component('a', "Contoso.Editor", "3.0.0");
    let mut observed = installed_from(&source, "3.0.0");
    observed.identity.provider_source = Some("private-feed".to_owned());
    observed.provenance.as_mut().expect("provenance").adapter_id = "private-feed".to_owned();
    let mut target = target_facts();
    target.installed.push(observed);

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::UnsupportedTarget);

    assert_eq!(conflict.resolution, ConflictResolution::Manual);
    assert!(diff.is_blocked());
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Blocked
    );
}

#[test]
fn secret_collision_preserves_target_and_never_auto_replaces() {
    let source = environment_component(
        's',
        ComponentKind::SecretReference,
        "CONTEXT7_API_KEY",
        ConfigScope::User,
        None,
    );
    let mut target = target_facts();
    target.environment.push(environment_fact(
        ConfigScope::User,
        "CONTEXT7_API_KEY",
        b"target-secret",
    ));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::SecretCollision);

    assert_eq!(conflict.resolution, ConflictResolution::PreserveTarget);
    assert!(conflict.requires_confirmation);
    assert!(!diff.is_blocked());
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::PreserveTarget
    );
    assert!(diff.backup_requirements.is_empty());
}

#[test]
fn matching_environment_value_is_already_satisfied() {
    let source = environment_component(
        'e',
        ComponentKind::EnvironmentVariable,
        "EDITOR_HOME",
        ConfigScope::User,
        Some("C:\\Editor"),
    );
    let mut target = target_facts();
    target.environment.push(environment_fact(
        ConfigScope::User,
        "editor_home",
        b"C:\\Editor",
    ));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::AlreadySatisfied);

    assert_eq!(conflict.resolution, ConflictResolution::Skip);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Skip
    );
    assert!(diff.backup_requirements.is_empty());
}

#[test]
fn path_collision_uses_case_insensitive_identity_and_safe_merge_default() {
    let source_value = r"C:\Tools;E:\Bin";
    let source = environment_component(
        'p',
        ComponentKind::EnvironmentVariable,
        "Path",
        ConfigScope::User,
        Some(source_value),
    );
    let mut target = target_facts();
    target
        .environment
        .push(environment_fact(ConfigScope::User, "PATH", b"target-path"));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::PathCollision);

    assert_eq!(conflict.resolution, ConflictResolution::Merge);
    assert!(!conflict.requires_confirmation);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Merge
    );
    assert!(matches!(
        diff.backup_requirements[0].target,
        BackupTarget::Environment {
            scope: ConfigScope::User,
            ref name,
        } if name == "PATH"
    ));
    assert!(diff.preserved_environment.is_empty());
    let merged = merge_path_entries(
        &[r"C:\Tools".to_owned(), r"D:\SDK".to_owned()],
        &[
            r"c:\tools".to_owned(),
            r"E:\Bin".to_owned(),
            r"d:\sdk".to_owned(),
        ],
    );
    assert_eq!(
        merged,
        vec![
            r"C:\Tools".to_owned(),
            r"D:\SDK".to_owned(),
            r"E:\Bin".to_owned(),
        ]
    );
}

#[test]
fn port_collision_is_manual_and_requires_confirmation() {
    let source = environment_component(
        'p',
        ComponentKind::EnvironmentVariable,
        "APP_PORT",
        ConfigScope::User,
        Some("3000"),
    );
    let mut target = target_facts();
    target
        .environment
        .push(environment_fact(ConfigScope::User, "app_port", b"8080"));

    let diff = compare(std::slice::from_ref(&source), Vec::new(), &target);
    let conflict = conflict(&diff, &source.id, ConflictKind::PortCollision);

    assert_eq!(conflict.resolution, ConflictResolution::Manual);
    assert!(conflict.requires_confirmation);
    assert_eq!(
        diff.component(&source.id)
            .expect("component diff")
            .disposition,
        ComponentDisposition::Manual
    );
}

#[test]
fn unrelated_target_state_is_preserved_verbatim() {
    let source = package_component('a', "Contoso.Editor", "3.0.0");
    let unrelated = installed_fact("Fabrikam.Terminal", "9.0.0");
    let unrelated_environment = environment_fact(ConfigScope::System, "FABRIKAM_HOME", b"value");
    let mut target = target_facts();
    target.installed.push(unrelated.clone());
    target.environment.push(unrelated_environment.clone());

    let diff = compare(&[source], Vec::new(), &target);

    assert_eq!(diff.preserved_target, vec![unrelated]);
    assert_eq!(diff.preserved_environment, vec![unrelated_environment]);
}

#[test]
fn blocked_dependency_blocks_its_dependent_transitively() {
    let mut root = package_component('a', "Contoso.Root", "1.0.0");
    let mut middle = package_component('b', "Contoso.Middle", "1.0.0");
    let mut blocked = package_component('c', "Contoso.Blocked", "1.0.0");
    blocked.restore.primary = RestoreStrategy::MachineBound;
    blocked.restore.portability = Portability::Unsupported;
    let root_edge = dependency(&root.id, &middle.id);
    let middle_edge = dependency(&middle.id, &blocked.id);
    root.dependencies.push(root_edge.clone());
    middle.dependencies.push(middle_edge.clone());

    let diff = compare(
        &[root.clone(), middle.clone(), blocked.clone()],
        vec![root_edge, middle_edge],
        &target_facts(),
    );

    assert!(diff.is_blocked());
    assert!(diff.conflicts.iter().any(|conflict| {
        conflict.component.as_ref() == Some(&root.id)
            && conflict.kind == ConflictKind::DependencyConflict
    }));
    assert!(diff.conflicts.iter().any(|conflict| {
        conflict.component.as_ref() == Some(&middle.id)
            && conflict.kind == ConflictKind::DependencyConflict
    }));
    assert_eq!(
        diff.component(&root.id).expect("root diff").disposition,
        ComponentDisposition::Blocked
    );
}

#[test]
fn duplicate_component_ids_fail_closed() {
    let source = package_component('a', "Contoso.Editor", "1.0.0");
    let graph = PackageGraph {
        components: vec![source.clone(), source],
        edges: Vec::new(),
    };

    let error = DiffEngine::new()
        .compare(&graph, &target_facts())
        .expect_err("duplicate component IDs must be rejected");

    assert_eq!(error.code, reforge_domain::ReforgeErrorCode::SchemaInvalid);
}

fn compare(
    components: &[Component],
    edges: Vec<DependencyEdge>,
    target: &TargetFacts,
) -> reforge_restore::TargetDiff {
    DiffEngine::new()
        .compare(
            &PackageGraph {
                components: components.to_vec(),
                edges,
            },
            target,
        )
        .expect("fixture diff")
}

fn conflict<'a>(
    diff: &'a reforge_restore::TargetDiff,
    component: &ComponentId,
    kind: ConflictKind,
) -> &'a reforge_domain::Conflict {
    diff.conflicts
        .iter()
        .find(|conflict| conflict.component.as_ref() == Some(component) && conflict.kind == kind)
        .expect("expected conflict")
}

fn package_component(id: char, package: &str, version: &str) -> Component {
    let mut component = base_component(id, ComponentKind::Application, package);
    let provider = ProviderId::new("winget").expect("provider ID");
    component.identity.provider_package = Some((provider.clone(), package.to_owned()));
    component.identity.provider_source = Some("winget-community".to_owned());
    component.identity.identity_quality = IdentityQuality::Provider;
    component.version = Some(version_value(version));
    component.provenance = Some(Provenance {
        provider: Some(provider),
        package_id: Some(package.to_owned()),
        source_url: None,
        observed_version: Some(version.to_owned()),
        adapter_id: "winget-community".to_owned(),
        adapter_version: "fixture".to_owned(),
    });
    component
}

fn environment_component(
    id: char,
    kind: ComponentKind,
    name: &str,
    scope: ConfigScope,
    value: Option<&str>,
) -> Component {
    let mut component = base_component(id, kind, name);
    component.identity.product_name = Some(name.to_owned());
    if let Some(value) = value {
        component.verification.push(VerificationRule::Environment {
            scope: scope.clone(),
            name: name.to_owned(),
            expected: SafeValueRef::LiteralNonSecret(value.to_owned()),
        });
    }
    component.artifacts.push(ArtifactRef {
        id: artifact_id(id),
        source_path: PathToken::new(KnownFolderToken::UserProfile, "environment")
            .expect("tokenized environment path"),
        scope,
        size_bytes: 0,
        content_type: ContentType::Utf8Text,
        policy: ArtifactPolicy::SecretReference,
        object: None,
    });
    component
}

fn base_component(id: char, kind: ComponentKind, name: &str) -> Component {
    Component {
        id: component_id(id),
        kind,
        identity: Identity {
            provider_package: None,
            provider_source: None,
            package_family: None,
            product_name: Some(name.to_owned()),
            executable_name: None,
            publisher: Some("Contoso".to_owned()),
            executable_hash: None,
            install_role: Some("fixture".to_owned()),
            identity_quality: IdentityQuality::Product,
        },
        display_name: name.to_owned(),
        version: None,
        architecture: Some(Architecture::X64),
        publisher: Some(Publisher {
            name: "Contoso".to_owned(),
            certificate_thumbprint: None,
        }),
        provenance: None,
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
            required_architecture: Some(Architecture::X64),
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

fn artifact(id: char, policy: ArtifactPolicy) -> ArtifactRef {
    ArtifactRef {
        id: artifact_id(id),
        source_path: PathToken::new(KnownFolderToken::RoamingAppData, "Contoso/settings.json")
            .expect("tokenized artifact path"),
        scope: ConfigScope::User,
        size_bytes: 128,
        content_type: ContentType::Json,
        policy,
        object: Some(ObjectId::from_content(b"source settings")),
    }
}

fn installed_from(component: &Component, version: &str) -> InstalledFact {
    InstalledFact {
        kind: component.kind.clone(),
        identity: component.identity.clone(),
        version: Some(version_value(version)),
        publisher: component.publisher.clone(),
        provenance: component.provenance.clone(),
    }
}

fn installed_fact(package: &str, version: &str) -> InstalledFact {
    let component = package_component('z', package, version);
    installed_from(&component, version)
}

fn environment_fact(scope: ConfigScope, name: &str, value: &[u8]) -> EnvironmentFact {
    EnvironmentFact {
        scope,
        name: name.to_owned(),
        value_hash: Some(ObjectId::from_content(value).as_str().to_owned()),
    }
}

fn dependency(from: &ComponentId, to: &ComponentId) -> DependencyEdge {
    DependencyEdge {
        from: from.clone(),
        to: to.clone(),
        kind: DependencyKind::RequiredPackage,
        required: true,
        evidence: Vec::new(),
        confidence: Confidence::High,
    }
}

fn version_value(value: &str) -> VersionValue {
    VersionValue {
        raw: value.to_owned(),
        normalized: Some(value.to_owned()),
    }
}

fn component_id(character: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", character.to_string().repeat(52))).expect("component ID")
}

fn artifact_id(character: char) -> ArtifactId {
    ArtifactId::new(format!("artifact-{character}")).expect("artifact ID")
}
