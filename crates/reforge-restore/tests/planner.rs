#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};

#[allow(
    dead_code,
    unused_imports,
    reason = "shared fixture harness exposes scenarios used by other restore suites"
)]
mod support;

use reforge_domain::{
    Architecture, ArtifactPolicy, ArtifactRef, Compatibility, CompatibilityResult, Component,
    ComponentId, ComponentKind, Confidence, ConfigScope, ContentType, DependencyEdge,
    DependencyKind, Identity, IdentityQuality, KnownFolderToken, LargeDataSelectionPolicy,
    McpServerSpec, McpTransport, ObjectEntry, ObjectId, ObjectIndex, PackageGraph, PackageManifest,
    PackageSpec, PathToken, Portability, ProviderId, Publisher, RestoreDescriptor, RestoreMode,
    RestoreStrategy, RunId, SafeValueRef, SecretSelectionPolicy, SelectionClosure, SelectionInput,
    SelectionMetadata, SelectionPolicy, SourceHostSummary, TrustState,
    UnknownBinarySelectionPolicy, VerificationRule, VersionValue,
};
use reforge_package::{
    ObjectStore, PackageReader, PackageWriteRequest, PackageWriter, TrustDecision,
};
use reforge_restore::{
    ComponentDiff, ComponentDisposition, Journal, PlannerInput, RestorePlanner, TargetDiff,
};
use support::fixtures::FixtureRoot;

#[test]
fn required_runtime_is_planned_before_typed_mcp_registration() {
    let runtime = runtime_component('r');
    let mcp_artifact = artifact('m');
    let mut mcp = mcp_component('m', mcp_artifact.clone(), runtime.id.clone());
    mcp.compatibility.requires_runtime = Some(runtime.id.clone());
    let server = mcp_server(mcp_artifact, runtime.id.clone());

    let input = input(
        vec![runtime.clone(), mcp.clone()],
        vec![DependencyEdge {
            from: mcp.id.clone(),
            to: runtime.id.clone(),
            kind: DependencyKind::RequiredRuntime,
            required: true,
            evidence: Vec::new(),
            confidence: Confidence::High,
        }],
        vec![mcp.id.clone()],
        vec![artifact_id('m')],
        vec![object_entry('m')],
    );
    let run_id = input.run_id.as_str();
    let mut mcp_servers = BTreeMap::new();
    mcp_servers.insert(mcp.id.clone(), server);

    let plan = RestorePlanner::new()
        .with_mcp_servers(mcp_servers)
        .plan(input)
        .expect("runtime and MCP operations should be planable");

    let runtime_index = plan
        .operations
        .iter()
        .position(|operation| {
            matches!(
                operation.kind,
                reforge_domain::OperationKind::EnsureRuntime { .. }
            )
        })
        .expect("runtime operation");
    let mcp_index = plan
        .operations
        .iter()
        .position(|operation| {
            matches!(
                operation.kind,
                reforge_domain::OperationKind::RegisterMcp { .. }
            )
        })
        .expect("MCP registration operation");
    assert!(runtime_index < mcp_index);
    let mcp_operation = &plan.operations[mcp_index];
    let runtime_operation = &plan.operations[runtime_index];
    assert!(mcp_operation.prerequisites.contains(&runtime_operation.id));
    assert!(mcp_operation.idempotency_key.contains(&run_id));
}

#[test]
fn generated_manual_actions_are_globally_unique_across_runs() {
    let mut component = base_component('m', ComponentKind::Application, "Manual fixture");
    component.restore.primary = RestoreStrategy::Manual;
    component.verification = vec![VerificationRule::File {
        destination: PathToken::new(KnownFolderToken::RoamingAppData, "manual/fixture")
            .expect("manual verification path"),
        object: None,
    }];
    let first_input = input(
        vec![component.clone()],
        Vec::new(),
        vec![component.id.clone()],
        Vec::new(),
        Vec::new(),
    );
    let first_run = first_input.run_id.clone();
    let second_run =
        RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e32".to_owned()).expect("second run ID");
    let mut second_input = first_input.clone();
    second_input.run_id = second_run.clone();

    let planner = RestorePlanner::new();
    let first = planner.plan(first_input).expect("first manual plan");
    let second = planner.plan(second_input).expect("second manual plan");

    assert_eq!(first.manual_actions.len(), 1);
    assert_eq!(second.manual_actions.len(), 1);
    assert_eq!(
        first.manual_actions[0].id,
        format!(
            "manual-action:{first_run}:component-manual:{}:component",
            component.id
        )
    );
    assert_eq!(
        second.manual_actions[0].id,
        format!(
            "manual-action:{second_run}:component-manual:{}:component",
            component.id
        )
    );
    assert_ne!(first.manual_actions[0].id, second.manual_actions[0].id);
    let fixture = FixtureRoot::new("planner-manual-action-identities").expect("fixture root");
    let journal = Journal::open(fixture.path("journal.sqlite").expect("journal path"))
        .expect("journal opens");
    journal.create_run(&first).expect("first run persists");
    journal.create_run(&second).expect("second run persists");
}

#[test]
fn required_dependency_cycle_blocks_plan() {
    let first = runtime_component('a');
    let second = runtime_component('b');
    let edges = vec![dependency(&first, &second), dependency(&second, &first)];
    let input = input(
        vec![first.clone(), second.clone()],
        edges,
        vec![first.id],
        Vec::new(),
        Vec::new(),
    );

    let error = RestorePlanner::new()
        .plan(input)
        .expect_err("cycle must block");
    assert_eq!(
        error.code,
        reforge_domain::ReforgeErrorCode::DependencyCycle
    );
}

#[test]
fn independent_operations_have_stable_order_and_ids() {
    let first = package_component('a', "Contoso.First", "1.0.0");
    let second = package_component('b', "Contoso.Second", "2.0.0");
    let input = input(
        vec![first.clone(), second.clone()],
        Vec::new(),
        vec![second.id.clone(), first.id.clone()],
        Vec::new(),
        Vec::new(),
    );
    let planner = RestorePlanner::new().with_first_ordinal(7);
    let first_plan = planner.plan(input.clone()).expect("first plan");
    let second_plan = planner.plan(input).expect("second plan");

    assert_eq!(first_plan, second_plan);
    assert_eq!(first_plan.operations.len(), 5);
    assert!(matches!(
        first_plan.operations[0].kind,
        reforge_domain::OperationKind::EnsureProvider { .. }
    ));
    assert!(matches!(
        first_plan.operations[1].kind,
        reforge_domain::OperationKind::InstallPackage { .. }
    ));
    assert!(
        first_plan.operations[0]
            .idempotency_key
            .contains("restore-v1:")
    );
    assert_eq!(
        first_plan.operations[0].id.as_str(),
        "op_01890f3e-7b6c-7cc0-98c4-dc0c0c0c0c0d_7"
    );
}

#[test]
fn wsl_provider_bootstrap_precedes_import() {
    let component = wsl_component('w');
    let input = input(
        vec![component.clone()],
        Vec::new(),
        vec![component.id.clone()],
        vec![artifact_id('w')],
        vec![object_entry('w')],
    );
    let plan = RestorePlanner::new().plan(input).expect("WSL plan");

    let provider_index = plan
        .operations
        .iter()
        .position(|operation| {
            matches!(
                operation.kind,
                reforge_domain::OperationKind::EnsureProvider { .. }
            )
        })
        .expect("WSL provider bootstrap");
    let import_index = plan
        .operations
        .iter()
        .position(|operation| {
            matches!(
                operation.kind,
                reforge_domain::OperationKind::ImportWsl { .. }
            )
        })
        .expect("WSL import");
    assert!(provider_index < import_index);
    assert!(
        plan.operations[import_index]
            .prerequisites
            .contains(&plan.operations[provider_index].id)
    );
}

#[test]
fn docker_image_plan_preserves_source_reference_and_immutable_id() {
    let image_id = format!("sha256:{}", "a".repeat(64));
    let mut component = base_component(
        'd',
        ComponentKind::DockerImage,
        "registry.example:5000/acme/editor:1.2.3",
    );
    component.identity.provider_package = Some((
        ProviderId::new("docker").expect("Docker provider ID"),
        format!("image:{image_id}"),
    ));
    component.identity.provider_source = Some("image".to_owned());
    component.compatibility.requires_docker = true;
    component.artifacts = vec![ArtifactRef {
        policy: ArtifactPolicy::LargeOptIn,
        content_type: ContentType::Archive,
        ..artifact('d')
    }];
    component.verification = vec![VerificationRule::DockerObject {
        kind: ComponentKind::DockerImage,
        identity: image_id.clone(),
    }];
    let mut object = object_entry('d');
    object.content_type = ContentType::Archive;
    let plan = RestorePlanner::new()
        .plan(input(
            vec![component.clone()],
            Vec::new(),
            vec![component.id],
            vec![artifact_id('d')],
            vec![object],
        ))
        .expect("Docker image plan");

    let image = plan
        .operations
        .iter()
        .find_map(|operation| match &operation.kind {
            reforge_domain::OperationKind::RestoreDockerImage { image, .. } => Some(image),
            _ => None,
        })
        .expect("Docker image operation");
    assert_eq!(image.repository, "registry.example:5000/acme/editor");
    assert_eq!(image.tag.as_deref(), Some("1.2.3"));
    assert_eq!(image.image_id.as_deref(), Some(image_id.as_str()));
}

#[test]
fn package_input_preserves_the_scanned_target_fingerprint() {
    let fixture = FixtureRoot::new("planner-from-package").expect("temporary fixture root");
    let component = runtime_component('r');
    let graph = PackageGraph {
        components: vec![component.clone()],
        edges: Vec::new(),
    };
    let selection = SelectionInput {
        components: vec![component.id.clone()],
        artifacts: Vec::new(),
        policy: SelectionPolicy {
            secrets: SecretSelectionPolicy::Exclude,
            large_data: LargeDataSelectionPolicy::RequireConfirmation,
            unknown_binaries: UnknownBinarySelectionPolicy::Exclude,
            max_bytes: None,
        },
    };
    let object_index = ObjectIndex {
        objects: Vec::new(),
    };
    let manifest = PackageManifest {
        package_id: "pkg_planner_from_package".to_owned(),
        format_version: 1,
        created_at: "2026-08-31T00:00:00Z".parse().expect("timestamp"),
        source_host: SourceHostSummary {
            os_version: "Windows 11".to_owned(),
            os_build: "26200".to_owned(),
            architecture: Architecture::X64,
            known_folder_tokens: vec![KnownFolderToken::UserProfile],
        },
        required_os: Some("windows".to_owned()),
        required_architecture: Some(Architecture::X64),
        component_ids: vec![component.id.clone()],
        warnings: Vec::new(),
        object_index_digest: PackageWriter::object_index_digest(&object_index)
            .expect("object index digest"),
    };
    let store = ObjectStore::open(fixture.root().join("objects")).expect("object store");
    let path = fixture.root().join("package.reforge");
    PackageWriter::default()
        .write(
            &path,
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
        .expect("package write");

    let mut package = PackageReader::new(path).inspect().expect("package inspect");
    package
        .decide_trust(TrustDecision::Approve)
        .expect("explicit package approval");
    let target_fingerprint = "target_scanned_fixture_v1";
    let input = PlannerInput::from_package(
        &package,
        run_id(),
        RestoreMode::Rebuild,
        target_fingerprint,
        TargetDiff {
            components: vec![ComponentDiff {
                component: component.id.clone(),
                disposition: ComponentDisposition::Install,
                target_present: false,
                conflict_ids: Vec::new(),
            }],
            conflicts: Vec::new(),
            blocking_conflict_ids: Vec::new(),
            backup_requirements: Vec::new(),
            preserved_target: Vec::new(),
            preserved_runtimes: Vec::new(),
            preserved_environment: Vec::new(),
            warnings: Vec::new(),
        },
        CompatibilityResult {
            status: reforge_domain::CompatibilityStatus::Ready,
            blockers: Vec::new(),
            confirmations: Vec::new(),
            warnings: Vec::new(),
        },
    )
    .expect("package planner input");

    let plan = RestorePlanner::new().plan(input).expect("restore plan");
    assert_eq!(plan.target_fingerprint, target_fingerprint);
}

fn input(
    components: Vec<Component>,
    edges: Vec<DependencyEdge>,
    selected_components: Vec<ComponentId>,
    selected_artifacts: Vec<reforge_domain::ArtifactId>,
    objects: Vec<ObjectEntry>,
) -> PlannerInput {
    let component_ids: BTreeSet<_> = components
        .iter()
        .map(|component| component.id.clone())
        .collect();
    let component_diffs = component_ids
        .into_iter()
        .map(|component| ComponentDiff {
            component,
            disposition: ComponentDisposition::Install,
            target_present: false,
            conflict_ids: Vec::new(),
        })
        .collect();
    PlannerInput::new(
        run_id(),
        "package-planner-fixture",
        RestoreMode::Rebuild,
        "target-fixture-v1",
        PackageGraph { components, edges },
        SelectionClosure {
            selected_components,
            selected_artifacts,
            auto_added_dependencies: Vec::new(),
            total_bytes: 0,
            warnings: Vec::new(),
        },
        TrustState::UserApproved,
        TargetDiff {
            components: component_diffs,
            conflicts: Vec::new(),
            blocking_conflict_ids: Vec::new(),
            backup_requirements: Vec::new(),
            preserved_target: Vec::new(),
            preserved_runtimes: Vec::new(),
            preserved_environment: Vec::new(),
            warnings: Vec::new(),
        },
        CompatibilityResult {
            status: reforge_domain::CompatibilityStatus::Ready,
            blockers: Vec::new(),
            confirmations: Vec::new(),
            warnings: Vec::new(),
        },
        ObjectIndex { objects },
    )
}

fn package_component(id: char, package: &str, version: &str) -> Component {
    let provider = ProviderId::new("winget").expect("provider");
    let package_spec = PackageSpec {
        provider: provider.clone(),
        id: package.to_owned(),
        version: Some(version.to_owned()),
        source_name: Some("winget-community".to_owned()),
        source_identifier: None,
        source: None,
        architecture: Some(Architecture::X64),
        installer_hash: None,
    };
    let mut component = base_component(id, ComponentKind::Application, package);
    component.identity.provider_package = Some((provider.clone(), package.to_owned()));
    component.identity.provider_source = Some("winget-community".to_owned());
    component.identity.identity_quality = IdentityQuality::Provider;
    component.version = Some(VersionValue {
        raw: version.to_owned(),
        normalized: Some(version.to_owned()),
    });
    component.verification = vec![VerificationRule::ProviderIdentity {
        provider,
        package: package_spec,
    }];
    component
}

fn runtime_component(id: char) -> Component {
    let mut component = base_component(id, ComponentKind::Runtime, "Node.js");
    component.verification = vec![VerificationRule::FileVersion {
        destination: PathToken::new(KnownFolderToken::UserProfile, "runtime/node.exe")
            .expect("runtime path"),
        version: component.version.clone(),
        publisher: component.publisher.clone(),
    }];
    component
}

fn mcp_component(id: char, artifact: ArtifactRef, runtime: ComponentId) -> Component {
    let mut component = base_component(id, ComponentKind::McpServer, "Fixture MCP");
    component.restore = RestoreDescriptor {
        primary: RestoreStrategy::ConfigPortable,
        alternatives: vec![RestoreStrategy::Manual],
        portability: Portability::PartiallyPortable,
        requires_elevation: false,
        requires_user_action: true,
        rationale: vec!["fixture MCP registration".to_owned()],
    };
    component.compatibility.requires_runtime = Some(runtime);
    component.artifacts = vec![artifact];
    component.verification = vec![VerificationRule::McpRegistration {
        name: "fixture".to_owned(),
        config: component.artifacts[0].source_path.clone(),
    }];
    component
}

fn mcp_server(artifact: ArtifactRef, runtime: ComponentId) -> McpServerSpec {
    McpServerSpec {
        name: "fixture".to_owned(),
        scope: ConfigScope::User,
        transport: McpTransport::Stdio,
        command: None,
        args: Vec::<SafeValueRef>::new(),
        cwd: None,
        endpoint: None,
        environment: Vec::new(),
        required_runtime: Some(runtime),
        required_package: None,
        source_config: ArtifactRef {
            object: artifact.object,
            ..artifact
        },
    }
}

fn wsl_component(id: char) -> Component {
    let mut component = base_component(id, ComponentKind::WslDistribution, "Ubuntu");
    component.restore.primary = RestoreStrategy::ExportImport;
    component.restore.portability = Portability::SupportedExport;
    component.compatibility.requires_wsl = true;
    component.artifacts = vec![ArtifactRef {
        policy: ArtifactPolicy::LargeOptIn,
        content_type: ContentType::Archive,
        ..artifact(id)
    }];
    component.verification = vec![VerificationRule::WslState {
        distro: "Ubuntu".to_owned(),
        version: Some("2".to_owned()),
    }];
    component
}

fn base_component(id: char, kind: ComponentKind, name: &str) -> Component {
    Component {
        id: component_id(id),
        kind,
        identity: Identity {
            provider_package: None,
            provider_source: None,
            package_family: Some(format!("fixture:{name}")),
            product_name: Some(name.to_owned()),
            executable_name: None,
            publisher: Some("Fixture Publisher".to_owned()),
            executable_hash: None,
            install_role: Some("fixture".to_owned()),
            identity_quality: IdentityQuality::PackageFamily,
        },
        display_name: name.to_owned(),
        version: None,
        architecture: Some(Architecture::X64),
        publisher: Some(Publisher {
            name: "Fixture Publisher".to_owned(),
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
            recommended: true,
            score: 100,
            selected_by_default: true,
            sensitive: false,
            size_bytes: 0,
        },
        extensions: BTreeMap::new(),
    }
}

fn artifact(id: char) -> ArtifactRef {
    ArtifactRef {
        id: artifact_id(id),
        source_path: PathToken::new(KnownFolderToken::RoamingAppData, "fixture/config.json")
            .expect("artifact path"),
        scope: ConfigScope::User,
        size_bytes: 32,
        content_type: ContentType::Json,
        policy: ArtifactPolicy::Config,
        object: Some(ObjectId::from_content(format!("object-{id}").as_bytes())),
    }
}

fn object_entry(id: char) -> ObjectEntry {
    ObjectEntry {
        id: ObjectId::from_content(format!("object-{id}").as_bytes()),
        uncompressed_bytes: 32,
        compressed_bytes: 32,
        content_type: if id == 'w' {
            ContentType::Archive
        } else {
            ContentType::Json
        },
    }
}

fn dependency(from: &Component, to: &Component) -> DependencyEdge {
    DependencyEdge {
        from: from.id.clone(),
        to: to.id.clone(),
        kind: DependencyKind::RequiredRuntime,
        required: true,
        evidence: Vec::new(),
        confidence: Confidence::High,
    }
}

fn component_id(id: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", id.to_string().repeat(52))).expect("component ID")
}

fn artifact_id(id: char) -> reforge_domain::ArtifactId {
    reforge_domain::ArtifactId::new(format!("artifact-{id}")).expect("artifact ID")
}

fn run_id() -> RunId {
    RunId::new(
        "01890f3e-7b6c-7cc0-98c4-dc0c0c0c0c0d"
            .parse()
            .expect("UUIDv7"),
    )
    .expect("run ID")
}
