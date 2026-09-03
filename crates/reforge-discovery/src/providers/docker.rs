//! Docker discovery through bounded, allowlisted CLI captures.
//!
//! The adapter records Docker metadata without copying Docker Desktop VM state
//! or credential stores. Contexts, images, volumes, containers, and credential
//! references remain separate typed records so selection can make large data
//! and reauthentication decisions explicitly.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind,
    Confidence, ConfigScope, ContentType, ErrorEnvelope, Evidence, EvidenceId, EvidenceRef,
    EvidenceSource, Identity, IdentityQuality, KnownFolderToken, ManualAction, ManualActionState,
    Operation, OperationId, OperationKind, PathToken, Portability, Precondition, Provenance,
    ProviderId, RedactionPolicy, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel,
    RunId, SelectionMetadata, TargetFacts, VerificationRule,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, KnownFolderMap, ProcessResult,
    TrustedExecutable,
};
use serde_json::{Map, Value};
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "docker";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 512;
const MAX_METADATA_BYTES: usize = 2_048;
const LARGE_DATA_THRESHOLD: u64 = 16 * 1024 * 1024;
const JSON_FORMAT: &str = "{{json .}}";
const DOCKER_CONFIG_RELATIVE: &str = ".docker/config.json";
const DOCKER_CREDENTIAL_DOCS: &str =
    "https://docs.docker.com/reference/cli/docker/login/#credential-stores";
const DOCKER_CONTEXT_DOCS: &str = "https://docs.docker.com/reference/cli/docker/context/export/";
const DOCKER_IMAGE_DOCS: &str = "https://docs.docker.com/reference/cli/docker/image/save/";
const DOCKER_VOLUME_DOCS: &str =
    "https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes";

/// Docker context metadata from `docker context ls` or an equivalent reviewed
/// JSON capture. Endpoint credentials and TLS material are never retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContext {
    pub name: String,
    pub description: Option<String>,
    pub current: bool,
    pub endpoint: Option<String>,
    pub endpoint_redacted: bool,
    pub orchestrator: Option<String>,
    pub export_eligible: bool,
}

/// Docker image metadata from `docker image ls`. The size is an estimate and
/// large images remain opt-in data objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerImage {
    pub repository: String,
    pub tag: Option<String>,
    pub image_id: Option<String>,
    pub size_bytes: u64,
    pub size_known: bool,
    pub large_data: bool,
    pub created_at: Option<String>,
    pub containers: Option<u64>,
    pub export_eligible: bool,
}

/// Docker volume metadata. The daemon mountpoint is deliberately omitted: it
/// is machine-bound state, not a portable source path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerVolume {
    pub name: String,
    pub driver: Option<String>,
    pub size_bytes: u64,
    pub size_known: bool,
    pub large_data: bool,
    pub in_use: bool,
    pub running: bool,
    pub backup_eligible: bool,
    pub requires_quiescence: bool,
}

/// Declarative container metadata. Container writable layers are not exported
/// by this adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContainer {
    pub id: Option<String>,
    pub name: String,
    pub image: Option<String>,
    pub running: bool,
    pub volumes: Vec<String>,
}

/// A reference to a Docker credential helper, never the helper's credential
/// store or an `auth` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerCredentialHelper {
    pub registry: Option<String>,
    pub helper: String,
    pub source_path: PathToken,
}

impl DockerCredentialHelper {
    /// Alias used by callers that refer to the source as a config path.
    pub fn source(&self) -> &PathToken {
        &self.source_path
    }
}

/// Process captures used by deterministic tests and by callers that already
/// ran the reviewed Docker commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerCaptures {
    pub contexts: ProcessResult,
    pub images: ProcessResult,
    pub volumes: ProcessResult,
    pub containers: Option<ProcessResult>,
    pub system_df: Option<ProcessResult>,
    pub config: Option<Vec<u8>>,
}

impl DockerCaptures {
    pub fn new(contexts: ProcessResult, images: ProcessResult, volumes: ProcessResult) -> Self {
        Self {
            contexts,
            images,
            volumes,
            containers: None,
            system_df: None,
            config: None,
        }
    }

    pub fn with_containers(mut self, containers: ProcessResult) -> Self {
        self.containers = Some(containers);
        self
    }

    pub fn with_system_df(mut self, system_df: ProcessResult) -> Self {
        self.system_df = Some(system_df);
        self
    }

    pub fn with_config(mut self, config: impl Into<Vec<u8>>) -> Self {
        self.config = Some(config.into());
        self
    }
}

/// Complete Docker discovery result. Images and volumes are metadata plus
/// explicit size estimates; no mutable Docker Desktop VM disk is represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerDiscovery {
    pub daemon_available: bool,
    pub contexts: Vec<DockerContext>,
    pub images: Vec<DockerImage>,
    pub volumes: Vec<DockerVolume>,
    pub containers: Vec<DockerContainer>,
    pub credential_helpers: Vec<DockerCredentialHelper>,
    pub auth_registries: Vec<String>,
    pub current_context: Option<String>,
    pub config_artifact: Option<ArtifactRef>,
    pub artifacts: Vec<ArtifactRef>,
    pub components: Vec<Component>,
    pub observations: Vec<Observation>,
    pub evidence: Vec<Evidence>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
    pub estimated_bytes: u64,
}

impl DockerDiscovery {
    pub fn credential_references(&self) -> &[DockerCredentialHelper] {
        &self.credential_helpers
    }
}

#[derive(Clone, Debug)]
pub struct DockerAdapter {
    id: ProviderId,
    metadata: Arc<RwLock<BTreeMap<ComponentId, DockerResource>>>,
}

impl DockerAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Docker provider ID"),
            metadata: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Return the token for the current user's Docker config without resolving
    /// it to an absolute path.
    pub fn config_path() -> ProviderResult<PathToken> {
        PathToken::new(KnownFolderToken::UserProfile, DOCKER_CONFIG_RELATIVE)
            .map_err(|_| schema_error("Docker config path token could not be constructed"))
    }

    /// Parse one bounded context JSON capture.
    pub fn parse_contexts(&self, bytes: &[u8]) -> ProviderResult<Vec<DockerContext>> {
        let records = parse_json_records(bytes, "contexts")?;
        parse_context_records(records)
    }

    /// Parse one bounded image JSON capture.
    pub fn parse_images(&self, bytes: &[u8]) -> ProviderResult<Vec<DockerImage>> {
        let records = parse_json_records(bytes, "images")?;
        parse_image_records(records)
    }

    /// Parse one bounded volume JSON capture.
    pub fn parse_volumes(&self, bytes: &[u8]) -> ProviderResult<Vec<DockerVolume>> {
        let records = parse_json_records(bytes, "volumes")?;
        parse_volume_records(records, &BTreeSet::new())
    }

    /// Parse a completed set of core Docker CLI captures.
    pub fn parse_capture(
        &self,
        contexts: &ProcessResult,
        images: &ProcessResult,
        volumes: &ProcessResult,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<DockerDiscovery> {
        self.parse_capture_with_config(contexts, images, volumes, None, None, None, observed_at)
    }

    /// Parse captures and an optional metadata-only Docker config. The config
    /// bytes are never retained in the returned discovery result.
    #[allow(clippy::too_many_arguments)]
    pub fn parse_capture_with_config(
        &self,
        contexts: &ProcessResult,
        images: &ProcessResult,
        volumes: &ProcessResult,
        containers: Option<&ProcessResult>,
        system_df: Option<&ProcessResult>,
        config: Option<&[u8]>,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<DockerDiscovery> {
        self.build_discovery(
            true,
            contexts,
            images,
            volumes,
            containers,
            system_df,
            config,
            Vec::new(),
            observed_at,
        )
    }

    /// Parse owned deterministic captures against a tokenized target.
    pub fn discover_from_captures(
        &self,
        known_folders: &KnownFolderMap,
        captures: DockerCaptures,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<DockerDiscovery> {
        let mut warnings = Vec::new();
        if !known_folders
            .entries
            .contains_key(&KnownFolderToken::UserProfile)
            && captures.config.is_some()
        {
            warnings.push(warning(
                ReforgeErrorCode::PathNotFound,
                "Docker config metadata was observed but the current user profile root is unavailable",
            ));
        }
        self.build_discovery(
            true,
            &captures.contexts,
            &captures.images,
            &captures.volumes,
            captures.containers.as_ref(),
            captures.system_df.as_ref(),
            captures.config.as_deref(),
            warnings,
            observed_at,
        )
    }

    /// Discover metadata already present in the current user's Docker config.
    /// CLI daemon data is intentionally absent here; use
    /// [`Self::discover_with_runner`] for contexts, images, and volumes.
    pub fn discover(&self, known_folders: &KnownFolderMap) -> ProviderResult<DockerDiscovery> {
        let (config, warnings) = read_config(known_folders);
        let empty = successful_process();
        self.build_discovery(
            false,
            &empty,
            &empty,
            &empty,
            None,
            None,
            config.as_deref(),
            warnings,
            Utc::now(),
        )
    }

    /// Run only the reviewed, shell-free Docker CLI commands and then parse
    /// their bounded output.
    pub async fn discover_with_runner(
        &self,
        known_folders: &KnownFolderMap,
        runner: &reforge_platform_windows::ProcessRunner,
        cancellation: &CancellationToken,
    ) -> ProviderResult<DockerDiscovery> {
        let contexts = run_docker_async(
            runner,
            cancellation,
            ["context", "ls", "--format", JSON_FORMAT],
        )
        .await?;
        let images = run_docker_async(
            runner,
            cancellation,
            ["image", "ls", "--all", "--format", JSON_FORMAT],
        )
        .await?;
        let volumes = run_docker_async(
            runner,
            cancellation,
            ["volume", "ls", "--format", JSON_FORMAT],
        )
        .await?;

        let mut warnings = Vec::new();
        let containers = match run_docker_async(
            runner,
            cancellation,
            ["container", "ls", "--all", "--format", JSON_FORMAT],
        )
        .await
        {
            Ok(result) => Some(result),
            Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
            Err(error) => {
                warnings.push(*error);
                None
            }
        };
        let system_df = match run_docker_async(
            runner,
            cancellation,
            ["system", "df", "--format", JSON_FORMAT],
        )
        .await
        {
            Ok(result) => Some(result),
            Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
            Err(error) => {
                warnings.push(*error);
                None
            }
        };
        let (config, mut config_warnings) = read_config(known_folders);
        warnings.append(&mut config_warnings);
        self.build_discovery(
            true,
            &contexts,
            &images,
            &volumes,
            containers.as_ref(),
            system_df.as_ref(),
            config.as_deref(),
            warnings,
            Utc::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_discovery(
        &self,
        daemon_available: bool,
        contexts: &ProcessResult,
        images: &ProcessResult,
        volumes: &ProcessResult,
        containers: Option<&ProcessResult>,
        system_df: Option<&ProcessResult>,
        config: Option<&[u8]>,
        mut warnings: Vec<ErrorEnvelope>,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<DockerDiscovery> {
        validate_process_result(contexts, "context listing")?;
        validate_process_result(images, "image listing")?;
        validate_process_result(volumes, "volume listing")?;
        append_process_warning(&mut warnings, contexts, "context listing");
        append_process_warning(&mut warnings, images, "image listing");
        append_process_warning(&mut warnings, volumes, "volume listing");

        let context_records = self.parse_contexts(contexts.stdout.as_bytes())?;
        let mut image_records = self.parse_images(images.stdout.as_bytes())?;
        let mut volume_records = self.parse_volumes(volumes.stdout.as_bytes())?;
        let mut container_records = Vec::new();

        if let Some(containers) = containers {
            match validate_process_result(containers, "container listing") {
                Ok(()) => {
                    append_process_warning(&mut warnings, containers, "container listing");
                    container_records = parse_container_records(parse_json_records(
                        containers.stdout.as_bytes(),
                        "containers",
                    )?)?;
                }
                Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
                Err(error) => warnings.push(*error),
            }
        }

        if let Some(system_df) = system_df {
            match validate_process_result(system_df, "size estimate") {
                Ok(()) => {
                    append_process_warning(&mut warnings, system_df, "size estimate");
                    apply_system_sizes(
                        &mut image_records,
                        &mut volume_records,
                        parse_size_records(parse_json_records(
                            system_df.stdout.as_bytes(),
                            "system df",
                        )?)?,
                    );
                }
                Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
                Err(error) => warnings.push(*error),
            }
        }

        let running_volume_names = container_records
            .iter()
            .filter(|container| container.running)
            .flat_map(|container| container.volumes.iter().cloned())
            .collect::<BTreeSet<_>>();
        for volume in &mut volume_records {
            if running_volume_names.contains(&volume.name) {
                volume.in_use = true;
                volume.running = true;
                volume.requires_quiescence = true;
            }
            if volume.running {
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!(
                        "Docker volume {} is referenced by a running container; quiesce it before backup",
                        volume.name
                    ),
                ));
            }
            if !volume.size_known {
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!(
                        "Docker volume {} has no reliable size estimate",
                        volume.name
                    ),
                ));
            }
        }
        for image in &image_records {
            if !image.size_known {
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!(
                        "Docker image {} has no reliable size estimate",
                        image_display_name(image)
                    ),
                ));
            }
        }

        let config_state = match config {
            Some(bytes) => parse_config(bytes, observed_at)?,
            None => ConfigState::empty(),
        };
        warnings.extend(config_state.warnings);

        let mut components = Vec::new();
        let mut observations = Vec::new();
        let mut evidence = Vec::new();
        for context in &context_records {
            let record = DockerResource::Context(context.clone());
            let record_evidence = vec![make_evidence(
                format!("docker-context:{}", context.name),
                format!(
                    "Docker context {} was recorded from the reviewed context listing",
                    context.name
                ),
                if context.endpoint_redacted { 60 } else { 75 },
                "docker-context",
                observed_at,
            )];
            let component = self.component_for_resource(record, &record_evidence)?;
            let identity = component.identity.clone();
            observations.push(Observation::Registration {
                kind: ComponentKind::DockerContext,
                identity,
                evidence: record_evidence.clone(),
            });
            evidence.extend(record_evidence);
            components.push(component);
        }
        for image in &image_records {
            let record = DockerResource::Image(image.clone());
            let record_evidence = vec![make_evidence(
                format!("docker-image:{}", image_identity(image)),
                format!(
                    "Docker image {} was recorded from the reviewed image listing",
                    image_display_name(image)
                ),
                if image.size_known { 75 } else { 55 },
                "docker-image",
                observed_at,
            )];
            let component = self.component_for_resource(record, &record_evidence)?;
            let identity = component.identity.clone();
            observations.push(Observation::Registration {
                kind: ComponentKind::DockerImage,
                identity,
                evidence: record_evidence.clone(),
            });
            evidence.extend(record_evidence);
            components.push(component);
        }
        for volume in &volume_records {
            let record = DockerResource::Volume(volume.clone());
            let record_evidence = vec![make_evidence(
                format!("docker-volume:{}", volume.name),
                format!(
                    "Docker volume {} was recorded from the reviewed volume listing",
                    volume.name
                ),
                if volume.size_known { 75 } else { 55 },
                "docker-volume",
                observed_at,
            )];
            let component = self.component_for_resource(record, &record_evidence)?;
            let identity = component.identity.clone();
            observations.push(Observation::Registration {
                kind: ComponentKind::DockerVolume,
                identity,
                evidence: record_evidence.clone(),
            });
            evidence.extend(record_evidence);
            components.push(component);
        }

        let mut artifacts = Vec::new();
        let mut manual_actions = config_state.manual_actions;
        let config_artifact = config_state.artifact;
        if let Some(artifact) = config_artifact.clone() {
            let config_evidence = vec![make_evidence(
                "docker-config".to_owned(),
                "Docker config was inspected as metadata-only credential state".to_owned(),
                70,
                "docker-config",
                observed_at,
            )];
            let component = self.component_for_config(artifact.clone(), &config_evidence)?;
            observations.push(Observation::Artifact {
                artifact: artifact.clone(),
                evidence: config_evidence.clone(),
            });
            evidence.extend(config_evidence);
            components.push(component);
            artifacts.push(artifact);
        }
        let config_credential_actions = credential_manual_actions(
            &config_state.credential_helpers,
            &config_state.auth_registries,
        );
        manual_actions.extend(config_credential_actions);

        let estimated_bytes = image_records
            .iter()
            .map(|image| image.size_bytes)
            .chain(volume_records.iter().map(|volume| volume.size_bytes))
            .sum();
        components.sort_by(|left, right| left.id.cmp(&right.id));
        observations.sort_by_key(observation_key);
        evidence.sort_by(|left, right| left.id.cmp(&right.id));
        evidence.dedup_by(|left, right| left.id == right.id);
        warnings.sort_by(|left, right| {
            format!("{:?}", left.code)
                .cmp(&format!("{:?}", right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
        warnings.truncate(MAX_WARNINGS);
        manual_actions.sort_by(|left, right| left.id.cmp(&right.id));
        manual_actions.dedup_by(|left, right| left.id == right.id);

        Ok(DockerDiscovery {
            daemon_available,
            contexts: context_records,
            images: image_records,
            volumes: volume_records,
            containers: container_records,
            credential_helpers: config_state.credential_helpers,
            auth_registries: config_state.auth_registries,
            current_context: config_state.current_context,
            config_artifact,
            artifacts,
            components,
            observations,
            evidence,
            manual_actions,
            warnings,
            estimated_bytes,
        })
    }

    fn component_for_resource(
        &self,
        resource: DockerResource,
        evidence: &[Evidence],
    ) -> ProviderResult<Component> {
        let (kind, identity_name, display_name, size_bytes, restore, verification, mut extensions) =
            match &resource {
                DockerResource::Context(context) => (
                    ComponentKind::DockerContext,
                    format!("context:{}", context.name),
                    context.name.clone(),
                    0,
                    RestoreDescriptor {
                        primary: RestoreStrategy::ExportImport,
                        alternatives: vec![RestoreStrategy::Manual],
                        portability: Portability::SupportedExport,
                        requires_elevation: false,
                        requires_user_action: true,
                        rationale: vec![
                            "Docker context metadata is exportable, but import remains an explicit user action".to_owned(),
                            "TLS material and credential stores are excluded".to_owned(),
                        ],
                    },
                    VerificationRule::DockerObject {
                        kind: ComponentKind::DockerContext,
                        identity: context.name.clone(),
                    },
                    BTreeMap::from([
                        ("docker_kind".to_owned(), Value::String("context".to_owned())),
                        ("current".to_owned(), Value::Bool(context.current)),
                        ("export_eligible".to_owned(), Value::Bool(context.export_eligible)),
                        ("endpoint_redacted".to_owned(), Value::Bool(context.endpoint_redacted)),
                    ]),
                ),
                DockerResource::Image(image) => (
                    ComponentKind::DockerImage,
                    format!("image:{}", image_identity(image)),
                    image_display_name(image),
                    image.size_bytes,
                    RestoreDescriptor {
                        primary: RestoreStrategy::Partial,
                        alternatives: vec![RestoreStrategy::Manual],
                        portability: Portability::PartiallyPortable,
                        requires_elevation: false,
                        requires_user_action: true,
                        rationale: vec![
                            "Docker image data requires an explicit image save selection".to_owned(),
                            "Large image objects are never included by default".to_owned(),
                        ],
                    },
                    VerificationRule::DockerObject {
                        kind: ComponentKind::DockerImage,
                        identity: image_identity(image),
                    },
                    BTreeMap::from([
                        ("docker_kind".to_owned(), Value::String("image".to_owned())),
                        ("image_id".to_owned(), option_string(&image.image_id)),
                        ("size_known".to_owned(), Value::Bool(image.size_known)),
                        ("large_data".to_owned(), Value::Bool(image.large_data)),
                        ("export_eligible".to_owned(), Value::Bool(image.export_eligible)),
                    ]),
                ),
                DockerResource::Volume(volume) => (
                    ComponentKind::DockerVolume,
                    format!("volume:{}", volume.name),
                    volume.name.clone(),
                    volume.size_bytes,
                    RestoreDescriptor {
                        primary: RestoreStrategy::Partial,
                        alternatives: vec![RestoreStrategy::Manual],
                        portability: Portability::PartiallyPortable,
                        requires_elevation: false,
                        requires_user_action: true,
                        rationale: vec![
                            "Docker volume data requires an explicit backup and restore selection".to_owned(),
                            "A running volume must be quiesced before backup".to_owned(),
                            "Large volume objects are never included by default".to_owned(),
                        ],
                    },
                    VerificationRule::DockerObject {
                        kind: ComponentKind::DockerVolume,
                        identity: volume.name.clone(),
                    },
                    BTreeMap::from([
                        ("docker_kind".to_owned(), Value::String("volume".to_owned())),
                        ("size_known".to_owned(), Value::Bool(volume.size_known)),
                        ("large_data".to_owned(), Value::Bool(volume.large_data)),
                        ("in_use".to_owned(), Value::Bool(volume.in_use)),
                        ("running".to_owned(), Value::Bool(volume.running)),
                        ("backup_eligible".to_owned(), Value::Bool(volume.backup_eligible)),
                    ]),
                ),
            };
        extensions.insert("size_bytes".to_owned(), Value::from(size_bytes));
        let identity = Identity {
            provider_package: Some((self.id.clone(), identity_name.clone())),
            provider_source: Some(resource.source_kind().to_owned()),
            package_family: None,
            product_name: Some(display_name.clone()),
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        };
        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("Docker resource identity is not canonical"))?;
        let component_id = canonical.id;
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.insert(component_id.clone(), resource);
        }
        Ok(Component {
            id: component_id,
            kind,
            identity,
            display_name,
            version: None,
            architecture: None,
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some(identity_name),
                source_url: None,
                observed_version: None,
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs(evidence),
            confidence: confidence_from_evidence(evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore,
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: true,
            },
            verification: vec![verification],
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes,
            },
            extensions,
        })
    }

    fn component_for_config(
        &self,
        artifact: ArtifactRef,
        evidence: &[Evidence],
    ) -> ProviderResult<Component> {
        let identity = Identity {
            provider_package: Some((self.id.clone(), "config".to_owned())),
            provider_source: Some("docker-config".to_owned()),
            package_family: None,
            product_name: Some("Docker configuration".to_owned()),
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        };
        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("Docker config identity is not canonical"))?;
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "docker_kind".to_owned(),
            Value::String("configuration".to_owned()),
        );
        extensions.insert(
            "credential_state".to_owned(),
            Value::String("reference_only".to_owned()),
        );
        Ok(Component {
            id: canonical.id,
            kind: ComponentKind::Configuration,
            identity,
            display_name: "Docker configuration".to_owned(),
            version: None,
            architecture: None,
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some("config".to_owned()),
                source_url: None,
                observed_version: None,
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs(evidence),
            confidence: confidence_from_evidence(evidence),
            dependencies: Vec::new(),
            artifacts: vec![artifact.clone()],
            restore: RestoreDescriptor {
                primary: RestoreStrategy::Partial,
                alternatives: vec![RestoreStrategy::Manual],
                portability: Portability::PartiallyPortable,
                requires_elevation: false,
                requires_user_action: true,
                rationale: vec![
                    "Docker config is retained as metadata-only credential-helper state".to_owned(),
                    "Active credential stores and auth values are never copied".to_owned(),
                ],
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: true,
            },
            verification: vec![VerificationRule::File {
                destination: artifact.source_path,
                object: artifact.object,
            }],
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: true,
                size_bytes: artifact.size_bytes,
            },
            extensions,
        })
    }

    fn resource_for_component(&self, component: &Component) -> ProviderResult<DockerResource> {
        if component
            .provenance
            .as_ref()
            .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
        {
            return Err(schema_error("Docker component belongs to another adapter"));
        }
        if let Ok(metadata) = self.metadata.read()
            && let Some(resource) = metadata.get(&component.id)
        {
            return Ok(resource.clone());
        }
        infer_resource(&component.identity)
    }

    fn manual_operation(
        &self,
        component: &Component,
        resource: &DockerResource,
        target: &TargetFacts,
        run_id: &RunId,
        ordinal: u64,
    ) -> ProviderResult<Operation> {
        let rule = resource.verification_rule();
        let target_available = target
            .providers
            .iter()
            .any(|provider| provider.id == self.id && provider.available);
        let reason = if !target_available {
            "Docker is unavailable on the target; bootstrap and object import require explicit user action"
        } else {
            resource.manual_reason()
        };
        let idempotency_key = operation_key(resource, reason);
        let operation_id = OperationId::for_run(run_id, ordinal)
            .map_err(|_| schema_error("Docker manual operation ID could not be constructed"))?;
        let docs_url = Url::parse(resource.docs_url()).ok();
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: resource.manual_title().to_owned(),
            reason: reason.to_owned(),
            risk: resource.risk_level(),
            instructions: resource.manual_instructions(),
            docs_url,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: Some(rule.clone()),
        };
        Ok(Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::OpenManualAction { action },
            prerequisites: Vec::new(),
            precondition: Precondition::Always,
            idempotency_key,
            verification: vec![rule],
            requires_elevation: false,
            non_idempotent: false,
        })
    }
    fn manual_config_operation(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &RunId,
        ordinal: u64,
    ) -> ProviderResult<Operation> {
        let artifact = component
            .artifacts
            .first()
            .ok_or_else(|| schema_error("Docker config component has no artifact"))?;
        let rule = VerificationRule::File {
            destination: artifact.source_path.clone(),
            object: artifact.object.clone(),
        };
        let target_available = target
            .providers
            .iter()
            .any(|provider| provider.id == self.id && provider.available);
        let reason = if target_available {
            "Docker configuration contains reference-only credential state; copy no credential store and reauthenticate on the target"
        } else {
            "Docker is unavailable on the target; configuration review and credential setup require explicit user action"
        };
        let idempotency_key = hashed_id("docker-config-operation", component.id.as_str());
        let operation_id = OperationId::for_run(run_id, ordinal).map_err(|_| {
            schema_error("Docker config manual operation ID could not be constructed")
        })?;
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: "Review Docker configuration".to_owned(),
            reason: reason.to_owned(),
            risk: RiskLevel::High,
            instructions: vec![
                "Restore only reviewed non-secret Docker configuration values".to_owned(),
                "Reauthenticate through the target credential helper".to_owned(),
            ],
            docs_url: Url::parse(DOCKER_CREDENTIAL_DOCS).ok(),
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: Some(rule.clone()),
        };
        Ok(Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::OpenManualAction { action },
            prerequisites: Vec::new(),
            precondition: Precondition::Always,
            idempotency_key,
            verification: vec![rule],
            requires_elevation: false,
            non_idempotent: false,
        })
    }
}
impl Default for DockerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for DockerAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::Docker) {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![make_evidence(
                "PATH:docker.exe".to_owned(),
                "The reviewed Docker executable name resolves from PATH".to_owned(),
                60,
                "docker-provider",
                Utc::now(),
            )],
            warnings: vec![
                "Docker Desktop VM disk state is never copied by discovery".to_owned(),
                "Docker images and volumes require explicit large-data selection".to_owned(),
            ],
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let discovery = self
            .discover_with_runner(context.known_folders, context.runner, context.cancellation)
            .await?;
        let warnings = discovery
            .warnings
            .iter()
            .map(|error| error.message.clone())
            .collect();
        Ok(ProviderEnumeration {
            observations: discovery.observations,
            warnings,
        })
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        match observation {
            Observation::Registration {
                kind,
                identity,
                evidence,
            } => {
                let resource = self.resource_for_identity_kind(kind, &identity)?;
                Ok(vec![self.component_for_resource(resource, &evidence)?])
            }
            Observation::Artifact { artifact, evidence } => {
                if artifact.policy != ArtifactPolicy::SecretReference {
                    return Err(schema_error(
                        "Docker config artifact must remain a secret reference",
                    ));
                }
                Ok(vec![self.component_for_config(artifact, &evidence)?])
            }
            _ => Err(schema_error(
                "Docker received an unsupported observation kind",
            )),
        }
    }

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        if component.kind == ComponentKind::Configuration {
            return Ok(vec![self.manual_config_operation(
                component,
                target,
                run_id,
                first_ordinal,
            )?]);
        }
        let resource = self.resource_for_component(component)?;
        Ok(vec![self.manual_operation(
            component,
            &resource,
            target,
            run_id,
            first_ordinal,
        )?])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        if component.kind == ComponentKind::Configuration {
            return component
                .artifacts
                .first()
                .map(|artifact| {
                    vec![VerificationRule::File {
                        destination: artifact.source_path.clone(),
                        object: artifact.object.clone(),
                    }]
                })
                .ok_or_else(|| schema_error("Docker config component has no artifact"));
        }
        Ok(vec![
            self.resource_for_component(component)?.verification_rule(),
        ])
    }
}

impl DockerAdapter {
    fn resource_for_identity_kind(
        &self,
        kind: ComponentKind,
        identity: &Identity,
    ) -> ProviderResult<DockerResource> {
        let resource = infer_resource(identity)?;
        if resource.kind() != kind {
            return Err(schema_error(
                "Docker registration kind disagrees with identity",
            ));
        }
        Ok(resource)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DockerResource {
    Context(DockerContext),
    Image(DockerImage),
    Volume(DockerVolume),
}

impl DockerResource {
    fn kind(&self) -> ComponentKind {
        match self {
            Self::Context(_) => ComponentKind::DockerContext,
            Self::Image(_) => ComponentKind::DockerImage,
            Self::Volume(_) => ComponentKind::DockerVolume,
        }
    }

    fn source_kind(&self) -> &'static str {
        match self {
            Self::Context(_) => "context",
            Self::Image(_) => "image",
            Self::Volume(_) => "volume",
        }
    }

    fn identity(&self) -> String {
        match self {
            Self::Context(context) => context.name.clone(),
            Self::Image(image) => image_identity(image),
            Self::Volume(volume) => volume.name.clone(),
        }
    }

    fn verification_rule(&self) -> VerificationRule {
        VerificationRule::DockerObject {
            kind: self.kind(),
            identity: self.identity(),
        }
    }

    fn manual_title(&self) -> &'static str {
        match self {
            Self::Context(_) => "Review Docker context import",
            Self::Image(_) => "Review Docker image restore",
            Self::Volume(_) => "Review Docker volume restore",
        }
    }

    fn manual_reason(&self) -> &'static str {
        match self {
            Self::Context(_) => {
                "Docker context export/import is explicit and credential material is excluded"
            }
            Self::Image(image) if image.large_data => {
                "Docker image exceeds the large-data threshold and needs explicit image save selection"
            }
            Self::Image(_) => {
                "Docker image bytes are not copied during discovery; select an image save object explicitly"
            }
            Self::Volume(volume) if volume.running => {
                "Docker volume is referenced by a running container and must be quiesced before backup"
            }
            Self::Volume(volume) if volume.large_data => {
                "Docker volume exceeds the large-data threshold and needs explicit backup selection"
            }
            Self::Volume(_) => {
                "Docker volume bytes are not copied during discovery; select a documented backup object explicitly"
            }
        }
    }

    fn docs_url(&self) -> &'static str {
        match self {
            Self::Context(_) => DOCKER_CONTEXT_DOCS,
            Self::Image(_) => DOCKER_IMAGE_DOCS,
            Self::Volume(_) => DOCKER_VOLUME_DOCS,
        }
    }

    fn risk_level(&self) -> RiskLevel {
        match self {
            Self::Context(_) => RiskLevel::Medium,
            Self::Image(_) | Self::Volume(_) => RiskLevel::High,
        }
    }

    fn manual_instructions(&self) -> Vec<String> {
        match self {
            Self::Context(_) => vec![
                "Review the context endpoint and export metadata".to_owned(),
                "Reauthenticate credential helpers and do not import protected TLS material blindly".to_owned(),
            ],
            Self::Image(_) => vec![
                "Confirm the repository, tag, image ID, and size estimate".to_owned(),
                "Create or select the reviewed docker image save object before restore".to_owned(),
            ],
            Self::Volume(_) => vec![
                "Stop or quiesce every container using the volume".to_owned(),
                "Review the volume name, driver, and size estimate before backup/restore".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ConfigState {
    artifact: Option<ArtifactRef>,
    credential_helpers: Vec<DockerCredentialHelper>,
    auth_registries: Vec<String>,
    current_context: Option<String>,
    manual_actions: Vec<ManualAction>,
    warnings: Vec<ErrorEnvelope>,
}

impl ConfigState {
    fn empty() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SizeRecord {
    kind: Option<String>,
    identity: Option<String>,
    size_bytes: Option<u64>,
}

fn parse_context_records(records: Vec<Value>) -> ProviderResult<Vec<DockerContext>> {
    let mut contexts = BTreeMap::<String, DockerContext>::new();
    for record in records {
        let name = required_text(&record, &["Name", "name"], "Docker context name")?;
        let endpoint_raw =
            optional_text(&record, &["DockerEndpoint", "Endpoint", "Host", "endpoint"]);
        let (endpoint, endpoint_redacted) = endpoint_raw
            .as_deref()
            .map(sanitize_endpoint)
            .unwrap_or((None, false));
        let context = DockerContext {
            name: name.clone(),
            description: optional_safe_text(
                &record,
                &["Description", "description"],
                MAX_METADATA_BYTES,
            ),
            current: value_is_true(&record, &["Current", "current"]),
            endpoint,
            endpoint_redacted,
            orchestrator: optional_safe_text(&record, &["Orchestrator", "orchestrator"], 128),
            export_eligible: true,
        };
        insert_unique(&mut contexts, name, context, "Docker context")?;
    }
    Ok(contexts.into_values().collect())
}

fn parse_image_records(records: Vec<Value>) -> ProviderResult<Vec<DockerImage>> {
    let mut images = BTreeMap::<String, DockerImage>::new();
    for record in records {
        let repository = required_text(
            &record,
            &["Repository", "repository", "Repo", "repo"],
            "Docker image repository",
        )?;
        let tag = optional_text(&record, &["Tag", "tag"])
            .filter(|value| value != "<none>" && value != "none");
        let image_id = optional_safe_text(
            &record,
            &["ID", "Id", "ImageID", "image_id"],
            MAX_METADATA_BYTES,
        );
        let size_value = optional_text(
            &record,
            &["SizeBytes", "size_bytes", "Size", "size", "VirtualSize"],
        );
        let size_bytes = size_value.as_deref().and_then(parse_size_bytes);
        let image = DockerImage {
            repository: validate_metadata(&repository, "Docker image repository", MAX_NAME_BYTES)?,
            tag: tag
                .as_deref()
                .map(|value| validate_metadata(value, "Docker image tag", MAX_NAME_BYTES))
                .transpose()?,
            image_id,
            size_bytes: size_bytes.unwrap_or(0),
            size_known: size_bytes.is_some(),
            large_data: size_bytes.is_some_and(|size| size > LARGE_DATA_THRESHOLD),
            created_at: optional_safe_text(
                &record,
                &["CreatedAt", "created_at", "Created", "created"],
                MAX_METADATA_BYTES,
            ),
            containers: optional_u64(&record, &["Containers", "containers"]),
            export_eligible: true,
        };
        let key = format!(
            "{}|{}|{}",
            image.repository,
            image.tag.as_deref().unwrap_or(""),
            image.image_id.as_deref().unwrap_or("")
        );
        insert_unique(&mut images, key, image, "Docker image")?;
    }
    Ok(images.into_values().collect())
}

fn parse_volume_records(
    records: Vec<Value>,
    running_volume_names: &BTreeSet<String>,
) -> ProviderResult<Vec<DockerVolume>> {
    let mut volumes = BTreeMap::<String, DockerVolume>::new();
    for record in records {
        let name = required_text(
            &record,
            &["Name", "name", "Volume", "volume"],
            "Docker volume name",
        )?;
        let size_value = optional_text(&record, &["SizeBytes", "size_bytes", "Size", "size"]);
        let usage_size = record
            .get("UsageData")
            .or_else(|| record.get("usage_data"))
            .and_then(Value::as_object)
            .and_then(|usage| value_text(usage, &["Size", "size", "SizeBytes", "size_bytes"]))
            .and_then(|value| parse_size_bytes(&value));
        let size_bytes = size_value
            .as_deref()
            .and_then(parse_size_bytes)
            .or(usage_size);
        let running = running_volume_names.contains(&name)
            || value_is_true(&record, &["Running", "running", "InUse", "in_use"])
            || optional_u64(
                &record,
                &["Containers", "containers", "RefCount", "ref_count"],
            )
            .is_some_and(|count| count > 0 && value_is_true(&record, &["Running", "running"]));
        let in_use = running
            || value_is_true(&record, &["InUse", "in_use"])
            || optional_u64(
                &record,
                &["Containers", "containers", "RefCount", "ref_count"],
            )
            .is_some_and(|count| count > 0);
        let volume = DockerVolume {
            name: validate_metadata(&name, "Docker volume name", MAX_NAME_BYTES)?,
            driver: optional_safe_text(&record, &["Driver", "driver"], 128),
            size_bytes: size_bytes.unwrap_or(0),
            size_known: size_bytes.is_some(),
            large_data: size_bytes.is_some_and(|size| size > LARGE_DATA_THRESHOLD),
            in_use,
            running,
            backup_eligible: true,
            requires_quiescence: running,
        };
        insert_unique(&mut volumes, name, volume, "Docker volume")?;
    }
    Ok(volumes.into_values().collect())
}

fn parse_container_records(records: Vec<Value>) -> ProviderResult<Vec<DockerContainer>> {
    let mut containers = Vec::new();
    for record in records {
        let name = required_text(
            &record,
            &["Names", "Name", "name", "Container"],
            "Docker container name",
        )?;
        let mounts = parse_mount_names(&record);
        containers.push(DockerContainer {
            id: optional_safe_text(&record, &["ID", "Id", "id"], 128),
            name: validate_metadata(&name, "Docker container name", MAX_NAME_BYTES)?,
            image: optional_safe_text(&record, &["Image", "image"], MAX_METADATA_BYTES),
            running: value_is_true(&record, &["Running", "running", "State", "state"]),
            volumes: mounts,
        });
    }
    containers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(containers)
}

fn parse_mount_names(record: &Value) -> Vec<String> {
    let Some(value) = record.get("Mounts").or_else(|| record.get("mounts")) else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();
    match value {
        Value::String(raw) => {
            for mount in raw.split(',') {
                let name = mount.split(':').next().unwrap_or_default().trim();
                if !name.is_empty() && !name.starts_with('.') && !name.contains('\\') {
                    names.insert(name.to_owned());
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                if let Some(object) = value.as_object() {
                    let kind = value_text(object, &["Type", "type"]).unwrap_or_default();
                    if (kind.eq_ignore_ascii_case("volume") || kind.is_empty())
                        && let Some(name) =
                            value_text(object, &["Name", "name", "Source", "source"])
                                .filter(|value| !value.contains('\\') && !value.contains('/'))
                    {
                        names.insert(name);
                    }
                }
            }
        }
        _ => {}
    }
    names.into_iter().collect()
}

fn parse_size_records(records: Vec<Value>) -> ProviderResult<Vec<SizeRecord>> {
    let mut output = Vec::new();
    for record in records {
        let kind = optional_safe_text(&record, &["Type", "type"], 64);
        let identity = optional_safe_text(
            &record,
            &["Name", "name", "ID", "Id", "Repository", "repository"],
            MAX_METADATA_BYTES,
        );
        let size = optional_text(&record, &["SizeBytes", "size_bytes", "Size", "size"])
            .and_then(|value| parse_size_bytes(&value));
        output.push(SizeRecord {
            kind,
            identity,
            size_bytes: size,
        });
    }
    Ok(output)
}

fn apply_system_sizes(
    images: &mut [DockerImage],
    volumes: &mut [DockerVolume],
    records: Vec<SizeRecord>,
) {
    for record in records {
        let Some(size) = record.size_bytes else {
            continue;
        };
        let Some(identity) = record.identity.as_deref() else {
            continue;
        };
        let kind = record
            .kind
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if kind.contains("volume") {
            if let Some(volume) = volumes.iter_mut().find(|volume| volume.name == identity)
                && !volume.size_known
            {
                volume.size_bytes = size;
                volume.size_known = true;
                volume.large_data = size > LARGE_DATA_THRESHOLD;
            }
        } else if let Some(image) = images.iter_mut().find(|image| {
            image.image_id.as_deref() == Some(identity)
                || image.repository == identity
                || image_display_name(image) == identity
        }) && !image.size_known
        {
            image.size_bytes = size;
            image.size_known = true;
            image.large_data = size > LARGE_DATA_THRESHOLD;
        }
    }
}

fn parse_config(bytes: &[u8], observed_at: DateTime<Utc>) -> ProviderResult<ConfigState> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(security_error(
            "Docker config exceeds the reviewed metadata bound",
        ));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::ProviderParseFailed,
                "Docker config is not valid JSON",
            )
            .with_technical_detail(error.to_string()),
        )
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| parse_error("Docker config root must be an object"))?;
    let path = DockerAdapter::config_path()?;
    let artifact = ArtifactRef {
        id: ArtifactId::new(format!("docker-config-{}", blake3::hash(bytes).to_hex()))
            .map_err(|_| schema_error("Docker config artifact ID is not valid"))?,
        source_path: path.clone(),
        scope: ConfigScope::User,
        size_bytes: bytes.len() as u64,
        content_type: ContentType::Json,
        policy: ArtifactPolicy::SecretReference,
        object: None,
    };

    let mut state = ConfigState {
        artifact: Some(artifact),
        current_context: value_text(object, &["currentContext", "current_context"]).and_then(
            |value| validate_metadata(&value, "Docker current context", MAX_NAME_BYTES).ok(),
        ),
        ..ConfigState::default()
    };
    if let Some(helper) = value_text(object, &["credsStore", "creds_store"])
        .and_then(|value| validate_helper(&value).ok())
    {
        state.credential_helpers.push(DockerCredentialHelper {
            registry: None,
            helper,
            source_path: path.clone(),
        });
    }
    if let Some(helpers) = object
        .get("credHelpers")
        .or_else(|| object.get("cred_helpers"))
        .and_then(Value::as_object)
    {
        for (registry, helper) in helpers {
            let Some(helper) = helper
                .as_str()
                .and_then(|value| validate_helper(value).ok())
            else {
                state.warnings.push(warning(
                    ReforgeErrorCode::ProviderParseFailed,
                    "Docker credential-helper metadata contained an invalid helper name",
                ));
                continue;
            };
            let Some(registry) = sanitize_registry(registry) else {
                state.warnings.push(warning(
                    ReforgeErrorCode::ProviderParseFailed,
                    "Docker credential-helper metadata contained an invalid registry",
                ));
                continue;
            };
            state.credential_helpers.push(DockerCredentialHelper {
                registry: Some(registry),
                helper,
                source_path: path.clone(),
            });
        }
    }
    if let Some(auths) = object
        .get("auths")
        .or_else(|| object.get("Auths"))
        .and_then(Value::as_object)
    {
        let mut registries = BTreeSet::new();
        for registry in auths.keys() {
            if let Some(registry) = sanitize_registry(registry) {
                registries.insert(registry);
            }
        }
        state.auth_registries = registries.into_iter().collect();
        if !state.auth_registries.is_empty() {
            state.warnings.push(warning(
                ReforgeErrorCode::ManualSecretRequired,
                "Docker auth entries were reduced to registry references; active credential values were not copied",
            ));
            state.manual_actions.push(ManualAction {
                id: hashed_id("docker-auth-review", &state.auth_registries.join("|")),
                component: None,
                title: "Reauthenticate Docker registries".to_owned(),
                reason: "Docker config contains auth references whose credential values are machine/account-bound".to_owned(),
                risk: RiskLevel::High,
                instructions: vec![
                    "Log in to each recorded registry using the target's approved credential helper".to_owned(),
                    "Do not import the source Docker credential store as a file".to_owned(),
                ],
                docs_url: Url::parse(DOCKER_CREDENTIAL_DOCS).ok(),
                state: ManualActionState::Pending,
                independent_operations_may_continue: true,
                acknowledged_at: None,
                verification: None,
            });
        }
    }
    state.credential_helpers.sort_by(|left, right| {
        left.registry
            .cmp(&right.registry)
            .then_with(|| left.helper.cmp(&right.helper))
    });
    state.credential_helpers.dedup();
    state.manual_actions.extend(state.credential_helpers.iter().map(|helper| ManualAction {
        id: hashed_id("docker-helper", &format!("{:?}:{}", helper.registry, helper.helper)),
        component: None,
        title: "Review Docker credential helper".to_owned(),
        reason: "Docker credential-helper identity is portable metadata; the helper store requires target reauthentication".to_owned(),
        risk: RiskLevel::High,
        instructions: vec![
            format!("Install or verify the {} credential helper on the target", helper.helper),
            "Reauthenticate through Docker's documented login flow".to_owned(),
        ],
        docs_url: Url::parse(DOCKER_CREDENTIAL_DOCS).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }));
    let _ = observed_at;
    Ok(state)
}

fn credential_manual_actions(
    helpers: &[DockerCredentialHelper],
    auth_registries: &[String],
) -> Vec<ManualAction> {
    let mut actions = Vec::new();
    if !helpers.is_empty() || !auth_registries.is_empty() {
        actions.push(ManualAction {
            id: hashed_id(
                "docker-credentials",
                &format!("{}|{}", helpers.len(), auth_registries.len()),
            ),
            component: None,
            title: "Reauthenticate Docker credentials".to_owned(),
            reason: "Docker credential stores are account-bound and are represented only by helper and registry references".to_owned(),
            risk: RiskLevel::High,
            instructions: vec![
                "Use the target Docker credential helper instead of copying config secrets".to_owned(),
                "Verify registry access after login".to_owned(),
            ],
            docs_url: Url::parse(DOCKER_CREDENTIAL_DOCS).ok(),
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: None,
        });
    }
    actions
}

fn infer_resource(identity: &Identity) -> ProviderResult<DockerResource> {
    let Some((provider, package_id)) = &identity.provider_package else {
        return Err(schema_error(
            "Docker identity has no provider package tuple",
        ));
    };
    if provider.as_str() != PROVIDER_ID {
        return Err(schema_error("Docker identity uses a different provider"));
    }
    let kind = identity
        .provider_source
        .as_deref()
        .ok_or_else(|| schema_error("Docker identity has no resource kind"))?;
    match kind {
        "context" => Ok(DockerResource::Context(DockerContext {
            name: package_id
                .strip_prefix("context:")
                .unwrap_or(package_id)
                .to_owned(),
            description: None,
            current: false,
            endpoint: None,
            endpoint_redacted: true,
            orchestrator: None,
            export_eligible: true,
        })),
        "image" => {
            let value = package_id.strip_prefix("image:").unwrap_or(package_id);
            let (repository, tag) = value
                .rsplit_once(':')
                .filter(|(repository, tag)| !repository.contains('/') || !tag.is_empty())
                .map_or((value.to_owned(), None), |(repository, tag)| {
                    (repository.to_owned(), Some(tag.to_owned()))
                });
            Ok(DockerResource::Image(DockerImage {
                repository,
                tag,
                image_id: None,
                size_bytes: 0,
                size_known: false,
                large_data: false,
                created_at: None,
                containers: None,
                export_eligible: true,
            }))
        }
        "volume" => Ok(DockerResource::Volume(DockerVolume {
            name: package_id
                .strip_prefix("volume:")
                .unwrap_or(package_id)
                .to_owned(),
            driver: None,
            size_bytes: 0,
            size_known: false,
            large_data: false,
            in_use: false,
            running: false,
            backup_eligible: true,
            requires_quiescence: false,
        })),
        _ => Err(schema_error(
            "Docker identity has an unsupported resource kind",
        )),
    }
}

fn parse_json_records(bytes: &[u8], label: &str) -> ProviderResult<Vec<Value>> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(security_error(&format!(
            "Docker {label} output exceeds the reviewed byte limit"
        )));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return records_from_value(value, label);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| parse_error(&format!("Docker {label} output is not valid UTF-8")))?;
    let mut records = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value = serde_json::from_str::<Value>(line).map_err(|error| {
            Box::new(
                ErrorEnvelope::new(
                    ReforgeErrorCode::ProviderParseFailed,
                    format!("Docker {label} output contains invalid JSON"),
                )
                .with_technical_detail(error.to_string()),
            )
        })?;
        records.extend(records_from_value(value, label)?);
        if records.len() > MAX_RECORDS {
            return Err(security_error(&format!(
                "Docker {label} output contains too many records"
            )));
        }
    }
    Ok(records)
}

fn records_from_value(value: Value, label: &str) -> ProviderResult<Vec<Value>> {
    let mut records = match value {
        Value::Array(values) => values,
        Value::Object(object) => {
            let key = match label {
                "contexts" => ["contexts", "Contexts"].as_slice(),
                "images" => ["images", "Images"].as_slice(),
                "volumes" => ["volumes", "Volumes"].as_slice(),
                "containers" => ["containers", "Containers"].as_slice(),
                "system df" => ["records", "Records", "items", "Items"].as_slice(),
                _ => [].as_slice(),
            };
            if let Some(array) = key
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_array))
            {
                array.clone()
            } else {
                vec![Value::Object(object)]
            }
        }
        _ => {
            return Err(parse_error(&format!(
                "Docker {label} output records must be objects"
            )));
        }
    };
    if records.len() > MAX_RECORDS {
        return Err(security_error(&format!(
            "Docker {label} output contains too many records"
        )));
    }
    if records.iter().any(|record| !record.is_object()) {
        return Err(parse_error(&format!(
            "Docker {label} output contains a non-object record"
        )));
    }
    Ok(std::mem::take(&mut records))
}

fn successful_process() -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        cancelled: false,
    }
}

fn validate_process_result(result: &ProcessResult, operation: &str) -> ProviderResult<()> {
    if result.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            format!("Docker {operation} was cancelled"),
        )));
    }
    if result.timed_out {
        return Err(operation_error(&format!("Docker {operation} timed out")));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(_) | None => Err(Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::ProviderUnavailable,
                "Docker daemon or CLI command is unavailable on this target",
            )
            .with_technical_detail(format!("Docker {operation} did not complete successfully")),
        )),
    }
}

fn append_process_warning(
    warnings: &mut Vec<ErrorEnvelope>,
    result: &ProcessResult,
    operation: &str,
) {
    if !result.stderr.trim().is_empty() {
        warnings.push(warning(
            ReforgeErrorCode::OperationFailed,
            &format!("Docker {operation} reported bounded diagnostics; metadata was retained without stderr content"),
        ));
    }
}

fn read_config(known_folders: &KnownFolderMap) -> (Option<Vec<u8>>, Vec<ErrorEnvelope>) {
    let mut warnings = Vec::new();
    let Ok(path) = DockerAdapter::config_path() else {
        return (
            None,
            vec![warning(
                ReforgeErrorCode::InvalidPath,
                "Docker config path token is invalid",
            )],
        );
    };
    let absolute = match known_folders.resolve(&path) {
        Ok(path) => path,
        Err(error) => return (None, vec![*error]),
    };
    match fs::read(absolute) {
        Ok(bytes) if bytes.len() <= MAX_CONFIG_BYTES => (Some(bytes), warnings),
        Ok(_) => {
            warnings.push(warning(
                ReforgeErrorCode::SecurityPolicy,
                "Docker config exceeds the reviewed metadata bound",
            ));
            (None, warnings)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, warnings),
        Err(error) => {
            warnings.push(ErrorEnvelope::from_io_error(
                &error,
                "Docker config could not be inspected safely",
            ));
            (None, warnings)
        }
    }
}

fn required_text(record: &Value, keys: &[&str], label: &str) -> ProviderResult<String> {
    optional_text(record, keys)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| parse_error(&format!("{label} is missing from Docker output")))
}

fn optional_text(record: &Value, keys: &[&str]) -> Option<String> {
    let object = record.as_object()?;
    value_text(object, keys)
}

fn optional_safe_text(record: &Value, keys: &[&str], max_bytes: usize) -> Option<String> {
    optional_text(record, keys).and_then(|value| safe_text(&value, max_bytes))
}

fn value_text(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match object.get(*key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    })
}

fn value_is_true(record: &Value, keys: &[&str]) -> bool {
    let Some(value) = optional_text(record, keys) else {
        return false;
    };
    let value = value.trim().to_ascii_lowercase();
    matches!(
        value.as_str(),
        "true" | "1" | "yes" | "*" | "running" | "up"
    ) || value.starts_with("running ")
        || value.starts_with("up ")
}

fn optional_u64(record: &Value, keys: &[&str]) -> Option<u64> {
    optional_text(record, keys).and_then(|value| value.trim().parse().ok())
}

fn validate_metadata(value: &str, label: &str, max_bytes: usize) -> ProviderResult<String> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(parse_error(&format!(
            "{label} is outside the reviewed metadata grammar"
        )));
    }
    Ok(value.to_owned())
}

fn validate_helper(value: &str) -> ProviderResult<String> {
    let value = validate_metadata(value, "Docker credential helper", 128)?;
    if value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.contains(';')
        || value.contains('&')
        || value.contains('|')
        || value.contains('$')
    {
        return Err(parse_error(
            "Docker credential helper contains command syntax",
        ));
    }
    Ok(value)
}

fn safe_text(value: &str, max_bytes: usize) -> Option<String> {
    RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
}

fn sanitize_endpoint(value: &str) -> (Option<String>, bool) {
    let Some(mut url) = Url::parse(value).ok() else {
        return (safe_text(value, MAX_METADATA_BYTES), false);
    };
    let redacted = !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some();
    if redacted {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
    }
    (safe_text(url.as_str(), MAX_METADATA_BYTES), redacted)
}

fn sanitize_registry(value: &str) -> Option<String> {
    if let Ok(mut url) = Url::parse(value) {
        let had_credentials = !url.username().is_empty() || url.password().is_some();
        if had_credentials {
            let _ = url.set_username("");
            let _ = url.set_password(None);
        }
        url.set_query(None);
        url.set_fragment(None);
        if let Some(host) = url.host_str() {
            let registry = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            };
            return safe_text(&registry, MAX_METADATA_BYTES);
        }
    }
    safe_text(value, MAX_METADATA_BYTES)
}

fn parse_size_bytes(value: &str) -> Option<u64> {
    let value = value.trim().replace(',', "");
    if value.is_empty() || matches!(value.to_ascii_lowercase().as_str(), "n/a" | "na" | "-") {
        return None;
    }
    if let Ok(bytes) = value.parse::<u64>() {
        return Some(bytes);
    }
    let split = value
        .char_indices()
        .find(|(_, character)| character.is_ascii_alphabetic())
        .map(|(index, _)| index)?;
    let (number, suffix) = value.split_at(split);
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "b" => 1u128,
        "kb" | "kib" => 1024,
        "mb" | "mib" => 1024u128.pow(2),
        "gb" | "gib" => 1024u128.pow(3),
        "tb" | "tib" => 1024u128.pow(4),
        "pb" | "pib" => 1024u128.pow(5),
        _ => return None,
    };
    let number = number.trim();
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let whole = whole.parse::<u128>().ok()?;
    let fraction_digits = fraction.len().min(6);
    let fraction_value = if fraction_digits == 0 {
        0
    } else {
        fraction[..fraction_digits].parse::<u128>().ok()?
    };
    let scale = 10u128.pow(fraction_digits as u32);
    let scaled = whole.checked_mul(scale)?.checked_add(fraction_value)?;
    let bytes = scaled.checked_mul(multiplier)?.checked_div(scale)?;
    u64::try_from(bytes).ok()
}

fn image_identity(image: &DockerImage) -> String {
    image
        .image_id
        .clone()
        .unwrap_or_else(|| image_display_name(image))
}

fn image_display_name(image: &DockerImage) -> String {
    match image.tag.as_deref() {
        Some(tag) => format!("{}:{tag}", image.repository),
        None => image.repository.clone(),
    }
}

fn option_string(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}

fn insert_unique<K: Ord + Clone, V: Eq>(
    values: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    label: &str,
) -> ProviderResult<()> {
    if let Some(existing) = values.get(&key)
        && existing != &value
    {
        return Err(parse_error(&format!(
            "{label} repeats with conflicting metadata"
        )));
    }
    values.insert(key, value);
    Ok(())
}

fn observation_key(observation: &Observation) -> String {
    observation
        .evidence()
        .first()
        .map(|evidence| evidence.locator.clone())
        .unwrap_or_default()
}

fn make_evidence(
    locator: String,
    summary: String,
    strength: u8,
    independent_group: &str,
    observed_at: DateTime<Utc>,
) -> Evidence {
    let locator =
        safe_text(&locator, MAX_METADATA_BYTES).unwrap_or_else(|| "docker:unknown".to_owned());
    let summary = safe_text(&summary, MAX_WARNING_BYTES)
        .unwrap_or_else(|| "Docker evidence was redacted".to_owned());
    let id = EvidenceId::new(format!(
        "docker-evidence-{}",
        blake3::hash(format!("{locator}|{summary}").as_bytes()).to_hex()
    ))
    .expect("hashed Docker evidence ID");
    Evidence {
        id,
        source: EvidenceSource::Docker,
        locator,
        observed_at,
        summary,
        strength,
        independent_group: independent_group.to_owned(),
    }
}

fn evidence_refs(evidence: &[Evidence]) -> Vec<EvidenceRef> {
    let mut refs = evidence
        .iter()
        .map(|evidence| EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        })
        .collect::<Vec<_>>();
    refs.sort_by(|left, right| left.id.cmp(&right.id));
    refs.dedup_by(|left, right| left.id == right.id);
    refs
}

fn confidence_from_evidence(evidence: &[Evidence]) -> Confidence {
    let score = evidence
        .iter()
        .fold(0u16, |total, evidence| {
            total.saturating_add(u16::from(evidence.strength))
        })
        .min(100);
    match score {
        90..=100 => Confidence::Confirmed,
        75..=89 => Confidence::High,
        45..=74 => Confidence::Medium,
        20..=44 => Confidence::Low,
        _ => Confidence::Unknown,
    }
}

fn operation_key(resource: &DockerResource, reason: &str) -> String {
    hashed_id(
        "docker-operation",
        &format!(
            "{}|{}|{}",
            resource.source_kind(),
            resource.identity(),
            reason
        ),
    )
}

fn hashed_id(prefix: &str, value: &str) -> String {
    format!("{prefix}-{}", blake3::hash(value.as_bytes()).to_hex())
}

fn warning(code: ReforgeErrorCode, message: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        code,
        safe_text(message, MAX_WARNING_BYTES).unwrap_or_else(|| "Docker warning".to_owned()),
    )
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Docker provider data is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Docker output did not match the reviewed JSON shape",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Docker output exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Docker discovery could not be completed",
        )
        .with_technical_detail(detail),
    )
}

// The runner stays immediately before tests so its allowlisted command
// construction is easy to audit.
async fn run_docker_async<const N: usize>(
    runner: &reforge_platform_windows::ProcessRunner,
    cancellation: &CancellationToken,
    args: [&str; N],
) -> ProviderResult<ProcessResult> {
    let command = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::Docker),
        args.into_iter().map(OsString::from),
        PROCESS_TIMEOUT,
        PROCESS_OUTPUT_BYTES,
    )?;
    let result = runner.run(&command, cancellation).await?;
    validate_process_result(&result, "CLI command")?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_docker_sizes_without_floating_point() {
        assert_eq!(parse_size_bytes("1.5MB"), Some(1_572_864));
        assert_eq!(parse_size_bytes("N/A"), None);
        assert_eq!(parse_size_bytes("42"), Some(42));
    }

    #[test]
    fn endpoint_credentials_are_removed_from_metadata() {
        let (endpoint, redacted) = sanitize_endpoint("tcp://user:secret@example.test:2376?x=1");
        assert_eq!(endpoint.as_deref(), Some("tcp://example.test:2376"));
        assert!(redacted);
    }

    #[test]
    fn config_parser_never_retains_auth_values() {
        let state = parse_config(
            br#"{"auths":{"https://registry.example":"TOP_SECRET"},"credsStore":"desktop"}"#,
            Utc::now(),
        )
        .expect("config parses");
        assert_eq!(state.credential_helpers[0].helper, "desktop");
        assert_eq!(state.auth_registries, vec!["registry.example"]);
        assert!(
            state
                .warnings
                .iter()
                .any(|warning| warning.code == ReforgeErrorCode::ManualSecretRequired)
        );
    }
}
