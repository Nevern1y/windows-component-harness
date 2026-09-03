//! WSL discovery through bounded, allowlisted commands.
//!
//! The adapter records distribution identity, state, Windows prerequisites, and
//! tokenized configuration metadata. Linux package lists, user IDs, mutable VM
//! disks, and implicit distribution exports are intentionally out of scope.

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
    Confidence, ConfigScope, ContentType, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken,
    ManualAction, ManualActionState, Operation, OperationId, OperationKind, PathToken, Portability,
    Precondition, Provenance, ProviderId, RedactionPolicy, ReforgeErrorCode, RestoreDescriptor,
    RestoreStrategy, RiskLevel, RunId, SelectionMetadata, TargetFacts, VerificationRule,
    VersionValue, WslSpec,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, FeatureState, KnownFolderMap, ProcessResult,
    TrustedExecutable, feature_probe_command, parse_feature_output,
};
use serde_json::Value;
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "wsl";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_DISTRIBUTIONS: usize = 256;
const MAX_CONFIGS: usize = 256;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 512;
const WSL_CONFIG_RELATIVE: &str = ".wslconfig";
const WSL_CONF_PATH: &str = "/etc/wsl.conf";
const WSL_DOCS: &str = "https://learn.microsoft.com/en-us/windows/wsl/basic-commands";
const WSL_CONFIG_DOCS: &str = "https://learn.microsoft.com/en-us/windows/wsl/wsl-config";

/// State reported by `wsl --list --verbose`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WslState {
    Running,
    Stopped,
    Installing,
    Uninstalling,
    Unknown,
}

impl WslState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Installing => "installing",
            Self::Uninstalling => "uninstalling",
            Self::Unknown => "unknown",
        }
    }
}

/// Export state for a distribution. `ExplicitSelection` means the documented
/// export can be offered, but it was not executed during discovery.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WslExportEligibility {
    ExplicitSelection,
    Eligible,
    Failed,
    Unavailable,
}

impl WslExportEligibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitSelection => "explicit_selection",
            Self::Eligible => "eligible",
            Self::Failed => "failed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A discovered WSL distribution. Export bytes are never implicit; the export
/// fields describe an explicit large-artifact choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslDistribution {
    pub name: String,
    pub wsl_version: Option<u8>,
    pub state: WslState,
    pub running: bool,
    pub default: bool,
    pub export_eligibility: WslExportEligibility,
    pub export_eligible: bool,
    pub large_data: bool,
    pub export_size_bytes: Option<u64>,
    pub export_artifact: Option<ArtifactRef>,
    pub config_artifacts: Vec<WslConfigArtifact>,
}

/// A Windows prerequisite relevant to WSL enablement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslPrerequisite {
    pub name: String,
    pub enabled: Option<bool>,
    pub restart_required: bool,
    pub required_for_wsl2: bool,
}

/// A configuration artifact. Windows-side `.wslconfig` has a token and can be
/// selected as a normal artifact; Linux-side `/etc/wsl.conf` is metadata-only
/// and remains a manual action because it has no Windows path token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslConfigArtifact {
    pub distribution: Option<String>,
    pub path: String,
    pub token: Option<PathToken>,
    pub artifact: Option<ArtifactRef>,
    pub size_bytes: u64,
    pub content_type: ContentType,
    pub policy: ArtifactPolicy,
}

/// Status metadata from `wsl --status`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WslStatus {
    pub default_distribution: Option<String>,
    pub default_version: Option<u8>,
    pub wsl_version: Option<String>,
    pub kernel_version: Option<String>,
}

/// Process and configuration captures used by deterministic tests and callers
/// that already ran the reviewed WSL commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslCaptures {
    pub list: ProcessResult,
    pub status: ProcessResult,
    pub feature_output: Option<String>,
    pub wslconfig: Option<Vec<u8>>,
    pub distro_configs: BTreeMap<String, ProcessResult>,
    pub exports: BTreeMap<String, ProcessResult>,
    pub export_artifacts: BTreeMap<String, ArtifactRef>,
}
impl WslCaptures {
    pub fn new(list: ProcessResult, status: ProcessResult) -> Self {
        Self {
            list,
            status,
            feature_output: None,
            wslconfig: None,
            distro_configs: BTreeMap::new(),
            exports: BTreeMap::new(),
            export_artifacts: BTreeMap::new(),
        }
    }
    pub fn with_feature_output(mut self, output: impl Into<String>) -> Self {
        self.feature_output = Some(output.into());
        self
    }

    pub fn with_wslconfig(mut self, contents: impl Into<Vec<u8>>) -> Self {
        self.wslconfig = Some(contents.into());
        self
    }

    pub fn with_distro_config(
        mut self,
        distribution: impl Into<String>,
        contents: impl Into<Vec<u8>>,
    ) -> Self {
        self.distro_configs.insert(
            distribution.into(),
            successful_process_with_stdout(contents.into()),
        );
        self
    }

    /// Retain an explicitly supplied export process result as metadata. The
    /// export payload itself is not retained by this discovery adapter.
    pub fn with_export(mut self, distribution: impl Into<String>, result: ProcessResult) -> Self {
        self.exports.insert(distribution.into(), result);
        self
    }

    pub fn with_export_artifact(
        mut self,
        distribution: impl Into<String>,
        artifact: ArtifactRef,
    ) -> Self {
        self.export_artifacts.insert(distribution.into(), artifact);
        self
    }
}

/// Complete WSL discovery result with graph edges for prerequisite ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WslDiscovery {
    pub available: bool,
    pub status: WslStatus,
    pub distributions: Vec<WslDistribution>,
    pub prerequisites: Vec<WslPrerequisite>,
    pub config_artifacts: Vec<WslConfigArtifact>,
    pub artifacts: Vec<ArtifactRef>,
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub observations: Vec<Observation>,
    pub evidence: Vec<Evidence>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
}

impl WslDiscovery {
    pub fn distribution_component(&self, name: &str) -> Option<&Component> {
        self.components.iter().find(|component| {
            component.kind == ComponentKind::WslDistribution && component.display_name == name
        })
    }
}

#[derive(Clone, Debug)]
pub struct WslAdapter {
    id: ProviderId,
    metadata: Arc<RwLock<BTreeMap<ComponentId, WslResource>>>,
}

impl WslAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant WSL provider ID"),
            metadata: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn wslconfig_path() -> ProviderResult<PathToken> {
        PathToken::new(KnownFolderToken::UserProfile, WSL_CONFIG_RELATIVE)
            .map_err(|_| schema_error(".wslconfig path token could not be constructed"))
    }

    /// Parse the documented table output of `wsl --list --verbose` without
    /// inferring Linux packages, users, or distribution internals.
    pub fn parse_list_output(&self, stdout: &str) -> ProviderResult<Vec<WslDistribution>> {
        parse_list_output(stdout)
    }

    /// Parse bounded status text. Unknown/localized fields remain absent.
    pub fn parse_status_output(&self, stdout: &str) -> ProviderResult<WslStatus> {
        parse_status_output(stdout)
    }

    /// Parse a complete deterministic capture against tokenized known folders.
    pub fn discover_from_captures(
        &self,
        known_folders: &KnownFolderMap,
        captures: WslCaptures,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<WslDiscovery> {
        let mut warnings = Vec::new();
        if captures.wslconfig.is_some()
            && !known_folders
                .entries
                .contains_key(&KnownFolderToken::UserProfile)
        {
            warnings.push(warning(
                ReforgeErrorCode::PathNotFound,
                ".wslconfig was captured but the current user profile root is unavailable",
            ));
        }
        self.build_discovery(true, &captures, None, warnings, observed_at)
    }

    /// Discover tokenized `.wslconfig` metadata without starting WSL. Use
    /// [`Self::discover_with_runner`] to query distributions and status.
    pub fn discover(&self, known_folders: &KnownFolderMap) -> ProviderResult<WslDiscovery> {
        let (config_artifact, warnings) = collect_wslconfig_artifact(known_folders);
        let captures = WslCaptures::new(successful_process(), successful_process());
        self.build_discovery(false, &captures, config_artifact, warnings, Utc::now())
    }

    /// Run only the reviewed WSL listing/status/feature probes. Distribution
    /// exports are never started automatically. A running distro's
    /// `/etc/wsl.conf` is read with a fixed `cat` argument; stopped distros are
    /// left manual so discovery never starts them implicitly.
    pub async fn discover_with_runner(
        &self,
        known_folders: &KnownFolderMap,
        runner: &reforge_platform_windows::ProcessRunner,
        cancellation: &CancellationToken,
    ) -> ProviderResult<WslDiscovery> {
        let list = run_wsl_async(runner, cancellation, ["--list", "--verbose"]).await?;
        let status = run_wsl_async(runner, cancellation, ["--status"]).await?;
        let mut captures = WslCaptures::new(list, status);
        let mut warnings = Vec::new();

        if runner.builtin_available(BuiltinExecutable::PowerShell) {
            match runner.run(&feature_probe_command()?, cancellation).await {
                Ok(result) if result.cancelled => return Err(cancelled_error()),
                Ok(result) if result.exit_code == Some(0) && !result.timed_out => {
                    captures.feature_output = Some(result.stdout);
                }
                Ok(_) => warnings.push(warning(
                    ReforgeErrorCode::ProviderUnavailable,
                    "Windows optional-feature probe did not return usable WSL prerequisite data",
                )),
                Err(error) => warnings.push(*error),
            }
        } else {
            warnings.push(warning(
                ReforgeErrorCode::ProviderUnavailable,
                "PowerShell is unavailable; WSL prerequisite states remain unknown",
            ));
        }

        let distributions = self.parse_list_output(&captures.list.stdout)?;
        for distribution in distributions
            .iter()
            .filter(|distribution| distribution.running)
        {
            let name = distribution.name.as_str();
            match run_wsl_async(
                runner,
                cancellation,
                ["--distribution", name, "--", "cat", WSL_CONF_PATH],
            )
            .await
            {
                Ok(result) => {
                    captures
                        .distro_configs
                        .insert(distribution.name.clone(), result);
                }
                Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
                Err(error) => warnings.push(*error),
            }
        }

        let (config_artifact, mut config_warnings) = collect_wslconfig_artifact(known_folders);
        warnings.append(&mut config_warnings);
        self.build_discovery(true, &captures, config_artifact, warnings, Utc::now())
    }

    /// Return operations in the required order: prerequisite reviews first,
    /// distribution import second, and tokenized Windows config review after
    /// the distribution. A typed import is emitted only when selection has
    /// supplied a verified export object; otherwise the distribution remains a
    /// manual action and no object ID is invented.
    pub fn plan_restore(
        &self,
        discovery: &WslDiscovery,
        target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        let mut operations = Vec::new();
        let mut operation_ids = BTreeMap::<ComponentId, OperationId>::new();
        let mut ordinal = first_ordinal;
        let mut prerequisites = discovery
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::SystemFeature)
            .collect::<Vec<_>>();
        prerequisites.sort_by(|left, right| left.id.cmp(&right.id));
        for component in prerequisites {
            let resource = self.resource_for_component(component)?;
            let operation = self.operation_for_resource(
                component,
                &resource,
                target,
                run_id,
                ordinal,
                Vec::new(),
            )?;
            operation_ids.insert(component.id.clone(), operation.id.clone());
            operations.push(operation);
            ordinal = ordinal.saturating_add(1);
        }

        let mut distributions = discovery
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::WslDistribution)
            .collect::<Vec<_>>();
        distributions.sort_by(|left, right| left.id.cmp(&right.id));
        for component in distributions {
            let mut operation_prerequisites = component
                .dependencies
                .iter()
                .filter_map(|edge| operation_ids.get(&edge.to).cloned())
                .collect::<Vec<_>>();
            operation_prerequisites.sort();
            operation_prerequisites.dedup();
            let resource = self.resource_for_component(component)?;
            let operation = self.operation_for_resource(
                component,
                &resource,
                target,
                run_id,
                ordinal,
                operation_prerequisites,
            )?;
            operation_ids.insert(component.id.clone(), operation.id.clone());
            operations.push(operation);
            ordinal = ordinal.saturating_add(1);
        }

        let mut configs = discovery
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::Configuration)
            .collect::<Vec<_>>();
        configs.sort_by(|left, right| left.id.cmp(&right.id));
        for component in configs {
            let mut operation_prerequisites = operation_ids.values().cloned().collect::<Vec<_>>();
            operation_prerequisites.sort();
            operation_prerequisites.dedup();
            let resource = self.resource_for_component(component)?;
            let operation = self.operation_for_resource(
                component,
                &resource,
                target,
                run_id,
                ordinal,
                operation_prerequisites,
            )?;
            operations.push(operation);
            ordinal = ordinal.saturating_add(1);
        }
        Ok(operations)
    }

    fn build_discovery(
        &self,
        available: bool,
        captures: &WslCaptures,
        windows_config_artifact: Option<ArtifactRef>,
        mut warnings: Vec<ErrorEnvelope>,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<WslDiscovery> {
        validate_process_result(&captures.list, "distribution listing")?;
        validate_process_result(&captures.status, "status query")?;
        let mut distributions = self.parse_list_output(&captures.list.stdout)?;
        let status = self.parse_status_output(&captures.status.stdout)?;
        let mut prerequisites =
            parse_prerequisites(captures.feature_output.as_deref(), &mut warnings);
        if prerequisites
            .iter()
            .any(|prerequisite| prerequisite.enabled.is_none())
        {
            warnings.push(warning(
                ReforgeErrorCode::ManualActionRequired,
                "WSL prerequisite state is unknown; enablement remains a manual review",
            ));
        }

        let mut config_artifacts = Vec::new();
        if let Some(artifact) = windows_config_artifact {
            config_artifacts.push(WslConfigArtifact {
                distribution: None,
                path: WSL_CONFIG_RELATIVE.to_owned(),
                token: Some(artifact.source_path.clone()),
                size_bytes: artifact.size_bytes,
                content_type: artifact.content_type.clone(),
                policy: artifact.policy.clone(),
                artifact: Some(artifact),
            });
        } else if let Some(bytes) = captures.wslconfig.as_deref() {
            if bytes.len() > MAX_CONFIG_BYTES {
                return Err(security_error(
                    ".wslconfig exceeds the reviewed metadata bound",
                ));
            }
            let token = WslAdapter::wslconfig_path()?;
            let artifact = ArtifactRef {
                id: ArtifactId::new(format!("wslconfig-{}", blake3::hash(bytes).to_hex()))
                    .map_err(|_| schema_error(".wslconfig artifact ID is invalid"))?,
                source_path: token.clone(),
                scope: ConfigScope::User,
                size_bytes: bytes.len() as u64,
                content_type: ContentType::Utf8Text,
                policy: ArtifactPolicy::Config,
                object: None,
            };
            config_artifacts.push(WslConfigArtifact {
                distribution: None,
                path: WSL_CONFIG_RELATIVE.to_owned(),
                token: Some(token),
                size_bytes: bytes.len() as u64,
                content_type: ContentType::Utf8Text,
                policy: ArtifactPolicy::Config,
                artifact: Some(artifact),
            });
        }

        if captures.distro_configs.len() > MAX_CONFIGS
            || captures.exports.len() > MAX_CONFIGS
            || captures.export_artifacts.len() > MAX_CONFIGS
        {
            return Err(security_error(
                "WSL capture contains too many per-distribution records",
            ));
        }
        let distribution_names = distributions
            .iter()
            .map(|distribution| distribution.name.clone())
            .collect::<BTreeSet<_>>();

        for name in captures.export_artifacts.keys() {
            if !distribution_names.contains(name) {
                warnings.push(warning(
                    ReforgeErrorCode::ProviderParseFailed,
                    "WSL export artifact referenced an unobserved distribution",
                ));
            }
        }
        for (name, process) in &captures.distro_configs {
            if !distribution_names.contains(name) {
                warnings.push(warning(
                    ReforgeErrorCode::ProviderParseFailed,
                    "WSL config capture referenced an unobserved distribution",
                ));
                continue;
            }
            match validate_process_result(process, "wsl.conf query") {
                Ok(()) => {
                    if process.stdout.len() > MAX_CONFIG_BYTES {
                        warnings.push(warning(
                            ReforgeErrorCode::SecurityPolicy,
                            "A WSL distribution config exceeded the reviewed metadata bound",
                        ));
                        continue;
                    }
                    config_artifacts.push(WslConfigArtifact {
                        distribution: Some(name.clone()),
                        path: WSL_CONF_PATH.to_owned(),
                        token: None,
                        artifact: None,
                        size_bytes: process.stdout.len() as u64,
                        content_type: ContentType::Utf8Text,
                        policy: ArtifactPolicy::Manual,
                    });
                }
                Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
                Err(error) => warnings.push(*error),
            }
        }
        config_artifacts.sort_by(|left, right| {
            left.distribution
                .cmp(&right.distribution)
                .then_with(|| left.path.cmp(&right.path))
        });

        for distribution in &mut distributions {
            let export_artifact = captures.export_artifacts.get(&distribution.name).cloned();
            if let Some(artifact) = export_artifact {
                if !matches!(
                    artifact.policy,
                    ArtifactPolicy::LargeOptIn | ArtifactPolicy::Export
                ) {
                    warnings.push(warning(
                        ReforgeErrorCode::SecurityPolicy,
                        "WSL export artifact did not use an explicit large-data policy",
                    ));
                } else {
                    distribution.export_size_bytes = Some(artifact.size_bytes);
                    distribution.export_artifact = Some(artifact);
                }
            }
            let export = captures.exports.get(&distribution.name);
            match export {
                Some(result) => match validate_process_result(result, "distribution export") {
                    Ok(()) => {
                        distribution.export_eligibility = WslExportEligibility::Eligible;
                        distribution.export_eligible = true;
                    }
                    Err(error) if error.code == ReforgeErrorCode::Cancelled => return Err(error),
                    Err(error) => {
                        distribution.export_eligibility = WslExportEligibility::Failed;
                        distribution.export_eligible = false;
                        distribution.export_artifact = None;
                        warnings.push(*error);
                    }
                },
                None if distribution.export_artifact.is_some() => {
                    distribution.export_eligibility = WslExportEligibility::Eligible;
                    distribution.export_eligible = true;
                }
                None if distribution.wsl_version.is_some() => {
                    distribution.export_eligibility = WslExportEligibility::ExplicitSelection;
                    distribution.export_eligible = true;
                }
                None => {
                    distribution.export_eligibility = WslExportEligibility::Unavailable;
                    distribution.export_eligible = false;
                }
            }
            distribution.large_data = true;
            distribution.config_artifacts = config_artifacts
                .iter()
                .filter(|artifact| {
                    artifact.distribution.as_deref() == Some(distribution.name.as_str())
                })
                .cloned()
                .collect();
            if distribution.export_eligibility == WslExportEligibility::ExplicitSelection {
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!(
                        "WSL distribution {} export is a large artifact and requires explicit selection",
                        distribution.name
                    ),
                ));
            }
            if distribution.export_eligibility == WslExportEligibility::Failed {
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!(
                        "WSL distribution {} export failed and remains manual",
                        distribution.name
                    ),
                ));
            }
        }

        let mut components = Vec::new();
        let mut observations = Vec::new();
        let mut evidence = Vec::new();
        let mut distribution_ids = BTreeMap::new();
        for distribution in &distributions {
            let record = WslResource::Distribution(distribution.clone());
            let record_evidence = vec![make_evidence(
                format!("wsl-distribution:{}", distribution.name),
                format!(
                    "WSL distribution {} was recorded from the reviewed listing",
                    distribution.name
                ),
                if distribution.wsl_version.is_some() {
                    75
                } else {
                    55
                },
                "wsl-distribution",
                observed_at,
            )];
            let component = self.component_for_resource(record, &record_evidence)?;
            distribution_ids.insert(distribution.name.clone(), component.id.clone());
            observations.push(Observation::Registration {
                kind: ComponentKind::WslDistribution,
                identity: component.identity.clone(),
                evidence: record_evidence.clone(),
            });
            evidence.extend(record_evidence);
            components.push(component);
        }

        let mut prerequisite_ids = BTreeMap::new();
        for prerequisite in &prerequisites {
            let record = WslResource::Prerequisite(prerequisite.clone());
            let record_evidence = vec![make_evidence(
                format!("wsl-prerequisite:{}", prerequisite.name),
                format!(
                    "WSL prerequisite {} was observed through Windows feature state",
                    prerequisite.name
                ),
                prerequisite
                    .enabled
                    .map_or(35, |enabled| if enabled { 75 } else { 60 }),
                "wsl-prerequisite",
                observed_at,
            )];
            let component = self.component_for_resource(record, &record_evidence)?;
            prerequisite_ids.insert(prerequisite.name.clone(), component.id.clone());
            observations.push(Observation::Registration {
                kind: ComponentKind::SystemFeature,
                identity: component.identity.clone(),
                evidence: record_evidence.clone(),
            });
            evidence.extend(record_evidence);
            components.push(component);
        }

        let mut edges = Vec::new();
        let required_names = prerequisites
            .iter()
            .filter(|prerequisite| {
                prerequisite.name == "Microsoft-Windows-Subsystem-Linux"
                    || distributions.iter().any(|distribution| {
                        distribution.wsl_version == Some(2)
                            && prerequisite.name == "VirtualMachinePlatform"
                    })
            })
            .map(|prerequisite| prerequisite.name.clone())
            .collect::<BTreeSet<_>>();
        for distribution in &distributions {
            let Some(from) = distribution_ids.get(&distribution.name).cloned() else {
                continue;
            };
            let mut dependencies = Vec::new();
            for name in &required_names {
                let Some(to) = prerequisite_ids.get(name).cloned() else {
                    continue;
                };
                let edge_evidence = evidence
                    .iter()
                    .filter(|record| {
                        record.locator == format!("wsl-distribution:{}", distribution.name)
                            || record.locator == format!("wsl-prerequisite:{name}")
                    })
                    .map(|record| record.id.clone())
                    .collect::<Vec<_>>();
                let edge = DependencyEdge {
                    from: from.clone(),
                    to,
                    kind: DependencyKind::RestoresBefore,
                    required: true,
                    evidence: edge_evidence,
                    confidence: Confidence::High,
                };
                dependencies.push(edge.clone());
                edges.push(edge);
            }
            if let Some(component) = components.iter_mut().find(|component| component.id == from) {
                component.dependencies = dependencies;
            }
        }

        let mut artifacts = Vec::new();
        let mut manual_actions = Vec::new();
        for config in &config_artifacts {
            if let Some(artifact) = config.artifact.clone() {
                let record_evidence = vec![make_evidence(
                    "wslconfig".to_owned(),
                    "Windows-side .wslconfig was recorded through a tokenized path".to_owned(),
                    70,
                    "wsl-config",
                    observed_at,
                )];
                let component = self.component_for_config(artifact.clone(), &record_evidence)?;
                observations.push(Observation::Artifact {
                    artifact: artifact.clone(),
                    evidence: record_evidence.clone(),
                });
                evidence.extend(record_evidence);
                components.push(component);
                artifacts.push(artifact);
            } else if let Some(distribution) = config.distribution.as_deref() {
                manual_actions.push(config_manual_action(distribution));
                warnings.push(warning(
                    ReforgeErrorCode::ManualActionRequired,
                    &format!("Linux-side wsl.conf for {distribution} is available only as manual metadata"),
                ));
            }
        }

        for distribution in &distributions {
            let Some(artifact) = distribution.export_artifact.clone() else {
                continue;
            };
            let export_evidence = vec![make_evidence(
                format!("wsl-export:{}", distribution.name),
                format!(
                    "An explicit WSL export artifact was selected for {}",
                    distribution.name
                ),
                80,
                "wsl-export",
                observed_at,
            )];
            observations.push(Observation::Artifact {
                artifact: artifact.clone(),
                evidence: export_evidence.clone(),
            });
            evidence.extend(export_evidence);
            artifacts.push(artifact);
        }

        let mut distribution_manual_actions = distributions
            .iter()
            .map(distribution_manual_action)
            .collect::<Vec<_>>();
        manual_actions.append(&mut distribution_manual_actions);
        components.sort_by(|left, right| left.id.cmp(&right.id));
        edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
        });
        edges.dedup();
        observations.sort_by_key(observation_key);
        evidence.sort_by(|left, right| left.id.cmp(&right.id));
        evidence.dedup_by(|left, right| left.id == right.id);
        prerequisites.sort_by(|left, right| left.name.cmp(&right.name));
        warnings.sort_by(|left, right| {
            format!("{:?}", left.code)
                .cmp(&format!("{:?}", right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
        warnings.truncate(MAX_WARNINGS);
        manual_actions.sort_by(|left, right| left.id.cmp(&right.id));
        manual_actions.dedup_by(|left, right| left.id == right.id);

        Ok(WslDiscovery {
            available,
            status,
            distributions,
            prerequisites,
            config_artifacts,
            artifacts,
            components,
            edges,
            observations,
            evidence,
            manual_actions,
            warnings,
        })
    }

    fn component_for_resource(
        &self,
        resource: WslResource,
        evidence: &[Evidence],
    ) -> ProviderResult<Component> {
        if let WslResource::Config(artifact) = &resource {
            return self.component_for_config(artifact.clone(), evidence);
        }
        let (
            kind,
            identity_name,
            display_name,
            version,
            restore,
            verification,
            selection,
            extensions,
            artifacts,
        ) = match &resource {
            WslResource::Distribution(distribution) => {
                let failed = distribution.export_eligibility == WslExportEligibility::Failed
                    || distribution.export_eligibility == WslExportEligibility::Unavailable;
                (
                        ComponentKind::WslDistribution,
                        format!("distribution:{}", distribution.name),
                        distribution.name.clone(),
                        distribution.wsl_version.map(|value| VersionValue {
                            raw: value.to_string(),
                            normalized: None,
                        }),
                        RestoreDescriptor {
                            primary: if failed {
                                RestoreStrategy::Partial
                            } else {
                                RestoreStrategy::ExportImport
                            },
                            alternatives: vec![RestoreStrategy::Manual],
                            portability: if failed {
                                Portability::PartiallyPortable
                            } else {
                                Portability::SupportedExport
                            },
                            requires_elevation: false,
                            requires_user_action: true,
                            rationale: vec![
                                "WSL distribution export is a large artifact and requires explicit selection".to_owned(),
                                "Linux package lists and user IDs are not inferred as portable state".to_owned(),
                            ],
                        },
                        VerificationRule::WslState {
                            distro: distribution.name.clone(),
                            version: distribution.wsl_version.map(|value| value.to_string()),
                        },
                        SelectionMetadata {
                            recommended: false,
                            score: 0,
                            selected_by_default: false,
                            sensitive: false,
                            size_bytes: distribution.export_size_bytes.unwrap_or(0),
                        },
                        BTreeMap::from([
                            ("wsl_kind".to_owned(), Value::String("distribution".to_owned())),
                            ("state".to_owned(), Value::String(distribution.state.as_str().to_owned())),
                            ("running".to_owned(), Value::Bool(distribution.running)),
                            ("default".to_owned(), Value::Bool(distribution.default)),
                            ("export_eligibility".to_owned(), Value::String(distribution.export_eligibility.as_str().to_owned())),
                            ("large_data".to_owned(), Value::Bool(distribution.large_data)),
                        ]),
                        distribution.export_artifact.clone().into_iter().collect(),
                    )
            }
            WslResource::Prerequisite(prerequisite) => (
                ComponentKind::SystemFeature,
                format!("feature:{}", prerequisite.name),
                prerequisite.name.clone(),
                None,
                RestoreDescriptor {
                    primary: RestoreStrategy::Manual,
                    alternatives: Vec::new(),
                    portability: Portability::PartiallyPortable,
                    requires_elevation: true,
                    requires_user_action: true,
                    rationale: vec![
                        "WSL Windows feature enablement requires an explicit privileged action"
                            .to_owned(),
                        "Unknown feature state is never treated as enabled".to_owned(),
                    ],
                },
                VerificationRule::WslState {
                    distro: prerequisite.name.clone(),
                    version: None,
                },
                SelectionMetadata {
                    recommended: false,
                    score: 0,
                    selected_by_default: false,
                    sensitive: false,
                    size_bytes: 0,
                },
                BTreeMap::from([
                    (
                        "wsl_kind".to_owned(),
                        Value::String("prerequisite".to_owned()),
                    ),
                    (
                        "enabled".to_owned(),
                        prerequisite.enabled.map_or(Value::Null, Value::Bool),
                    ),
                    (
                        "restart_required".to_owned(),
                        Value::Bool(prerequisite.restart_required),
                    ),
                    (
                        "required_for_wsl2".to_owned(),
                        Value::Bool(prerequisite.required_for_wsl2),
                    ),
                ]),
                Vec::new(),
            ),
            WslResource::Export(artifact) => (
                ComponentKind::DataArtifact,
                format!("export:{}", artifact.id),
                "WSL distribution export".to_owned(),
                None,
                RestoreDescriptor {
                    primary: RestoreStrategy::ExportImport,
                    alternatives: vec![RestoreStrategy::Manual],
                    portability: Portability::SupportedExport,
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale: vec![
                        "WSL export data is a large artifact and requires explicit selection".to_owned(),
                        "The export is retained as data; Linux package and user identity state is not inferred".to_owned(),
                    ],
                },
                VerificationRule::File {
                    destination: artifact.source_path.clone(),
                    object: artifact.object.clone(),
                },
                SelectionMetadata {
                    recommended: false,
                    score: 0,
                    selected_by_default: false,
                    sensitive: false,
                    size_bytes: artifact.size_bytes,
                },
                BTreeMap::from([
                    ("wsl_kind".to_owned(), Value::String("export".to_owned())),
                    ("large_data".to_owned(), Value::Bool(true)),
                ]),
                vec![artifact.clone()],
            ),
            WslResource::Config(artifact) => {
                return self.component_for_config(artifact.clone(), evidence);
            }
        };
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
            .map_err(|_| schema_error("WSL resource identity is not canonical"))?;
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.insert(canonical.id.clone(), resource);
        }
        let requires_elevation = kind == ComponentKind::SystemFeature;
        Ok(Component {
            id: canonical.id,
            kind,
            identity,
            display_name,
            version,
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
            artifacts,
            restore,
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation,
                requires_wsl: true,
                requires_docker: false,
            },
            verification: vec![verification],
            selection,
            extensions,
        })
    }

    fn component_for_config(
        &self,
        artifact: ArtifactRef,
        evidence: &[Evidence],
    ) -> ProviderResult<Component> {
        let identity = Identity {
            provider_package: Some((self.id.clone(), "config:.wslconfig".to_owned())),
            provider_source: Some("config".to_owned()),
            package_family: None,
            product_name: Some("WSL Windows configuration".to_owned()),
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        };
        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("WSL config identity is not canonical"))?;
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.insert(canonical.id.clone(), WslResource::Config(artifact.clone()));
        }
        Ok(Component {
            id: canonical.id,
            kind: ComponentKind::Configuration,
            identity,
            display_name: "WSL Windows configuration".to_owned(),
            version: None,
            architecture: None,
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some("config:.wslconfig".to_owned()),
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
                primary: RestoreStrategy::ConfigPortable,
                alternatives: vec![RestoreStrategy::Manual],
                portability: Portability::PartiallyPortable,
                requires_elevation: false,
                requires_user_action: true,
                rationale: vec![
                    "The Windows-side .wslconfig path is tokenized for the target user".to_owned(),
                    "Host-specific resource values require target review".to_owned(),
                ],
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: true,
                requires_docker: false,
            },
            verification: vec![VerificationRule::File {
                destination: artifact.source_path,
                object: artifact.object,
            }],
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: artifact.size_bytes,
            },
            extensions: BTreeMap::from([(
                "wsl_kind".to_owned(),
                Value::String("configuration".to_owned()),
            )]),
        })
    }

    fn resource_for_component(&self, component: &Component) -> ProviderResult<WslResource> {
        if component
            .provenance
            .as_ref()
            .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
        {
            return Err(schema_error("WSL component belongs to another adapter"));
        }
        if let Ok(metadata) = self.metadata.read()
            && let Some(resource) = metadata.get(&component.id)
        {
            return Ok(resource.clone());
        }
        infer_resource(&component.identity)
    }

    fn operation_for_resource(
        &self,
        component: &Component,
        resource: &WslResource,
        target: &TargetFacts,
        run_id: &RunId,
        ordinal: u64,
        prerequisites: Vec<OperationId>,
    ) -> ProviderResult<Operation> {
        if let WslResource::Distribution(distribution) = resource
            && let Some(artifact) = distribution.export_artifact.as_ref()
            && let Some(object) = artifact.object.clone()
        {
            return self.import_operation(
                component,
                distribution,
                object,
                run_id,
                ordinal,
                prerequisites,
            );
        }
        self.manual_operation(component, resource, target, run_id, ordinal, prerequisites)
    }

    fn import_operation(
        &self,
        component: &Component,
        distribution: &WslDistribution,
        object: reforge_domain::ObjectId,
        run_id: &RunId,
        ordinal: u64,
        prerequisites: Vec<OperationId>,
    ) -> ProviderResult<Operation> {
        let verification = VerificationRule::WslState {
            distro: distribution.name.clone(),
            version: distribution.wsl_version.map(|value| value.to_string()),
        };
        let idempotency_key = hashed_id(
            "wsl-import-operation",
            &format!("{}|{}", component.id, object.as_str()),
        );
        let operation_id = OperationId::for_run(run_id, ordinal)
            .map_err(|_| schema_error("WSL import operation ID could not be constructed"))?;
        Ok(Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::ImportWsl {
                distro: WslSpec {
                    distribution: distribution.name.clone(),
                    wsl_version: distribution.wsl_version,
                },
                object,
            },
            prerequisites,
            precondition: Precondition::ComponentAbsent {
                component: component.id.clone(),
            },
            idempotency_key,
            verification: vec![verification],
            requires_elevation: false,
            non_idempotent: false,
        })
    }

    fn manual_operation(
        &self,
        component: &Component,
        resource: &WslResource,
        target: &TargetFacts,
        run_id: &RunId,
        ordinal: u64,
        prerequisites: Vec<OperationId>,
    ) -> ProviderResult<Operation> {
        let (rule, title, reason, risk, instructions, docs_url, requires_elevation) =
            resource.manual_details();
        let target_available = target
            .providers
            .iter()
            .any(|provider| provider.id == self.id && provider.available);
        let reason = if target_available {
            reason.to_owned()
        } else {
            "WSL is unavailable on the target; enablement and restore require explicit user action"
                .to_owned()
        };
        let idempotency_key = hashed_id(
            "wsl-operation",
            &format!("{}|{}", component.id, resource.identity()),
        );
        let operation_id = OperationId::for_run(run_id, ordinal)
            .map_err(|_| schema_error("WSL operation ID could not be constructed"))?;
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: title.to_owned(),
            reason,
            risk,
            instructions,
            docs_url,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: rule.clone(),
        };
        Ok(Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::OpenManualAction { action },
            prerequisites,
            precondition: Precondition::Always,
            idempotency_key,
            verification: rule.into_iter().collect(),
            requires_elevation,
            non_idempotent: false,
        })
    }
}

impl Default for WslAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for WslAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::Wsl) {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![make_evidence(
                "PATH:wsl.exe".to_owned(),
                "The reviewed WSL executable name resolves from PATH".to_owned(),
                60,
                "wsl-provider",
                Utc::now(),
            )],
            warnings: vec![
                "WSL distribution exports are large artifacts and require explicit selection"
                    .to_owned(),
                "Linux package and user identity state is not inferred".to_owned(),
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
        Ok(ProviderEnumeration {
            observations: discovery.observations,
            warnings: discovery
                .warnings
                .iter()
                .map(|error| error.message.clone())
                .collect(),
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
                if artifact.source_path.relative == WSL_CONFIG_RELATIVE
                    && artifact.policy == ArtifactPolicy::Config
                {
                    return Ok(vec![self.component_for_config(artifact, &evidence)?]);
                }
                if matches!(
                    artifact.policy,
                    ArtifactPolicy::LargeOptIn | ArtifactPolicy::Export
                ) {
                    return Ok(vec![self.component_for_resource(
                        WslResource::Export(artifact),
                        &evidence,
                    )?]);
                }
                Err(schema_error(
                    "WSL artifact observation is neither tokenized config nor explicit export",
                ))
            }
            _ => Err(schema_error("WSL received an unsupported observation kind")),
        }
    }

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        let resource = self.resource_for_component(component)?;
        Ok(vec![self.operation_for_resource(
            component,
            &resource,
            target,
            run_id,
            first_ordinal,
            Vec::new(),
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
                .ok_or_else(|| schema_error("WSL config component has no artifact"));
        }
        Ok(vec![
            self.resource_for_component(component)?.verification_rule(),
        ])
    }
}

impl WslAdapter {
    fn resource_for_identity_kind(
        &self,
        kind: ComponentKind,
        identity: &Identity,
    ) -> ProviderResult<WslResource> {
        let resource = infer_resource(identity)?;
        if resource.kind() != kind {
            return Err(schema_error(
                "WSL registration kind disagrees with identity",
            ));
        }
        Ok(resource)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WslResource {
    Distribution(WslDistribution),
    Prerequisite(WslPrerequisite),
    Config(ArtifactRef),
    Export(ArtifactRef),
}

impl WslResource {
    fn kind(&self) -> ComponentKind {
        match self {
            Self::Distribution(_) => ComponentKind::WslDistribution,
            Self::Prerequisite(_) => ComponentKind::SystemFeature,
            Self::Config(_) => ComponentKind::Configuration,
            Self::Export(_) => ComponentKind::DataArtifact,
        }
    }

    fn source_kind(&self) -> &'static str {
        match self {
            Self::Distribution(_) => "distribution",
            Self::Prerequisite(_) => "prerequisite",
            Self::Config(_) => "config",
            Self::Export(_) => "export",
        }
    }

    fn identity(&self) -> String {
        match self {
            Self::Distribution(distribution) => distribution.name.clone(),
            Self::Prerequisite(prerequisite) => prerequisite.name.clone(),
            Self::Config(_) => WSL_CONFIG_RELATIVE.to_owned(),
            Self::Export(artifact) => artifact.id.to_string(),
        }
    }

    fn verification_rule(&self) -> VerificationRule {
        match self {
            Self::Distribution(distribution) => VerificationRule::WslState {
                distro: distribution.name.clone(),
                version: distribution.wsl_version.map(|value| value.to_string()),
            },
            Self::Prerequisite(prerequisite) => VerificationRule::WslState {
                distro: prerequisite.name.clone(),
                version: None,
            },
            Self::Config(artifact) | Self::Export(artifact) => VerificationRule::File {
                destination: artifact.source_path.clone(),
                object: artifact.object.clone(),
            },
        }
    }

    fn manual_details(
        &self,
    ) -> (
        Option<VerificationRule>,
        &'static str,
        &'static str,
        RiskLevel,
        Vec<String>,
        Option<Url>,
        bool,
    ) {
        match self {
            Self::Distribution(distribution) => {
                let reason = match distribution.export_eligibility {
                    WslExportEligibility::Failed => "The documented WSL export failed and must be retried manually",
                    WslExportEligibility::Unavailable => "The WSL distribution version is unknown; export eligibility cannot be assumed",
                    WslExportEligibility::ExplicitSelection => "The WSL distribution export is a large artifact and was not started automatically",
                    WslExportEligibility::Eligible => "The WSL distribution export is available only after explicit object selection",
                };
                (
                    Some(self.verification_rule()),
                    "Review WSL distribution import",
                    reason,
                    RiskLevel::High,
                    vec![
                        "Enable and verify required Windows WSL features first".to_owned(),
                        "Select the documented wsl --export artifact explicitly".to_owned(),
                        "Do not infer Linux package lists or user IDs from the distribution".to_owned(),
                    ],
                    Url::parse(WSL_DOCS).ok(),
                    false,
                )
            }
            Self::Prerequisite(_) => (
                None,
                "Enable WSL prerequisite",
                "The Windows WSL prerequisite requires an explicit privileged action",
                RiskLevel::High,
                vec![
                    "Review the observed feature state".to_owned(),
                    "Enable the feature through the supported Windows procedure and reboot if required".to_owned(),
                ],
                Url::parse(WSL_DOCS).ok(),
                true,
            ),
            Self::Config(_) => (
                Some(self.verification_rule()),
                "Review .wslconfig restore",
                "Windows-side .wslconfig is tokenized, but host-specific resource values require review",
                RiskLevel::Medium,
                vec![
                    "Review .wslconfig resource and networking settings for the target".to_owned(),
                    "Apply only the selected tokenized configuration artifact".to_owned(),
                ],
                Url::parse(WSL_CONFIG_DOCS).ok(),
                false,
            ),
            Self::Export(_) => (
                Some(self.verification_rule()),
                "Review WSL export artifact",
                "The WSL export is large data and requires explicit import review",
                RiskLevel::High,
                vec![
                    "Confirm the selected export object and its size".to_owned(),
                    "Import it only after required WSL features are enabled".to_owned(),
                ],
                Url::parse(WSL_DOCS).ok(),
                false,
            ),
        }
    }
}

fn parse_list_output(stdout: &str) -> ProviderResult<Vec<WslDistribution>> {
    if stdout.len() > MAX_TEXT_BYTES {
        return Err(security_error(
            "WSL list output exceeds the reviewed byte bound",
        ));
    }
    let text = normalize_wsl_text(stdout);
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut distributions = BTreeMap::<String, WslDistribution>::new();
    let mut parsed_any = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty()
            || line
                .chars()
                .all(|character| character == '-' || character.is_whitespace())
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("name") && lower.contains("state") && lower.contains("version") {
            continue;
        }
        if lower.contains("no installed distributions") || lower.starts_with("wsl version") {
            continue;
        }
        let (line, default) = line
            .strip_prefix('*')
            .map_or((line, false), |value| (value.trim_start(), true));
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 {
            return Err(parse_error(
                "WSL list row has fewer than name, state, and version fields",
            ));
        }
        let version_raw = fields[fields.len() - 1];
        let version = version_raw.parse::<u8>().ok();
        if version.is_none() {
            return Err(parse_error("WSL list row has an unknown version field"));
        }
        let state_raw = fields[fields.len() - 2];
        let name = validate_name(&fields[..fields.len() - 2].join(" "))?;
        let state = parse_wsl_state(state_raw);
        let distribution = WslDistribution {
            name: name.clone(),
            wsl_version: version,
            state,
            running: state == WslState::Running,
            default,
            export_eligibility: if version.is_some() {
                WslExportEligibility::ExplicitSelection
            } else {
                WslExportEligibility::Unavailable
            },
            export_eligible: version.is_some(),
            large_data: true,
            export_size_bytes: None,
            export_artifact: None,
            config_artifacts: Vec::new(),
        };
        if let Some(existing) = distributions.get(&name)
            && existing != &distribution
        {
            return Err(parse_error(
                "WSL list repeats a distribution with conflicting metadata",
            ));
        }
        distributions.insert(name, distribution);
        parsed_any = true;
        if distributions.len() > MAX_DISTRIBUTIONS {
            return Err(security_error("WSL list contains too many distributions"));
        }
    }
    if !parsed_any {
        return Err(parse_error(
            "WSL list output did not contain a reviewed distribution table",
        ));
    }
    let mut distributions = distributions.into_values().collect::<Vec<_>>();
    distributions.sort_by(|left, right| {
        right
            .default
            .cmp(&left.default)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(distributions)
}

fn parse_status_output(stdout: &str) -> ProviderResult<WslStatus> {
    if stdout.len() > MAX_TEXT_BYTES {
        return Err(security_error(
            "WSL status output exceeds the reviewed byte bound",
        ));
    }
    let mut status = WslStatus::default();
    for line in normalize_wsl_text(stdout).lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = safe_text(value, MAX_NAME_BYTES);
        let Some(value) = value else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "default distribution" => status.default_distribution = Some(value),
            "default version" => status.default_version = value.parse().ok(),
            "wsl version" => status.wsl_version = Some(value),
            "kernel version" => status.kernel_version = Some(value),
            _ => {}
        }
    }
    Ok(status)
}

fn parse_prerequisites(
    feature_output: Option<&str>,
    warnings: &mut Vec<ErrorEnvelope>,
) -> Vec<WslPrerequisite> {
    const WSL_FEATURE: &str = "Microsoft-Windows-Subsystem-Linux";
    const VM_FEATURE: &str = "VirtualMachinePlatform";
    let observations = match feature_output {
        Some(output) => match parse_feature_output(output) {
            Ok(observations) => observations,
            Err(error) => {
                warnings.push(*error);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let mut by_name = observations
        .into_iter()
        .map(|observation| (observation.name.to_ascii_lowercase(), observation))
        .collect::<BTreeMap<_, _>>();
    [WSL_FEATURE, VM_FEATURE]
        .into_iter()
        .map(|name| {
            let observation = by_name.remove(&name.to_ascii_lowercase());
            let (enabled, restart_required) = match observation {
                Some(observation) => (
                    match observation.state {
                        FeatureState::Enabled => Some(true),
                        FeatureState::Disabled
                        | FeatureState::EnablePending
                        | FeatureState::DisablePending
                        | FeatureState::Staged
                        | FeatureState::Removed => Some(false),
                        FeatureState::Unknown => None,
                    },
                    observation.restart_required,
                ),
                None => (None, false),
            };
            WslPrerequisite {
                name: name.to_owned(),
                enabled,
                restart_required,
                required_for_wsl2: name == VM_FEATURE,
            }
        })
        .collect()
}

fn collect_wslconfig_artifact(
    known_folders: &KnownFolderMap,
) -> (Option<ArtifactRef>, Vec<ErrorEnvelope>) {
    let mut warnings = Vec::new();
    let Ok(token) = WslAdapter::wslconfig_path() else {
        return (
            None,
            vec![warning(
                ReforgeErrorCode::InvalidPath,
                ".wslconfig path token is invalid",
            )],
        );
    };
    let Ok(absolute) = known_folders.resolve(&token) else {
        return (None, warnings);
    };
    let is_file = fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.is_file());
    if !is_file {
        return (None, warnings);
    }
    let collection = crate::collect_artifacts(
        known_folders,
        &[crate::ArtifactRequest::new(
            token,
            ConfigScope::User,
            ArtifactPolicy::Config,
        )],
    );
    match collection {
        Ok(collection) => {
            warnings.extend(collection.warnings);
            (collection.artifacts.into_iter().next(), warnings)
        }
        Err(error) => {
            warnings.push(*error);
            (None, warnings)
        }
    }
}

fn infer_resource(identity: &Identity) -> ProviderResult<WslResource> {
    let Some((provider, package_id)) = &identity.provider_package else {
        return Err(schema_error("WSL identity has no provider package tuple"));
    };
    if provider.as_str() != PROVIDER_ID {
        return Err(schema_error("WSL identity uses a different provider"));
    }
    let source = identity
        .provider_source
        .as_deref()
        .ok_or_else(|| schema_error("WSL identity has no resource kind"))?;
    match source {
        "distribution" => Ok(WslResource::Distribution(WslDistribution {
            name: validate_name(
                package_id
                    .strip_prefix("distribution:")
                    .unwrap_or(package_id),
            )?,
            wsl_version: None,
            state: WslState::Unknown,
            running: false,
            default: false,
            export_eligibility: WslExportEligibility::Unavailable,
            export_eligible: false,
            large_data: true,
            export_size_bytes: None,
            export_artifact: None,
            config_artifacts: Vec::new(),
        })),
        "prerequisite" => Ok(WslResource::Prerequisite(WslPrerequisite {
            name: validate_name(package_id.strip_prefix("feature:").unwrap_or(package_id))?,
            enabled: None,
            restart_required: false,
            required_for_wsl2: package_id.ends_with("VirtualMachinePlatform"),
        })),
        "config" => Err(schema_error(
            "WSL config metadata was not available for inference",
        )),
        _ => Err(schema_error(
            "WSL identity has an unsupported resource kind",
        )),
    }
}

fn distribution_manual_action(distribution: &WslDistribution) -> ManualAction {
    let id = hashed_id("wsl-distribution", &distribution.name);
    ManualAction {
        id,
        component: None,
        title: "Review WSL distribution export".to_owned(),
        reason: "WSL distribution data is a large artifact and requires explicit export selection"
            .to_owned(),
        risk: RiskLevel::High,
        instructions: vec![
            "Review distribution name, WSL version, and running state".to_owned(),
            "Select a documented wsl --export artifact explicitly".to_owned(),
        ],
        docs_url: Url::parse(WSL_DOCS).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

fn config_manual_action(distribution: &str) -> ManualAction {
    ManualAction {
        id: hashed_id("wsl-conf", distribution),
        component: None,
        title: "Review Linux wsl.conf".to_owned(),
        reason: "Linux-side /etc/wsl.conf has no Windows path token and remains manual metadata"
            .to_owned(),
        risk: RiskLevel::Medium,
        instructions: vec![
            format!("Review {WSL_CONF_PATH} inside the target distribution"),
            "Do not infer Linux package or user identity state from this file".to_owned(),
        ],
        docs_url: Url::parse(WSL_CONFIG_DOCS).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

async fn run_wsl_async<const N: usize>(
    runner: &reforge_platform_windows::ProcessRunner,
    cancellation: &CancellationToken,
    args: [&str; N],
) -> ProviderResult<ProcessResult> {
    let command = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::Wsl),
        args.into_iter().map(OsString::from),
        PROCESS_TIMEOUT,
        PROCESS_OUTPUT_BYTES,
    )?;
    let result = runner.run(&command, cancellation).await?;
    validate_process_result(&result, "CLI command")?;
    Ok(result)
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

fn successful_process_with_stdout(stdout: Vec<u8>) -> ProcessResult {
    ProcessResult {
        exit_code: Some(0),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::new(),
        timed_out: false,
        cancelled: false,
    }
}

fn validate_process_result(result: &ProcessResult, operation: &str) -> ProviderResult<()> {
    if result.cancelled {
        return Err(cancelled_error());
    }
    if result.timed_out {
        return Err(operation_error(&format!("WSL {operation} timed out")));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(_) | None => Err(Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::ProviderUnavailable,
                "WSL is unavailable on this Windows target",
            )
            .with_technical_detail(format!("WSL {operation} did not complete successfully")),
        )),
    }
}

fn normalize_wsl_text(text: &str) -> String {
    if !text.as_bytes().contains(&0) {
        return text.trim_start_matches('\u{feff}').to_owned();
    }
    let bytes = text.as_bytes();
    let mut code_units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        code_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&code_units)
        .trim_start_matches('\u{feff}')
        .to_owned()
}

fn parse_wsl_state(value: &str) -> WslState {
    match value.trim().to_ascii_lowercase().as_str() {
        "running" => WslState::Running,
        "stopped" => WslState::Stopped,
        "installing" => WslState::Installing,
        "uninstalling" => WslState::Uninstalling,
        _ => WslState::Unknown,
    }
}

fn validate_name(value: &str) -> ProviderResult<String> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.trim() != value
        || value.starts_with('-')
        || value.chars().any(char::is_control)
    {
        return Err(parse_error(
            "WSL distribution or prerequisite name is invalid",
        ));
    }
    Ok(value.to_owned())
}

fn safe_text(value: &str, max_bytes: usize) -> Option<String> {
    RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
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
    let locator = safe_text(&locator, MAX_NAME_BYTES).unwrap_or_else(|| "wsl:unknown".to_owned());
    let summary = safe_text(&summary, MAX_WARNING_BYTES)
        .unwrap_or_else(|| "WSL evidence was redacted".to_owned());
    let id = EvidenceId::new(format!(
        "wsl-evidence-{}",
        blake3::hash(format!("{locator}|{summary}").as_bytes()).to_hex()
    ))
    .expect("hashed WSL evidence ID");
    Evidence {
        id,
        source: EvidenceSource::Wsl,
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

fn hashed_id(prefix: &str, value: &str) -> String {
    format!("{prefix}-{}", blake3::hash(value.as_bytes()).to_hex())
}

fn warning(code: ReforgeErrorCode, message: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        code,
        safe_text(message, MAX_WARNING_BYTES).unwrap_or_else(|| "WSL warning".to_owned()),
    )
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "WSL provider data is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "WSL output did not match the reviewed shape",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "WSL output exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "WSL discovery could not be completed",
        )
        .with_technical_detail(detail),
    )
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "WSL discovery was cancelled",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wsl_table_and_utf16_console_text() {
        let adapter = WslAdapter::new();
        let output = "  NAME                   STATE           VERSION\n* Ubuntu-22.04           Running         2\n  Debian                 Stopped         1\n";
        let distributions = adapter.parse_list_output(output).expect("WSL list");
        assert_eq!(distributions.len(), 2);
        assert!(distributions[0].default);
        assert!(distributions[0].running);

        let utf16 = output
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(char::from)
            .collect::<String>();
        let parsed = adapter.parse_list_output(&utf16).expect("UTF-16 WSL list");
        assert_eq!(parsed, distributions);
    }

    #[test]
    fn unknown_feature_state_is_not_enabled() {
        let mut warnings = Vec::new();
        let prerequisites = parse_prerequisites(
            Some(
                r#"[{"FeatureName":"Microsoft-Windows-Subsystem-Linux","State":"Future","RestartNeeded":false}]"#,
            ),
            &mut warnings,
        );
        assert_eq!(prerequisites[0].enabled, None);
        assert_eq!(prerequisites[1].enabled, None);
    }

    #[test]
    fn status_parser_keeps_only_bounded_known_fields() {
        let status = parse_status_output(
            "Default Distribution: Ubuntu-22.04\nDefault Version: 2\nKernel version: 5.15\n",
        )
        .expect("status parses");
        assert_eq!(status.default_distribution.as_deref(), Some("Ubuntu-22.04"));
        assert_eq!(status.default_version, Some(2));
    }
    #[test]
    fn rejects_option_like_distribution_names() {
        let adapter = WslAdapter::new();
        let error = adapter
            .parse_list_output("NAME STATE VERSION\n--help Stopped 2\n")
            .expect_err("option-like distribution names must not reach wsl arguments");
        assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
    }
}
