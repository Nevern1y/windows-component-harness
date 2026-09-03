//! Shared discovery adapter boundary and deterministic registry.
pub mod chocolatey;
pub mod docker;
pub mod dotnet;
pub mod go;
pub mod javascript;
pub mod powershell;
pub mod python;
pub mod rust;
pub mod scoop;
pub mod windows_registration;
pub mod winget;
pub mod wsl;
pub use wsl::{
    WslAdapter, WslCaptures, WslConfigArtifact, WslDiscovery, WslDistribution,
    WslExportEligibility, WslPrerequisite, WslState, WslStatus,
};

pub use crate::generic::GenericExecutableAdapter;
pub use chocolatey::ChocolateyAdapter;
pub use docker::{
    DockerAdapter, DockerCaptures, DockerContainer, DockerContext, DockerCredentialHelper,
    DockerDiscovery, DockerImage, DockerVolume,
};
pub use dotnet::DotnetAdapter;
pub use go::GoAdapter;
pub use javascript::{
    JavaScriptAdapter, JavaScriptDependency, JavaScriptPackage, NodePackageManager,
    NodePackageScope,
};
pub use powershell::PowerShellAdapter;
pub use python::PythonAdapter;
pub use rust::RustAdapter;
pub use scoop::ScoopAdapter;
pub use windows_registration::WindowsRegistrationAdapter;
pub use winget::WinGetAdapter;
// Application adapters retain their own typed discovery results while sharing
// this crate's provider-facing module boundary.
pub use crate::browsers::{BrowserAdapter, ChromiumAdapter, FirefoxAdapter};
pub use crate::editors::VSCodeAdapter;

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use reforge_domain::{
    ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, Confidence, DependencyEdge,
    DependencyKind, ErrorEnvelope, Evidence, EvidenceId, EvidenceRef, EvidenceSource, HostFacts,
    Identity, IdentityQuality, ManualAction, ManualActionState, Operation, OperationId,
    OperationKind, PackageInstallPolicy, PackageSpec, PathToken, Portability, Precondition,
    Provenance, ProviderId, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel, RunId,
    RuntimeSpec, ScanPhase, SelectionMetadata, TargetFacts, VerificationRule, VersionValue,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap, ProcessRunner};
const MAX_REGISTERED_ADAPTERS: usize = 256;

pub struct ProviderContext<'a> {
    pub host: &'a HostFacts,
    pub known_folders: &'a KnownFolderMap,
    pub runner: &'a ProcessRunner,
    pub cancellation: &'a CancellationToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectionResult {
    pub available: bool,
    pub version: Option<VersionValue>,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

impl DetectionResult {
    pub fn unavailable() -> Self {
        Self {
            available: false,
            version: None,
            evidence: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observation {
    Package {
        spec: PackageSpec,
        version: Option<VersionValue>,
        evidence: Vec<Evidence>,
    },
    Executable {
        path: PathToken,
        identity: Identity,
        version: Option<VersionValue>,
        evidence: Vec<Evidence>,
    },
    Runtime {
        spec: RuntimeSpec,
        evidence: Vec<Evidence>,
    },
    Artifact {
        artifact: ArtifactRef,
        evidence: Vec<Evidence>,
    },
    Registration {
        kind: ComponentKind,
        identity: Identity,
        evidence: Vec<Evidence>,
    },
    /// A domain adapter can return a complete graph when its normalization
    /// requires more context than the provider observation variants expose.
    /// The coordinator still validates and deduplicates every component.
    Components {
        components: Vec<Component>,
        edges: Vec<DependencyEdge>,
        evidence: Vec<Evidence>,
    },
}

impl Observation {
    pub fn evidence(&self) -> &[Evidence] {
        match self {
            Self::Package { evidence, .. }
            | Self::Executable { evidence, .. }
            | Self::Runtime { evidence, .. }
            | Self::Artifact { evidence, .. }
            | Self::Registration { evidence, .. }
            | Self::Components { evidence, .. } => evidence,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEnumeration {
    pub observations: Vec<Observation>,
    pub warnings: Vec<String>,
}

impl ProviderEnumeration {
    pub fn empty() -> Self {
        Self {
            observations: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

pub type ProviderResult<T> = Result<T, Box<ErrorEnvelope>>;

#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn id(&self) -> ProviderId;

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult;

    async fn enumerate(&self, context: &ProviderContext<'_>)
    -> ProviderResult<ProviderEnumeration>;

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>>;

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &reforge_domain::RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>>;

    fn verify(
        &self,
        component: &Component,
        target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>>;
}

pub struct AdapterRegistry {
    entries: Vec<AdapterRegistration>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        phase: ScanPhase,
        adapter: Arc<dyn ProviderAdapter>,
    ) -> ProviderResult<()> {
        if self.entries.len() >= MAX_REGISTERED_ADAPTERS {
            return Err(registry_error(
                "discovery adapter registry exceeds the reviewed bound",
            ));
        }
        let id = adapter.id();
        if self.entries.iter().any(|entry| entry.id == id) {
            return Err(registry_error("discovery adapter ID is already registered"));
        }
        self.entries
            .push(AdapterRegistration { phase, id, adapter });
        self.entries.sort_by(|left, right| {
            phase_index(&left.phase)
                .cmp(&phase_index(&right.phase))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn for_phase(
        &self,
        phase: &ScanPhase,
    ) -> impl Iterator<Item = &AdapterRegistration> {
        self.entries
            .iter()
            .filter(move |entry| &entry.phase == phase)
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct AdapterRegistration {
    phase: ScanPhase,
    id: ProviderId,
    adapter: Arc<dyn ProviderAdapter>,
}

impl AdapterRegistration {
    pub(crate) fn id(&self) -> &ProviderId {
        &self.id
    }

    pub(crate) fn adapter(&self) -> &dyn ProviderAdapter {
        self.adapter.as_ref()
    }
}

pub(crate) fn phase_index(phase: &ScanPhase) -> u8 {
    match phase {
        ScanPhase::HostPreflight => 0,
        ScanPhase::PackageExports => 1,
        ScanPhase::WindowsRegistration => 2,
        ScanPhase::RuntimeProbes => 3,
        ScanPhase::KnownFolderConfig => 4,
        ScanPhase::AppAdapters => 5,
        ScanPhase::GenericExecutables => 6,
        ScanPhase::Correlation => 7,
    }
}

fn registry_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "The discovery adapter registry is invalid",
        )
        .with_technical_detail(detail),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeSourceKind {
    Registry,
    Git,
    Path,
    Editable,
    Unknown,
}

pub(crate) fn normalize_runtime_observation(
    observation: Observation,
    provider: &ProviderId,
    adapter_id: &str,
    runtime_id: &str,
    force_manual_packages: bool,
) -> ProviderResult<Vec<Component>> {
    match observation {
        Observation::Runtime { spec, evidence } => {
            validate_runtime_spec(&spec, runtime_id)?;
            if evidence.is_empty() {
                return Err(runtime_schema_error(
                    provider,
                    "runtime observation has no supporting evidence",
                ));
            }
            let identity = runtime_identity(provider, runtime_id, "runtime");
            let canonical = ComponentId::from_identity(&identity, None)
                .map_err(|_| runtime_schema_error(provider, "runtime identity is not canonical"))?;
            let mut extensions = BTreeMap::new();
            extensions.insert("runtime_id".to_owned(), serde_json::json!(runtime_id));
            extensions.insert("provider".to_owned(), serde_json::json!(adapter_id));
            for record in &evidence {
                for field in record.locator.split('|') {
                    if let Some(abi) = field.strip_prefix("abi=")
                        && runtime_valid_text(abi, 128)
                    {
                        extensions.insert("abi".to_owned(), serde_json::json!(abi));
                    }
                }
            }
            let version = runtime_version_value(spec.version.as_deref());
            Ok(vec![Component {
                id: canonical.id,
                kind: ComponentKind::Runtime,
                identity,
                display_name: runtime_id.to_owned(),
                version,
                architecture: spec.architecture.clone(),
                publisher: None,
                provenance: Some(Provenance {
                    provider: Some(provider.clone()),
                    package_id: Some(runtime_id.to_owned()),
                    source_url: None,
                    observed_version: spec.version.clone(),
                    adapter_id: adapter_id.to_owned(),
                    adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                }),
                evidence: runtime_evidence_refs(&evidence),
                confidence: runtime_confidence(&evidence),
                dependencies: Vec::new(),
                artifacts: Vec::new(),
                restore: RestoreDescriptor {
                    primary: RestoreStrategy::Reinstall,
                    alternatives: vec![RestoreStrategy::Manual],
                    portability: Portability::PartiallyPortable,
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale: vec![
                        "The runtime was observed locally; installing it on another host requires target compatibility review"
                            .to_owned(),
                    ],
                },
                compatibility: Compatibility {
                    required_os: Some("Windows".to_owned()),
                    required_architecture: spec.architecture,
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
                extensions,
            }])
        }
        Observation::Package {
            spec,
            version,
            evidence,
        } => {
            validate_runtime_package_spec(&spec, provider)?;
            if evidence.is_empty() {
                return Err(runtime_schema_error(
                    provider,
                    "package observation has no supporting evidence",
                ));
            }
            if spec.version.as_deref() != version.as_ref().map(|value| value.raw.as_str()) {
                return Err(runtime_schema_error(
                    provider,
                    "package and observation versions disagree",
                ));
            }
            let source_kind = runtime_source_kind(&spec);
            let automatic = !force_manual_packages
                && spec.version.is_some()
                && source_kind == RuntimeSourceKind::Registry
                && (spec.source.is_some() || spec.source_identifier.is_some());
            let source_identity = runtime_package_source_identity(&spec);
            let identity = runtime_identity(provider, &spec.id, &source_identity);
            let canonical = ComponentId::from_identity(&identity, None)
                .map_err(|_| runtime_schema_error(provider, "package identity is not canonical"))?;
            let runtime = runtime_component_id(provider, runtime_id)?;
            let evidence_ids = runtime_evidence_refs(&evidence)
                .into_iter()
                .map(|record| record.id)
                .collect();
            let dependency = DependencyEdge {
                from: canonical.id.clone(),
                to: runtime,
                kind: DependencyKind::RequiredRuntime,
                required: true,
                evidence: evidence_ids,
                confidence: runtime_confidence(&evidence),
            };
            let source_label = runtime_source_label(source_kind);
            let mut rationale = vec![format!(
                "{} recorded package {} with {} source evidence",
                adapter_id, spec.id, source_label
            )];
            if !automatic {
                rationale.push(
                    "Automatic restore is disabled without an exact reviewed registry source"
                        .to_owned(),
                );
            }
            if force_manual_packages {
                rationale.push(
                    "Module installation is an executable supply-chain action and remains manual"
                        .to_owned(),
                );
            }
            let mut extensions = BTreeMap::new();
            extensions.insert("source_kind".to_owned(), serde_json::json!(source_label));
            extensions.insert("runtime_id".to_owned(), serde_json::json!(runtime_id));
            Ok(vec![Component {
                id: canonical.id,
                kind: ComponentKind::Package,
                identity,
                display_name: spec.id.clone(),
                version,
                architecture: spec.architecture.clone(),
                publisher: None,
                provenance: Some(Provenance {
                    provider: Some(provider.clone()),
                    package_id: Some(spec.id.clone()),
                    source_url: spec.source.clone(),
                    observed_version: spec.version.clone(),
                    adapter_id: adapter_id.to_owned(),
                    adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                }),
                evidence: runtime_evidence_refs(&evidence),
                confidence: runtime_confidence(&evidence),
                dependencies: vec![dependency],
                artifacts: Vec::new(),
                restore: RestoreDescriptor {
                    primary: if automatic {
                        RestoreStrategy::Reinstall
                    } else {
                        RestoreStrategy::Manual
                    },
                    alternatives: if automatic {
                        vec![RestoreStrategy::Manual]
                    } else {
                        vec![RestoreStrategy::Reinstall]
                    },
                    portability: if automatic {
                        Portability::SupportedExport
                    } else {
                        Portability::PartiallyPortable
                    },
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale,
                },
                compatibility: Compatibility {
                    required_os: Some("Windows".to_owned()),
                    required_architecture: spec.architecture.clone(),
                    requires_provider: Some(provider.clone()),
                    requires_runtime: Some(runtime_component_id(provider, runtime_id)?),
                    requires_elevation: false,
                    requires_wsl: false,
                    requires_docker: false,
                },
                verification: vec![VerificationRule::ProviderIdentity {
                    provider: provider.clone(),
                    package: spec,
                }],
                selection: SelectionMetadata {
                    recommended: false,
                    score: 0,
                    selected_by_default: false,
                    sensitive: false,
                    size_bytes: 0,
                },
                extensions,
            }])
        }
        _ => Err(runtime_schema_error(
            provider,
            "runtime adapter received an observation owned by another adapter",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
// The planner keeps component, target, run, provider, runtime, and policy inputs explicit.
pub(crate) fn plan_runtime_install(
    component: &Component,
    target: &TargetFacts,
    run_id: &RunId,
    first_ordinal: u64,
    provider: &ProviderId,
    adapter_id: &str,
    runtime_id: &str,
    force_manual_packages: bool,
) -> ProviderResult<Vec<Operation>> {
    validate_runtime_component_owner(component, adapter_id, provider)?;
    let provider_available = target
        .providers
        .iter()
        .any(|record| record.id == *provider && record.available);
    if component.kind == ComponentKind::Runtime {
        let runtime = runtime_spec_from_component(component, runtime_id)?;
        if !provider_available {
            return Ok(vec![runtime_manual_operation(
                component,
                None,
                format!("Review {adapter_id} runtime restore"),
                "The recorded runtime provider is unavailable on the target",
                run_id,
                first_ordinal,
                adapter_id,
            )?]);
        }
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| runtime_schema_error(provider, "runtime operation ID is invalid"))?;
        let idempotency_key = runtime_operation_key("ensure", provider, &runtime);
        return Ok(vec![Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::EnsureRuntime { runtime },
            prerequisites: Vec::new(),
            precondition: Precondition::ComponentAbsent {
                component: component.id.clone(),
            },
            idempotency_key,
            verification: Vec::new(),
            requires_elevation: false,
            non_idempotent: false,
        }]);
    }

    if component.kind != ComponentKind::Package {
        return Err(runtime_schema_error(
            provider,
            "runtime provider plan received a non-runtime component",
        ));
    }
    let package = runtime_package_from_component(component, provider, adapter_id)?.clone();
    let verification = VerificationRule::ProviderIdentity {
        provider: provider.clone(),
        package: package.clone(),
    };
    let source_kind = runtime_source_kind(&package);
    if !provider_available {
        return Ok(vec![runtime_manual_operation(
            component,
            Some(verification),
            format!("Review {adapter_id} package restore"),
            "The recorded runtime provider is unavailable on the target",
            run_id,
            first_ordinal,
            adapter_id,
        )?]);
    }
    if force_manual_packages
        || package.version.is_none()
        || source_kind != RuntimeSourceKind::Registry
    {
        return Ok(vec![runtime_manual_operation(
            component,
            Some(verification),
            format!("Review {adapter_id} package restore"),
            "The package source is unknown, non-registry, or requires a manual supply-chain review",
            run_id,
            first_ordinal,
            adapter_id,
        )?]);
    }
    let operation_id = OperationId::for_run(run_id, first_ordinal)
        .map_err(|_| runtime_schema_error(provider, "package operation ID is invalid"))?;
    let idempotency_key = runtime_operation_key("install", provider, &package);
    Ok(vec![Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::InstallPackage {
            provider: provider.clone(),
            package,
            policy: PackageInstallPolicy {
                accept_source_agreements: false,
                accept_package_agreements: false,
                silent: false,
                allow_reboot: false,
            },
        },
        prerequisites: Vec::new(),
        precondition: Precondition::ComponentAbsent {
            component: component.id.clone(),
        },
        idempotency_key,
        verification: vec![verification],
        requires_elevation: false,
        non_idempotent: false,
    }])
}

pub(crate) fn verify_runtime_component(
    component: &Component,
    target: &TargetFacts,
    provider: &ProviderId,
    adapter_id: &str,
) -> ProviderResult<Vec<VerificationRule>> {
    let _ = target;
    validate_runtime_component_owner(component, adapter_id, provider)?;
    if component.kind == ComponentKind::Runtime {
        return Ok(Vec::new());
    }
    let package = runtime_package_from_component(component, provider, adapter_id)?;
    Ok(vec![VerificationRule::ProviderIdentity {
        provider: provider.clone(),
        package: package.clone(),
    }])
}

pub(crate) fn runtime_process_result(
    process: &reforge_platform_windows::ProcessResult,
    provider: &ProviderId,
    operation: &str,
) -> ProviderResult<()> {
    if process.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            format!("{operation} was cancelled"),
        )));
    }
    if process.timed_out {
        return Err(runtime_operation_error(
            provider,
            &format!("{operation} timed out"),
        ));
    }
    if process.exit_code != Some(0) {
        return Err(runtime_operation_error(
            provider,
            &format!("{operation} failed"),
        ));
    }
    Ok(())
}

pub(crate) fn runtime_output_text<'a>(
    output: &'a [u8],
    max_bytes: usize,
    provider: &ProviderId,
    operation: &str,
) -> ProviderResult<&'a str> {
    if output.len() > max_bytes {
        return Err(runtime_security_error(
            provider,
            &format!("{operation} output exceeds the reviewed byte limit"),
        ));
    }
    std::str::from_utf8(output)
        .map_err(|_| runtime_parse_error(provider, &format!("{operation} output is not UTF-8")))
}

pub(crate) fn runtime_make_evidence(
    source: EvidenceSource,
    locator: impl Into<String>,
    summary: &str,
    strength: u8,
    independent_group: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Evidence {
    let summary = if runtime_valid_text(summary, 512) {
        summary.to_owned()
    } else {
        "Runtime provider evidence was redacted".to_owned()
    };
    let locator = locator.into();
    let id = runtime_evidence_id(&source, &locator, &summary);
    Evidence {
        id,
        source,
        locator,
        observed_at,
        summary,
        strength,
        independent_group: independent_group.to_owned(),
    }
}

pub(crate) fn runtime_warning(warnings: &mut Vec<String>, warning: impl Into<String>) {
    let warning = warning.into();
    let warning = if runtime_valid_text(&warning, 512) {
        warning
    } else {
        "Runtime provider warning was redacted".to_owned()
    };
    warnings.push(warning);
    warnings.sort();
    warnings.dedup();
    warnings.truncate(4_096);
}

fn validate_runtime_spec(spec: &RuntimeSpec, expected_id: &str) -> ProviderResult<()> {
    if spec.id != expected_id {
        return Err(runtime_schema_error(
            &ProviderId::new(expected_id).expect("validated runtime provider ID"),
            "runtime observation uses an unexpected runtime ID",
        ));
    }
    if !runtime_valid_text(&spec.id, 128) {
        return Err(runtime_parse_error(
            &ProviderId::new(expected_id).expect("validated runtime provider ID"),
            "runtime ID is outside the reviewed grammar",
        ));
    }
    if let Some(version) = &spec.version
        && !runtime_valid_text(version, 256)
    {
        return Err(runtime_parse_error(
            &ProviderId::new(expected_id).expect("validated runtime provider ID"),
            "runtime version is outside the reviewed grammar",
        ));
    }
    Ok(())
}

fn validate_runtime_package_spec(spec: &PackageSpec, provider: &ProviderId) -> ProviderResult<()> {
    if spec.provider != *provider {
        return Err(runtime_schema_error(
            provider,
            "package observation uses a different provider ID",
        ));
    }
    if !runtime_valid_package_id(&spec.id) {
        return Err(runtime_parse_error(
            provider,
            "package ID is outside the reviewed grammar",
        ));
    }
    if let Some(version) = &spec.version
        && !runtime_valid_text(version, 256)
    {
        return Err(runtime_parse_error(
            provider,
            "package version is outside the reviewed grammar",
        ));
    }
    for value in [&spec.source_name, &spec.source_identifier] {
        if let Some(value) = value
            && !runtime_valid_text(value, 512)
        {
            return Err(runtime_parse_error(
                provider,
                "package source metadata is outside the reviewed grammar",
            ));
        }
    }
    if let Some(identifier) = &spec.source_identifier
        && !runtime_safe_source_identifier(identifier)
    {
        return Err(runtime_security_error(
            provider,
            "package source identifier contains a local path",
        ));
    }
    if let Some(source) = &spec.source
        && !(matches!(source.scheme(), "http" | "https")
            && source.username().is_empty()
            && source.password().is_none()
            && source.query().is_none()
            && source.fragment().is_none())
    {
        return Err(runtime_security_error(
            provider,
            "package source URL is not a public credential-free HTTP(S) URL",
        ));
    }
    Ok(())
}

fn runtime_valid_package_id(value: &str) -> bool {
    runtime_valid_text(value, 512) && value != "." && value != ".." && !value.contains(['\\', '\0'])
}
pub(crate) fn runtime_safe_source_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !value.starts_with('/')
        && !value.starts_with('\\')
        && !(bytes.len() >= 2 && bytes[1] == b':')
        && !value
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file:"))
}

fn runtime_valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.contains('\0')
}

fn runtime_source_kind(spec: &PackageSpec) -> RuntimeSourceKind {
    let Some(name) = spec.source_name.as_deref() else {
        return RuntimeSourceKind::Unknown;
    };
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "registry" | "pypi" | "crates.io" | "nuget" | "powershell-gallery" | "go-proxy"
    ) {
        RuntimeSourceKind::Registry
    } else if name == "git" || name.contains("git") {
        RuntimeSourceKind::Git
    } else if name == "editable" {
        RuntimeSourceKind::Editable
    } else if name == "path" {
        RuntimeSourceKind::Path
    } else {
        RuntimeSourceKind::Unknown
    }
}

fn runtime_source_label(source: RuntimeSourceKind) -> &'static str {
    match source {
        RuntimeSourceKind::Registry => "registry",
        RuntimeSourceKind::Git => "git",
        RuntimeSourceKind::Path => "path",
        RuntimeSourceKind::Editable => "editable",
        RuntimeSourceKind::Unknown => "unknown",
    }
}

fn runtime_package_source_identity(spec: &PackageSpec) -> String {
    if let Some(identifier) = &spec.source_identifier {
        return format!("identifier:{identifier}");
    }
    if let Some(source) = &spec.source {
        return format!("url:{source}");
    }
    if let Some(source_name) = &spec.source_name {
        return format!("kind:{source_name}");
    }
    "unknown".to_owned()
}

fn runtime_identity(provider: &ProviderId, id: &str, source: &str) -> Identity {
    Identity {
        provider_package: Some((provider.clone(), id.to_owned())),
        provider_source: Some(source.to_owned()),
        package_family: None,
        product_name: None,
        executable_name: None,
        publisher: None,
        executable_hash: None,
        install_role: None,
        identity_quality: IdentityQuality::Provider,
    }
}

pub(crate) fn runtime_component_id(
    provider: &ProviderId,
    runtime_id: &str,
) -> ProviderResult<ComponentId> {
    ComponentId::from_identity(&runtime_identity(provider, runtime_id, "runtime"), None)
        .map(|canonical| canonical.id)
        .map_err(|_| runtime_schema_error(provider, "runtime identity is not canonical"))
}

fn runtime_version_value(version: Option<&str>) -> Option<VersionValue> {
    version.map(|raw| VersionValue {
        raw: raw.to_owned(),
        normalized: None,
    })
}

fn runtime_evidence_refs(evidence: &[Evidence]) -> Vec<EvidenceRef> {
    let mut refs: Vec<_> = evidence
        .iter()
        .map(|record| EvidenceRef {
            id: record.id.clone(),
            strength: record.strength,
        })
        .collect();
    refs.sort_by(|left, right| left.id.cmp(&right.id));
    refs.dedup_by(|left, right| left.id == right.id);
    refs
}

fn runtime_confidence(evidence: &[Evidence]) -> Confidence {
    let score = evidence
        .iter()
        .fold(0u16, |sum, record| {
            sum.saturating_add(u16::from(record.strength))
        })
        .min(100);
    match score {
        90..=100 => Confidence::Confirmed,
        70..=89 => Confidence::High,
        45..=69 => Confidence::Medium,
        1..=44 => Confidence::Low,
        _ => Confidence::Unknown,
    }
}

fn validate_runtime_component_owner(
    component: &Component,
    adapter_id: &str,
    provider: &ProviderId,
) -> ProviderResult<()> {
    if component
        .provenance
        .as_ref()
        .is_none_or(|provenance| provenance.adapter_id != adapter_id)
        || component
            .identity
            .provider_package
            .as_ref()
            .is_none_or(|(owner, _)| owner != provider)
    {
        return Err(runtime_schema_error(
            provider,
            "component belongs to another runtime adapter",
        ));
    }
    Ok(())
}

fn runtime_package_from_component<'a>(
    component: &'a Component,
    provider: &ProviderId,
    adapter_id: &str,
) -> ProviderResult<&'a PackageSpec> {
    if component.kind != ComponentKind::Package {
        return Err(runtime_schema_error(
            provider,
            "component is not a runtime package",
        ));
    }
    let mut packages = component.verification.iter().filter_map(|rule| match rule {
        VerificationRule::ProviderIdentity {
            provider: rule_provider,
            package,
        } if rule_provider == provider => Some(package),
        _ => None,
    });
    let package = packages.next().ok_or_else(|| {
        runtime_schema_error(provider, "component has no provider package identity")
    })?;
    if packages.next().is_some() {
        return Err(runtime_schema_error(
            provider,
            "component has multiple provider package identities",
        ));
    }
    if component
        .provenance
        .as_ref()
        .is_none_or(|provenance| provenance.adapter_id != adapter_id)
    {
        return Err(runtime_schema_error(
            provider,
            "component package provenance belongs to another adapter",
        ));
    }
    validate_runtime_package_spec(package, provider)?;
    Ok(package)
}

fn runtime_spec_from_component(
    component: &Component,
    runtime_id: &str,
) -> ProviderResult<RuntimeSpec> {
    let spec = RuntimeSpec {
        id: runtime_id.to_owned(),
        version: component.version.as_ref().map(|value| value.raw.clone()),
        architecture: component.architecture.clone(),
    };
    validate_runtime_spec(&spec, runtime_id)?;
    Ok(spec)
}

fn runtime_manual_operation(
    component: &Component,
    verification: Option<VerificationRule>,
    title: String,
    reason: &str,
    run_id: &RunId,
    ordinal: u64,
    adapter_id: &str,
) -> ProviderResult<Operation> {
    let verification_for_action = verification.clone();
    let idempotency_key = runtime_component_operation_key("manual", component, adapter_id);
    let operation_id = OperationId::for_run(run_id, ordinal).map_err(|_| {
        runtime_schema_error(
            &ProviderId::new(adapter_id).expect("adapter ID"),
            "manual operation ID is invalid",
        )
    })?;
    Ok(Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::OpenManualAction {
            action: ManualAction {
                id: idempotency_key.clone(),
                component: Some(component.id.clone()),
                title,
                reason: reason.to_owned(),
                risk: RiskLevel::High,
                instructions: vec![
                    "Confirm the runtime or package source and target compatibility before restore"
                        .to_owned(),
                    "Do not execute unreviewed module, script, git, or path installation content"
                        .to_owned(),
                ],
                docs_url: None,
                state: ManualActionState::Pending,
                independent_operations_may_continue: true,
                acknowledged_at: None,
                verification: verification_for_action,
            },
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key,
        verification: verification.into_iter().collect(),
        requires_elevation: false,
        non_idempotent: false,
    })
}

fn runtime_operation_key(role: &str, provider: &ProviderId, spec: &impl std::fmt::Debug) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_runtime_field(&mut hasher, provider.as_str());
    hash_runtime_field(&mut hasher, role);
    hash_runtime_field(&mut hasher, &format!("{spec:?}"));
    format!("runtime-{role}-{}", hasher.finalize().to_hex())
}

fn runtime_component_operation_key(role: &str, component: &Component, adapter_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_runtime_field(&mut hasher, adapter_id);
    hash_runtime_field(&mut hasher, role);
    hash_runtime_field(&mut hasher, component.id.as_str());
    format!("{adapter_id}-{role}-{}", hasher.finalize().to_hex())
}

fn hash_runtime_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn runtime_evidence_id(source: &EvidenceSource, locator: &str, summary: &str) -> EvidenceId {
    let mut hasher = blake3::Hasher::new();
    hash_runtime_field(&mut hasher, &format!("{source:?}"));
    hash_runtime_field(&mut hasher, locator);
    hash_runtime_field(&mut hasher, summary);
    EvidenceId::new(format!("runtime-evidence-{}", hasher.finalize().to_hex()))
        .expect("hashed runtime evidence ID")
}

fn runtime_schema_error(provider: &ProviderId, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            format!("The {provider} runtime adapter received invalid data"),
        )
        .with_technical_detail(detail),
    )
}

fn runtime_parse_error(provider: &ProviderId, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            format!("The {provider} runtime provider output could not be parsed"),
        )
        .with_technical_detail(detail),
    )
}

fn runtime_security_error(provider: &ProviderId, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            format!("The {provider} runtime provider output violated a safety policy"),
        )
        .with_technical_detail(detail),
    )
}

fn runtime_operation_error(provider: &ProviderId, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            format!("The {provider} runtime provider operation failed"),
        )
        .with_technical_detail(detail),
    )
}
