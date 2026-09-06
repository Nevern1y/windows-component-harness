//! AI development harness discovery modules.
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
};

use async_trait::async_trait;
use chrono::Utc;
use reforge_domain::{
    ArtifactId, Component, ComponentKind, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceSource, ManualAction, ManualActionState, Operation, OperationId,
    OperationKind, Precondition, ProviderId, ReforgeErrorCode, RiskLevel, RunId, TargetFacts,
    VerificationRule,
};
use reforge_platform_windows::KnownFolderMap;

use crate::providers::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

// The registry bridge below keeps the domain-specific adapters on the shared
// coordinator boundary.

pub mod agent_catalog;
pub mod agent_runtimes;
pub mod claude;
pub mod codex;
pub mod mcp;
pub mod opencode;

pub use agent_catalog::{AgentCatalogAdapter, AgentCatalogEntry, SCREENSHOT_AGENT_CATALOG};
pub use agent_runtimes::{AgentRuntimeAdapter, AgentRuntimeKind};
pub use claude::{
    ClaudeAgent, ClaudeCodeAdapter, ClaudeCommand, ClaudeDiscovery, ClaudeDiscoveryOptions,
    ClaudeHook, ClaudeInstruction, ClaudePlugin, ClaudeSettingsRecord, ClaudeSkill,
    ClaudeTrustScope,
};
pub use codex::{
    CodexAdapter, CodexAgent, CodexAuthMode, CodexAuthReference, CodexConfigRecord, CodexDiscovery,
    CodexDiscoveryOptions, CodexHook, CodexInstruction, CodexProfile, CodexSkill, CodexTrustScope,
};
pub use mcp::{
    McpInputFormat, McpManualReview, McpNormalization, McpParser, McpParserOptions,
    McpReferenceCatalog, McpSecretReference, normalize_mcp_config, parse_mcp_config,
};
pub use opencode::{
    OpenCodeAdapter, OpenCodeAgent, OpenCodeCommand, OpenCodeConfigOwner, OpenCodeConfigRecord,
    OpenCodeConfigSource, OpenCodeDiscovery, OpenCodeDiscoveryOptions, OpenCodeInstruction,
    OpenCodePlugin, OpenCodeTrustScope,
};

/// The harnesses whose documented discovery implementations are registered
/// with the shared coordinator.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HarnessKind {
    Codex,
    ClaudeCode,
    OpenCode,
}

impl HarnessKind {
    pub const ALL: [Self; 3] = [Self::Codex, Self::ClaudeCode, Self::OpenCode];

    fn registry_id(self) -> ProviderId {
        let value = match self {
            Self::Codex => "harness-codex",
            Self::ClaudeCode => "harness-claude-code",
            Self::OpenCode => "harness-opencode",
        };
        ProviderId::new(value).expect("constant harness provider ID")
    }

    fn adapter_id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::OpenCode => "opencode",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::OpenCode => "OpenCode",
        }
    }

    fn evidence_id(self) -> &'static str {
        match self {
            Self::Codex => "harness-codex-registry",
            Self::ClaudeCode => "harness-claude-code-registry",
            Self::OpenCode => "harness-opencode-registry",
        }
    }
}

/// Provider-registry bridge for the domain-specific harness adapters.
///
/// The child adapters already perform parsing, redaction, trust classification,
/// and artifact collection. This bridge keeps those results intact while
/// allowing the coordinator to apply its normal evidence and graph bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarnessRegistryAdapter {
    kind: HarnessKind,
}

impl HarnessRegistryAdapter {
    pub const fn new(kind: HarnessKind) -> Self {
        Self { kind }
    }

    pub const fn codex() -> Self {
        Self::new(HarnessKind::Codex)
    }

    pub const fn claude_code() -> Self {
        Self::new(HarnessKind::ClaudeCode)
    }

    pub const fn opencode() -> Self {
        Self::new(HarnessKind::OpenCode)
    }

    pub const fn kind(self) -> HarnessKind {
        self.kind
    }
}

impl Default for HarnessRegistryAdapter {
    fn default() -> Self {
        Self::codex()
    }
}

#[async_trait]
impl ProviderAdapter for HarnessRegistryAdapter {
    fn id(&self) -> ProviderId {
        self.kind.registry_id()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        DetectionResult {
            // Discovery is useful when the harness executable is absent: the
            // documented configuration can still be restored after install.
            available: !context.known_folders.entries.is_empty(),
            version: None,
            evidence: vec![Evidence {
                id: EvidenceId::new(self.kind.evidence_id()).expect("constant harness evidence ID"),
                source: EvidenceSource::Harness,
                locator: format!("registry:{}", self.kind.adapter_id()),
                observed_at: Utc::now(),
                summary: format!(
                    "{} discovery is enabled for documented tokenized configuration roots",
                    self.kind.display_name()
                ),
                strength: 20,
                independent_group: "harness-registry".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        if context.cancellation.is_cancelled() {
            return Err(harness_cancelled_error());
        }

        let project_roots = current_project_roots(context.known_folders);
        let references = McpReferenceCatalog::default();
        let enumeration = match self.kind {
            HarnessKind::Codex => {
                let discovery = CodexAdapter::new().discover_with_options(
                    context.known_folders,
                    &CodexDiscoveryOptions::current(project_roots, references),
                )?;
                complete_harness_enumeration(
                    discovery.components,
                    discovery.edges,
                    discovery.evidence,
                    discovery.warnings,
                )
            }
            HarnessKind::ClaudeCode => {
                let discovery = ClaudeCodeAdapter::new().discover_with_options(
                    context.known_folders,
                    &ClaudeDiscoveryOptions::current(project_roots, references),
                )?;
                complete_harness_enumeration(
                    discovery.components,
                    discovery.edges,
                    discovery.evidence,
                    discovery.warnings,
                )
            }
            HarnessKind::OpenCode => {
                let discovery = OpenCodeAdapter::new().discover_with_options(
                    context.known_folders,
                    &OpenCodeDiscoveryOptions::current(project_roots, references),
                )?;
                complete_harness_enumeration(
                    discovery.components,
                    discovery.edges,
                    discovery.evidence,
                    discovery.warnings,
                )
            }
        };

        if context.cancellation.is_cancelled() {
            return Err(harness_cancelled_error());
        }
        Ok(enumeration)
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Components {
            mut components,
            edges,
            evidence: _evidence,
        } = observation
        else {
            return Err(harness_schema_error(
                "harness registry adapter received a non-graph observation",
            ));
        };

        if components.is_empty() {
            return Err(harness_schema_error(
                "harness graph observation contains no components",
            ));
        }
        for component in &components {
            let owned = component
                .provenance
                .as_ref()
                .is_some_and(|provenance| provenance.adapter_id == self.kind.adapter_id());
            if !owned {
                return Err(harness_schema_error(
                    "harness graph contains a component owned by another adapter",
                ));
            }
        }
        for edge in edges {
            let Some(component) = components
                .iter_mut()
                .find(|component| component.id == edge.from)
            else {
                return Err(harness_schema_error(
                    "harness graph edge refers to a missing source component",
                ));
            };
            if !component.dependencies.contains(&edge) {
                component.dependencies.push(edge);
            }
        }
        normalize_shared_artifact_ownership(&mut components);
        Ok(components)
    }

    fn plan_install(
        &self,
        component: &Component,
        _target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        self.ensure_owned(component)?;
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| harness_schema_error("harness operation ID could not be constructed"))?;
        let idempotency_key = manual_operation_key(self.kind, component);
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: format!("Review {} restore", self.kind.display_name()),
            reason: format!(
                "{} configuration and extension state requires explicit review; discovered commands are never executed",
                self.kind.display_name()
            ),
            risk: if component.kind == reforge_domain::ComponentKind::SecretReference {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            },
            instructions: vec![
                "Review the selected harness configuration and trust scope".to_owned(),
                "Sign in again through the harness after restore when authentication is required"
                    .to_owned(),
                "Do not execute hook, plugin, skill, agent, or MCP command metadata".to_owned(),
            ],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: None,
        };
        Ok(vec![Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::OpenManualAction { action },
            prerequisites: Vec::new(),
            precondition: Precondition::ComponentAbsent {
                component: component.id.clone(),
            },
            idempotency_key,
            verification: component.verification.clone(),
            requires_elevation: component.restore.requires_elevation,
            non_idempotent: false,
        }])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        self.ensure_owned(component)?;
        Ok(component.verification.clone())
    }
}
fn normalize_shared_artifact_ownership(components: &mut [Component]) {
    let mut owners = BTreeMap::<ArtifactId, usize>::new();
    for (index, component) in components.iter().enumerate() {
        for artifact in &component.artifacts {
            let should_replace = match owners.get(&artifact.id) {
                None => true,
                Some(current) => {
                    let current_component = &components[*current];
                    (artifact_owner_rank(&component.kind), component.id.as_str())
                        < (
                            artifact_owner_rank(&current_component.kind),
                            current_component.id.as_str(),
                        )
                }
            };
            if should_replace {
                owners.insert(artifact.id.clone(), index);
            }
        }
    }

    for index in 0..components.len() {
        let original = std::mem::take(&mut components[index].artifacts);
        let mut retained = Vec::with_capacity(original.len());
        let mut retained_ids = BTreeSet::new();
        for artifact in original {
            let owner = *owners
                .get(&artifact.id)
                .expect("every harness artifact has an owner");
            if owner == index {
                if retained_ids.insert(artifact.id.clone()) {
                    retained.push(artifact);
                }
                continue;
            }

            let owner_id = components[owner].id.clone();
            let from_id = components[index].id.clone();
            let already_linked = components[index].dependencies.iter().any(|edge| {
                edge.from == from_id
                    && edge.to == owner_id
                    && edge.kind == DependencyKind::Configures
                    && edge.required
            });
            if !already_linked {
                let evidence = components[index]
                    .evidence
                    .first()
                    .map(|reference| reference.id.clone())
                    .into_iter()
                    .collect();
                components[index].dependencies.push(DependencyEdge {
                    from: from_id,
                    to: owner_id,
                    kind: DependencyKind::Configures,
                    required: true,
                    evidence,
                    confidence: components[index].confidence.clone(),
                });
            }
        }
        components[index].artifacts = retained;
        components[index].selection.size_bytes = components[index]
            .artifacts
            .iter()
            .map(|artifact| artifact.size_bytes)
            .fold(0, u64::saturating_add);
    }
}

fn artifact_owner_rank(kind: &ComponentKind) -> u8 {
    match kind {
        ComponentKind::Configuration => 0,
        ComponentKind::McpServer => 1,
        _ => 2,
    }
}

impl HarnessRegistryAdapter {
    fn ensure_owned(&self, component: &Component) -> ProviderResult<()> {
        if component
            .provenance
            .as_ref()
            .is_some_and(|provenance| provenance.adapter_id == self.kind.adapter_id())
        {
            Ok(())
        } else {
            Err(harness_schema_error(
                "harness operation received a component owned by another adapter",
            ))
        }
    }
}

fn complete_harness_enumeration(
    mut components: Vec<Component>,
    edges: Vec<DependencyEdge>,
    evidence: Vec<Evidence>,
    warnings: Vec<ErrorEnvelope>,
) -> ProviderEnumeration {
    let mut warnings: Vec<String> = warnings.into_iter().map(|error| error.message).collect();
    if components.is_empty() {
        return ProviderEnumeration {
            observations: Vec::new(),
            warnings,
        };
    }

    let mut graph_edges = Vec::new();
    for edge in edges {
        if components.iter().any(|component| component.id == edge.from) {
            graph_edges.push(edge);
        } else {
            warnings
                .push("harness graph contained an edge for an unavailable component".to_owned());
        }
    }
    graph_edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.to.cmp(&right.to))
            .then_with(|| {
                dependency_kind_order(&left.kind).cmp(&dependency_kind_order(&right.kind))
            })
            .then_with(|| left.required.cmp(&right.required))
    });
    graph_edges.dedup();

    // Keep the result's own dependency list intact. The registry bridge adds
    // any separately emitted edge during normalize, then the coordinator's
    // graph boundary performs the final deterministic merge.
    components.sort_by(|left, right| left.id.cmp(&right.id));
    ProviderEnumeration {
        observations: vec![Observation::Components {
            components,
            edges: graph_edges,
            evidence,
        }],
        warnings,
    }
}

fn dependency_kind_order(kind: &DependencyKind) -> u8 {
    match kind {
        DependencyKind::RequiredRuntime => 0,
        DependencyKind::RequiredPackage => 1,
        DependencyKind::InstalledThrough => 2,
        DependencyKind::Configures => 3,
        DependencyKind::UsesSecret => 4,
        DependencyKind::OptionalFeature => 5,
        DependencyKind::ProvidesExecutable => 6,
        DependencyKind::Contains => 7,
        DependencyKind::RestoresBefore => 8,
        DependencyKind::VerifiesWith => 9,
        DependencyKind::RelatedOnly => 10,
    }
}

fn current_project_roots(known_folders: &KnownFolderMap) -> Vec<reforge_domain::PathToken> {
    let Ok(current_dir) = env::current_dir() else {
        return Vec::new();
    };
    let current_dir = fs::canonicalize(&current_dir).unwrap_or(current_dir);
    let current_key = path_key(&current_dir);
    let mut matches: Vec<_> = known_folders
        .entries
        .iter()
        .filter_map(|(root, path)| {
            let canonical_root = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            let root_key = path_key(&canonical_root);
            if current_key == root_key {
                return reforge_domain::PathToken::new(root.clone(), "").ok();
            }
            let prefix = format!("{root_key}/");
            current_key
                .strip_prefix(&prefix)
                .and_then(|relative| reforge_domain::PathToken::new(root.clone(), relative).ok())
        })
        .collect();
    matches.sort_by_key(|left| left.relative.len());
    matches.pop().into_iter().collect()
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn manual_operation_key(kind: HarnessKind, component: &Component) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind.adapter_id().as_bytes());
    hasher.update(component.id.as_str().as_bytes());
    format!(
        "{}-manual-{}",
        kind.adapter_id(),
        hasher.finalize().to_hex()
    )
}

fn harness_schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Harness discovery output failed validation",
        )
        .with_technical_detail(detail),
    )
}

fn harness_cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "Harness discovery was cancelled",
    ))
}
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reforge_domain::{
        ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, ComponentId, Confidence,
        ConfigScope, ContentType, Identity, IdentityQuality, KnownFolderToken, PathToken,
        Portability, Provenance, RestoreDescriptor, RestoreStrategy, SelectionMetadata,
    };

    use super::*;

    #[test]
    fn all_documented_harnesses_have_distinct_registry_ids() {
        let ids: Vec<_> = HarnessKind::ALL
            .into_iter()
            .map(|kind| kind.registry_id().as_str().to_owned())
            .collect();
        assert_eq!(
            ids,
            vec![
                "harness-codex".to_owned(),
                "harness-claude-code".to_owned(),
                "harness-opencode".to_owned(),
            ]
        );
    }

    #[test]
    fn graph_observation_keeps_edges_from_domain_discovery() {
        let evidence = Evidence {
            id: EvidenceId::new("harness-test-evidence").expect("evidence ID"),
            source: EvidenceSource::Harness,
            locator: "fixture:harness".to_owned(),
            observed_at: Utc::now(),
            summary: "fixture harness graph".to_owned(),
            strength: 80,
            independent_group: "fixture".to_owned(),
        };
        let parent = test_component("a", "codex");
        let child = test_component("b", "codex");
        let edge = DependencyEdge {
            from: child.id.clone(),
            to: parent.id.clone(),
            kind: DependencyKind::Configures,
            required: true,
            evidence: vec![evidence.id.clone()],
            confidence: Confidence::High,
        };
        let normalized = HarnessRegistryAdapter::codex()
            .normalize(Observation::Components {
                components: vec![parent, child],
                edges: vec![edge.clone()],
                evidence: vec![evidence],
            })
            .expect("graph observation should normalize");
        let child = normalized
            .iter()
            .find(|component| component.identity.package_family.as_deref() == Some("codex:b"))
            .expect("child component");
        assert_eq!(child.dependencies, vec![edge]);
    }

    #[test]
    fn shared_artifacts_have_one_owner_and_a_required_dependency() {
        let artifact = ArtifactRef {
            id: ArtifactId::new("shared-harness-artifact").expect("artifact ID"),
            source_path: PathToken::new(KnownFolderToken::UserProfile, ".codex/config.toml")
                .expect("path token"),
            scope: ConfigScope::User,
            size_bytes: 12,
            content_type: ContentType::Toml,
            policy: ArtifactPolicy::Config,
            object: None,
        };
        let mut owner = test_component("a", "codex");
        owner.kind = ComponentKind::Configuration;
        owner.artifacts = vec![artifact.clone()];
        let mut child = test_component("b", "codex");
        child.kind = ComponentKind::Hook;
        child.artifacts = vec![artifact];

        let normalized = HarnessRegistryAdapter::codex()
            .normalize(Observation::Components {
                components: vec![child, owner],
                edges: Vec::new(),
                evidence: Vec::new(),
            })
            .expect("shared artifact graph should normalize");
        let owner = normalized
            .iter()
            .find(|component| component.kind == ComponentKind::Configuration)
            .expect("configuration owner");
        let child = normalized
            .iter()
            .find(|component| component.kind == ComponentKind::Hook)
            .expect("hook child");
        assert_eq!(owner.artifacts.len(), 1);
        assert!(child.artifacts.is_empty());
        assert!(child.dependencies.iter().any(|edge| {
            edge.to == owner.id && edge.kind == DependencyKind::Configures && edge.required
        }));
    }

    fn test_component(suffix: &str, adapter_id: &str) -> Component {
        let identity = Identity {
            provider_package: None,
            provider_source: None,
            package_family: Some(format!("codex:{suffix}")),
            product_name: Some("Codex".to_owned()),
            executable_name: None,
            publisher: Some("OpenAI".to_owned()),
            executable_hash: None,
            install_role: Some("Harness".to_owned()),
            identity_quality: IdentityQuality::PackageFamily,
        };
        Component {
            id: ComponentId::new(format!("cmp_{}", suffix.repeat(52))).expect("component ID"),
            kind: reforge_domain::ComponentKind::Harness,
            identity,
            display_name: "Codex".to_owned(),
            version: None,
            architecture: None,
            publisher: None,
            provenance: Some(Provenance {
                provider: None,
                package_id: Some("codex".to_owned()),
                source_url: None,
                observed_version: None,
                adapter_id: adapter_id.to_owned(),
                adapter_version: "test".to_owned(),
            }),
            evidence: Vec::new(),
            confidence: Confidence::High,
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: RestoreStrategy::Manual,
                alternatives: Vec::new(),
                portability: Portability::PartiallyPortable,
                requires_elevation: false,
                requires_user_action: true,
                rationale: vec!["fixture".to_owned()],
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
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
}
