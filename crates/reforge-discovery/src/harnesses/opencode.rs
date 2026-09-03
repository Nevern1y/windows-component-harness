//! OpenCode configuration discovery and safe normalization.
//!
//! This adapter inspects only documented OpenCode configuration roots and
//! environment-selected files. JSONC is parsed as data, interpolation is
//! preserved symbolically, and plugin/instruction/agent/command files remain
//! explicit manual boundaries. No discovered command or plugin is executed.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use reforge_domain::{
    ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, Confidence,
    ConfigScope, ContentType, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence, EvidenceId,
    EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken, ManualAction,
    ManualActionState, McpServerSpec, PathToken, Portability, Publisher, RedactionPolicy,
    ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel, SelectionMetadata,
    VerificationRule,
};
use reforge_platform_windows::{
    BoundedFileReader, FileObservationKind, KnownFolderMap, SafePath, WalkLimits, walk_reparse_safe,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::mcp::{
    McpInputFormat, McpManualReview, McpNormalization, McpParserOptions, McpReferenceCatalog,
    McpSecretReference, normalize_mcp_config,
};

const ADAPTER_ID: &str = "opencode";
const OPENCODE_DOCS_URL: &str = "https://opencode.ai/docs/config/";
const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_DIRECTORY_DEPTH: usize = 8;
const MAX_MANUAL_ACTIONS: usize = 4_096;
const MAX_WARNINGS: usize = 4_096;

/// Trust state supplied by the caller for a project-scoped OpenCode layer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenCodeTrustScope {
    Trusted,
    Untrusted,
    #[default]
    Unknown,
}

impl OpenCodeTrustScope {
    fn label(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Unknown => "unknown",
        }
    }
}

/// Configuration layer that supplied one OpenCode file.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenCodeConfigSource {
    Global,
    GlobalTui,
    UserDirectory,
    Custom,
    Project,
    ProjectDirectory,
    Managed,
}

impl OpenCodeConfigSource {
    fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::GlobalTui => "global_tui",
            Self::UserDirectory => "user_directory",
            Self::Custom => "custom",
            Self::Project => "project",
            Self::ProjectDirectory => "project_directory",
            Self::Managed => "managed",
        }
    }
}

/// Policy owner for an OpenCode configuration layer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpenCodeConfigOwner {
    User,
    Project,
    Managed,
}

impl OpenCodeConfigOwner {
    fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Managed => "managed",
        }
    }
}

/// Inputs for a deterministic OpenCode discovery run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenCodeDiscoveryOptions {
    /// Project roots whose `opencode.json` and `.opencode` layers are inspected.
    pub project_roots: Vec<PathToken>,
    /// Trust decisions for project roots. Missing entries remain `Unknown`.
    pub project_trust: BTreeMap<String, OpenCodeTrustScope>,
    /// Environment visible to the discovery call. Only OpenCode path selectors are read.
    pub environment: BTreeMap<String, String>,
    /// Known executable/runtime/package references passed to MCP normalization.
    pub references: McpReferenceCatalog,
    /// Optional timestamp used by deterministic tests.
    pub observed_at: Option<DateTime<Utc>>,
}

impl OpenCodeDiscoveryOptions {
    /// Build options from the current process environment.
    pub fn current(project_roots: Vec<PathToken>, references: McpReferenceCatalog) -> Self {
        Self {
            project_roots,
            environment: env::vars().collect(),
            references,
            ..Self::default()
        }
    }

    pub fn with_project_trust(
        mut self,
        project_root: PathToken,
        trust: OpenCodeTrustScope,
    ) -> Self {
        self.project_trust
            .insert(token_string(&project_root), trust);
        self
    }

    pub fn with_observed_at(mut self, observed_at: DateTime<Utc>) -> Self {
        self.observed_at = Some(observed_at);
        self
    }
}

/// One OpenCode configuration layer and its safe package-facing representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeConfigRecord {
    pub path: PathToken,
    pub scope: ConfigScope,
    pub trust: OpenCodeTrustScope,
    pub source: OpenCodeConfigSource,
    pub owner: OpenCodeConfigOwner,
    pub precedence: u8,
    pub managed: bool,
    pub artifact: ArtifactRef,
    pub safe_config: Value,
    pub mcp: Option<McpNormalization>,
}

/// Metadata for an OpenCode instruction file or inline instruction entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeInstruction {
    pub name: String,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: OpenCodeTrustScope,
    pub artifact: Option<ArtifactRef>,
    pub metadata: Value,
}

/// Metadata for an OpenCode agent file or inline agent entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeAgent {
    pub name: String,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: OpenCodeTrustScope,
    pub artifact: Option<ArtifactRef>,
    pub metadata: Value,
}

/// Metadata for an OpenCode command file or inline command entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeCommand {
    pub name: String,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: OpenCodeTrustScope,
    pub artifact: Option<ArtifactRef>,
    pub metadata: Value,
}

/// Metadata for an OpenCode plugin file or inline plugin entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodePlugin {
    pub name: String,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: OpenCodeTrustScope,
    pub owner: OpenCodeConfigOwner,
    pub managed: bool,
    pub artifact: Option<ArtifactRef>,
    pub metadata: Value,
}

/// Complete result of an OpenCode discovery run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeDiscovery {
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub evidence: Vec<Evidence>,
    pub artifacts: Vec<ArtifactRef>,
    pub configs: Vec<OpenCodeConfigRecord>,
    pub instructions: Vec<OpenCodeInstruction>,
    pub agents: Vec<OpenCodeAgent>,
    pub commands: Vec<OpenCodeCommand>,
    pub plugins: Vec<OpenCodePlugin>,
    pub mcp_servers: Vec<McpServerSpec>,
    pub secret_references: Vec<McpSecretReference>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
}

impl OpenCodeDiscovery {
    fn empty() -> Self {
        Self {
            components: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            artifacts: Vec::new(),
            configs: Vec::new(),
            instructions: Vec::new(),
            agents: Vec::new(),
            commands: Vec::new(),
            plugins: Vec::new(),
            mcp_servers: Vec::new(),
            secret_references: Vec::new(),
            manual_actions: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Adapter for documented OpenCode configuration and extension layouts.
#[derive(Clone, Debug, Default)]
pub struct OpenCodeAdapter {
    collector: crate::ArtifactCollector,
}

impl OpenCodeAdapter {
    pub fn new() -> Self {
        Self {
            collector: crate::ArtifactCollector::default(),
        }
    }

    /// Discover OpenCode using the current process environment.
    pub fn discover(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        references: McpReferenceCatalog,
    ) -> Result<OpenCodeDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &OpenCodeDiscoveryOptions::current(project_roots.to_vec(), references),
        )
    }

    /// Discover OpenCode with a supplied environment for isolated tests.
    pub fn discover_with_environment(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        environment: BTreeMap<String, String>,
        references: McpReferenceCatalog,
    ) -> Result<OpenCodeDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &OpenCodeDiscoveryOptions {
                project_roots: project_roots.to_vec(),
                environment,
                references,
                ..OpenCodeDiscoveryOptions::default()
            },
        )
    }

    /// Discover OpenCode with fully controlled paths, trust, and timestamp.
    pub fn discover_with_options(
        &self,
        known_folders: &KnownFolderMap,
        options: &OpenCodeDiscoveryOptions,
    ) -> Result<OpenCodeDiscovery, Box<ErrorEnvelope>> {
        let observed_at = options.observed_at.unwrap_or_else(Utc::now);
        let home = PathToken::new(KnownFolderToken::UserProfile, "").map_err(|_| {
            discovery_error(
                ReforgeErrorCode::InvalidPath,
                "The default OpenCode home token could not be constructed",
            )
        })?;
        let mut state = DiscoveryState::new(observed_at);
        let global_root = join_token(&home, ".config/opencode")?;

        add_config_candidate(
            known_folders,
            &mut state,
            join_token(&global_root, "opencode.json")?,
            ConfigScope::User,
            OpenCodeTrustScope::Trusted,
            "global".to_owned(),
            OpenCodeConfigSource::Global,
            OpenCodeConfigOwner::User,
            30,
            false,
        );
        add_config_candidate(
            known_folders,
            &mut state,
            join_token(&global_root, "opencode.jsonc")?,
            ConfigScope::User,
            OpenCodeTrustScope::Trusted,
            "global".to_owned(),
            OpenCodeConfigSource::Global,
            OpenCodeConfigOwner::User,
            30,
            false,
        );
        add_config_candidate(
            known_folders,
            &mut state,
            join_token(&global_root, "tui.json")?,
            ConfigScope::User,
            OpenCodeTrustScope::Trusted,
            "global".to_owned(),
            OpenCodeConfigSource::GlobalTui,
            OpenCodeConfigOwner::User,
            20,
            false,
        );
        add_config_candidate(
            known_folders,
            &mut state,
            join_token(&global_root, "tui.jsonc")?,
            ConfigScope::User,
            OpenCodeTrustScope::Trusted,
            "global".to_owned(),
            OpenCodeConfigSource::GlobalTui,
            OpenCodeConfigOwner::User,
            20,
            false,
        );
        scan_opencode_directory(
            known_folders,
            &mut state,
            &join_token(&home, ".opencode")?,
            ConfigScope::User,
            OpenCodeTrustScope::Trusted,
            "user".to_owned(),
            OpenCodeConfigSource::UserDirectory,
            OpenCodeConfigOwner::User,
            25,
            false,
        );

        let mut project_roots = options.project_roots.clone();
        project_roots.sort_by_key(token_string);
        project_roots.dedup();
        for project_root in &project_roots {
            let trust = project_trust(options, project_root);
            let namespace = format!("project:{}", token_string(project_root));
            add_config_candidate(
                known_folders,
                &mut state,
                join_token(project_root, "opencode.json")?,
                ConfigScope::Project,
                trust,
                namespace.clone(),
                OpenCodeConfigSource::Project,
                OpenCodeConfigOwner::Project,
                70,
                false,
            );
            add_config_candidate(
                known_folders,
                &mut state,
                join_token(project_root, "opencode.jsonc")?,
                ConfigScope::Project,
                trust,
                namespace.clone(),
                OpenCodeConfigSource::Project,
                OpenCodeConfigOwner::Project,
                70,
                false,
            );
            scan_opencode_directory(
                known_folders,
                &mut state,
                &join_token(project_root, ".opencode")?,
                ConfigScope::Project,
                trust,
                namespace,
                OpenCodeConfigSource::ProjectDirectory,
                OpenCodeConfigOwner::Project,
                80,
                false,
            );
        }

        if let Some(raw) = environment_value(&options.environment, "OPENCODE_CONFIG") {
            let path = resolve_absolute_environment_path(known_folders, raw, "OPENCODE_CONFIG")?;
            add_config_candidate(
                known_folders,
                &mut state,
                path,
                ConfigScope::User,
                OpenCodeTrustScope::Trusted,
                "custom".to_owned(),
                OpenCodeConfigSource::Custom,
                OpenCodeConfigOwner::User,
                90,
                false,
            );
        }
        if let Some(raw) = environment_value(&options.environment, "OPENCODE_CONFIG_DIR") {
            let directory =
                resolve_absolute_environment_path(known_folders, raw, "OPENCODE_CONFIG_DIR")?;
            scan_opencode_directory(
                known_folders,
                &mut state,
                &directory,
                ConfigScope::User,
                OpenCodeTrustScope::Trusted,
                "custom".to_owned(),
                OpenCodeConfigSource::Custom,
                OpenCodeConfigOwner::User,
                85,
                false,
            );
        }

        let managed_root =
            PathToken::new(KnownFolderToken::ProgramData, "opencode").map_err(|_| {
                discovery_error(
                    ReforgeErrorCode::InvalidPath,
                    "The managed OpenCode root token could not be constructed",
                )
            })?;
        scan_opencode_directory(
            known_folders,
            &mut state,
            &managed_root,
            ConfigScope::Managed,
            OpenCodeTrustScope::Trusted,
            "managed".to_owned(),
            OpenCodeConfigSource::Managed,
            OpenCodeConfigOwner::Managed,
            100,
            true,
        );

        if state.candidates.is_empty() {
            return Ok(OpenCodeDiscovery::empty());
        }

        let requests: Vec<_> = state
            .candidates
            .values()
            .map(|candidate| {
                crate::ArtifactRequest::new(
                    candidate.path.clone(),
                    candidate.scope.clone(),
                    candidate.policy.clone(),
                )
            })
            .collect();
        let collection = self.collector.collect(known_folders, &requests)?;
        state.warnings.extend(collection.warnings);
        let artifacts = collection.artifacts;
        let artifact_by_path: BTreeMap<String, ArtifactRef> = artifacts
            .iter()
            .cloned()
            .map(|artifact| (token_string(&artifact.source_path), artifact))
            .collect();
        let candidates: Vec<ArtifactCandidate> = state.candidates.values().cloned().collect();

        let mut result = OpenCodeDiscovery {
            artifacts: sorted_artifacts(artifacts),
            ..OpenCodeDiscovery::empty()
        };
        let harness_evidence =
            state.evidence(&global_root, "OpenCode configuration roots discovered");
        let harness = build_component(
            ComponentKind::Harness,
            "harness",
            "OpenCode",
            Vec::new(),
            &harness_evidence,
            harness_restore(),
            Vec::new(),
            false,
            json_map([
                ("adapter", json!(ADAPTER_ID)),
                ("global_root", json!(token_string(&global_root))),
                ("managed_root", json!(token_string(&managed_root))),
            ]),
        )?;
        let harness_id = harness.id.clone();
        result.components.push(harness);

        let mut parsed_configs = Vec::new();
        for candidate in &candidates {
            let CandidateRole::Config {
                source,
                owner,
                precedence,
                managed,
            } = &candidate.role
            else {
                continue;
            };
            let Some(artifact) = artifact_by_path
                .get(&token_string(&candidate.path))
                .cloned()
            else {
                state.add_review(
                    candidate.path.clone(),
                    "OpenCode configuration was not safely collected",
                );
                continue;
            };
            let document = parse_config_file(known_folders, &candidate.path)?;
            let mut safe_config = RedactionPolicy::default()
                .redact_json(&document)
                .unwrap_or_else(|| json!({"redacted": true}));
            let normalization = match mcp_document(&document)? {
                Some(mcp_document) => {
                    let parser_options =
                        McpParserOptions::new(candidate.scope.clone(), artifact.clone())
                            .with_known_folders(known_folders.clone())
                            .with_references(options.references.clone());
                    match normalize_mcp_config(
                        &serde_json::to_vec(&mcp_document).map_err(|_| {
                            discovery_error(
                                ReforgeErrorCode::SchemaInvalid,
                                "OpenCode MCP configuration could not be serialized safely",
                            )
                        })?,
                        McpInputFormat::Json,
                        &parser_options,
                    ) {
                        Ok(normalization) => {
                            replace_safe_mcp(&mut safe_config, &document, &normalization);
                            Some(normalization)
                        }
                        Err(error) => {
                            state.push_warning(*error);
                            state.add_review(
                                candidate.path.clone(),
                                "OpenCode MCP configuration requires manual review",
                            );
                            None
                        }
                    }
                }
                None => None,
            };
            parsed_configs.push(ParsedConfig {
                candidate: candidate.clone(),
                artifact,
                document,
                safe_config,
                normalization,
                source: *source,
                owner: *owner,
                precedence: *precedence,
                managed: *managed,
            });
        }

        for parsed in &parsed_configs {
            let candidate = &parsed.candidate;
            let config_component = build_component(
                ComponentKind::Configuration,
                &format!(
                    "config:{}:{}",
                    parsed.source.label(),
                    token_string(&candidate.path)
                ),
                &format!("OpenCode {} configuration", parsed.source.label()),
                vec![parsed.artifact.clone()],
                &state.evidence(&candidate.path, "OpenCode configuration discovered"),
                config_restore(
                    parsed.managed
                        || (candidate.scope == ConfigScope::Project
                            && candidate.trust != OpenCodeTrustScope::Trusted),
                ),
                vec![VerificationRule::ConfigParses {
                    destination: candidate.path.clone(),
                    content_type: content_type_for_path(&candidate.path),
                }],
                parsed.managed,
                json_map([
                    ("scope", json!(scope_label(&candidate.scope))),
                    ("trust", json!(candidate.trust.label())),
                    ("namespace", json!(candidate.namespace.clone())),
                    ("source", json!(parsed.source.label())),
                    ("owner", json!(parsed.owner.label())),
                    ("precedence", json!(parsed.precedence)),
                    ("managed", json!(parsed.managed)),
                    ("safe_config", parsed.safe_config.clone()),
                ]),
            )?;
            let component_id = config_component.id.clone();
            result.components.push(config_component);
            result.configs.push(OpenCodeConfigRecord {
                path: candidate.path.clone(),
                scope: candidate.scope.clone(),
                trust: candidate.trust,
                source: parsed.source,
                owner: parsed.owner,
                precedence: parsed.precedence,
                managed: parsed.managed,
                artifact: parsed.artifact.clone(),
                safe_config: parsed.safe_config.clone(),
                mcp: parsed.normalization.clone(),
            });
            add_dependency(
                &mut result,
                component_id,
                harness_id.clone(),
                DependencyKind::Configures,
                &state.evidence(&candidate.path, "OpenCode configuration belongs to harness"),
            );
            materialize_inline_metadata(&mut result, &harness_id, parsed, &mut state)?;
        }

        for candidate in &candidates {
            let CandidateRole::Config { .. } = candidate.role else {
                let Some(artifact) = artifact_by_path
                    .get(&token_string(&candidate.path))
                    .cloned()
                else {
                    continue;
                };
                materialize_file_metadata(
                    &mut result,
                    &harness_id,
                    candidate,
                    artifact,
                    &mut state,
                )?;
                continue;
            };
        }

        let mut seen_secrets = BTreeSet::new();
        let mut seen_servers = BTreeSet::new();
        for parsed in &parsed_configs {
            let Some(normalization) = &parsed.normalization else {
                continue;
            };
            for secret in &normalization.secret_references {
                if seen_secrets.insert(secret.id.clone()) {
                    let component =
                        build_secret_component(secret, &parsed.candidate.path, &mut state)?;
                    result.secret_references.push(secret.clone());
                    result.components.push(component);
                }
            }
            for review in &normalization.manual_reviews {
                result.warnings.push(mcp_review_warning(review));
            }
            for server in &normalization.servers {
                let server_key = format!(
                    "{}:{}:{}",
                    scope_label(&parsed.candidate.scope),
                    parsed.candidate.namespace,
                    server.name
                );
                if !seen_servers.insert(server_key) {
                    continue;
                }
                let evidence =
                    state.evidence(&parsed.candidate.path, "OpenCode MCP server discovered");
                let mut component = build_mcp_component(
                    server,
                    &parsed.candidate.namespace,
                    &harness_id,
                    &evidence,
                )?;
                let component_id = component.id.clone();
                for secret in normalization
                    .secret_references
                    .iter()
                    .filter(|secret| secret.server == server.name)
                {
                    let dependency = edge(
                        component_id.clone(),
                        secret.id.clone(),
                        DependencyKind::UsesSecret,
                        &state.evidence(
                            &parsed.candidate.path,
                            "OpenCode MCP server references a secret",
                        ),
                    );
                    component.dependencies.push(dependency.clone());
                    result.edges.push(dependency);
                }
                result.mcp_servers.push(server.clone());
                result.components.push(component);
            }
        }

        for review in state.reviews.clone() {
            let component = result.components.iter().find(|component| {
                component.artifacts.iter().any(|artifact| {
                    token_string(&artifact.source_path) == token_string(&review.path)
                })
            });
            let component_id = component
                .map(|component| component.id.clone())
                .unwrap_or_else(|| harness_id.clone());
            add_manual_action(
                &mut result.manual_actions,
                manual_action(
                    &component_id,
                    &format!("review:{}", token_string(&review.path)),
                    "Review OpenCode discovery input",
                    &review.reason,
                    vec!["Inspect this OpenCode input before restoring it".to_owned()],
                    RiskLevel::High,
                ),
            );
        }

        result.evidence = state.evidence_records;
        result
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        result
            .components
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
        });
        result
            .manual_actions
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.manual_actions.truncate(MAX_MANUAL_ACTIONS);
        result.warnings.extend(state.warnings);
        result.warnings.truncate(MAX_WARNINGS);
        Ok(result)
    }
}

#[derive(Clone, Debug)]
struct DiscoveryState {
    observed_at: DateTime<Utc>,
    candidates: BTreeMap<String, ArtifactCandidate>,
    reviews: Vec<Review>,
    evidence_records: Vec<Evidence>,
    evidence_ids: BTreeSet<EvidenceId>,
    warnings: Vec<ErrorEnvelope>,
}

impl DiscoveryState {
    fn new(observed_at: DateTime<Utc>) -> Self {
        Self {
            observed_at,
            candidates: BTreeMap::new(),
            reviews: Vec::new(),
            evidence_records: Vec::new(),
            evidence_ids: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn add_review(&mut self, path: PathToken, reason: impl Into<String>) {
        self.reviews.push(Review {
            path,
            reason: reason.into(),
        });
    }

    fn push_warning(&mut self, warning: ErrorEnvelope) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(warning);
        }
    }

    fn evidence(&mut self, path: &PathToken, summary: &str) -> Evidence {
        let locator = format!("opencode:{}:{}", token_string(path), summary);
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &locator);
        let id = EvidenceId::new(format!("opencode-evidence-{}", hasher.finalize().to_hex()))
            .expect("hashed OpenCode evidence ID");
        let evidence = Evidence {
            id: id.clone(),
            source: EvidenceSource::Harness,
            locator,
            observed_at: self.observed_at,
            summary: summary.to_owned(),
            strength: 90,
            independent_group: "opencode-config".to_owned(),
        };
        if self.evidence_ids.insert(id) {
            self.evidence_records.push(evidence.clone());
        }
        evidence
    }
}

#[derive(Clone, Debug)]
struct Review {
    path: PathToken,
    reason: String,
}

#[derive(Clone, Debug)]
struct ArtifactCandidate {
    path: PathToken,
    scope: ConfigScope,
    trust: OpenCodeTrustScope,
    namespace: String,
    role: CandidateRole,
    policy: ArtifactPolicy,
    priority: u8,
}

#[derive(Clone, Debug)]
enum CandidateRole {
    Config {
        source: OpenCodeConfigSource,
        owner: OpenCodeConfigOwner,
        precedence: u8,
        managed: bool,
    },
    Instruction,
    Agent,
    Command,
    Plugin,
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    candidate: ArtifactCandidate,
    artifact: ArtifactRef,
    document: Value,
    safe_config: Value,
    normalization: Option<McpNormalization>,
    source: OpenCodeConfigSource,
    owner: OpenCodeConfigOwner,
    precedence: u8,
    managed: bool,
}

#[allow(clippy::too_many_arguments)]
fn add_config_candidate(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    path: PathToken,
    scope: ConfigScope,
    trust: OpenCodeTrustScope,
    namespace: String,
    source: OpenCodeConfigSource,
    owner: OpenCodeConfigOwner,
    precedence: u8,
    managed: bool,
) {
    add_file_candidate(
        known_folders,
        state,
        path,
        scope,
        trust,
        namespace,
        CandidateRole::Config {
            source,
            owner,
            precedence,
            managed,
        },
        ArtifactPolicy::Config,
        precedence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_file_candidate(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    path: PathToken,
    scope: ConfigScope,
    trust: OpenCodeTrustScope,
    namespace: String,
    role: CandidateRole,
    policy: ArtifactPolicy,
    priority: u8,
) {
    match entry_kind(known_folders, &path) {
        Ok(Some(EntryKind::File)) => {
            let key = token_string(&path);
            let replace = state
                .candidates
                .get(&key)
                .is_none_or(|candidate| priority > candidate.priority);
            if replace {
                state.candidates.insert(
                    key,
                    ArtifactCandidate {
                        path,
                        scope,
                        trust,
                        namespace,
                        role,
                        policy,
                        priority,
                    },
                );
            }
        }
        Ok(Some(EntryKind::Directory)) | Ok(None) => {}
        Err(error) => state.push_warning(*error),
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_opencode_directory(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    directory: &PathToken,
    scope: ConfigScope,
    trust: OpenCodeTrustScope,
    namespace: String,
    source: OpenCodeConfigSource,
    owner: OpenCodeConfigOwner,
    precedence: u8,
    managed: bool,
) {
    let Ok(Some(EntryKind::Directory)) = entry_kind(known_folders, directory) else {
        return;
    };
    let Ok(absolute) = known_folders.resolve(directory) else {
        return;
    };
    let observations = match walk_reparse_safe(
        absolute,
        WalkLimits {
            max_entries: MAX_DIRECTORY_ENTRIES,
            max_depth: MAX_DIRECTORY_DEPTH,
        },
    ) {
        Ok(observations) => observations,
        Err(error) => {
            state.push_warning(*error);
            return;
        }
    };
    for observation in observations {
        if observation.kind != FileObservationKind::File {
            continue;
        }
        let relative = observation.path.as_str().replace('\\', "/");
        let Ok(path) = join_token(directory, &relative) else {
            state.add_review(
                directory.clone(),
                "An OpenCode directory entry could not be tokenized",
            );
            continue;
        };
        if is_config_file(&relative) {
            add_config_candidate(
                known_folders,
                state,
                path,
                scope.clone(),
                trust,
                namespace.clone(),
                source,
                owner,
                precedence,
                managed,
            );
            continue;
        }
        let role = metadata_role(&relative);
        let Some(role) = role else {
            continue;
        };
        add_file_candidate(
            known_folders,
            state,
            path,
            scope.clone(),
            trust,
            namespace.clone(),
            role,
            ArtifactPolicy::Manual,
            precedence,
        );
    }
}

fn metadata_role(relative: &str) -> Option<CandidateRole> {
    let lower = relative.to_ascii_lowercase();
    let is_markdown = lower.ends_with(".md");
    if is_markdown && (has_directory_segment(&lower, "instructions") || lower == "agents.md") {
        return Some(CandidateRole::Instruction);
    }
    if is_markdown && has_directory_segment(&lower, "agents") {
        return Some(CandidateRole::Agent);
    }
    if is_markdown && has_directory_segment(&lower, "commands") {
        return Some(CandidateRole::Command);
    }
    if has_directory_segment(&lower, "plugins")
        && [".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".jsonc"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    {
        return Some(CandidateRole::Plugin);
    }
    None
}

fn has_directory_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|part| part == segment)
}

fn is_config_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    matches!(
        lower.rsplit('/').next(),
        Some(
            "opencode.json"
                | "opencode.jsonc"
                | "tui.json"
                | "tui.jsonc"
                | "managed.json"
                | "managed.jsonc"
        )
    )
}

fn resolve_absolute_environment_path(
    known_folders: &KnownFolderMap,
    raw: &str,
    variable: &str,
) -> Result<PathToken, Box<ErrorEnvelope>> {
    let path = PathBuf::from(raw);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(discovery_error(
            ReforgeErrorCode::InvalidPath,
            &format!("{variable} must be an absolute path without parent segments"),
        ));
    }
    token_for_absolute_path(known_folders, &path).ok_or_else(|| {
        discovery_error(
            ReforgeErrorCode::SecurityPolicy,
            &format!("{variable} is outside the known-folder map"),
        )
    })
}

fn token_for_absolute_path(known_folders: &KnownFolderMap, path: &Path) -> Option<PathToken> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return None;
    }
    let candidate = normalized_path(path);
    let mut matches = known_folders
        .entries
        .iter()
        .filter_map(|(root, root_path)| {
            let root_text = normalized_path(root_path);
            if candidate == root_text {
                return PathToken::new(root.clone(), "")
                    .ok()
                    .map(|token| (root_text.len(), token));
            }
            let prefix = format!("{root_text}/");
            candidate
                .strip_prefix(&prefix)
                .and_then(|relative| PathToken::new(root.clone(), relative).ok())
                .map(|token| (root_text.len(), token))
        });
    matches.next().map(|(_, token)| token)
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn join_token(base: &PathToken, relative: &str) -> Result<PathToken, Box<ErrorEnvelope>> {
    let value = if base.relative.is_empty() {
        relative.to_owned()
    } else {
        format!("{}/{}", base.relative, relative)
    };
    PathToken::new(base.root.clone(), value).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::InvalidPath,
            "An OpenCode path could not be represented as a safe token",
        )
    })
}

fn entry_kind(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Option<EntryKind>, Box<ErrorEnvelope>> {
    let absolute = known_folders.resolve(path)?;
    match fs::symlink_metadata(absolute) {
        Ok(metadata) if metadata.is_file() => Ok(Some(EntryKind::File)),
        Ok(metadata) if metadata.is_dir() => Ok(Some(EntryKind::Directory)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Box::new(ErrorEnvelope::from_io_error(
            &error,
            "An OpenCode path could not be inspected",
        ))),
    }
}

fn read_bounded(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let root = known_folders.entries.get(&path.root).ok_or_else(|| {
        discovery_error(
            ReforgeErrorCode::PathNotFound,
            "OpenCode path root is not available",
        )
    })?;
    let safe_path = SafePath::from_token(path)?;
    let mut reader = BoundedFileReader::open(root, &safe_path, MAX_TEXT_BYTES)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

fn parse_config_file(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Value, Box<ErrorEnvelope>> {
    let bytes = read_bounded(known_folders, path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::ProviderParseFailed,
            "OpenCode configuration is not valid UTF-8",
        )
    })?;
    if path.relative.to_ascii_lowercase().ends_with(".jsonc") {
        json5::from_str(text).map_err(|_| {
            discovery_error(
                ReforgeErrorCode::ProviderParseFailed,
                "OpenCode JSONC configuration could not be parsed",
            )
        })
    } else {
        serde_json::from_str(text).map_err(|_| {
            discovery_error(
                ReforgeErrorCode::ProviderParseFailed,
                "OpenCode JSON configuration could not be parsed",
            )
        })
    }
}

fn mcp_document(document: &Value) -> Result<Option<Value>, Box<ErrorEnvelope>> {
    let Some(object) = document.as_object() else {
        return Err(discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "OpenCode configuration root must be an object",
        ));
    };
    let keys = ["mcp", "mcpServers", "mcp_servers"]
        .into_iter()
        .filter(|key| object.contains_key(*key))
        .collect::<Vec<_>>();
    if keys.len() > 1 {
        return Err(discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "OpenCode MCP configuration contains multiple server tables",
        ));
    }
    let Some(key) = keys.first().copied() else {
        return Ok(None);
    };
    let Some(raw_servers) = object.get(key).and_then(Value::as_object) else {
        return Err(discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "OpenCode MCP configuration must be an object",
        ));
    };
    let mut servers = Map::new();
    for (name, raw_server) in raw_servers {
        let Some(raw_server) = raw_server.as_object() else {
            return Err(discovery_error(
                ReforgeErrorCode::SchemaInvalid,
                "OpenCode MCP server entry must be an object",
            ));
        };
        let mut server = raw_server.clone();
        if let Some(Value::Array(values)) = server.get("command").cloned() {
            let mut strings = values.iter().map(Value::as_str);
            let Some(first) = strings.next().flatten() else {
                return Err(discovery_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "OpenCode MCP command array must contain a command",
                ));
            };
            server.insert("command".to_owned(), Value::String(first.to_owned()));
            if !server.contains_key("args") {
                let args = strings
                    .map(|value| {
                        value.map_or_else(
                            || Value::String("<REDACTED>".to_owned()),
                            |value| Value::String(value.to_owned()),
                        )
                    })
                    .collect();
                server.insert("args".to_owned(), Value::Array(args));
            }
        }
        servers.insert(name.clone(), Value::Object(server));
    }
    let _ = key;
    Ok(Some(json!({"mcpServers": servers})))
}

fn replace_safe_mcp(safe_config: &mut Value, source: &Value, normalization: &McpNormalization) {
    let Some(safe_servers) = normalization.safe_config.get("mcpServers") else {
        return;
    };
    let Some(source_object) = source.as_object() else {
        return;
    };
    let Some(safe_object) = safe_config.as_object_mut() else {
        return;
    };
    for key in ["mcp", "mcpServers", "mcp_servers"] {
        if source_object.contains_key(key) {
            safe_object.insert(key.to_owned(), safe_servers.clone());
        }
    }
}

fn content_type_for_path(path: &PathToken) -> ContentType {
    let lower = path.relative.to_ascii_lowercase();
    if lower.ends_with(".jsonc") {
        ContentType::Jsonc
    } else {
        ContentType::Json
    }
}

fn materialize_file_metadata(
    result: &mut OpenCodeDiscovery,
    harness_id: &ComponentId,
    candidate: &ArtifactCandidate,
    artifact: ArtifactRef,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let (kind, name, display_name) = match candidate.role {
        CandidateRole::Instruction => (
            ComponentKind::Configuration,
            metadata_name(&candidate.path),
            "OpenCode instruction",
        ),
        CandidateRole::Agent => (
            ComponentKind::Agent,
            metadata_name(&candidate.path),
            "OpenCode agent",
        ),
        CandidateRole::Command => (
            ComponentKind::Skill,
            metadata_name(&candidate.path),
            "OpenCode command",
        ),
        CandidateRole::Plugin => (
            ComponentKind::Plugin,
            metadata_name(&candidate.path),
            "OpenCode plugin",
        ),
        CandidateRole::Config { .. } => return Ok(()),
    };
    let component = build_component(
        kind.clone(),
        &format!(
            "metadata:{}:{}",
            kind_label(&kind),
            token_string(&candidate.path)
        ),
        &format!("{display_name} {name}"),
        vec![artifact.clone()],
        &state.evidence(&candidate.path, "OpenCode extension metadata discovered"),
        untrusted_restore("OpenCode extension metadata is untrusted and is never executed"),
        vec![VerificationRule::File {
            destination: candidate.path.clone(),
            object: artifact.object.clone(),
        }],
        false,
        json_map([
            ("name", json!(name.clone())),
            ("namespace", json!(candidate.namespace.clone())),
            ("executed", json!(false)),
            (
                "managed",
                json!(matches!(candidate.scope, ConfigScope::Managed)),
            ),
        ]),
    )?;
    let component_id = component.id.clone();
    result.components.push(component);
    match candidate.role {
        CandidateRole::Instruction => result.instructions.push(OpenCodeInstruction {
            name,
            path: Some(candidate.path.clone()),
            scope: candidate.scope.clone(),
            namespace: candidate.namespace.clone(),
            trust: candidate.trust,
            artifact: Some(artifact),
            metadata: Value::Null,
        }),
        CandidateRole::Agent => result.agents.push(OpenCodeAgent {
            name,
            path: Some(candidate.path.clone()),
            scope: candidate.scope.clone(),
            namespace: candidate.namespace.clone(),
            trust: candidate.trust,
            artifact: Some(artifact),
            metadata: Value::Null,
        }),
        CandidateRole::Command => result.commands.push(OpenCodeCommand {
            name,
            path: Some(candidate.path.clone()),
            scope: candidate.scope.clone(),
            namespace: candidate.namespace.clone(),
            trust: candidate.trust,
            artifact: Some(artifact),
            metadata: Value::Null,
        }),
        CandidateRole::Plugin => result.plugins.push(OpenCodePlugin {
            name,
            path: Some(candidate.path.clone()),
            scope: candidate.scope.clone(),
            namespace: candidate.namespace.clone(),
            trust: candidate.trust,
            owner: if candidate.scope == ConfigScope::Managed {
                OpenCodeConfigOwner::Managed
            } else if candidate.scope == ConfigScope::Project {
                OpenCodeConfigOwner::Project
            } else {
                OpenCodeConfigOwner::User
            },
            managed: candidate.scope == ConfigScope::Managed,
            artifact: Some(artifact),
            metadata: Value::Null,
        }),
        CandidateRole::Config { .. } => {}
    }
    add_dependency(
        result,
        component_id.clone(),
        harness_id.clone(),
        DependencyKind::Contains,
        &state.evidence(&candidate.path, "OpenCode metadata belongs to harness"),
    );
    add_review_action(
        &mut result.manual_actions,
        &component_id,
        "metadata-review",
        "Review OpenCode extension metadata before restore",
        "OpenCode extension, command, agent, and instruction inputs are untrusted data",
    );
    Ok(())
}

fn materialize_inline_metadata(
    result: &mut OpenCodeDiscovery,
    harness_id: &ComponentId,
    parsed: &ParsedConfig,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let entries = [
        ("instructions", InlineKind::Instruction),
        ("agent", InlineKind::Agent),
        ("agents", InlineKind::Agent),
        ("command", InlineKind::Command),
        ("commands", InlineKind::Command),
        ("plugin", InlineKind::Plugin),
        ("plugins", InlineKind::Plugin),
    ];
    for (key, kind) in entries {
        for (index, (name, metadata)) in named_entries(parsed.document.get(key), key)
            .into_iter()
            .enumerate()
        {
            let metadata = RedactionPolicy::default()
                .redact_json(&metadata)
                .unwrap_or_else(|| json!({"redacted": true}));
            materialize_inline_entry(
                result, harness_id, parsed, kind, key, &name, index, metadata, state,
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum InlineKind {
    Instruction,
    Agent,
    Command,
    Plugin,
}

#[allow(clippy::too_many_arguments)]
fn materialize_inline_entry(
    result: &mut OpenCodeDiscovery,
    harness_id: &ComponentId,
    parsed: &ParsedConfig,
    kind: InlineKind,
    field: &str,
    name: &str,
    index: usize,
    metadata: Value,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let safe_name = safe_name(name).unwrap_or_else(|| format!("entry-{index}"));
    let (component_kind, label) = match kind {
        InlineKind::Instruction => (ComponentKind::Configuration, "instruction"),
        InlineKind::Agent => (ComponentKind::Agent, "agent"),
        InlineKind::Command => (ComponentKind::Skill, "command"),
        InlineKind::Plugin => (ComponentKind::Plugin, "plugin"),
    };
    let component = build_component(
        component_kind.clone(),
        &format!(
            "inline:{}:{}:{}:{}:{}",
            label,
            field,
            parsed.source.label(),
            token_string(&parsed.candidate.path),
            safe_name
        ),
        &format!("OpenCode {label} {safe_name}"),
        Vec::new(),
        &state.evidence(
            &parsed.candidate.path,
            "OpenCode inline metadata discovered",
        ),
        untrusted_restore("OpenCode inline extension metadata is never executed"),
        Vec::new(),
        false,
        json_map([
            ("name", json!(safe_name.clone())),
            ("namespace", json!(parsed.candidate.namespace.clone())),
            ("metadata", metadata.clone()),
            ("inline", json!(true)),
            ("executed", json!(false)),
        ]),
    )?;
    let component_id = component.id.clone();
    result.components.push(component);
    match kind {
        InlineKind::Instruction => result.instructions.push(OpenCodeInstruction {
            name: safe_name,
            path: None,
            scope: parsed.candidate.scope.clone(),
            namespace: parsed.candidate.namespace.clone(),
            trust: parsed.candidate.trust,
            artifact: None,
            metadata,
        }),
        InlineKind::Agent => result.agents.push(OpenCodeAgent {
            name: safe_name,
            path: None,
            scope: parsed.candidate.scope.clone(),
            namespace: parsed.candidate.namespace.clone(),
            trust: parsed.candidate.trust,
            artifact: None,
            metadata,
        }),
        InlineKind::Command => result.commands.push(OpenCodeCommand {
            name: safe_name,
            path: None,
            scope: parsed.candidate.scope.clone(),
            namespace: parsed.candidate.namespace.clone(),
            trust: parsed.candidate.trust,
            artifact: None,
            metadata,
        }),
        InlineKind::Plugin => result.plugins.push(OpenCodePlugin {
            name: safe_name,
            path: None,
            scope: parsed.candidate.scope.clone(),
            namespace: parsed.candidate.namespace.clone(),
            trust: parsed.candidate.trust,
            owner: parsed.owner,
            managed: parsed.managed,
            artifact: None,
            metadata,
        }),
    }
    add_dependency(
        result,
        component_id.clone(),
        harness_id.clone(),
        DependencyKind::Contains,
        &state.evidence(
            &parsed.candidate.path,
            "OpenCode inline metadata belongs to harness",
        ),
    );
    add_review_action(
        &mut result.manual_actions,
        &component_id,
        "inline-review",
        "Review OpenCode inline metadata before restore",
        "OpenCode inline extension metadata is untrusted configuration data",
    );
    Ok(())
}

fn named_entries(value: Option<&Value>, prefix: &str) -> Vec<(String, Value)> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        Value::Object(object) => object
            .iter()
            .map(|(name, metadata)| (name.clone(), metadata.clone()))
            .collect(),
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let name = value
                    .as_str()
                    .and_then(safe_name)
                    .or_else(|| {
                        value
                            .get("name")
                            .and_then(Value::as_str)
                            .and_then(safe_name)
                    })
                    .unwrap_or_else(|| format!("{prefix}-{index}"));
                (name, value.clone())
            })
            .collect(),
        Value::String(value) => vec![(
            safe_name(value).unwrap_or_else(|| format!("{prefix}-0")),
            Value::String(value.clone()),
        )],
        _ => Vec::new(),
    }
}

fn build_secret_component(
    secret: &McpSecretReference,
    source_path: &PathToken,
    state: &mut DiscoveryState,
) -> Result<Component, Box<ErrorEnvelope>> {
    let component = build_component(
        ComponentKind::SecretReference,
        &format!("mcp-secret:{}:{}", secret.server, secret.source_field),
        &format!("MCP secret reference {}", secret.label),
        Vec::new(),
        &state.evidence(source_path, "OpenCode MCP secret reference discovered"),
        RestoreDescriptor {
            primary: RestoreStrategy::SecretExportable,
            alternatives: vec![RestoreStrategy::ReauthRequired, RestoreStrategy::Manual],
            portability: Portability::ReauthRequired,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "The secret value is excluded; restore requires an explicit vault or reauthentication decision".to_owned(),
            ],
        },
        vec![VerificationRule::SecureTarget {
            secret: secret.id.clone(),
        }],
        true,
        json_map([
            ("server", json!(secret.server.clone())),
            ("source_field", json!(secret.source_field.clone())),
            ("value_present", json!(false)),
        ]),
    )?;
    Ok(Component {
        id: secret.id.clone(),
        ..component
    })
}

fn build_mcp_component(
    server: &McpServerSpec,
    namespace: &str,
    harness_id: &ComponentId,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    let mut component = build_component(
        ComponentKind::McpServer,
        &format!(
            "mcp:{}:{}:{}",
            scope_label(&server.scope),
            namespace,
            server.name
        ),
        &format!("OpenCode MCP server {namespace}:{}", server.name),
        vec![server.source_config.clone()],
        evidence,
        RestoreDescriptor {
            primary: RestoreStrategy::ConfigPortable,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "The MCP registration is normalized without executing its command".to_owned(),
            ],
        },
        vec![VerificationRule::McpRegistration {
            name: server.name.clone(),
            config: server.source_config.source_path.clone(),
        }],
        false,
        json_map([
            ("scope", json!(scope_label(&server.scope))),
            ("namespace", json!(namespace)),
            (
                "mcp",
                serde_json::to_value(server).map_err(|_| {
                    discovery_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "OpenCode MCP server could not be serialized safely",
                    )
                })?,
            ),
            ("executed", json!(false)),
        ]),
    )?;
    component.dependencies.push(DependencyEdge {
        from: component.id.clone(),
        to: harness_id.clone(),
        kind: DependencyKind::Configures,
        required: true,
        evidence: vec![evidence.id.clone()],
        confidence: Confidence::High,
    });
    Ok(component)
}

#[allow(clippy::too_many_arguments)]
fn build_component(
    kind: ComponentKind,
    key: &str,
    display_name: &str,
    artifacts: Vec<ArtifactRef>,
    evidence: &Evidence,
    restore: RestoreDescriptor,
    verification: Vec<VerificationRule>,
    sensitive: bool,
    extensions: BTreeMap<String, Value>,
) -> Result<Component, Box<ErrorEnvelope>> {
    let publisher = Publisher {
        name: "OpenCode".to_owned(),
        certificate_thumbprint: None,
    };
    let mut identity = Identity {
        provider_package: None,
        provider_source: None,
        package_family: Some(format!("opencode:{key}")),
        product_name: Some("OpenCode".to_owned()),
        executable_name: None,
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some(format!("{kind:?}")),
        identity_quality: IdentityQuality::PackageFamily,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "OpenCode component identity could not be canonicalized",
        )
    })?;
    identity.identity_quality = canonical.quality;
    let size_bytes = artifacts
        .iter()
        .map(|artifact| artifact.size_bytes)
        .fold(0u64, u64::saturating_add);
    Ok(Component {
        id: canonical.id,
        kind,
        identity,
        display_name: display_name.to_owned(),
        version: None,
        architecture: None,
        publisher: Some(publisher),
        provenance: Some(reforge_domain::Provenance {
            provider: None,
            package_id: Some("opencode".to_owned()),
            source_url: None,
            observed_version: None,
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        evidence: vec![EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        }],
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts,
        restore,
        compatibility: Compatibility {
            required_os: Some("Windows 10 22H2+".to_owned()),
            required_architecture: None,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
        verification,
        selection: SelectionMetadata {
            recommended: false,
            score: 0,
            selected_by_default: false,
            sensitive,
            size_bytes,
        },
        extensions,
    })
}

fn harness_restore() -> RestoreDescriptor {
    RestoreDescriptor {
        primary: RestoreStrategy::Reinstall,
        alternatives: vec![RestoreStrategy::Manual],
        portability: Portability::PartiallyPortable,
        requires_elevation: false,
        requires_user_action: true,
        rationale: vec![
            "The OpenCode executable is an install-time dependency; this adapter restores configuration metadata only".to_owned(),
        ],
    }
}

fn config_restore(review: bool) -> RestoreDescriptor {
    if review {
        RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: vec![RestoreStrategy::ConfigPortable],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "This OpenCode configuration is project-untrusted or policy-owned and requires an explicit decision".to_owned(),
            ],
        }
    } else {
        RestoreDescriptor {
            primary: RestoreStrategy::ConfigPortable,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::Portable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec!["Documented OpenCode configuration is portable data".to_owned()],
        }
    }
}

fn untrusted_restore(reason: &str) -> RestoreDescriptor {
    RestoreDescriptor {
        primary: RestoreStrategy::Manual,
        alternatives: Vec::new(),
        portability: Portability::PartiallyPortable,
        requires_elevation: false,
        requires_user_action: true,
        rationale: vec![reason.to_owned()],
    }
}

fn add_dependency(
    result: &mut OpenCodeDiscovery,
    from: ComponentId,
    to: ComponentId,
    kind: DependencyKind,
    evidence: &Evidence,
) {
    let dependency = edge(from.clone(), to, kind, evidence);
    if let Some(component) = result
        .components
        .iter_mut()
        .find(|component| component.id == from)
    {
        component.dependencies.push(dependency.clone());
    }
    result.edges.push(dependency);
}

fn edge(
    from: ComponentId,
    to: ComponentId,
    kind: DependencyKind,
    evidence: &Evidence,
) -> DependencyEdge {
    DependencyEdge {
        from,
        to,
        kind,
        required: true,
        evidence: vec![evidence.id.clone()],
        confidence: Confidence::High,
    }
}

fn add_review_action(
    actions: &mut Vec<ManualAction>,
    component: &ComponentId,
    kind: &str,
    title: &str,
    reason: &str,
) {
    add_manual_action(
        actions,
        manual_action(
            component,
            kind,
            title,
            reason,
            vec!["Select and review this OpenCode input explicitly before restoring it".to_owned()],
            RiskLevel::High,
        ),
    );
}

fn manual_action(
    component: &ComponentId,
    kind: &str,
    title: &str,
    reason: &str,
    instructions: Vec<String>,
    risk: RiskLevel,
) -> ManualAction {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, component.as_str());
    hash_field(&mut hasher, kind);
    ManualAction {
        id: format!("opencode-manual-{}", hasher.finalize().to_hex()),
        component: Some(component.clone()),
        title: title.to_owned(),
        reason: reason.to_owned(),
        risk,
        instructions,
        docs_url: url::Url::parse(OPENCODE_DOCS_URL).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

fn add_manual_action(actions: &mut Vec<ManualAction>, action: ManualAction) {
    if actions.len() < MAX_MANUAL_ACTIONS
        && !actions.iter().any(|existing| existing.id == action.id)
    {
        actions.push(action);
    }
}

fn mcp_review_warning(review: &McpManualReview) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ReforgeErrorCode::ManualActionRequired,
        "OpenCode MCP configuration contains a value requiring manual review",
    )
    .with_context_id(format!("opencode-mcp:{}:{}", review.server, review.field))
}

fn project_trust(options: &OpenCodeDiscoveryOptions, root: &PathToken) -> OpenCodeTrustScope {
    options
        .project_trust
        .get(&token_string(root))
        .copied()
        .unwrap_or_default()
}

fn environment_value<'a>(environment: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case(key) && !value.trim().is_empty())
        .map(|(_, value)| value.as_str())
}

fn metadata_name(path: &PathToken) -> String {
    path.relative
        .rsplit('/')
        .next()
        .and_then(file_stem)
        .and_then(safe_name)
        .unwrap_or_else(|| "metadata".to_owned())
}

fn file_stem(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    name.rsplit_once('.')
        .map_or(Some(name), |(stem, _)| Some(stem))
}

fn safe_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn kind_label(kind: &ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Configuration => "configuration",
        ComponentKind::Agent => "agent",
        ComponentKind::Skill => "skill",
        ComponentKind::Plugin => "plugin",
        _ => "metadata",
    }
}

fn token_string(path: &PathToken) -> String {
    format!("{:?}/{}", path.root, path.relative)
}

fn sorted_artifacts(mut artifacts: Vec<ArtifactRef>) -> Vec<ArtifactRef> {
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    artifacts
}

fn scope_label(scope: &ConfigScope) -> &'static str {
    match scope {
        ConfigScope::Process => "process",
        ConfigScope::User => "user",
        ConfigScope::System => "system",
        ConfigScope::Project => "project",
        ConfigScope::Managed => "managed",
    }
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn json_map<const N: usize>(entries: [(&str, Value); N]) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn discovery_error(code: ReforgeErrorCode, message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(code, message))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_config_paths_and_names_are_bounded() {
        let root = PathToken::new(KnownFolderToken::UserProfile, ".config/opencode").unwrap();
        assert_eq!(token_string(&root), "UserProfile/.config/opencode");
        assert_eq!(
            metadata_name(
                &PathToken::new(
                    KnownFolderToken::UserProfile,
                    ".opencode/commands/review.md"
                )
                .unwrap()
            ),
            "review"
        );
        assert!(safe_name("bad/name").is_none());
    }

    #[test]
    fn jsonc_is_classified_without_interpolation_evaluation() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "opencode.jsonc").unwrap();
        assert_eq!(content_type_for_path(&path), ContentType::Jsonc);
        let value = json!({"model":"${OPENCODE_MODEL}"});
        let safe = RedactionPolicy::default().redact_json(&value).unwrap();
        assert_eq!(safe["model"], "${OPENCODE_MODEL}");
    }
}
