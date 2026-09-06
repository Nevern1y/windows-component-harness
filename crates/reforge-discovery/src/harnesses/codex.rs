//! Codex configuration discovery and safe normalization.
//!
//! This adapter only inspects documented Codex configuration locations.  It
//! emits tokenized artifact references and typed metadata; it never executes
//! hook, agent, skill, or MCP commands and never reads credential contents.

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
    VerificationRule, redact_text,
};
use reforge_platform_windows::{
    BoundedFileReader, FileObservationKind, KnownFolderMap, SafePath, WalkLimits, walk_reparse_safe,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::mcp::{
    McpInputFormat, McpManualReview, McpNormalization, McpParserOptions, McpReferenceCatalog,
    McpSecretReference, normalize_mcp_config,
};

const ADAPTER_ID: &str = "codex";
const AUTH_DOCS_URL: &str = "https://learn.chatgpt.com/docs/auth";
const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_DIRECTORY_DEPTH: usize = 8;
const MAX_MANUAL_ACTIONS: usize = 4096;
const MAX_WARNINGS: usize = 4096;

/// Trust state supplied by the caller for a project-scoped Codex layer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexTrustScope {
    Trusted,
    Untrusted,
    #[default]
    Unknown,
}

impl CodexTrustScope {
    fn label(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Unknown => "unknown",
        }
    }
}

/// Documented Codex credential storage mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexAuthMode {
    File,
    Keyring,
    Auto,
    Unknown,
}

impl CodexAuthMode {
    fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Keyring => "keyring",
            Self::Auto => "auto",
            Self::Unknown => "unknown",
        }
    }
}

/// Inputs for a deterministic Codex discovery run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CodexDiscoveryOptions {
    /// Project roots whose `.codex` layer and `AGENTS.md` should be inspected.
    pub project_roots: Vec<PathToken>,
    /// Trust decisions for project roots.  Missing entries remain `Unknown`.
    pub project_trust: BTreeMap<String, CodexTrustScope>,
    /// Environment visible to the discovery call.  Only `CODEX_HOME` is read.
    pub environment: BTreeMap<String, String>,
    /// Known executable/runtime/package references passed to MCP normalization.
    pub references: McpReferenceCatalog,
    /// Optional timestamp used by deterministic tests.
    pub observed_at: Option<DateTime<Utc>>,
}

impl CodexDiscoveryOptions {
    /// Build options from the current process environment.
    pub fn current(project_roots: Vec<PathToken>, references: McpReferenceCatalog) -> Self {
        Self {
            project_roots,
            project_trust: BTreeMap::new(),
            environment: env::vars().collect(),
            references,
            observed_at: None,
        }
    }

    pub fn with_project_trust(mut self, project_root: PathToken, trust: CodexTrustScope) -> Self {
        self.project_trust
            .insert(token_string(&project_root), trust);
        self
    }

    pub fn with_observed_at(mut self, observed_at: DateTime<Utc>) -> Self {
        self.observed_at = Some(observed_at);
        self
    }
}

/// A parsed Codex config layer and its safe, package-facing representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexConfigRecord {
    pub path: PathToken,
    pub scope: ConfigScope,
    pub trust: CodexTrustScope,
    pub artifact: ArtifactRef,
    pub safe_config: Value,
    pub auth_mode: Option<CodexAuthMode>,
    pub ignored_project_keys: Vec<String>,
    pub mcp: Option<McpNormalization>,
}

/// A profile file adjacent to `config.toml`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexProfile {
    pub name: String,
    pub path: PathToken,
    pub artifact: ArtifactRef,
    pub safe_config: Value,
    pub auth_mode: Option<CodexAuthMode>,
    pub mcp: Option<McpNormalization>,
}

/// A portable instruction artifact such as `AGENTS.md` or a configured file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexInstruction {
    pub kind: String,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub trust: CodexTrustScope,
    pub artifact: ArtifactRef,
}

/// A skill folder's documented `SKILL.md` metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexSkill {
    pub name: String,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub trust: CodexTrustScope,
    pub enabled: Option<bool>,
    pub artifact: ArtifactRef,
}

/// An agent definition, either inline in config or backed by an agent file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAgent {
    pub name: String,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub trust: CodexTrustScope,
    pub artifact: Option<ArtifactRef>,
}

/// Hook metadata.  Commands are redacted metadata and are never executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexHook {
    pub event: String,
    pub matcher: Option<String>,
    pub command: Option<String>,
    pub path: Option<PathToken>,
    pub scope: ConfigScope,
    pub trust: CodexTrustScope,
    pub artifact: Option<ArtifactRef>,
}

/// Metadata-only reference to Codex authentication state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexAuthReference {
    pub id: ComponentId,
    pub mode: CodexAuthMode,
    pub artifact: Option<ArtifactRef>,
}

/// Complete result of a Codex discovery run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexDiscovery {
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub evidence: Vec<Evidence>,
    pub artifacts: Vec<ArtifactRef>,
    pub configs: Vec<CodexConfigRecord>,
    pub profiles: Vec<CodexProfile>,
    pub instructions: Vec<CodexInstruction>,
    pub skills: Vec<CodexSkill>,
    pub agents: Vec<CodexAgent>,
    pub hooks: Vec<CodexHook>,
    pub mcp_servers: Vec<McpServerSpec>,
    pub secret_references: Vec<McpSecretReference>,
    pub auth_mode: Option<CodexAuthMode>,
    pub auth_reference: Option<CodexAuthReference>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
}

impl CodexDiscovery {
    fn empty() -> Self {
        Self {
            components: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            artifacts: Vec::new(),
            configs: Vec::new(),
            profiles: Vec::new(),
            instructions: Vec::new(),
            skills: Vec::new(),
            agents: Vec::new(),
            hooks: Vec::new(),
            mcp_servers: Vec::new(),
            secret_references: Vec::new(),
            auth_mode: None,
            auth_reference: None,
            manual_actions: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Adapter for documented Codex user/project configuration.
#[derive(Clone, Debug, Default)]
pub struct CodexAdapter {
    collector: crate::ArtifactCollector,
}

impl CodexAdapter {
    pub fn new() -> Self {
        Self {
            collector: crate::ArtifactCollector::default(),
        }
    }

    /// Discover Codex using the current process environment.
    pub fn discover(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        references: McpReferenceCatalog,
    ) -> Result<CodexDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &CodexDiscoveryOptions::current(project_roots.to_vec(), references),
        )
    }

    /// Discover Codex with a supplied environment, suitable for isolated tests.
    pub fn discover_with_environment(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        environment: BTreeMap<String, String>,
        references: McpReferenceCatalog,
    ) -> Result<CodexDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &CodexDiscoveryOptions {
                project_roots: project_roots.to_vec(),
                environment,
                references,
                ..CodexDiscoveryOptions::default()
            },
        )
    }

    /// Discover Codex with fully controlled trust, environment, and timestamp.
    pub fn discover_with_options(
        &self,
        known_folders: &KnownFolderMap,
        options: &CodexDiscoveryOptions,
    ) -> Result<CodexDiscovery, Box<ErrorEnvelope>> {
        let observed_at = options.observed_at.unwrap_or_else(Utc::now);
        let home = resolve_codex_home(known_folders, &options.environment)?;
        let mut state = DiscoveryState::new(observed_at);
        let mut parsed_configs = Vec::new();

        // The user layer is always rooted in CODEX_HOME/config.toml.
        if let Some(path) = existing_file(
            known_folders,
            &join_token(&home, "config.toml")?,
            &mut state,
        ) {
            parsed_configs.push(parse_config_source(
                known_folders,
                path.clone(),
                ConfigScope::User,
                CodexTrustScope::Trusted,
                ConfigKind::User,
            )?);
            state.add_file_candidate(
                known_folders,
                path,
                ConfigScope::User,
                CodexTrustScope::Trusted,
                CandidateRole::Config,
                ArtifactPolicy::Config,
            );
        }

        // Profiles are documented sibling files: <name>.config.toml.
        for (name, path) in profile_paths(known_folders, &home, &mut state) {
            parsed_configs.push(parse_config_source(
                known_folders,
                path.clone(),
                ConfigScope::User,
                CodexTrustScope::Trusted,
                ConfigKind::Profile(name),
            )?);
            state.add_file_candidate(
                known_folders,
                path,
                ConfigScope::User,
                CodexTrustScope::Trusted,
                CandidateRole::Profile,
                ArtifactPolicy::Config,
            );
        }

        // Project layers remain independent records; no project value is merged
        // into the user layer and trust is retained on every record.
        let mut project_roots = options.project_roots.clone();
        project_roots.sort_by_key(token_string);
        project_roots.dedup();
        for project_root in project_roots {
            let trust = project_trust(options, &project_root);
            let project_config = join_token(&project_root, ".codex/config.toml")?;
            if let Some(path) = existing_file(known_folders, &project_config, &mut state) {
                parsed_configs.push(parse_config_source(
                    known_folders,
                    path.clone(),
                    ConfigScope::Project,
                    trust,
                    ConfigKind::Project,
                )?);
                state.add_file_candidate(
                    known_folders,
                    path,
                    ConfigScope::Project,
                    trust,
                    CandidateRole::Config,
                    ArtifactPolicy::Config,
                );
            }
        }

        // Global and project instruction/hook locations are fixed documented
        // paths.  No unbounded AppData scan is performed.
        state.add_file_candidate(
            known_folders,
            join_token(&home, "AGENTS.md")?,
            ConfigScope::User,
            CodexTrustScope::Trusted,
            CandidateRole::Instruction("agents_md".to_owned()),
            ArtifactPolicy::Config,
        );
        state.add_file_candidate(
            known_folders,
            join_token(&home, "hooks.json")?,
            ConfigScope::User,
            CodexTrustScope::Trusted,
            CandidateRole::HookFile,
            ArtifactPolicy::Manual,
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&home, "skills")?,
            ConfigScope::User,
            CodexTrustScope::Trusted,
            DirectoryRole::Skills { enabled: None },
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&home, "agents")?,
            ConfigScope::User,
            CodexTrustScope::Trusted,
            DirectoryRole::Agents,
        );

        for project_root in &options.project_roots {
            let trust = project_trust(options, project_root);
            state.add_file_candidate(
                known_folders,
                join_token(project_root, "AGENTS.md")?,
                ConfigScope::Project,
                trust,
                CandidateRole::Instruction("agents_md".to_owned()),
                ArtifactPolicy::Config,
            );
            let project_codex = join_token(project_root, ".codex")?;
            state.add_file_candidate(
                known_folders,
                join_token(&project_codex, "hooks.json")?,
                ConfigScope::Project,
                trust,
                CandidateRole::HookFile,
                ArtifactPolicy::Manual,
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_codex, "skills")?,
                ConfigScope::Project,
                trust,
                DirectoryRole::Skills { enabled: None },
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_codex, "agents")?,
                ConfigScope::Project,
                trust,
                DirectoryRole::Agents,
            );
        }

        // Configured model-instruction and skill paths are adapter-approved
        // explicit paths, resolved relative to their config layer.
        for source in &parsed_configs {
            if let Some(raw) = string_field(&source.document, "model_instructions_file") {
                match resolve_config_path(known_folders, &source.path, raw) {
                    Ok(Some(path)) => state.add_file_candidate(
                        known_folders,
                        path,
                        source.scope.clone(),
                        source.trust,
                        CandidateRole::Instruction("model_instructions_file".to_owned()),
                        ArtifactPolicy::Config,
                    ),
                    Ok(None) => state.add_review(
                        source.path.clone(),
                        "Configured Codex model-instruction file is outside known folders",
                    ),
                    Err(_) => state.add_review(
                        source.path.clone(),
                        "Configured Codex model-instruction file could not be tokenized",
                    ),
                }
            }
            for (raw, enabled) in configured_skill_paths(&source.document) {
                match resolve_config_path(known_folders, &source.path, &raw) {
                    Ok(Some(path)) => match entry_kind(known_folders, &path) {
                        Ok(Some(EntryKind::Directory)) => add_directory_candidates(
                            known_folders,
                            &mut state,
                            &path,
                            source.scope.clone(),
                            source.trust,
                            DirectoryRole::Skills { enabled },
                        ),
                        Ok(Some(EntryKind::File)) => {
                            let name = skill_name_from_path(&path);
                            state.add_file_candidate(
                                known_folders,
                                path,
                                source.scope.clone(),
                                source.trust,
                                CandidateRole::Skill { name, enabled },
                                ArtifactPolicy::Manual,
                            );
                        }
                        Ok(None) => state.add_review(
                            source.path.clone(),
                            "Configured Codex skill path is missing",
                        ),
                        Err(_) => state.add_review(
                            source.path.clone(),
                            "Configured Codex skill path could not be inspected",
                        ),
                    },
                    Ok(None) | Err(_) => state.add_review(
                        source.path.clone(),
                        "Configured Codex skill path could not be tokenized",
                    ),
                }
            }
        }

        // Authentication is metadata-only.  The auth file is never read; the
        // artifact collector uses SecretReference policy and therefore records
        // only bounded file metadata.
        let auth_mode = parsed_configs
            .iter()
            .find(|source| matches!(&source.kind, ConfigKind::User))
            .and_then(|source| source.auth_mode)
            .unwrap_or(CodexAuthMode::Auto);
        let auth_path = join_token(&home, "auth.json")?;
        state.add_file_candidate(
            known_folders,
            auth_path,
            ConfigScope::User,
            CodexTrustScope::Trusted,
            CandidateRole::Auth,
            ArtifactPolicy::SecretReference,
        );

        if state.candidates.is_empty() {
            return Ok(CodexDiscovery::empty());
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

        // Normalize each TOML layer only after its source artifact exists, so
        // every McpServerSpec points at the same tokenized ArtifactRef.
        let mut normalizations: Vec<Option<McpNormalization>> = vec![None; parsed_configs.len()];
        let mut mcp_reviews = Vec::new();
        for (index, source) in parsed_configs.iter().enumerate() {
            let Some(mcp_value) = source.document.get("mcp_servers") else {
                continue;
            };
            let Some(artifact) = artifact_by_path.get(&token_string(&source.path)).cloned() else {
                state.add_review(
                    source.path.clone(),
                    "Codex MCP source configuration was not safely collected",
                );
                continue;
            };
            let document = json!({
                "mcp_servers": toml_to_json(mcp_value).map_err(|_| {
                    discovery_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "Codex MCP configuration could not be converted safely",
                    )
                })?
            });
            let bytes = serde_json::to_vec(&document).map_err(|_| {
                discovery_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "Codex MCP configuration could not be serialized safely",
                )
            })?;
            let parser_options = McpParserOptions::new(source.scope.clone(), artifact)
                .with_known_folders(known_folders.clone())
                .with_references(options.references.clone());
            match normalize_mcp_config(&bytes, McpInputFormat::Json, &parser_options) {
                Ok(normalization) => normalizations[index] = Some(normalization),
                Err(error) => {
                    mcp_reviews.push((source.path.clone(), safe_mcp_review(&error)));
                    state.warnings.push(*error);
                }
            }
        }

        let mut result = CodexDiscovery {
            artifacts: collection_artifacts_sorted(artifacts),
            auth_mode: Some(auth_mode),
            warnings: state.warnings.clone(),
            ..CodexDiscovery::empty()
        };
        result.artifacts = collection_artifacts_sorted(result.artifacts);
        let mut path_components: BTreeMap<String, ComponentId> = BTreeMap::new();

        // Harness node is the install/configuration anchor.  It does not claim
        // that an executable or credential is portable.  Use a documented
        // config surface as the verification anchor required by restore.
        let fallback_harness_config = join_token(&home, "config.toml")?;
        let harness_verification = if let Some(artifact) =
            result.artifacts.iter().find(|artifact| {
                artifact.policy == ArtifactPolicy::Config
                    && matches!(
                        &artifact.content_type,
                        ContentType::Json | ContentType::Jsonc | ContentType::Toml
                    )
            }) {
            vec![VerificationRule::ConfigParses {
                destination: artifact.source_path.clone(),
                content_type: artifact.content_type.clone(),
            }]
        } else {
            vec![VerificationRule::ConfigParses {
                destination: fallback_harness_config,
                content_type: ContentType::Toml,
            }]
        };
        let harness_evidence = state.evidence(&home, "Codex home discovered");
        let harness_component = build_component(
            ComponentKind::Harness,
            "harness",
            "Codex",
            Vec::new(),
            &harness_evidence,
            harness_restore(),
            harness_verification,
            false,
            json_map([
                ("adapter", json!(ADAPTER_ID)),
                ("home", json!(token_string(&home))),
            ]),
        )?;
        let harness_id = harness_component.id.clone();
        result.components.push(harness_component);

        // Config and profile components.
        for (index, source) in parsed_configs.iter().enumerate() {
            let Some(artifact) = artifact_by_path.get(&token_string(&source.path)).cloned() else {
                continue;
            };
            let normalization = normalizations[index].clone();
            let safe_config = safe_config(source.document.clone(), normalization.as_ref());
            let config_id_key = match &source.kind {
                ConfigKind::User => format!("config:user:{}", token_string(&source.path)),
                ConfigKind::Project => format!("config:project:{}", token_string(&source.path)),
                ConfigKind::Profile(name) => {
                    format!("profile:{name}:{}", token_string(&source.path))
                }
            };
            let project_requires_review =
                source.scope == ConfigScope::Project && source.trust != CodexTrustScope::Trusted;
            let component = build_component(
                ComponentKind::Configuration,
                &config_id_key,
                config_display_name(&source.kind),
                vec![artifact.clone()],
                &state.evidence(&source.path, "Codex TOML configuration discovered"),
                config_restore(project_requires_review),
                vec![VerificationRule::ConfigParses {
                    destination: source.path.clone(),
                    content_type: ContentType::Toml,
                }],
                false,
                json_map([
                    ("scope", json!(scope_label(&source.scope))),
                    ("trust", json!(source.trust.label())),
                    ("safe_config", safe_config.clone()),
                    ("ignored_project_keys", json!(source.ignored_project_keys)),
                ]),
            )?;
            let component_id = component.id.clone();
            path_components.insert(token_string(&source.path), component_id.clone());
            result.components.push(component);
            let dependency = edge(
                component_id,
                harness_id.clone(),
                DependencyKind::Configures,
                &state.evidence(&source.path, "Codex configuration belongs to harness"),
            );
            result.edges.push(dependency.clone());
            if let Some(config_component) = result.components.last_mut() {
                config_component.dependencies.push(dependency);
            }

            match &source.kind {
                ConfigKind::Profile(name) => result.profiles.push(CodexProfile {
                    name: name.clone(),
                    path: source.path.clone(),
                    artifact,
                    safe_config,
                    auth_mode: source.auth_mode,
                    mcp: normalization,
                }),
                _ => result.configs.push(CodexConfigRecord {
                    path: source.path.clone(),
                    scope: source.scope.clone(),
                    trust: source.trust,
                    artifact,
                    safe_config,
                    auth_mode: source.auth_mode,
                    ignored_project_keys: source.ignored_project_keys.clone(),
                    mcp: normalization,
                }),
            }
        }
        let auth_candidate = state
            .candidates
            .values()
            .find(|candidate| matches!(&candidate.role, CandidateRole::Auth));
        let auth_artifact = auth_candidate
            .and_then(|candidate| {
                artifact_by_path
                    .get(&token_string(&candidate.path))
                    .cloned()
            })
            .filter(|_| matches!(auth_mode, CodexAuthMode::File | CodexAuthMode::Auto));
        if !parsed_configs.is_empty() || auth_candidate.is_some() {
            let auth_component =
                build_auth_component(auth_mode, auth_artifact.clone(), &mut state)?;
            let auth_id = auth_component.id.clone();
            result.components.push(auth_component);
            result.auth_reference = Some(CodexAuthReference {
                id: auth_id.clone(),
                mode: auth_mode,
                artifact: auth_artifact,
            });
            add_manual_action(
                &mut result.manual_actions,
                manual_action(
                    &auth_id,
                    "reauth",
                    "Sign in to Codex",
                    "Codex authentication is account-bound and is never copied",
                    vec![
                        "Run `codex login` on the target machine".to_owned(),
                        "Complete the documented ChatGPT or API-key sign-in flow".to_owned(),
                    ],
                    Some(AUTH_DOCS_URL),
                    RiskLevel::Medium,
                ),
            );
        }

        // Materialize config-backed instruction, skill, agent, hook, and auth
        // records.  Candidate paths remain tokenized throughout this phase.
        let candidates: Vec<ArtifactCandidate> = state.candidates.values().cloned().collect();
        for candidate in &candidates {
            let Some(artifact) = artifact_by_path
                .get(&token_string(&candidate.path))
                .cloned()
            else {
                continue;
            };
            match &candidate.role {
                CandidateRole::Instruction(kind) => {
                    let component = build_component(
                        ComponentKind::Configuration,
                        &format!("instruction:{}", token_string(&candidate.path)),
                        &format!("Codex {kind}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Codex instruction artifact discovered"),
                        config_restore(
                            candidate.trust != CodexTrustScope::Trusted
                                && candidate.scope == ConfigScope::Project,
                        ),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("scope", json!(scope_label(&candidate.scope))),
                            ("trust", json!(candidate.trust.label())),
                            ("instruction_kind", json!(kind)),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    path_components.insert(token_string(&candidate.path), component_id.clone());
                    result.components.push(component);
                    result.instructions.push(CodexInstruction {
                        kind: kind.clone(),
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        trust: candidate.trust,
                        artifact,
                    });
                    add_dependency(
                        &mut result,
                        component_id,
                        harness_id.clone(),
                        DependencyKind::Configures,
                        &state.evidence(&candidate.path, "Codex instruction belongs to harness"),
                    );
                }
                CandidateRole::Skill { name, enabled } => {
                    let component = build_component(
                        ComponentKind::Skill,
                        &format!("skill:{}", token_string(&candidate.path)),
                        &format!("Codex skill {name}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Codex skill metadata discovered"),
                        untrusted_restore("Codex skills are untrusted data"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("scope", json!(scope_label(&candidate.scope))),
                            ("trust", json!(candidate.trust.label())),
                            ("enabled", json!(enabled)),
                            ("content", json!("SKILL.md")),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    path_components.insert(token_string(&candidate.path), component_id.clone());
                    result.components.push(component);
                    result.skills.push(CodexSkill {
                        name: name.clone(),
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        trust: candidate.trust,
                        enabled: *enabled,
                        artifact,
                    });
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Codex skill belongs to harness"),
                    );
                    add_manual_action(
                        &mut result.manual_actions,
                        manual_action(
                            &component_id,
                            "skill-review",
                            "Review Codex skill before restore",
                            "Skills may contain executable workflow data and are never auto-executed",
                            vec![
                                "Select and review this skill explicitly before restoring it"
                                    .to_owned(),
                            ],
                            None,
                            RiskLevel::High,
                        ),
                    );
                }
                CandidateRole::Agent { name } => {
                    let component = build_component(
                        ComponentKind::Agent,
                        &format!("agent:{}", token_string(&candidate.path)),
                        &format!("Codex agent {name}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Codex agent metadata discovered"),
                        untrusted_restore("Codex agents are untrusted data"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("scope", json!(scope_label(&candidate.scope))),
                            ("trust", json!(candidate.trust.label())),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    path_components.insert(token_string(&candidate.path), component_id.clone());
                    result.components.push(component);
                    result.agents.push(CodexAgent {
                        name: name.clone(),
                        path: Some(candidate.path.clone()),
                        scope: candidate.scope.clone(),
                        trust: candidate.trust,
                        artifact: Some(artifact),
                    });
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Codex agent belongs to harness"),
                    );
                    add_manual_action(
                        &mut result.manual_actions,
                        manual_action(
                            &component_id,
                            "agent-review",
                            "Review Codex agent before restore",
                            "Agent definitions are untrusted data and are never auto-executed",
                            vec![
                                "Select and review this agent explicitly before restoring it"
                                    .to_owned(),
                            ],
                            None,
                            RiskLevel::High,
                        ),
                    );
                }
                CandidateRole::HookFile => {
                    let hooks = parse_hook_file(known_folders, &candidate.path, &mut state);
                    for hook in hooks {
                        materialize_hook(
                            &mut result,
                            &mut path_components,
                            &harness_id,
                            candidate,
                            Some(artifact.clone()),
                            hook,
                            &mut state,
                        )?;
                    }
                }
                CandidateRole::Config | CandidateRole::Profile | CandidateRole::Auth => {}
            }
        }

        // Inline [hooks] and [agents] records are metadata on the config
        // artifact, not commands to execute.
        for source in &parsed_configs {
            let Some(config_artifact) = artifact_by_path.get(&token_string(&source.path)).cloned()
            else {
                continue;
            };
            for hook in inline_hooks(&source.document) {
                materialize_hook(
                    &mut result,
                    &mut path_components,
                    &harness_id,
                    &ArtifactCandidate {
                        path: source.path.clone(),
                        scope: source.scope.clone(),
                        trust: source.trust,
                        role: CandidateRole::Config,
                        policy: ArtifactPolicy::Config,
                    },
                    Some(config_artifact.clone()),
                    hook,
                    &mut state,
                )?;
            }
            if let Some(agents) = source
                .document
                .get("agents")
                .and_then(|value| value.as_table())
            {
                for name in agents.keys() {
                    let Some(name) = safe_name(name) else {
                        continue;
                    };
                    let component = build_component(
                        ComponentKind::Agent,
                        &format!("inline-agent:{}:{}", token_string(&source.path), name),
                        &format!("Codex agent {name}"),
                        vec![config_artifact.clone()],
                        &state.evidence(&source.path, "Inline Codex agent discovered"),
                        untrusted_restore("Codex agents are untrusted data"),
                        vec![VerificationRule::File {
                            destination: source.path.clone(),
                            object: config_artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("scope", json!(scope_label(&source.scope))),
                            ("trust", json!(source.trust.label())),
                            ("inline", json!(true)),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    result.agents.push(CodexAgent {
                        name: name.to_owned(),
                        path: None,
                        scope: source.scope.clone(),
                        trust: source.trust,
                        artifact: Some(config_artifact.clone()),
                    });
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&source.path, "Inline Codex agent belongs to harness"),
                    );
                    add_manual_action(
                        &mut result.manual_actions,
                        manual_action(
                            &component_id,
                            "agent-review",
                            "Review Codex agent before restore",
                            "Agent definitions are untrusted data and are never auto-executed",
                            vec![
                                "Select and review this agent explicitly before restoring it"
                                    .to_owned(),
                            ],
                            None,
                            RiskLevel::High,
                        ),
                    );
                }
            }
        }

        // Build semantic MCP and secret-reference nodes from every normalized
        // layer, including profile files.
        let mut seen_secrets = BTreeSet::new();
        let mut seen_servers = BTreeSet::new();
        for normalization in normalizations.into_iter().flatten() {
            for secret in normalization.secret_references {
                if seen_secrets.insert(secret.id.clone()) {
                    result.secret_references.push(secret.clone());
                    let component = build_secret_component(&secret, &mut state)?;
                    result.components.push(component);
                }
            }
            for review in normalization.manual_reviews {
                result.warnings.push(mcp_review_warning(&review));
            }
            for server in normalization.servers {
                let server_key = format!("{}:{}", scope_label(&server.scope), server.name);
                if !seen_servers.insert(server_key) {
                    continue;
                }
                let component = build_mcp_component(
                    &server,
                    &harness_id,
                    &state.evidence(
                        &server.source_config.source_path,
                        "Codex MCP server discovered",
                    ),
                )?;
                let component_id = component.id.clone();
                for secret in result
                    .secret_references
                    .iter()
                    .filter(|secret| secret.server == server.name)
                {
                    let dependency = edge(
                        component_id.clone(),
                        secret.id.clone(),
                        DependencyKind::UsesSecret,
                        &state.evidence(
                            &server.source_config.source_path,
                            "Codex MCP server references a secret",
                        ),
                    );
                    result.edges.push(dependency.clone());
                    // The component is appended below, after all dependencies
                    // are assembled, to keep its dependency list complete.
                }
                let mut component = component;
                for secret in result
                    .secret_references
                    .iter()
                    .filter(|secret| secret.server == server.name)
                {
                    component.dependencies.push(edge(
                        component_id.clone(),
                        secret.id.clone(),
                        DependencyKind::UsesSecret,
                        &state.evidence(
                            &server.source_config.source_path,
                            "Codex MCP server references a secret",
                        ),
                    ));
                }
                component.dependencies.push(edge(
                    component_id.clone(),
                    harness_id.clone(),
                    DependencyKind::Configures,
                    &state.evidence(
                        &server.source_config.source_path,
                        "Codex MCP server belongs to harness",
                    ),
                ));
                result.edges.push(
                    component
                        .dependencies
                        .last()
                        .cloned()
                        .expect("MCP harness edge"),
                );
                result.mcp_servers.push(server);
                result.components.push(component);
            }
        }

        // Project trust and ignored machine-local keys are explicit manual
        // boundaries, never silently applied during restore.
        for source in &parsed_configs {
            if source.scope == ConfigScope::Project
                && source.trust != CodexTrustScope::Trusted
                && let Some(component) = path_components.get(&token_string(&source.path))
            {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        component,
                        "project-trust",
                        "Review untrusted Codex project configuration",
                        "Codex project configuration is loaded only for trusted projects",
                        vec!["Trust the project explicitly before restoring this layer".to_owned()],
                        None,
                        RiskLevel::High,
                    ),
                );
            }
            if !source.ignored_project_keys.is_empty()
                && let Some(component) = path_components.get(&token_string(&source.path))
            {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        component,
                        "project-policy",
                        "Review Codex project policy overrides",
                        "Project configuration cannot override machine-local Codex policy",
                        vec!["Review the ignored machine-local keys on the target".to_owned()],
                        None,
                        RiskLevel::Medium,
                    ),
                );
            }
        }
        for (path, reason) in mcp_reviews {
            if let Some(component) = path_components.get(&token_string(&path)) {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        component,
                        "mcp-review",
                        "Review Codex MCP configuration",
                        &reason,
                        vec![
                            "Inspect the MCP entry and approve it explicitly before restore"
                                .to_owned(),
                        ],
                        None,
                        RiskLevel::High,
                    ),
                );
            }
        }
        for review in state.reviews {
            if let Some(component) = path_components.get(&token_string(&review.path)) {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        component,
                        "config-review",
                        "Review Codex configuration boundary",
                        &review.reason,
                        vec!["Resolve the configuration boundary before restoring it".to_owned()],
                        None,
                        RiskLevel::Medium,
                    ),
                );
            }
        }

        if auth_mode == CodexAuthMode::Unknown {
            let component = result
                .auth_reference
                .as_ref()
                .map(|reference| reference.id.clone());
            if let Some(component) = component {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        &component,
                        "auth-mode",
                        "Review Codex authentication storage",
                        "The configured Codex credential storage mode is not documented",
                        vec!["Choose file, keyring, or auto storage on the target".to_owned()],
                        Some(AUTH_DOCS_URL),
                        RiskLevel::High,
                    ),
                );
            }
        }

        // Stable output ordering prevents filesystem enumeration order from
        // changing package graphs or tests.
        result
            .components
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
        });
        result.evidence = state.evidence_records;
        result
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        result
            .manual_actions
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.manual_actions.truncate(MAX_MANUAL_ACTIONS);
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

    fn add_file_candidate(
        &mut self,
        known_folders: &KnownFolderMap,
        path: PathToken,
        scope: ConfigScope,
        trust: CodexTrustScope,
        role: CandidateRole,
        policy: ArtifactPolicy,
    ) {
        match entry_kind(known_folders, &path) {
            Ok(Some(EntryKind::File)) => {
                self.candidates
                    .entry(token_string(&path))
                    .or_insert(ArtifactCandidate {
                        path,
                        scope,
                        trust,
                        role,
                        policy,
                    });
            }
            Ok(Some(EntryKind::Directory)) => {}
            Ok(None) => {}
            Err(error) => self.push_warning(*error),
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
        let locator = format!("codex:{}:{}", token_string(path), summary);
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &locator);
        let id = EvidenceId::new(format!("codex-evidence-{}", hasher.finalize().to_hex()))
            .expect("hashed Codex evidence ID");
        let evidence = Evidence {
            id: id.clone(),
            source: EvidenceSource::Harness,
            locator,
            observed_at: self.observed_at,
            summary: summary.to_owned(),
            strength: 90,
            independent_group: "codex-config".to_owned(),
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
    trust: CodexTrustScope,
    role: CandidateRole,
    policy: ArtifactPolicy,
}

#[derive(Clone, Debug)]
enum CandidateRole {
    Config,
    Profile,
    Instruction(String),
    Skill { name: String, enabled: Option<bool> },
    Agent { name: String },
    HookFile,
    Auth,
}

#[derive(Clone, Debug)]
enum DirectoryRole {
    Skills { enabled: Option<bool> },
    Agents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug)]
enum ConfigKind {
    User,
    Profile(String),
    Project,
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    path: PathToken,
    scope: ConfigScope,
    trust: CodexTrustScope,
    kind: ConfigKind,
    document: toml::Value,
    auth_mode: Option<CodexAuthMode>,
    ignored_project_keys: Vec<String>,
}

#[derive(Clone, Debug)]
struct HookData {
    event: String,
    matcher: Option<String>,
    command: Option<String>,
}

fn resolve_codex_home(
    known_folders: &KnownFolderMap,
    environment: &BTreeMap<String, String>,
) -> Result<PathToken, Box<ErrorEnvelope>> {
    let configured = environment
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case("CODEX_HOME") && !value.trim().is_empty())
        .map(|(_, value)| value.as_str());
    if let Some(raw) = configured {
        let path = PathBuf::from(raw);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(discovery_error(
                ReforgeErrorCode::InvalidPath,
                "CODEX_HOME must be an absolute path without parent segments",
            ));
        }
        return token_for_absolute_path(known_folders, &path).ok_or_else(|| {
            discovery_error(
                ReforgeErrorCode::SecurityPolicy,
                "CODEX_HOME is outside the known-folder map",
            )
        });
    }
    PathToken::new(KnownFolderToken::UserProfile, ".codex").map_err(|_| {
        discovery_error(
            ReforgeErrorCode::InvalidPath,
            "The default Codex home token could not be constructed",
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
            "A Codex path could not be represented as a safe token",
        )
    })
}

fn parent_token(path: &PathToken) -> Result<PathToken, Box<ErrorEnvelope>> {
    let parent = path
        .relative
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    PathToken::new(path.root.clone(), parent).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::InvalidPath,
            "A Codex config parent could not be represented as a safe token",
        )
    })
}

fn resolve_config_path(
    known_folders: &KnownFolderMap,
    config_path: &PathToken,
    raw: &str,
) -> Result<Option<PathToken>, Box<ErrorEnvelope>> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let raw_path = Path::new(raw);
    let token = if raw_path.is_absolute() {
        token_for_absolute_path(known_folders, raw_path)
    } else {
        Some(join_token(&parent_token(config_path)?, raw)?)
    };
    Ok(token)
}

fn existing_file(
    known_folders: &KnownFolderMap,
    path: &PathToken,
    state: &mut DiscoveryState,
) -> Option<PathToken> {
    match entry_kind(known_folders, path) {
        Ok(Some(EntryKind::File)) => Some(path.clone()),
        Ok(_) => None,
        Err(error) => {
            state.push_warning(*error);
            None
        }
    }
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
            "A Codex path could not be inspected",
        ))),
    }
}

fn profile_paths(
    known_folders: &KnownFolderMap,
    home: &PathToken,
    state: &mut DiscoveryState,
) -> Vec<(String, PathToken)> {
    let Ok(absolute) = known_folders.resolve(home) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(absolute) else {
        return Vec::new();
    };
    let mut profiles = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let lower = file_name.to_ascii_lowercase();
        if !lower.ends_with(".config.toml") || lower == "config.toml" {
            continue;
        }
        let name = file_name[..file_name.len() - ".config.toml".len()].to_owned();
        if !valid_profile_name(&name) {
            state.add_review(
                home.clone(),
                "A Codex profile filename is not a documented profile name",
            );
            continue;
        }
        let Ok(path) = join_token(home, &file_name) else {
            state.add_review(home.clone(), "A Codex profile path could not be tokenized");
            continue;
        };
        if matches!(entry_kind(known_folders, &path), Ok(Some(EntryKind::File))) {
            profiles.push((name, path));
        }
    }
    profiles.sort_by(|left, right| left.0.cmp(&right.0));
    profiles
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn add_directory_candidates(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    directory: &PathToken,
    scope: ConfigScope,
    trust: CodexTrustScope,
    role: DirectoryRole,
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
        let Ok(path) = join_token(directory, observation.path.as_str()) else {
            state.add_review(
                directory.clone(),
                "A Codex directory entry could not be tokenized",
            );
            continue;
        };
        match &role {
            DirectoryRole::Skills { enabled } => {
                if observation
                    .path
                    .as_str()
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
                {
                    state.add_file_candidate(
                        known_folders,
                        path.clone(),
                        scope.clone(),
                        trust,
                        CandidateRole::Skill {
                            name: skill_name_from_path(&path),
                            enabled: *enabled,
                        },
                        ArtifactPolicy::Manual,
                    );
                }
            }
            DirectoryRole::Agents => {
                let name = observation
                    .path
                    .as_str()
                    .rsplit('/')
                    .next()
                    .and_then(safe_name)
                    .unwrap_or_else(|| "agent".to_owned());
                state.add_file_candidate(
                    known_folders,
                    path,
                    scope.clone(),
                    trust,
                    CandidateRole::Agent { name },
                    ArtifactPolicy::Manual,
                );
            }
        }
    }
}

fn parse_config_source(
    known_folders: &KnownFolderMap,
    path: PathToken,
    scope: ConfigScope,
    trust: CodexTrustScope,
    kind: ConfigKind,
) -> Result<ParsedConfig, Box<ErrorEnvelope>> {
    let bytes = read_bounded(known_folders, &path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::ProviderParseFailed,
            "Codex TOML configuration is not valid UTF-8",
        )
    })?;
    let document: toml::Value = toml::from_str(text).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::ProviderParseFailed,
            "Codex TOML configuration could not be parsed",
        )
    })?;
    let auth_mode = document
        .get("cli_auth_credentials_store")
        .and_then(|value| value.as_str())
        .map(parse_auth_mode);
    let ignored_project_keys = if scope == ConfigScope::Project {
        const MACHINE_KEYS: &[&str] = &[
            "openai_base_url",
            "chatgpt_base_url",
            "apps_mcp_product_sku",
            "model_provider",
            "model_providers",
            "notify",
            "profile",
            "profiles",
            "experimental_realtime_ws_base_url",
            "otel",
            "cli_auth_credentials_store",
        ];
        let table = document.as_table().ok_or_else(|| {
            discovery_error(
                ReforgeErrorCode::SchemaInvalid,
                "Codex TOML configuration root must be a table",
            )
        })?;
        let mut keys: Vec<_> = table
            .keys()
            .filter(|key| MACHINE_KEYS.iter().any(|candidate| candidate == key))
            .cloned()
            .collect();
        keys.sort();
        keys
    } else {
        Vec::new()
    };
    Ok(ParsedConfig {
        path,
        scope,
        trust,
        kind,
        document,
        auth_mode,
        ignored_project_keys,
    })
}

fn parse_auth_mode(value: &str) -> CodexAuthMode {
    match value.trim().to_ascii_lowercase().as_str() {
        "file" => CodexAuthMode::File,
        "keyring" => CodexAuthMode::Keyring,
        "auto" => CodexAuthMode::Auto,
        _ => CodexAuthMode::Unknown,
    }
}

fn configured_skill_paths(document: &toml::Value) -> Vec<(String, Option<bool>)> {
    document
        .get("skills")
        .and_then(|skills| skills.as_table())
        .and_then(|skills| skills.get("config"))
        .and_then(|skills| skills.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let table = entry.as_table()?;
            let path = table.get("path")?.as_str()?.to_owned();
            let enabled = table.get("enabled").and_then(|value| value.as_bool());
            Some((path, enabled))
        })
        .collect()
}

fn string_field<'a>(document: &'a toml::Value, key: &str) -> Option<&'a str> {
    document.get(key).and_then(|value| value.as_str())
}

fn read_bounded(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let root = known_folders.entries.get(&path.root).ok_or_else(|| {
        discovery_error(
            ReforgeErrorCode::PathNotFound,
            "Codex path root is not available",
        )
    })?;
    let safe_path = SafePath::from_token(path)?;
    let mut reader = BoundedFileReader::open(root, &safe_path, MAX_TEXT_BYTES)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

fn parse_hook_file(
    known_folders: &KnownFolderMap,
    path: &PathToken,
    state: &mut DiscoveryState,
) -> Vec<HookData> {
    let bytes = match read_bounded(known_folders, path) {
        Ok(bytes) => bytes,
        Err(error) => {
            state.push_warning(*error);
            return Vec::new();
        }
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            state.push_warning(*discovery_error(
                ReforgeErrorCode::ProviderParseFailed,
                "Codex hooks.json could not be parsed",
            ));
            state.add_review(path.clone(), "Codex hooks.json requires manual review");
            return Vec::new();
        }
    };
    hook_data_from_json(&value)
}

fn inline_hooks(document: &toml::Value) -> Vec<HookData> {
    let Some(hooks) = document.get("hooks") else {
        return Vec::new();
    };
    hook_data_from_json(&toml_to_json(hooks).unwrap_or(Value::Null))
}

fn hook_data_from_json(value: &Value) -> Vec<HookData> {
    let Some(events) = value.as_object() else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for (event, entries) in events {
        let entries = entries
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![entries.clone()]);
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            let matcher = object
                .get("matcher")
                .and_then(Value::as_str)
                .and_then(redact_text);
            let nested = object
                .get("hooks")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| vec![Value::Object(object.clone())]);
            for hook in nested {
                let Some(hook) = hook.as_object() else {
                    continue;
                };
                let command = hook
                    .get("command")
                    .and_then(Value::as_str)
                    .and_then(redact_text);
                output.push(HookData {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    command,
                });
            }
        }
    }
    output
}

fn materialize_hook(
    result: &mut CodexDiscovery,
    _path_components: &mut BTreeMap<String, ComponentId>,
    harness_id: &ComponentId,
    candidate: &ArtifactCandidate,
    artifact: Option<ArtifactRef>,
    hook: HookData,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let artifact_list = artifact.clone().into_iter().collect::<Vec<_>>();
    let key = format!(
        "hook:{}:{}:{}",
        token_string(&candidate.path),
        hook.event,
        hook.matcher.as_deref().unwrap_or("")
    );
    let component = build_component(
        ComponentKind::Hook,
        &key,
        &format!("Codex hook {}", hook.event),
        artifact_list,
        &state.evidence(&candidate.path, "Codex hook metadata discovered"),
        untrusted_restore("Codex hooks are untrusted data"),
        vec![VerificationRule::File {
            destination: candidate.path.clone(),
            object: artifact.as_ref().and_then(|value| value.object.clone()),
        }],
        false,
        json_map([
            ("scope", json!(scope_label(&candidate.scope))),
            ("trust", json!(candidate.trust.label())),
            ("event", json!(hook.event.clone())),
            ("matcher", json!(hook.matcher.clone())),
            ("command", json!(hook.command.clone())),
            ("executed", json!(false)),
        ]),
    )?;
    let component_id = component.id.clone();
    result.components.push(component);
    result.hooks.push(CodexHook {
        event: hook.event,
        matcher: hook.matcher,
        command: hook.command,
        path: Some(candidate.path.clone()),
        scope: candidate.scope.clone(),
        trust: candidate.trust,
        artifact,
    });
    add_dependency(
        result,
        component_id.clone(),
        harness_id.clone(),
        DependencyKind::Contains,
        &state.evidence(&candidate.path, "Codex hook belongs to harness"),
    );
    add_manual_action(
        &mut result.manual_actions,
        manual_action(
            &component_id,
            "hook-review",
            "Review Codex hook before restore",
            "Hook commands are untrusted metadata and are never auto-executed",
            vec!["Select and review this hook explicitly before restoring it".to_owned()],
            None,
            RiskLevel::High,
        ),
    );
    Ok(())
}

fn build_auth_component(
    mode: CodexAuthMode,
    artifact: Option<ArtifactRef>,
    state: &mut DiscoveryState,
) -> Result<Component, Box<ErrorEnvelope>> {
    let artifacts = artifact.clone().into_iter().collect::<Vec<_>>();
    let evidence_path = artifact
        .as_ref()
        .map(|value| value.source_path.clone())
        .unwrap_or_else(|| {
            PathToken::new(KnownFolderToken::UserProfile, ".codex").expect("default Codex path")
        });
    build_component(
        ComponentKind::SecretReference,
        &format!("auth:{}", mode.label()),
        "Codex authentication",
        artifacts,
        &state.evidence(&evidence_path, "Codex authentication storage discovered"),
        RestoreDescriptor {
            primary: RestoreStrategy::ReauthRequired,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::ReauthRequired,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "Codex authentication is account-bound and credential values are not copied"
                    .to_owned(),
            ],
        },
        vec![],
        true,
        json_map([
            ("storage_mode", json!(mode.label())),
            ("credential_values_read", json!(false)),
            ("auth_file_present", json!(artifact.is_some())),
        ]),
    )
}

fn build_secret_component(
    secret: &McpSecretReference,
    state: &mut DiscoveryState,
) -> Result<Component, Box<ErrorEnvelope>> {
    let component = build_component(
        ComponentKind::SecretReference,
        &format!("mcp-secret:{}:{}", secret.server, secret.source_field),
        &format!("MCP secret reference {}", secret.label),
        Vec::new(),
        &state.evidence(
            &PathToken::new(KnownFolderToken::UserProfile, ".codex/config.toml")
                .expect("default Codex source path"),
            "Codex MCP secret reference discovered",
        ),
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
            ("label", json!(secret.label.clone())),
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
    harness_id: &ComponentId,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    let mut component = build_component(
        ComponentKind::McpServer,
        &format!("mcp:{}:{}", scope_label(&server.scope), server.name),
        &format!("MCP server {}", server.name),
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
                "Referenced runtimes, packages, and secrets require separate target review"
                    .to_owned(),
            ],
        },
        vec![VerificationRule::McpRegistration {
            name: server.name.clone(),
            config: server.source_config.source_path.clone(),
        }],
        false,
        json_map([
            ("scope", json!(scope_label(&server.scope))),
            (
                "mcp",
                serde_json::to_value(server).map_err(|_| {
                    discovery_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "Codex MCP server could not be serialized safely",
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
        name: "OpenAI".to_owned(),
        certificate_thumbprint: None,
    };
    let mut identity = Identity {
        provider_package: None,
        provider_source: None,
        package_family: Some(format!("codex:{key}")),
        product_name: Some("Codex".to_owned()),
        executable_name: None,
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some(format!("{kind:?}")),
        identity_quality: IdentityQuality::PackageFamily,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "Codex component identity could not be canonicalized",
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
            package_id: Some("codex".to_owned()),
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

fn config_display_name(kind: &ConfigKind) -> &'static str {
    match kind {
        ConfigKind::User => "Codex user configuration",
        ConfigKind::Profile(_) => "Codex profile configuration",
        ConfigKind::Project => "Codex project configuration",
    }
}

fn harness_restore() -> RestoreDescriptor {
    RestoreDescriptor {
        primary: RestoreStrategy::Reinstall,
        alternatives: vec![RestoreStrategy::Manual],
        portability: Portability::PartiallyPortable,
        requires_elevation: false,
        requires_user_action: true,
        rationale: vec![
            "The harness executable is an install-time dependency; this adapter restores configuration only".to_owned(),
        ],
    }
}

fn config_restore(project_requires_review: bool) -> RestoreDescriptor {
    if project_requires_review {
        RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: vec![RestoreStrategy::ConfigPortable],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "Project Codex configuration requires an explicit trust decision".to_owned(),
            ],
        }
    } else {
        RestoreDescriptor {
            primary: RestoreStrategy::ConfigPortable,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::Portable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec!["Documented Codex configuration is portable data".to_owned()],
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

fn add_dependency(
    result: &mut CodexDiscovery,
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

fn manual_action(
    component: &ComponentId,
    kind: &str,
    title: &str,
    reason: &str,
    instructions: Vec<String>,
    docs_url: Option<&str>,
    risk: RiskLevel,
) -> ManualAction {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, component.as_str());
    hash_field(&mut hasher, kind);
    ManualAction {
        id: format!("codex-manual-{}", hasher.finalize().to_hex()),
        component: Some(component.clone()),
        title: title.to_owned(),
        reason: reason.to_owned(),
        risk,
        instructions,
        docs_url: docs_url.and_then(|value| url::Url::parse(value).ok()),
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

fn safe_config(document: toml::Value, normalization: Option<&McpNormalization>) -> Value {
    let mut safe = toml_to_json(&document)
        .ok()
        .and_then(|value| RedactionPolicy::default().redact_json(&value))
        .unwrap_or_else(|| json!({"redacted": true}));
    if let Some(normalization) = normalization
        && let (Some(safe_object), Some(mcp_safe)) = (
            safe.as_object_mut(),
            normalization.safe_config.get("mcp_servers"),
        )
    {
        safe_object.insert("mcp_servers".to_owned(), mcp_safe.clone());
    }
    safe
}

fn toml_to_json(value: &toml::Value) -> Result<Value, serde_json::Error> {
    serde_json::to_value(value)
}

fn mcp_review_warning(review: &McpManualReview) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ReforgeErrorCode::ManualActionRequired,
        "Codex MCP configuration contains a value requiring manual review",
    )
    .with_context_id(format!("codex-mcp:{}:{}", review.server, review.field))
}

fn safe_mcp_review(error: &ErrorEnvelope) -> String {
    match error.code {
        ReforgeErrorCode::ManualActionRequired => {
            "Codex MCP configuration requires manual review".to_owned()
        }
        ReforgeErrorCode::SchemaInvalid => {
            "Codex MCP configuration has an unsupported documented shape".to_owned()
        }
        _ => "Codex MCP configuration could not be normalized safely".to_owned(),
    }
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

fn project_trust(options: &CodexDiscoveryOptions, root: &PathToken) -> CodexTrustScope {
    options
        .project_trust
        .get(&token_string(root))
        .copied()
        .unwrap_or_default()
}

fn token_string(path: &PathToken) -> String {
    format!("{:?}/{}", path.root, path.relative)
}

fn skill_name_from_path(path: &PathToken) -> String {
    let mut parts = path.relative.rsplit('/');
    let _ = parts.next();
    parts
        .next()
        .and_then(safe_name)
        .unwrap_or_else(|| "skill".to_owned())
}

fn safe_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_owned())
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

fn collection_artifacts_sorted(mut artifacts: Vec<ArtifactRef>) -> Vec<ArtifactRef> {
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    artifacts
}

fn discovery_error(code: ReforgeErrorCode, message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(code, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_follow_documented_filename_grammar() {
        assert!(valid_profile_name("deep-review_2"));
        assert!(!valid_profile_name("deep.review"));
        assert!(!valid_profile_name(""));
    }

    #[test]
    fn auth_mode_unknown_is_not_promoted_to_file_or_keyring() {
        assert_eq!(parse_auth_mode("file"), CodexAuthMode::File);
        assert_eq!(parse_auth_mode("keyring"), CodexAuthMode::Keyring);
        assert_eq!(parse_auth_mode("auto"), CodexAuthMode::Auto);
        assert_eq!(parse_auth_mode("credential-helper"), CodexAuthMode::Unknown);
    }
}
