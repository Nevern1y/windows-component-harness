//! Claude Code configuration discovery and safe normalization.
//!
//! This adapter inspects only documented Claude Code configuration roots. It
//! records settings, MCP, skills, commands, agents, hooks, and plugin metadata
//! as typed, reviewable discovery output; it never executes discovered code.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use reforge_domain::{
    ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, Confidence,
    ConfigScope, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence, EvidenceId, EvidenceRef,
    EvidenceSource, Identity, IdentityQuality, KnownFolderToken, ManualAction, ManualActionState,
    McpServerSpec, PathToken, Portability, Publisher, RedactionPolicy, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, RiskLevel, SelectionMetadata, VerificationRule,
    redact_text,
};
use reforge_platform_windows::{
    BoundedFileReader, FileObservationKind, KnownFolderMap, SafePath, WalkLimits, walk_reparse_safe,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::mcp::{
    McpInputFormat, McpManualReview, McpNormalization, McpReferenceCatalog, McpSecretReference,
    normalize_mcp_config,
};

const ADAPTER_ID: &str = "claude-code";
const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_DIRECTORY_DEPTH: usize = 8;
const MAX_MANUAL_ACTIONS: usize = 4_096;
const MAX_WARNINGS: usize = 4_096;
const CLAUDE_DOCS_URL: &str = "https://code.claude.com/docs/en/settings";

/// Trust state supplied by the caller for a project-scoped Claude layer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeTrustScope {
    Trusted,
    Untrusted,
    #[default]
    Unknown,
}

impl ClaudeTrustScope {
    fn label(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Unknown => "unknown",
        }
    }
}

/// Inputs for a deterministic Claude Code discovery run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaudeDiscoveryOptions {
    /// Project roots whose `.claude` and `.mcp.json` layers are inspected.
    pub project_roots: Vec<PathToken>,
    /// Trust decisions for project roots. Missing entries remain `Unknown`.
    pub project_trust: BTreeMap<String, ClaudeTrustScope>,
    /// Environment visible to the discovery call. Only `CLAUDE_CONFIG_DIR` is read.
    pub environment: BTreeMap<String, String>,
    /// Known executable/runtime/package references passed to MCP normalization.
    pub references: McpReferenceCatalog,
    /// Optional timestamp used by deterministic tests.
    pub observed_at: Option<DateTime<Utc>>,
}

impl ClaudeDiscoveryOptions {
    /// Build options from the current process environment.
    pub fn current(project_roots: Vec<PathToken>, references: McpReferenceCatalog) -> Self {
        Self {
            project_roots,
            environment: env::vars().collect(),
            references,
            ..Self::default()
        }
    }

    pub fn with_project_trust(mut self, project_root: PathToken, trust: ClaudeTrustScope) -> Self {
        self.project_trust
            .insert(token_string(&project_root), trust);
        self
    }

    pub fn with_observed_at(mut self, observed_at: DateTime<Utc>) -> Self {
        self.observed_at = Some(observed_at);
        self
    }
}

/// One Claude settings file and its redacted package-facing representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeSettingsRecord {
    pub path: PathToken,
    pub scope: ConfigScope,
    pub local: bool,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
    pub safe_config: Value,
}

/// A standalone or plugin skill.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeSkill {
    pub name: String,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
}

/// A standalone or plugin command file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeCommand {
    pub name: String,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
}

/// A standalone or plugin agent definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeAgent {
    pub name: String,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
}

/// A project instruction file such as `CLAUDE.md`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeInstruction {
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
}

/// Hook metadata. Commands are redacted metadata and are never executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeHook {
    pub event: String,
    pub matcher: Option<String>,
    pub command: Option<String>,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub artifact: ArtifactRef,
}

/// A plugin manifest and its bounded executable metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudePlugin {
    pub name: String,
    pub version: Option<String>,
    pub path: PathToken,
    pub scope: ConfigScope,
    pub namespace: String,
    pub trust: ClaudeTrustScope,
    pub manifest: Value,
    pub artifact: ArtifactRef,
    pub binaries: Vec<PathToken>,
}

/// Complete result of a Claude Code discovery run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeDiscovery {
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub evidence: Vec<Evidence>,
    pub artifacts: Vec<ArtifactRef>,
    pub settings: Vec<ClaudeSettingsRecord>,
    pub instructions: Vec<ClaudeInstruction>,
    pub skills: Vec<ClaudeSkill>,
    pub commands: Vec<ClaudeCommand>,
    pub agents: Vec<ClaudeAgent>,
    pub hooks: Vec<ClaudeHook>,
    pub plugins: Vec<ClaudePlugin>,
    pub mcp_servers: Vec<McpServerSpec>,
    pub secret_references: Vec<McpSecretReference>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
}

impl ClaudeDiscovery {
    fn empty() -> Self {
        Self {
            components: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            artifacts: Vec::new(),
            settings: Vec::new(),
            instructions: Vec::new(),
            skills: Vec::new(),
            commands: Vec::new(),
            agents: Vec::new(),
            hooks: Vec::new(),
            plugins: Vec::new(),
            mcp_servers: Vec::new(),
            secret_references: Vec::new(),
            manual_actions: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Adapter for documented Claude Code settings and extension layouts.
#[derive(Clone, Debug, Default)]
pub struct ClaudeCodeAdapter {
    collector: crate::ArtifactCollector,
}

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self {
            collector: crate::ArtifactCollector::default(),
        }
    }

    /// Discover Claude Code using the current process environment.
    pub fn discover(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        references: McpReferenceCatalog,
    ) -> Result<ClaudeDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &ClaudeDiscoveryOptions::current(project_roots.to_vec(), references),
        )
    }

    /// Discover Claude Code with a supplied environment for isolated tests.
    pub fn discover_with_environment(
        &self,
        known_folders: &KnownFolderMap,
        project_roots: &[PathToken],
        environment: BTreeMap<String, String>,
        references: McpReferenceCatalog,
    ) -> Result<ClaudeDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_options(
            known_folders,
            &ClaudeDiscoveryOptions {
                project_roots: project_roots.to_vec(),
                environment,
                references,
                ..ClaudeDiscoveryOptions::default()
            },
        )
    }

    /// Discover Claude Code with fully controlled trust, environment, and time.
    pub fn discover_with_options(
        &self,
        known_folders: &KnownFolderMap,
        options: &ClaudeDiscoveryOptions,
    ) -> Result<ClaudeDiscovery, Box<ErrorEnvelope>> {
        let observed_at = options.observed_at.unwrap_or_else(Utc::now);
        let config_home = resolve_config_home(known_folders, &options.environment)?;
        let mut state = DiscoveryState::new(observed_at);
        let user_namespace = "user".to_owned();
        let user_trust = ClaudeTrustScope::Trusted;

        add_file_candidate(
            known_folders,
            &mut state,
            join_token(&config_home, "settings.json")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            CandidateRole::Settings { local: false },
            ArtifactPolicy::Config,
        );
        add_file_candidate(
            known_folders,
            &mut state,
            join_token(&config_home, "CLAUDE.md")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            CandidateRole::Instruction,
            ArtifactPolicy::Config,
        );
        let user_parent = parent_token(&config_home)?;
        add_file_candidate(
            known_folders,
            &mut state,
            join_token(&user_parent, ".claude.json")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            CandidateRole::Mcp,
            ArtifactPolicy::Config,
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&config_home, "skills")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            DirectoryRole::Skills { plugin_root: None },
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&config_home, "commands")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            DirectoryRole::Commands { plugin_root: None },
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&config_home, "agents")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            DirectoryRole::Agents { plugin_root: None },
        );
        add_directory_candidates(
            known_folders,
            &mut state,
            &join_token(&config_home, "hooks")?,
            ConfigScope::User,
            user_trust,
            user_namespace.clone(),
            DirectoryRole::Hooks,
        );
        discover_plugins(
            known_folders,
            &mut state,
            &config_home,
            ConfigScope::User,
            user_trust,
        );

        let mut project_roots = options.project_roots.clone();
        project_roots.sort_by_key(token_string);
        project_roots.dedup();
        for project_root in project_roots {
            let trust = project_trust(options, &project_root);
            let project_namespace = format!("project:{}", token_string(&project_root));
            let project_claude = join_token(&project_root, ".claude")?;
            add_file_candidate(
                known_folders,
                &mut state,
                join_token(&project_claude, "settings.json")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                CandidateRole::Settings { local: false },
                ArtifactPolicy::Config,
            );
            add_file_candidate(
                known_folders,
                &mut state,
                join_token(&project_claude, "settings.local.json")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                CandidateRole::Settings { local: true },
                ArtifactPolicy::Config,
            );
            add_file_candidate(
                known_folders,
                &mut state,
                join_token(&project_root, ".mcp.json")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                CandidateRole::Mcp,
                ArtifactPolicy::Config,
            );
            add_file_candidate(
                known_folders,
                &mut state,
                join_token(&project_root, "CLAUDE.md")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                CandidateRole::Instruction,
                ArtifactPolicy::Config,
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_claude, "skills")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                DirectoryRole::Skills { plugin_root: None },
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_claude, "commands")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                DirectoryRole::Commands { plugin_root: None },
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_claude, "agents")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                DirectoryRole::Agents { plugin_root: None },
            );
            add_directory_candidates(
                known_folders,
                &mut state,
                &join_token(&project_claude, "hooks")?,
                ConfigScope::Project,
                trust,
                project_namespace.clone(),
                DirectoryRole::Hooks,
            );
            discover_plugins(
                known_folders,
                &mut state,
                &project_claude,
                ConfigScope::Project,
                trust,
            );
            let direct_manifest = join_token(&project_root, ".claude-plugin/plugin.json")?;
            if matches!(
                entry_kind(known_folders, &direct_manifest),
                Ok(Some(EntryKind::File))
            ) {
                register_plugin(
                    known_folders,
                    &mut state,
                    direct_manifest,
                    ConfigScope::Project,
                    trust,
                );
            }
        }

        if state.candidates.is_empty() {
            return Ok(ClaudeDiscovery::empty());
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

        let mut result = ClaudeDiscovery {
            artifacts: sorted_artifacts(artifacts),
            ..ClaudeDiscovery::empty()
        };
        let harness_evidence = state.evidence(&config_home, "Claude Code home discovered");
        let harness = build_component(
            ComponentKind::Harness,
            "harness",
            "Claude Code",
            Vec::new(),
            &harness_evidence,
            harness_restore(),
            Vec::new(),
            false,
            json_map([
                ("adapter", json!(ADAPTER_ID)),
                ("home", json!(token_string(&config_home))),
            ]),
        )?;
        let harness_id = harness.id.clone();
        result.components.push(harness);

        // Resolve plugin names before materializing plugin-owned children so
        // every child receives the manifest namespace rather than a path name.
        let mut plugin_names = BTreeMap::new();
        for candidate in &candidates {
            let CandidateRole::PluginManifest { root } = &candidate.role else {
                continue;
            };
            let Some(artifact) = artifact_by_path
                .get(&token_string(&candidate.path))
                .cloned()
            else {
                continue;
            };
            let manifest = match parse_json_file(known_folders, &candidate.path) {
                Ok(value) => value,
                Err(error) => {
                    state.push_warning(*error);
                    json!({"redacted": true})
                }
            };
            let fallback = plugin_name_from_root(root);
            let name = manifest
                .get("name")
                .and_then(Value::as_str)
                .and_then(safe_name)
                .unwrap_or(fallback);
            let namespace = format!("plugin:{name}");
            plugin_names.insert(token_string(root), namespace.clone());
            let binaries = candidates
                .iter()
                .filter_map(|child| match &child.role {
                    CandidateRole::PluginBinary {
                        root: child_root, ..
                    } if token_string(child_root) == token_string(root) => Some(child.path.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let component = build_component(
                ComponentKind::Plugin,
                &format!("plugin:{}:{}", namespace, token_string(&candidate.path)),
                &format!("Claude plugin {name}"),
                vec![artifact.clone()],
                &state.evidence(&candidate.path, "Claude plugin manifest discovered"),
                untrusted_restore("Claude plugins are executable supply-chain metadata"),
                vec![VerificationRule::File {
                    destination: candidate.path.clone(),
                    object: artifact.object.clone(),
                }],
                false,
                json_map([
                    ("namespace", json!(namespace.clone())),
                    ("manifest", manifest.clone()),
                    ("executed", json!(false)),
                ]),
            )?;
            let component_id = component.id.clone();
            result.components.push(component);
            result.plugins.push(ClaudePlugin {
                name,
                version: manifest
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                path: candidate.path.clone(),
                scope: candidate.scope.clone(),
                namespace,
                trust: candidate.trust,
                manifest,
                artifact,
                binaries,
            });
            add_dependency(
                &mut result,
                component_id.clone(),
                harness_id.clone(),
                DependencyKind::Contains,
                &state.evidence(&candidate.path, "Claude plugin belongs to harness"),
            );
            add_manual_action(
                &mut result.manual_actions,
                manual_action(
                    &component_id,
                    "plugin-review",
                    "Review Claude plugin before restore",
                    "Plugin files and binaries are untrusted supply-chain inputs",
                    vec!["Select and review this plugin explicitly before restoring it".to_owned()],
                    Some(CLAUDE_DOCS_URL),
                    RiskLevel::High,
                ),
            );
        }

        let mut normalizations: Vec<(ArtifactCandidate, ArtifactRef, McpNormalization)> =
            Vec::new();
        for candidate in &candidates {
            let Some(artifact) = artifact_by_path
                .get(&token_string(&candidate.path))
                .cloned()
            else {
                continue;
            };
            let namespace = candidate_namespace(candidate, &plugin_names);
            match &candidate.role {
                CandidateRole::PluginManifest { .. } => {}
                CandidateRole::Settings { local } => {
                    let document = parse_json_file(known_folders, &candidate.path)?;
                    let safe_config = RedactionPolicy::default()
                        .redact_json(&document)
                        .unwrap_or_else(|| json!({"redacted": true}));
                    let review = candidate.scope == ConfigScope::Project
                        && candidate.trust != ClaudeTrustScope::Trusted;
                    let component = build_component(
                        ComponentKind::Configuration,
                        &format!("settings:{}:{}", namespace, token_string(&candidate.path)),
                        "Claude Code settings",
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Claude settings discovered"),
                        config_restore(review || *local),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("scope", json!(scope_label(&candidate.scope))),
                            ("namespace", json!(namespace.clone())),
                            ("local", json!(*local)),
                            ("trust", json!(candidate.trust.label())),
                            ("safe_config", safe_config.clone()),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    result.settings.push(ClaudeSettingsRecord {
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        local: *local,
                        namespace: namespace.clone(),
                        trust: candidate.trust,
                        artifact: artifact.clone(),
                        safe_config,
                    });
                    add_dependency(
                        &mut result,
                        component_id,
                        harness_id.clone(),
                        DependencyKind::Configures,
                        &state.evidence(&candidate.path, "Claude settings belong to harness"),
                    );
                    for hook in hook_data_from_json(&document) {
                        materialize_hook(
                            &mut result,
                            &harness_id,
                            candidate,
                            namespace.clone(),
                            artifact.clone(),
                            hook,
                            &mut state,
                        )?;
                    }
                }
                CandidateRole::Mcp => {
                    let bytes = read_bounded(known_folders, &candidate.path)?;
                    match normalize_mcp_config(
                        &bytes,
                        McpInputFormat::Json,
                        &super::mcp::McpParserOptions::new(
                            candidate.scope.clone(),
                            artifact.clone(),
                        )
                        .with_known_folders(known_folders.clone())
                        .with_references(options.references.clone()),
                    ) {
                        Ok(normalization) => {
                            normalizations.push((
                                candidate.clone(),
                                artifact.clone(),
                                normalization,
                            ));
                        }
                        Err(error) => {
                            state.push_warning(*error);
                            state.add_review(
                                candidate.path.clone(),
                                "Claude MCP configuration requires manual review",
                            );
                        }
                    }
                }
                CandidateRole::Instruction => {
                    let component = build_component(
                        ComponentKind::Configuration,
                        &format!("instruction:{}", token_string(&candidate.path)),
                        "Claude project instructions",
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Claude instruction file discovered"),
                        untrusted_restore("Instruction files are untrusted configuration data"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("namespace", json!(namespace.clone())),
                            ("scope", json!(scope_label(&candidate.scope))),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    result.instructions.push(ClaudeInstruction {
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        namespace,
                        trust: candidate.trust,
                        artifact,
                    });
                    add_dependency(
                        &mut result,
                        component_id,
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Claude instructions belong to harness"),
                    );
                    add_review_action(
                        &mut result.manual_actions,
                        &result.components.last().expect("instruction component").id,
                        "instructions-review",
                        "Review Claude instructions before restore",
                        "Instructions are untrusted prompt/configuration data",
                    );
                }
                CandidateRole::Skill { name, plugin_root } => {
                    materialize_skill(
                        &mut result,
                        &harness_id,
                        candidate,
                        name,
                        namespace,
                        artifact,
                        plugin_root.is_some(),
                        &mut state,
                    )?;
                }
                CandidateRole::Command { name, .. } => {
                    let component = build_component(
                        ComponentKind::Skill,
                        &format!("command:{}", token_string(&candidate.path)),
                        &format!("Claude command {name}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Claude command discovered"),
                        untrusted_restore("Claude commands are executable prompt metadata"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("name", json!(name)),
                            ("namespace", json!(namespace.clone())),
                            ("executed", json!(false)),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    result.commands.push(ClaudeCommand {
                        name: name.clone(),
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        namespace,
                        trust: candidate.trust,
                        artifact,
                    });
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Claude command belongs to harness"),
                    );
                    add_review_action(
                        &mut result.manual_actions,
                        &component_id,
                        "command-review",
                        "Review Claude command before restore",
                        "Command files are untrusted prompt/execution metadata",
                    );
                }
                CandidateRole::Agent { name, .. } => {
                    let component = build_component(
                        ComponentKind::Agent,
                        &format!("agent:{}", token_string(&candidate.path)),
                        &format!("Claude agent {name}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Claude agent discovered"),
                        untrusted_restore("Claude agents are untrusted prompt metadata"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("name", json!(name)),
                            ("namespace", json!(namespace.clone())),
                            ("executed", json!(false)),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    result.agents.push(ClaudeAgent {
                        name: name.clone(),
                        path: candidate.path.clone(),
                        scope: candidate.scope.clone(),
                        namespace,
                        trust: candidate.trust,
                        artifact,
                    });
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Claude agent belongs to harness"),
                    );
                    add_review_action(
                        &mut result.manual_actions,
                        &component_id,
                        "agent-review",
                        "Review Claude agent before restore",
                        "Agent files are untrusted prompt metadata",
                    );
                }
                CandidateRole::HookFile => {
                    for hook in parse_hook_file(known_folders, &candidate.path, &mut state)? {
                        materialize_hook(
                            &mut result,
                            &harness_id,
                            candidate,
                            namespace.clone(),
                            artifact.clone(),
                            hook,
                            &mut state,
                        )?;
                    }
                }
                CandidateRole::PluginBinary { name, .. } => {
                    let component = build_component(
                        ComponentKind::PortableBinary,
                        &format!("plugin-bin:{}", token_string(&candidate.path)),
                        &format!("Claude plugin binary {name}"),
                        vec![artifact.clone()],
                        &state.evidence(&candidate.path, "Claude plugin binary discovered"),
                        untrusted_restore("Plugin binaries are executable supply-chain inputs"),
                        vec![VerificationRule::File {
                            destination: candidate.path.clone(),
                            object: artifact.object.clone(),
                        }],
                        false,
                        json_map([
                            ("namespace", json!(namespace.clone())),
                            ("executed", json!(false)),
                        ]),
                    )?;
                    let component_id = component.id.clone();
                    result.components.push(component);
                    add_dependency(
                        &mut result,
                        component_id.clone(),
                        harness_id.clone(),
                        DependencyKind::Contains,
                        &state.evidence(&candidate.path, "Claude plugin binary belongs to harness"),
                    );
                    add_review_action(
                        &mut result.manual_actions,
                        &component_id,
                        "plugin-bin-review",
                        "Review Claude plugin binary before restore",
                        "Plugin binaries are executable supply-chain inputs",
                    );
                }
            }
        }

        let mut seen_secrets = BTreeSet::new();
        let mut seen_servers = BTreeSet::new();
        for (candidate, artifact, normalization) in normalizations {
            for secret in normalization.secret_references {
                if seen_secrets.insert(secret.id.clone()) {
                    let component = build_secret_component(&secret, &candidate.path, &mut state)?;
                    result.secret_references.push(secret);
                    result.components.push(component);
                }
            }
            for review in normalization.manual_reviews {
                result.warnings.push(mcp_review_warning(&review));
            }
            for server in normalization.servers {
                let namespace = candidate_namespace(&candidate, &plugin_names);
                let server_key = format!(
                    "{}:{}:{}",
                    scope_label(&candidate.scope),
                    namespace,
                    server.name
                );
                if !seen_servers.insert(server_key) {
                    continue;
                }
                let evidence = state.evidence(&candidate.path, "Claude MCP server discovered");
                let mut component =
                    build_mcp_component(&server, &namespace, &harness_id, &evidence)?;
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
                        &state.evidence(&candidate.path, "Claude MCP server references a secret"),
                    );
                    component.dependencies.push(dependency.clone());
                    result.edges.push(dependency);
                }
                result.mcp_servers.push(server);
                result.components.push(component);
            }
            let _ = artifact;
        }

        for review in state.reviews {
            let key = format!("review:{}", token_string(&review.path));
            let component = result.components.iter().find(|component| {
                component.artifacts.iter().any(|artifact| {
                    token_string(&artifact.source_path) == token_string(&review.path)
                })
            });
            if let Some(component) = component {
                add_manual_action(
                    &mut result.manual_actions,
                    manual_action(
                        &component.id,
                        &key,
                        "Review Claude discovery input",
                        &review.reason,
                        vec!["Inspect this input before restoring it".to_owned()],
                        None,
                        RiskLevel::High,
                    ),
                );
            }
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
        let locator = format!("claude:{}:{}", token_string(path), summary);
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &locator);
        let id = EvidenceId::new(format!("claude-evidence-{}", hasher.finalize().to_hex()))
            .expect("hashed Claude evidence ID");
        let evidence = Evidence {
            id: id.clone(),
            source: EvidenceSource::Harness,
            locator,
            observed_at: self.observed_at,
            summary: summary.to_owned(),
            strength: 90,
            independent_group: "claude-code-config".to_owned(),
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
    trust: ClaudeTrustScope,
    namespace: String,
    role: CandidateRole,
    policy: ArtifactPolicy,
}

#[derive(Clone, Debug)]
enum CandidateRole {
    Settings {
        local: bool,
    },
    Mcp,
    Instruction,
    Skill {
        name: String,
        plugin_root: Option<PathToken>,
    },
    Command {
        name: String,
        plugin_root: Option<PathToken>,
    },
    Agent {
        name: String,
        plugin_root: Option<PathToken>,
    },
    HookFile,
    PluginManifest {
        root: PathToken,
    },
    PluginBinary {
        root: PathToken,
        name: String,
    },
}

#[derive(Clone, Debug)]
enum DirectoryRole {
    Skills { plugin_root: Option<PathToken> },
    Commands { plugin_root: Option<PathToken> },
    Agents { plugin_root: Option<PathToken> },
    Hooks,
    Binaries { plugin_root: PathToken },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[allow(clippy::too_many_arguments)]
fn add_file_candidate(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    path: PathToken,
    scope: ConfigScope,
    trust: ClaudeTrustScope,
    namespace: String,
    role: CandidateRole,
    policy: ArtifactPolicy,
) {
    match entry_kind(known_folders, &path) {
        Ok(Some(EntryKind::File)) => {
            state
                .candidates
                .entry(token_string(&path))
                .or_insert(ArtifactCandidate {
                    path,
                    scope,
                    trust,
                    namespace,
                    role,
                    policy,
                });
        }
        Ok(Some(EntryKind::Directory)) | Ok(None) => {}
        Err(error) => state.push_warning(*error),
    }
}

fn add_directory_candidates(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    directory: &PathToken,
    scope: ConfigScope,
    trust: ClaudeTrustScope,
    namespace: String,
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
                "A Claude directory entry could not be tokenized",
            );
            continue;
        };
        let relative = observation.path.as_str().replace('\\', "/");
        match &role {
            DirectoryRole::Skills { plugin_root } => {
                if relative
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
                {
                    let Some(name) = relative.rsplit('/').nth(1).and_then(safe_name) else {
                        continue;
                    };
                    add_file_candidate(
                        known_folders,
                        state,
                        path,
                        scope.clone(),
                        trust,
                        namespace.clone(),
                        CandidateRole::Skill {
                            name,
                            plugin_root: plugin_root.clone(),
                        },
                        ArtifactPolicy::Manual,
                    );
                }
            }
            DirectoryRole::Commands { plugin_root } => {
                if is_markdown_file(&relative) {
                    let Some(name) = file_stem(&relative).and_then(safe_name) else {
                        continue;
                    };
                    add_file_candidate(
                        known_folders,
                        state,
                        path,
                        scope.clone(),
                        trust,
                        namespace.clone(),
                        CandidateRole::Command {
                            name,
                            plugin_root: plugin_root.clone(),
                        },
                        ArtifactPolicy::Manual,
                    );
                }
            }
            DirectoryRole::Agents { plugin_root } => {
                if is_markdown_file(&relative) {
                    let Some(name) = file_stem(&relative).and_then(safe_name) else {
                        continue;
                    };
                    add_file_candidate(
                        known_folders,
                        state,
                        path,
                        scope.clone(),
                        trust,
                        namespace.clone(),
                        CandidateRole::Agent {
                            name,
                            plugin_root: plugin_root.clone(),
                        },
                        ArtifactPolicy::Manual,
                    );
                }
            }
            DirectoryRole::Hooks => {
                if relative.eq_ignore_ascii_case("hooks.json") {
                    add_file_candidate(
                        known_folders,
                        state,
                        path,
                        scope.clone(),
                        trust,
                        namespace.clone(),
                        CandidateRole::HookFile,
                        ArtifactPolicy::Manual,
                    );
                }
            }
            DirectoryRole::Binaries { plugin_root } => {
                let name = relative
                    .rsplit('/')
                    .next()
                    .and_then(safe_name)
                    .unwrap_or_else(|| "binary".to_owned());
                add_file_candidate(
                    known_folders,
                    state,
                    path,
                    scope.clone(),
                    trust,
                    namespace.clone(),
                    CandidateRole::PluginBinary {
                        root: plugin_root.clone(),
                        name,
                    },
                    ArtifactPolicy::Manual,
                );
            }
        }
    }
}

fn discover_plugins(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    scan_root: &PathToken,
    scope: ConfigScope,
    trust: ClaudeTrustScope,
) {
    let Ok(Some(EntryKind::Directory)) = entry_kind(known_folders, scan_root) else {
        return;
    };
    let Ok(absolute) = known_folders.resolve(scan_root) else {
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
    let mut manifests = BTreeSet::new();
    for observation in observations {
        if observation.kind != FileObservationKind::File {
            continue;
        }
        let relative = observation.path.as_str().replace('\\', "/");
        if !relative
            .to_ascii_lowercase()
            .ends_with(".claude-plugin/plugin.json")
        {
            continue;
        }
        if let Ok(path) = join_token(scan_root, &relative) {
            manifests.insert(token_string(&path));
            register_plugin(known_folders, state, path, scope.clone(), trust);
        }
    }
    let _ = manifests;
}

fn register_plugin(
    known_folders: &KnownFolderMap,
    state: &mut DiscoveryState,
    manifest: PathToken,
    scope: ConfigScope,
    trust: ClaudeTrustScope,
) {
    let Some(root) = manifest
        .relative
        .rsplit_once('/')
        .and_then(|(parent, _)| PathToken::new(manifest.root.clone(), parent).ok())
        .and_then(|parent| parent_token(&parent).ok())
    else {
        state.add_review(
            manifest,
            "A Claude plugin manifest path could not be tokenized",
        );
        return;
    };
    let namespace = format!("plugin:{}", plugin_name_from_root(&root));
    add_file_candidate(
        known_folders,
        state,
        manifest,
        scope.clone(),
        trust,
        namespace.clone(),
        CandidateRole::PluginManifest { root: root.clone() },
        ArtifactPolicy::Manual,
    );
    if let Ok(path) = join_token(&root, ".mcp.json") {
        add_file_candidate(
            known_folders,
            state,
            path,
            scope.clone(),
            trust,
            namespace.clone(),
            CandidateRole::Mcp,
            ArtifactPolicy::Manual,
        );
    }
    if let Ok(path) = join_token(&root, "settings.json") {
        add_file_candidate(
            known_folders,
            state,
            path,
            scope.clone(),
            trust,
            namespace.clone(),
            CandidateRole::Settings { local: false },
            ArtifactPolicy::Manual,
        );
    }
    if let Ok(path) = join_token(&root, "skills") {
        add_directory_candidates(
            known_folders,
            state,
            &path,
            scope.clone(),
            trust,
            namespace.clone(),
            DirectoryRole::Skills {
                plugin_root: Some(root.clone()),
            },
        );
    }
    if let Ok(path) = join_token(&root, "commands") {
        add_directory_candidates(
            known_folders,
            state,
            &path,
            scope.clone(),
            trust,
            namespace.clone(),
            DirectoryRole::Commands {
                plugin_root: Some(root.clone()),
            },
        );
    }
    if let Ok(path) = join_token(&root, "agents") {
        add_directory_candidates(
            known_folders,
            state,
            &path,
            scope.clone(),
            trust,
            namespace.clone(),
            DirectoryRole::Agents {
                plugin_root: Some(root.clone()),
            },
        );
    }
    if let Ok(path) = join_token(&root, "hooks") {
        add_directory_candidates(
            known_folders,
            state,
            &path,
            scope.clone(),
            trust,
            namespace.clone(),
            DirectoryRole::Hooks,
        );
    }
    if let Ok(path) = join_token(&root, "bin") {
        add_directory_candidates(
            known_folders,
            state,
            &path,
            scope,
            trust,
            namespace,
            DirectoryRole::Binaries { plugin_root: root },
        );
    }
}

fn resolve_config_home(
    known_folders: &KnownFolderMap,
    environment: &BTreeMap<String, String>,
) -> Result<PathToken, Box<ErrorEnvelope>> {
    let configured = environment
        .iter()
        .find(|(name, value)| {
            name.eq_ignore_ascii_case("CLAUDE_CONFIG_DIR") && !value.trim().is_empty()
        })
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
                "CLAUDE_CONFIG_DIR must be an absolute path without parent segments",
            ));
        }
        return token_for_absolute_path(known_folders, &path).ok_or_else(|| {
            discovery_error(
                ReforgeErrorCode::SecurityPolicy,
                "CLAUDE_CONFIG_DIR is outside the known-folder map",
            )
        });
    }
    PathToken::new(KnownFolderToken::UserProfile, ".claude").map_err(|_| {
        discovery_error(
            ReforgeErrorCode::InvalidPath,
            "The default Claude config home token could not be constructed",
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
    known_folders.entries.iter().find_map(|(root, root_path)| {
        let root_text = normalized_path(root_path);
        if candidate == root_text {
            return PathToken::new(root.clone(), "").ok();
        }
        let prefix = format!("{root_text}/");
        candidate
            .strip_prefix(&prefix)
            .and_then(|relative| PathToken::new(root.clone(), relative).ok())
    })
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
            "A Claude path could not be represented as a safe token",
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
            "A Claude parent path could not be represented as a safe token",
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
            "A Claude path could not be inspected",
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
            "Claude path root is not available",
        )
    })?;
    let safe_path = SafePath::from_token(path)?;
    let mut reader = BoundedFileReader::open(root, &safe_path, MAX_TEXT_BYTES)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

fn parse_json_file(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Value, Box<ErrorEnvelope>> {
    let bytes = read_bounded(known_folders, path)?;
    serde_json::from_slice(&bytes).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::ProviderParseFailed,
            "Claude JSON configuration could not be parsed",
        )
    })
}

fn parse_hook_file(
    known_folders: &KnownFolderMap,
    path: &PathToken,
    state: &mut DiscoveryState,
) -> Result<Vec<HookData>, Box<ErrorEnvelope>> {
    match parse_json_file(known_folders, path) {
        Ok(value) => Ok(hook_data_from_json(&value)),
        Err(error) => {
            state.push_warning(*error);
            state.add_review(path.clone(), "Claude hooks.json requires manual review");
            Ok(Vec::new())
        }
    }
}

#[derive(Clone, Debug)]
struct HookData {
    event: String,
    matcher: Option<String>,
    command: Option<String>,
}

fn hook_data_from_json(value: &Value) -> Vec<HookData> {
    let events = value
        .get("hooks")
        .and_then(Value::as_object)
        .or_else(|| value.as_object());
    let Some(events) = events else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for (event, raw_entries) in events {
        if event == "hooks" {
            continue;
        }
        let entries = raw_entries
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![raw_entries.clone()]);
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
                    .and_then(|value| RedactionPolicy::default().redact_text(value));
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
    result: &mut ClaudeDiscovery,
    harness_id: &ComponentId,
    candidate: &ArtifactCandidate,
    namespace: String,
    artifact: ArtifactRef,
    hook: HookData,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let component = build_component(
        ComponentKind::Hook,
        &format!(
            "hook:{}:{}:{}",
            token_string(&candidate.path),
            hook.event,
            namespace
        ),
        &format!("Claude hook {}", hook.event),
        vec![artifact.clone()],
        &state.evidence(&candidate.path, "Claude hook metadata discovered"),
        untrusted_restore("Claude hooks are untrusted commands and are never executed"),
        vec![VerificationRule::File {
            destination: candidate.path.clone(),
            object: artifact.object.clone(),
        }],
        false,
        json_map([
            ("event", json!(hook.event.clone())),
            ("matcher", json!(hook.matcher.clone())),
            ("command", json!(hook.command.clone())),
            ("namespace", json!(namespace.clone())),
            ("executed", json!(false)),
        ]),
    )?;
    let component_id = component.id.clone();
    result.components.push(component);
    result.hooks.push(ClaudeHook {
        event: hook.event,
        matcher: hook.matcher,
        command: hook.command,
        path: candidate.path.clone(),
        scope: candidate.scope.clone(),
        namespace,
        trust: candidate.trust,
        artifact,
    });
    add_dependency(
        result,
        component_id.clone(),
        harness_id.clone(),
        DependencyKind::Contains,
        &state.evidence(&candidate.path, "Claude hook belongs to harness"),
    );
    add_review_action(
        &mut result.manual_actions,
        &component_id,
        "hook-review",
        "Review Claude hook before restore",
        "Hook commands are untrusted metadata and are never executed",
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn materialize_skill(
    result: &mut ClaudeDiscovery,
    harness_id: &ComponentId,
    candidate: &ArtifactCandidate,
    name: &str,
    namespace: String,
    artifact: ArtifactRef,
    plugin: bool,
    state: &mut DiscoveryState,
) -> Result<(), Box<ErrorEnvelope>> {
    let component = build_component(
        ComponentKind::Skill,
        &format!("skill:{}", token_string(&candidate.path)),
        &format!("Claude skill {namespace}:{name}"),
        vec![artifact.clone()],
        &state.evidence(&candidate.path, "Claude skill discovered"),
        untrusted_restore("Claude skills are untrusted prompt metadata"),
        vec![VerificationRule::File {
            destination: candidate.path.clone(),
            object: artifact.object.clone(),
        }],
        false,
        json_map([
            ("name", json!(name)),
            ("namespace", json!(namespace.clone())),
            ("plugin", json!(plugin)),
            ("executed", json!(false)),
        ]),
    )?;
    let component_id = component.id.clone();
    result.components.push(component);
    result.skills.push(ClaudeSkill {
        name: name.to_owned(),
        path: candidate.path.clone(),
        scope: candidate.scope.clone(),
        namespace,
        trust: candidate.trust,
        artifact,
    });
    add_dependency(
        result,
        component_id.clone(),
        harness_id.clone(),
        DependencyKind::Contains,
        &state.evidence(&candidate.path, "Claude skill belongs to harness"),
    );
    add_review_action(
        &mut result.manual_actions,
        &component_id,
        "skill-review",
        "Review Claude skill before restore",
        "Skill files are untrusted prompt metadata",
    );
    Ok(())
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
        &state.evidence(source_path, "Claude MCP secret reference discovered"),
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
        &format!("Claude MCP server {}:{}", namespace, server.name),
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
                        "Claude MCP server could not be serialized safely",
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
        name: "Anthropic".to_owned(),
        certificate_thumbprint: None,
    };
    let mut identity = Identity {
        provider_package: None,
        provider_source: None,
        package_family: Some(format!("claude-code:{key}")),
        product_name: Some("Claude Code".to_owned()),
        executable_name: None,
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some(format!("{kind:?}")),
        identity_quality: IdentityQuality::PackageFamily,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "Claude component identity could not be canonicalized",
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
            package_id: Some("claude-code".to_owned()),
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
            "The Claude Code executable is an install-time dependency; this adapter restores configuration only".to_owned(),
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
                "This Claude configuration requires an explicit trust decision".to_owned(),
            ],
        }
    } else {
        RestoreDescriptor {
            primary: RestoreStrategy::ConfigPortable,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::Portable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec!["Documented Claude configuration is portable data".to_owned()],
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
    result: &mut ClaudeDiscovery,
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
            vec!["Select and review this Claude input explicitly before restoring it".to_owned()],
            Some(CLAUDE_DOCS_URL),
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
    docs_url: Option<&str>,
    risk: RiskLevel,
) -> ManualAction {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, component.as_str());
    hash_field(&mut hasher, kind);
    ManualAction {
        id: format!("claude-manual-{}", hasher.finalize().to_hex()),
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

fn mcp_review_warning(review: &McpManualReview) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ReforgeErrorCode::ManualActionRequired,
        "Claude MCP configuration contains a value requiring manual review",
    )
    .with_context_id(format!("claude-mcp:{}:{}", review.server, review.field))
}

fn project_trust(options: &ClaudeDiscoveryOptions, root: &PathToken) -> ClaudeTrustScope {
    options
        .project_trust
        .get(&token_string(root))
        .copied()
        .unwrap_or_default()
}

fn candidate_namespace(
    candidate: &ArtifactCandidate,
    plugin_names: &BTreeMap<String, String>,
) -> String {
    let plugin_root = match &candidate.role {
        CandidateRole::Skill { plugin_root, .. }
        | CandidateRole::Command { plugin_root, .. }
        | CandidateRole::Agent { plugin_root, .. } => plugin_root.as_ref(),
        CandidateRole::PluginBinary { root, .. } => Some(root),
        _ => None,
    };
    plugin_root
        .and_then(|root| plugin_names.get(&token_string(root)).cloned())
        .unwrap_or_else(|| candidate.namespace.clone())
}

fn plugin_name_from_root(root: &PathToken) -> String {
    root.relative
        .rsplit('/')
        .next()
        .and_then(safe_name)
        .unwrap_or_else(|| "plugin".to_owned())
}

fn token_string(path: &PathToken) -> String {
    format!("{:?}/{}", path.root, path.relative)
}

fn sorted_artifacts(mut artifacts: Vec<ArtifactRef>) -> Vec<ArtifactRef> {
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    artifacts
}

fn is_markdown_file(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".md")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_names_are_safe_and_namespaced() {
        let root = PathToken::new(KnownFolderToken::UserProfile, ".claude/plugins/review").unwrap();
        assert_eq!(plugin_name_from_root(&root), "review");
        assert_eq!(safe_name("review-plugin").as_deref(), Some("review-plugin"));
        assert!(safe_name("bad/name").is_none());
    }

    #[test]
    fn markdown_file_stem_is_stable() {
        assert_eq!(file_stem("commands/review.md"), Some("review"));
        assert_eq!(file_stem("agents/reviewer"), Some("reviewer"));
    }
}
