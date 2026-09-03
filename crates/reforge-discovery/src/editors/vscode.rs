//! Visual Studio Code settings, extension, and Settings Sync discovery.
//!
//! Only documented user configuration and extension identities are captured.
//! Settings Sync is account-mediated: its local sign-in/session state is never
//! copied and always becomes an explicit reauthentication action.

use std::{collections::BTreeMap, env, fs, time::Duration};

use reforge_domain::{
    Architecture, ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId,
    ComponentKind, Confidence, ConfigScope, DependencyEdge, DependencyKind, ErrorEnvelope,
    Evidence, EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken,
    ManualAction, ManualActionState, PathToken, Portability, Publisher, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, RiskLevel, SelectionMetadata, VerificationRule,
    VersionValue,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, FileObservationKind, KnownFolderMap,
    ProcessRunner, RegistryKeyObservation, RegistryQuery, RegistryRoot, RegistryScope,
    RegistryValueData, RegistryView, TrustedExecutable, WalkLimits, enumerate_registry_with,
    walk_reparse_safe,
};
use serde_json::{Value, json};

use crate::{ArtifactCollector, ArtifactLimits, ArtifactRequest};

const ADAPTER_ID: &str = "editors.vscode";
const MAX_EXTENSIONS: usize = 1_024;
const MAX_ARTIFACT_REQUESTS: usize = 32;
const MAX_WARNINGS: usize = 256;
const MAX_MANUAL_ACTIONS: usize = 256;
const VSCODE_DOCS_URL: &str = "https://code.visualstudio.com/docs/configure/settings-sync";
const MAX_ARTIFACTS: usize = 1_024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WORKSPACE_ENTRIES: usize = 512;
const MAX_WORKSPACE_DEPTH: usize = 4;

/// Parsed VS Code CLI observations. Tests can provide fixture output without
/// launching a real editor process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VSCodeObservations {
    pub version_output: Option<String>,
    pub extensions_output: Option<String>,
    pub cli_available: bool,
}

/// Extension identity enumerated by `code --list-extensions --show-versions`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VSCodeExtension {
    pub id: String,
    pub version: Option<String>,
}

/// Complete VS Code discovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VSCodeDiscovery {
    pub component: Option<Component>,
    pub extensions: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub artifacts: Vec<ArtifactRef>,
    pub evidence: Vec<Evidence>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
    pub version: Option<String>,
}
#[derive(Default)]
struct CodeRegistrationEvidence {
    records: Vec<Evidence>,
    version: Option<String>,
    reinstall_source: bool,
    warnings: Vec<ErrorEnvelope>,
}
#[derive(Default)]
struct VSCodeSources {
    workspace_roots: Vec<PathToken>,
    installation_evidence: Vec<Evidence>,
    installation_version: Option<String>,
    reinstall_source: bool,
    warnings: Vec<ErrorEnvelope>,
}

#[derive(Default)]
struct SettingsArtifactCollection {
    artifacts: Vec<ArtifactRef>,
    warnings: Vec<ErrorEnvelope>,
}

/// VS Code settings and extension adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct VSCodeAdapter;

impl VSCodeAdapter {
    pub fn new() -> Self {
        Self
    }
    pub fn discover(
        &self,
        known_folders: &KnownFolderMap,
    ) -> Result<VSCodeDiscovery, Box<ErrorEnvelope>> {
        let registration = code_registration_evidence(chrono::Utc::now());
        let workspace_roots = current_workspace_roots(known_folders);
        self.discover_internal(
            known_folders,
            VSCodeObservations::default(),
            VSCodeSources {
                workspace_roots,
                installation_evidence: registration.records,
                installation_version: registration.version,
                reinstall_source: registration.reinstall_source,
                warnings: registration.warnings,
            },
        )
    }

    pub async fn discover_with_runner(
        &self,
        known_folders: &KnownFolderMap,
        runner: &ProcessRunner,
        cancellation: &CancellationToken,
    ) -> Result<VSCodeDiscovery, Box<ErrorEnvelope>> {
        let mut observations = VSCodeObservations {
            cli_available: runner.builtin_available(BuiltinExecutable::Code),
            ..VSCodeObservations::default()
        };
        let mut warnings = Vec::new();
        if observations.cli_available {
            match run_code(runner, cancellation, ["--version"]).await {
                Ok(output) if output.cancelled => return Err(cancelled_error()),
                Ok(output) if output.exit_code == Some(0) && !output.timed_out => {
                    observations.version_output = Some(output.stdout);
                }
                Ok(_) | Err(_) => warnings.push(ErrorEnvelope::new(
                    ReforgeErrorCode::ProviderUnavailable,
                    "The VS Code version command did not return a usable result",
                )),
            }
            match run_code(
                runner,
                cancellation,
                ["--list-extensions", "--show-versions"],
            )
            .await
            {
                Ok(output) if output.cancelled => return Err(cancelled_error()),
                Ok(output) if output.exit_code == Some(0) && !output.timed_out => {
                    observations.extensions_output = Some(output.stdout);
                }
                Ok(_) | Err(_) => warnings.push(ErrorEnvelope::new(
                    ReforgeErrorCode::ProviderUnavailable,
                    "The VS Code extension enumeration command did not return a usable result",
                )),
            }
        } else {
            warnings.push(ErrorEnvelope::new(
                ReforgeErrorCode::ProviderUnavailable,
                "The documented VS Code CLI is unavailable; extension identity enumeration was skipped",
            ));
        }
        let registration = code_registration_evidence(chrono::Utc::now());
        let workspace_roots = current_workspace_roots(known_folders);
        let mut discovery = self.discover_internal(
            known_folders,
            observations,
            VSCodeSources {
                workspace_roots,
                installation_evidence: registration.records,
                installation_version: registration.version,
                reinstall_source: registration.reinstall_source,
                warnings: registration.warnings,
            },
        )?;
        discovery.warnings.extend(warnings);
        discovery.warnings.truncate(MAX_WARNINGS);
        Ok(discovery)
    }

    pub fn discover_with_observations(
        &self,
        known_folders: &KnownFolderMap,
        observations: VSCodeObservations,
    ) -> Result<VSCodeDiscovery, Box<ErrorEnvelope>> {
        self.discover_with_observations_and_workspace_roots(known_folders, observations, &[])
    }

    pub fn discover_with_observations_and_workspace_roots(
        &self,
        known_folders: &KnownFolderMap,
        observations: VSCodeObservations,
        workspace_roots: &[PathToken],
    ) -> Result<VSCodeDiscovery, Box<ErrorEnvelope>> {
        self.discover_internal(
            known_folders,
            observations,
            VSCodeSources {
                workspace_roots: workspace_roots.to_vec(),
                ..VSCodeSources::default()
            },
        )
    }

    fn discover_internal(
        &self,
        known_folders: &KnownFolderMap,
        observations: VSCodeObservations,
        sources: VSCodeSources,
    ) -> Result<VSCodeDiscovery, Box<ErrorEnvelope>> {
        let observed_at = chrono::Utc::now();
        let VSCodeSources {
            workspace_roots,
            installation_evidence,
            installation_version,
            reinstall_source,
            mut warnings,
        } = sources;
        let editor_evidence = evidence(
            &format!("vscode:cli:{}", observations.cli_available),
            "VS Code editor identity/configuration adapter observation",
            observed_at,
        );
        let version = observations
            .version_output
            .as_deref()
            .and_then(parse_version_output)
            .or(installation_version);
        let extension_inventory = observations
            .extensions_output
            .as_deref()
            .map(parse_extensions)
            .transpose()?
            .unwrap_or_default();
        let settings = collect_settings_artifacts(known_folders, &workspace_roots)?;
        warnings.extend(settings.warnings);
        let artifacts = settings.artifacts;
        let mut evidence_records = installation_evidence;
        let has_editor_evidence = observations.cli_available
            || observations
                .version_output
                .as_deref()
                .is_some_and(|output| !output.trim().is_empty())
            || observations
                .extensions_output
                .as_deref()
                .is_some_and(|output| !output.trim().is_empty())
            || !artifacts.is_empty()
            || !evidence_records.is_empty();
        if has_editor_evidence {
            evidence_records.push(editor_evidence.clone());
        }
        let editor = if has_editor_evidence {
            Some(build_editor_component(
                version.as_deref(),
                artifacts.clone(),
                &evidence_records,
                reinstall_source || observations.cli_available,
            )?)
        } else {
            None
        };
        let editor_id = editor.as_ref().map(|editor| editor.id.clone());
        let mut result = VSCodeDiscovery {
            component: editor,
            extensions: Vec::new(),
            edges: Vec::new(),
            artifacts,
            evidence: evidence_records,
            manual_actions: Vec::new(),
            warnings,
            version,
        };
        if let Some(editor_id) = editor_id.as_ref() {
            add_manual_action(
                &mut result.manual_actions,
                editor_id,
                "settings-sync-reauth",
                "Sign in to VS Code Settings Sync after restore",
                "Settings Sync is account-mediated; local sign-in/session state is excluded",
            );
        }
        for extension in extension_inventory {
            let extension_evidence = evidence(
                &format!("vscode:extension:{}", extension.id),
                "VS Code extension identity returned by the documented CLI",
                observed_at,
            );
            result.evidence.push(extension_evidence.clone());
            let mut component = build_extension_component(&extension, &extension_evidence)?;
            if let Some(editor_id) = editor_id.as_ref() {
                let edge = DependencyEdge {
                    from: component.id.clone(),
                    to: editor_id.clone(),
                    kind: DependencyKind::Contains,
                    required: true,
                    evidence: vec![extension_evidence.id.clone()],
                    confidence: Confidence::High,
                };
                component.dependencies.push(edge.clone());
                result.edges.push(edge);
            }
            result.extensions.push(component);
        }
        if !(reinstall_source || observations.cli_available) {
            result.warnings.push(ErrorEnvelope::new(
                ReforgeErrorCode::ManualActionRequired,
                "Inspect the VS Code installation manually to verify its source before restore",
            ));
        }
        result
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        result
            .extensions
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
        });
        result.manual_actions.truncate(MAX_MANUAL_ACTIONS);
        Ok(result)
    }
}

fn evidence_refs(records: &[Evidence]) -> Vec<EvidenceRef> {
    let mut references = records
        .iter()
        .map(|record| EvidenceRef {
            id: record.id.clone(),
            strength: record.strength,
        })
        .collect::<Vec<_>>();
    references.sort_by(|left, right| left.id.cmp(&right.id));
    references.dedup_by(|left, right| left.id == right.id);
    references
}

fn build_editor_component(
    version: Option<&str>,
    artifacts: Vec<ArtifactRef>,
    evidence: &[Evidence],
    reinstall_source: bool,
) -> Result<Component, Box<ErrorEnvelope>> {
    let publisher = Publisher {
        name: "Microsoft Corporation".to_owned(),
        certificate_thumbprint: None,
    };
    let identity = Identity {
        provider_package: None,
        provider_source: Some("visual-studio-code".to_owned()),
        package_family: Some("editor:visual-studio-code".to_owned()),
        product_name: Some("Visual Studio Code".to_owned()),
        executable_name: Some("code.exe".to_owned()),
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some("editor".to_owned()),
        identity_quality: IdentityQuality::Product,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "VS Code editor identity could not be canonicalized",
        ))
    })?;
    Ok(Component {
        id: canonical.id,
        kind: ComponentKind::Editor,
        identity,
        display_name: "Visual Studio Code".to_owned(),
        version: version.map(version_value),
        architecture: Some(Architecture::X64),
        publisher: Some(publisher),
        provenance: Some(reforge_domain::Provenance {
            provider: None,
            package_id: Some("visual-studio-code".to_owned()),
            source_url: None,
            observed_version: version.map(ToOwned::to_owned),
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        evidence: evidence_refs(evidence),
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts: artifacts.clone(),
        restore: RestoreDescriptor {
            primary: if reinstall_source {
                RestoreStrategy::Reinstall
            } else {
                RestoreStrategy::Manual
            },
            alternatives: if reinstall_source {
                vec![RestoreStrategy::Manual]
            } else {
                vec![RestoreStrategy::PortableBinary]
            },
            portability: if reinstall_source {
                Portability::PartiallyPortable
            } else {
                Portability::Unknown
            },
            requires_elevation: false,
            requires_user_action: true,
            rationale: if reinstall_source {
                vec![
                    "Restore the editor through its documented installer, then apply portable user settings and extensions".to_owned(),
                ]
            } else {
                vec![
                    "No trusted local VS Code installation source was established; identify and install the editor manually before applying user settings".to_owned(),
                ]
            },
        },
        compatibility: Compatibility {
            required_os: Some("Windows 10 22H2+".to_owned()),
            required_architecture: Some(Architecture::X64),
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
        verification: artifacts
            .iter()
            .map(|artifact| VerificationRule::ConfigParses {
                destination: artifact.source_path.clone(),
                content_type: artifact.content_type.clone(),
            })
            .collect(),
        selection: SelectionMetadata {
            recommended: reinstall_source,
            score: if reinstall_source { 90 } else { 35 },
            selected_by_default: reinstall_source,
            sensitive: false,
            size_bytes: artifacts.iter().map(|artifact| artifact.size_bytes).sum(),
        },
        extensions: BTreeMap::from([
            ("settings_sync_state".to_owned(), json!("reauth_required")),
            ("protected_state_copied".to_owned(), json!(false)),
        ]),
    })
}

fn build_extension_component(
    extension: &VSCodeExtension,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    let publisher_name = extension.id.split('.').next().unwrap_or("unknown");
    let publisher = Publisher {
        name: publisher_name.to_owned(),
        certificate_thumbprint: None,
    };
    let identity = Identity {
        provider_package: None,
        provider_source: Some("visual-studio-code-marketplace".to_owned()),
        package_family: Some(format!("vscode-extension:{}", extension.id)),
        product_name: Some(extension.id.clone()),
        executable_name: None,
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some("vscode-extension".to_owned()),
        identity_quality: IdentityQuality::Product,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "VS Code extension identity could not be canonicalized",
        ))
    })?;
    Ok(Component {
        id: canonical.id,
        kind: ComponentKind::Extension,
        identity,
        display_name: extension.id.clone(),
        version: extension.version.as_deref().map(version_value),
        architecture: None,
        publisher: Some(publisher),
        provenance: Some(reforge_domain::Provenance {
            provider: None,
            package_id: Some(extension.id.clone()),
            source_url: url::Url::parse(&format!(
                "https://marketplace.visualstudio.com/items?itemName={}",
                extension.id
            ))
            .ok(),
            observed_version: extension.version.clone(),
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        evidence: vec![EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        }],
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Reinstall,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec![
                "Reinstall the extension by its stable marketplace identity".to_owned(),
            ],
        },
        compatibility: Compatibility {
            required_os: Some("Windows 10 22H2+".to_owned()),
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
            score: 70,
            selected_by_default: true,
            sensitive: false,
            size_bytes: 0,
        },
        extensions: BTreeMap::from([
            ("extension_id".to_owned(), json!(extension.id.clone())),
            ("protected_state_copied".to_owned(), json!(false)),
        ]),
    })
}

fn collect_settings_artifacts(
    known_folders: &KnownFolderMap,
    workspace_roots: &[PathToken],
) -> Result<SettingsArtifactCollection, Box<ErrorEnvelope>> {
    let user = PathToken::new(KnownFolderToken::RoamingAppData, "Code/User")
        .map_err(|_| invalid_path())?;
    let mut requests = Vec::new();
    for relative in ["settings.json", "keybindings.json", "snippets", "profiles"] {
        let path = join_token(&user, relative)?;
        if path_exists(known_folders, &path) {
            requests.push(ArtifactRequest::new(
                path,
                ConfigScope::User,
                ArtifactPolicy::Config,
            ));
        }
    }

    let mut warnings = Vec::new();
    for root in workspace_roots.iter().take(MAX_ARTIFACT_REQUESTS) {
        let absolute = match known_folders.resolve(root) {
            Ok(path) => path,
            Err(error) => {
                warnings.push(ErrorEnvelope::new(
                    error.code.clone(),
                    "A configured VS Code workspace root could not be resolved safely",
                ));
                continue;
            }
        };
        let observations = match walk_reparse_safe(
            &absolute,
            WalkLimits {
                max_entries: MAX_WORKSPACE_ENTRIES,
                max_depth: MAX_WORKSPACE_DEPTH,
            },
        ) {
            Ok(observations) => observations,
            Err(error) => {
                warnings.push(ErrorEnvelope::new(
                    error.code.clone(),
                    "A configured VS Code workspace root could not be inspected safely",
                ));
                continue;
            }
        };
        for observation in observations {
            if observation.kind != FileObservationKind::File
                || !is_workspace_config(observation.path.as_str())
                || requests.len() >= MAX_ARTIFACT_REQUESTS
            {
                continue;
            }
            let path = join_token(root, observation.path.as_str())?;
            requests.push(ArtifactRequest::new(
                path,
                ConfigScope::Project,
                ArtifactPolicy::Config,
            ));
        }
        if requests.len() >= MAX_ARTIFACT_REQUESTS {
            break;
        }
    }

    let collection = ArtifactCollector::new(ArtifactLimits {
        max_requests: MAX_ARTIFACT_REQUESTS,
        max_artifacts: MAX_ARTIFACTS,
        max_total_bytes: MAX_ARTIFACT_BYTES,
        max_file_bytes: MAX_ARTIFACT_FILE_BYTES,
        large_file_threshold: MAX_ARTIFACT_FILE_BYTES,
        max_depth: MAX_WORKSPACE_DEPTH,
    })
    .collect(known_folders, &requests)?;
    warnings.extend(collection.warnings);
    warnings.truncate(MAX_WARNINGS);
    Ok(SettingsArtifactCollection {
        artifacts: collection.artifacts,
        warnings,
    })
}

fn is_workspace_config(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let direct_vscode_file = path.strip_prefix(".vscode/").is_some_and(|file| {
        matches!(
            file,
            "settings.json" | "keybindings.json" | "tasks.json" | "launch.json" | "extensions.json"
        )
    });
    path.ends_with(".code-workspace")
        || direct_vscode_file
        || [
            "/.vscode/settings.json",
            "/.vscode/keybindings.json",
            "/.vscode/tasks.json",
            "/.vscode/launch.json",
            "/.vscode/extensions.json",
        ]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

fn path_exists(known_folders: &KnownFolderMap, path: &PathToken) -> bool {
    known_folders
        .resolve(path)
        .ok()
        .and_then(|absolute| fs::symlink_metadata(absolute).ok())
        .is_some_and(|metadata| {
            !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir())
        })
}

fn code_registration_evidence(
    observed_at: chrono::DateTime<chrono::Utc>,
) -> CodeRegistrationEvidence {
    let snapshot = enumerate_registry_with(&RegistryQuery {
        scopes: vec![RegistryScope::CurrentUser, RegistryScope::LocalMachine],
        views: vec![RegistryView::View32, RegistryView::View64],
        roots: vec![RegistryRoot::AppPaths, RegistryRoot::Uninstall],
    });
    let mut result = CodeRegistrationEvidence::default();
    for error in snapshot.errors {
        result.warnings.push(ErrorEnvelope::new(
            error.error.code.clone(),
            "A VS Code registry observation could not be read safely",
        ));
    }
    for observation in snapshot.observations {
        let key_name = observation
            .key_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let display_name = registry_text(&observation, "DisplayName");
        let display_lower = display_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_app_path = observation.root == RegistryRoot::AppPaths
            && matches!(key_name.as_str(), "code.exe" | "code-insiders.exe");
        let is_uninstall = observation.root == RegistryRoot::Uninstall
            && (display_lower.contains("visual studio code")
                || display_lower.contains("visual studio code insiders"));
        if !is_app_path && !is_uninstall {
            continue;
        }
        let locator = format!(
            "registry:{:?}:{:?}:{:?}:{}",
            observation.scope, observation.view, observation.root, observation.key_path
        );
        let summary = display_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("Visual Studio Code registration");
        result
            .records
            .push(evidence(&locator, summary, observed_at));
        if result.version.is_none() {
            result.version = registry_text(&observation, "DisplayVersion")
                .or_else(|| registry_text(&observation, "Version"))
                .and_then(|value| parse_version_output(&value));
        }
        result.reinstall_source = true;
    }
    result.records.sort_by(|left, right| left.id.cmp(&right.id));
    result.records.dedup_by(|left, right| left.id == right.id);
    result.warnings.truncate(MAX_WARNINGS);
    result
}

fn registry_text(observation: &RegistryKeyObservation, name: &str) -> Option<String> {
    observation
        .values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
        .and_then(|value| match &value.data {
            RegistryValueData::Text(text) => text.redacted.clone(),
            RegistryValueData::MultiString(values) => {
                values.iter().find_map(|value| value.redacted.clone())
            }
            _ => None,
        })
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 512)
}

fn current_workspace_roots(known_folders: &KnownFolderMap) -> Vec<PathToken> {
    let mut roots = Vec::new();
    let mut seen = BTreeMap::new();
    for token in [KnownFolderToken::Documents, KnownFolderToken::Desktop] {
        if known_folders.entries.contains_key(&token) {
            add_workspace_root(&mut roots, &mut seen, token, "");
        }
    }
    for token in known_folders.entries.keys() {
        if matches!(token, KnownFolderToken::UserSelected { .. }) {
            add_workspace_root(&mut roots, &mut seen, token.clone(), "");
        }
    }
    for relative in ["Projects", "src", "workspace", "code", "dev", "repos"] {
        if path_exists(
            known_folders,
            &PathToken {
                root: KnownFolderToken::UserProfile,
                relative: relative.to_owned(),
            },
        ) {
            add_workspace_root(
                &mut roots,
                &mut seen,
                KnownFolderToken::UserProfile,
                relative,
            );
        }
    }
    if let Ok(current) = env::current_dir() {
        let current = fs::canonicalize(&current).unwrap_or(current);
        for (token, root) in &known_folders.entries {
            let root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            let Ok(relative) = current.strip_prefix(root) else {
                continue;
            };
            let relative = relative.to_string_lossy().replace('\\', "/");
            add_workspace_root(&mut roots, &mut seen, token.clone(), &relative);
        }
    }
    roots
}

fn add_workspace_root(
    roots: &mut Vec<PathToken>,
    seen: &mut BTreeMap<String, ()>,
    root: KnownFolderToken,
    relative: &str,
) {
    let Ok(token) = PathToken::new(root, relative) else {
        return;
    };
    let key = format!("{:?}:{}", token.root, token.relative);
    if seen.insert(key, ()).is_none() {
        roots.push(token);
    }
}

fn join_token(base: &PathToken, relative: &str) -> Result<PathToken, Box<ErrorEnvelope>> {
    let relative = if base.relative.is_empty() {
        relative.to_owned()
    } else {
        format!("{}/{}", base.relative, relative)
    };
    PathToken::new(base.root.clone(), relative).map_err(|_| invalid_path())
}

fn parse_version_output(output: &str) -> Option<String> {
    output.lines().map(str::trim).find_map(|line| {
        let candidate = line.strip_prefix('v').unwrap_or(line);
        (!candidate.is_empty()
            && candidate
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit()))
        .then(|| {
            candidate
                .split_whitespace()
                .next()
                .unwrap_or(candidate)
                .to_owned()
        })
    })
}

/// Parse plain CLI lines, JSON fixture arrays, and object-shaped fixture
/// records. Untrusted lines are ignored rather than treated as extension IDs.
pub fn parse_extensions(output: &str) -> Result<Vec<VSCodeExtension>, Box<ErrorEnvelope>> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut parsed = BTreeMap::new();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let items = value.as_array().cloned().unwrap_or_else(|| vec![value]);
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_str).or_else(|| {
                item.get("identifier")
                    .and_then(|identifier| identifier.get("id"))
                    .and_then(Value::as_str)
            }) else {
                continue;
            };
            if valid_extension_id(id) {
                parsed.insert(
                    id.to_owned(),
                    VSCodeExtension {
                        id: id.to_owned(),
                        version: item
                            .get("version")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                    },
                );
            }
            if parsed.len() >= MAX_EXTENSIONS {
                break;
            }
        }
    } else {
        for line in trimmed
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let (id, version) = line
                .split_once('@')
                .map_or((line, None), |(id, version)| (id, Some(version)));
            if !valid_extension_id(id) {
                continue;
            }
            parsed.insert(
                id.to_owned(),
                VSCodeExtension {
                    id: id.to_owned(),
                    version: version
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned),
                },
            );
            if parsed.len() >= MAX_EXTENSIONS {
                break;
            }
        }
    }
    Ok(parsed.into_values().collect())
}

fn valid_extension_id(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(publisher) = parts.next() else {
        return false;
    };
    let Some(name) = parts.next() else {
        return false;
    };
    publisher.len() <= 128
        && name.len() <= 256
        && parts.next().is_none()
        && value.bytes().all(|character| {
            character.is_ascii_alphanumeric()
                || character == b'.'
                || character == b'-'
                || character == b'_'
        })
}

fn version_value(value: &str) -> VersionValue {
    VersionValue {
        raw: value.to_owned(),
        normalized: Some(value.to_ascii_lowercase()),
    }
}

fn evidence(locator: &str, summary: &str, observed_at: chrono::DateTime<chrono::Utc>) -> Evidence {
    let digest = blake3::hash(locator.as_bytes());
    Evidence {
        id: EvidenceId::new(format!("vscode-evidence-{}", digest.to_hex()))
            .expect("hashed VS Code evidence ID"),
        source: EvidenceSource::Editor,
        locator: locator.to_owned(),
        observed_at,
        summary: summary.to_owned(),
        strength: 85,
        independent_group: "vscode-discovery".to_owned(),
    }
}

fn add_manual_action(
    actions: &mut Vec<ManualAction>,
    component: &ComponentId,
    kind: &str,
    title: &str,
    reason: &str,
) {
    let digest = blake3::hash(format!("{}:{kind}", component.as_str()).as_bytes());
    actions.push(ManualAction {
        id: format!("vscode-manual-{}", digest.to_hex()),
        component: Some(component.clone()),
        title: title.to_owned(),
        reason: reason.to_owned(),
        risk: RiskLevel::High,
        instructions: vec![
            "Complete this account-mediated action after portable restore".to_owned(),
        ],
        docs_url: url::Url::parse(VSCODE_DOCS_URL).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    });
}

async fn run_code<const N: usize>(
    runner: &ProcessRunner,
    cancellation: &CancellationToken,
    args: [&str; N],
) -> Result<reforge_platform_windows::ProcessResult, Box<ErrorEnvelope>> {
    let command = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::Code),
        args,
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    runner.run(&command, cancellation).await
}

fn invalid_path() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::InvalidPath,
        "The documented VS Code user path could not be tokenized",
    ))
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "VS Code discovery was cancelled",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_extension_lines_deterministically() {
        let extensions = parse_extensions("ms-python.python@2025.10.0\nredhat.java@1.40.0\n")
            .expect("CLI output parses");
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].id, "ms-python.python");
    }

    #[test]
    fn rejects_untrusted_extension_lines() {
        let extensions = parse_extensions("--user-data-dir=C:\\secret\nnot-an-extension\n")
            .expect("invalid lines are ignored");
        assert!(extensions.is_empty());
    }

    #[test]
    fn parses_documented_json_fixture_shape() {
        let extensions = parse_extensions(r#"[{"identifier":{"id":"foo.bar"},"version":"1.0"}]"#)
            .expect("fixture parses");
        assert_eq!(extensions[0].id, "foo.bar");
    }
}
