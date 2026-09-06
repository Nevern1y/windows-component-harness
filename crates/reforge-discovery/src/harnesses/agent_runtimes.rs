//! Safe discovery for local AI-agent runtime configuration surfaces.
//!
//! These runtimes have large, stateful directories containing sessions, browser
//! profiles, credentials, databases, and executable extensions. This adapter
//! intentionally collects only an allowlisted set of human-authored text
//! configuration files. It never copies a runtime directory wholesale and it
//! never executes discovered files.

use std::{collections::BTreeMap, fs};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use reforge_domain::{
    ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, Confidence,
    ConfigScope, ContentType, ErrorEnvelope, Evidence, EvidenceId, EvidenceRef, EvidenceSource,
    Identity, IdentityQuality, KnownFolderToken, ManualAction, ManualActionState, Operation,
    OperationId, OperationKind, PathToken, Portability, Precondition, ProviderId, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, RiskLevel, RunId, SelectionMetadata, TargetFacts,
    VerificationRule,
};
use reforge_platform_windows::{
    FileObservationKind, KnownFolderMap, WalkLimits, walk_reparse_safe,
};

use crate::{
    artifacts::{ArtifactRequest, collect_artifacts},
    providers::{
        DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
        ProviderResult,
    },
};

const ADAPTER_ID: &str = "agent-runtime";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_SAFE_FILES_PER_RUNTIME: usize = 512;
const MAX_SAFE_DEPTH: usize = 8;

/// Additional agent runtimes whose local configuration can be backed up
/// without copying authentication or session state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentRuntimeKind {
    Antigravity,
    Hermes,
    Omp,
    Orca,
}

impl AgentRuntimeKind {
    pub const ALL: [Self; 4] = [Self::Antigravity, Self::Hermes, Self::Omp, Self::Orca];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Antigravity => "antigravity",
            Self::Hermes => "hermes",
            Self::Omp => "omp",
            Self::Orca => "orca",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Antigravity => "Antigravity",
            Self::Hermes => "Hermes",
            Self::Omp => "OMP agent runtime",
            Self::Orca => "Orca",
        }
    }

    fn provider_id(self) -> ProviderId {
        ProviderId::new(format!("harness-agent-runtime-{}", self.id()))
            .expect("constant agent runtime provider ID")
    }

    fn evidence_id(self) -> EvidenceId {
        EvidenceId::new(format!("agent-runtime-{}-registry", self.id()))
            .expect("constant agent runtime evidence ID")
    }

    fn surfaces(self) -> &'static [SurfaceSpec] {
        const ANTIGRAVITY: &[SurfaceSpec] = &[
            SurfaceSpec::user(".antigravity/config.json"),
            SurfaceSpec::user(".antigravity/settings.json"),
            SurfaceSpec::user(".antigravity/rules.json"),
            SurfaceSpec::user(".antigravity/AGENTS.md"),
            SurfaceSpec::user(".antigravity/instructions.md"),
            SurfaceSpec::user_tree(".antigravity/skills"),
            SurfaceSpec::user_tree(".antigravity/instructions"),
            // The installed desktop client stores its small preferences file
            // under RoamingAppData rather than a dot-directory.
            SurfaceSpec::roaming("Antigravity/Preferences"),
        ];
        const HERMES: &[SurfaceSpec] = &[
            SurfaceSpec::user(".hermes/config.json"),
            SurfaceSpec::user(".hermes/config.toml"),
            SurfaceSpec::user(".hermes/settings.json"),
            SurfaceSpec::user(".hermes/AGENTS.md"),
            SurfaceSpec::user(".hermes/instructions.md"),
            SurfaceSpec::user_tree(".hermes/skills"),
            SurfaceSpec::user_tree(".hermes/instructions"),
            // Hermes on Windows keeps its reviewed user configuration in
            // LocalAppData. Authentication, state databases, and caches are
            // filtered by safe_text_path and are never collected.
            SurfaceSpec::local("hermes/config.yaml"),
            SurfaceSpec::local("hermes/SOUL.md"),
            SurfaceSpec::local_tree("hermes/skills"),
        ];
        const OMP: &[SurfaceSpec] = &[
            // OMP's agent directory also contains databases, WAL files,
            // sessions, blobs, and provider key material. Only this explicit
            // user-authored preference file is portable by default.
            SurfaceSpec::user(".omp/agent/config.yml"),
            SurfaceSpec::user(".omp/agent/AGENTS.md"),
            SurfaceSpec::user_tree(".omp/agent/skills"),
            SurfaceSpec::user_tree(".omp/agent/instructions"),
        ];
        const ORCA: &[SurfaceSpec] = &[
            // Preferences is a small Electron settings file. Auth, profile,
            // browser, database, cache, and runtime files are never selected.
            SurfaceSpec::roaming("orca/Preferences"),
            SurfaceSpec::user(".orca/keybindings.json"),
        ];

        match self {
            Self::Antigravity => ANTIGRAVITY,
            Self::Hermes => HERMES,
            Self::Omp => OMP,
            Self::Orca => ORCA,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SurfaceRoot {
    UserProfile,
    RoamingAppData,
    LocalAppData,
}

impl SurfaceRoot {
    fn token(self) -> KnownFolderToken {
        match self {
            Self::UserProfile => KnownFolderToken::UserProfile,
            Self::RoamingAppData => KnownFolderToken::RoamingAppData,
            Self::LocalAppData => KnownFolderToken::LocalAppData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SurfaceSpec {
    root: SurfaceRoot,
    relative: &'static str,
    recursive: bool,
}

impl SurfaceSpec {
    const fn user(relative: &'static str) -> Self {
        Self {
            root: SurfaceRoot::UserProfile,
            relative,
            recursive: false,
        }
    }

    const fn user_tree(relative: &'static str) -> Self {
        Self {
            root: SurfaceRoot::UserProfile,
            relative,
            recursive: true,
        }
    }

    const fn roaming(relative: &'static str) -> Self {
        Self {
            root: SurfaceRoot::RoamingAppData,
            relative,
            recursive: false,
        }
    }

    const fn local(relative: &'static str) -> Self {
        Self {
            root: SurfaceRoot::LocalAppData,
            relative,
            recursive: false,
        }
    }

    const fn local_tree(relative: &'static str) -> Self {
        Self {
            root: SurfaceRoot::LocalAppData,
            relative,
            recursive: true,
        }
    }
}

/// Provider adapter for one additional local agent runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentRuntimeAdapter {
    kind: AgentRuntimeKind,
}

impl AgentRuntimeAdapter {
    pub const fn new(kind: AgentRuntimeKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> AgentRuntimeKind {
        self.kind
    }

    fn requests(&self, known_folders: &KnownFolderMap) -> (Vec<ArtifactRequest>, bool) {
        let mut requests = Vec::new();
        let mut detected = false;
        for surface in self.kind.surfaces() {
            let Some(base) = PathToken::new(surface.root.token(), surface.relative).ok() else {
                continue;
            };
            let Ok(resolved) = known_folders.resolve(&base) else {
                continue;
            };
            let Ok(metadata) = fs::symlink_metadata(&resolved) else {
                continue;
            };
            detected = true;
            if surface.recursive {
                if !metadata.is_dir() {
                    continue;
                }
                let Ok(observations) = walk_reparse_safe(
                    &resolved,
                    WalkLimits {
                        max_entries: MAX_SAFE_FILES_PER_RUNTIME,
                        max_depth: MAX_SAFE_DEPTH,
                    },
                ) else {
                    continue;
                };
                for observation in observations {
                    if observation.kind != FileObservationKind::File
                        || !safe_text_path(observation.path.as_str())
                    {
                        continue;
                    }
                    let Ok(path) = PathToken::new(
                        base.root.clone(),
                        format!("{}/{}", base.relative, observation.path.as_str()),
                    ) else {
                        continue;
                    };
                    requests.push(ArtifactRequest::new(
                        path,
                        ConfigScope::User,
                        ArtifactPolicy::Config,
                    ));
                }
            } else if metadata.is_file() && safe_text_path(surface.relative) {
                requests.push(ArtifactRequest::new(
                    base,
                    ConfigScope::User,
                    ArtifactPolicy::Config,
                ));
            }
        }
        requests.sort_by(|left, right| {
            left.path
                .root
                .cmp(&right.path.root)
                .then_with(|| left.path.relative.cmp(&right.path.relative))
        });
        requests.dedup_by(|left, right| left.path == right.path);
        (requests, detected)
    }
}

#[async_trait]
impl ProviderAdapter for AgentRuntimeAdapter {
    fn id(&self) -> ProviderId {
        self.kind.provider_id()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        let (_, detected) = self.requests(context.known_folders);
        DetectionResult {
            available: detected,
            version: None,
            evidence: vec![Evidence {
                id: self.kind.evidence_id(),
                source: EvidenceSource::Harness,
                locator: format!("registry:agent-runtime:{}", self.kind.id()),
                observed_at: Utc::now(),
                summary: format!(
                    "{} safe configuration discovery is enabled; authentication and runtime state are excluded",
                    self.kind.display_name()
                ),
                strength: 25,
                independent_group: "agent-runtime-registry".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        if context.cancellation.is_cancelled() {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::Cancelled,
                "Agent runtime discovery was cancelled",
            )));
        }
        let (requests, detected) = self.requests(context.known_folders);
        if !detected || requests.is_empty() {
            return Ok(ProviderEnumeration::empty());
        }

        let collection = collect_artifacts(context.known_folders, &requests)?;
        let mut warnings = collection
            .warnings
            .into_iter()
            .map(|warning| warning.message)
            .collect::<Vec<_>>();
        warnings.push(format!(
            "{}: authentication, sessions, browser state, caches, databases, and executable extensions were excluded",
            self.kind.display_name()
        ));
        if collection.artifacts.is_empty() {
            return Ok(ProviderEnumeration {
                observations: Vec::new(),
                warnings,
            });
        }

        let evidence = Evidence {
            id: self.kind.evidence_id(),
            source: EvidenceSource::Harness,
            locator: format!("agent-runtime:{}", self.kind.id()),
            observed_at: Utc::now(),
            summary: format!(
                "{} portable configuration files were observed without authentication state",
                self.kind.display_name()
            ),
            strength: 70,
            independent_group: "agent-runtime-files".to_owned(),
        };
        let component = build_component(self.kind, collection.artifacts, &evidence)?;
        Ok(ProviderEnumeration {
            observations: vec![Observation::Components {
                components: vec![component],
                edges: Vec::new(),
                evidence: vec![evidence],
            }],
            warnings,
        })
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Components { components, .. } = observation else {
            return Err(schema_error(
                "agent runtime adapter received a non-graph observation",
            ));
        };
        if components.is_empty() {
            return Err(schema_error("agent runtime graph contains no components"));
        }
        if components.iter().any(|component| {
            component
                .provenance
                .as_ref()
                .is_none_or(|provenance| provenance.adapter_id != ADAPTER_ID)
        }) {
            return Err(schema_error(
                "agent runtime graph contains an unowned component",
            ));
        }
        Ok(components)
    }

    fn plan_install(
        &self,
        component: &Component,
        _target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        ensure_owned(component)?;
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| schema_error("agent runtime operation ID could not be constructed"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ADAPTER_ID.as_bytes());
        hasher.update(self.kind.id().as_bytes());
        hasher.update(component.id.as_str().as_bytes());
        let idempotency_key = format!(
            "agent-runtime-{}-{}",
            self.kind.id(),
            hasher.finalize().to_hex()
        );
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: format!("Review {} configuration restore", self.kind.display_name()),
            reason: format!(
                "{} itself is not installed by Reforge; restore only the reviewed configuration files and sign in again if required",
                self.kind.display_name()
            ),
            risk: RiskLevel::Medium,
            instructions: vec![
                "Install the runtime separately from its trusted source".to_owned(),
                "Review configuration and instructions before using them".to_owned(),
                "Authenticate again; credentials and sessions are never restored".to_owned(),
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
            requires_elevation: false,
            non_idempotent: false,
        }])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        ensure_owned(component)?;
        Ok(component.verification.clone())
    }
}

fn build_component(
    kind: AgentRuntimeKind,
    artifacts: Vec<ArtifactRef>,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    let mut identity = Identity {
        provider_package: Some((kind.provider_id(), format!("configuration:{}", kind.id()))),
        provider_source: Some(format!("agent-runtime:{}", kind.id())),
        package_family: Some(format!("agent-runtime:{}", kind.id())),
        product_name: Some(kind.display_name().to_owned()),
        executable_name: None,
        publisher: None,
        executable_hash: None,
        install_role: Some("configuration".to_owned()),
        identity_quality: IdentityQuality::PackageFamily,
    };
    let canonical = ComponentId::from_identity(&identity, None)
        .map_err(|_| schema_error("agent runtime component identity could not be canonicalized"))?;
    identity.identity_quality = canonical.quality;
    let size_bytes = artifacts
        .iter()
        .map(|artifact| artifact.size_bytes)
        .fold(0u64, u64::saturating_add);
    let verification = artifacts
        .iter()
        .map(|artifact| match &artifact.content_type {
            ContentType::Json | ContentType::Jsonc | ContentType::Toml => {
                VerificationRule::ConfigParses {
                    destination: artifact.source_path.clone(),
                    content_type: artifact.content_type.clone(),
                }
            }
            _ => VerificationRule::File {
                destination: artifact.source_path.clone(),
                object: None,
            },
        })
        .collect();
    let included_surfaces = artifacts
        .iter()
        .map(|artifact| json!(artifact.source_path.relative))
        .collect::<Vec<_>>();
    let mut extensions = BTreeMap::new();
    extensions.insert("ai_workstation".to_owned(), json!(true));
    extensions.insert("runtime_kind".to_owned(), json!(kind.id()));
    extensions.insert(
        "safe_backup".to_owned(),
        json!({
            "included_surfaces": included_surfaces,
            "security_note": "Authentication, sessions, browser state, caches, databases, and executable extensions are excluded."
        }),
    );

    Ok(Component {
        id: canonical.id,
        kind: ComponentKind::Harness,
        identity,
        display_name: format!("{} configuration", kind.display_name()),
        version: None,
        architecture: None,
        publisher: None,
        provenance: Some(reforge_domain::Provenance {
            provider: Some(kind.provider_id()),
            package_id: Some(format!("agent-runtime:{}", kind.id())),
            source_url: None,
            observed_version: None,
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: ADAPTER_VERSION.to_owned(),
        }),
        evidence: vec![EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        }],
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts,
        restore: RestoreDescriptor {
            primary: RestoreStrategy::ConfigPortable,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "Only reviewed user configuration is portable; runtime installation and authentication remain manual".to_owned(),
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
        verification,
        selection: SelectionMetadata {
            recommended: true,
            score: 85,
            selected_by_default: true,
            sensitive: false,
            size_bytes,
        },
        extensions,
    })
}

fn safe_text_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let blocked_segment = lower.split('/').any(|segment| {
        matches!(
            segment,
            "auth"
                | "authentication"
                | "blobs"
                | "browser"
                | "cache"
                | "caches"
                | "cookies"
                | "credential"
                | "credentials"
                | "database"
                | "databases"
                | "db"
                | "history"
                | "keys"
                | "logs"
                | "secrets"
                | "sessions"
                | "terminal-sessions"
                | "tokens"
                | "vault"
        )
    });
    if blocked_segment {
        return false;
    }
    let name = lower.rsplit('/').next().unwrap_or_default();
    if [".env", ".env.local", "id_rsa", "id_ed25519"].contains(&name) {
        return false;
    }
    matches!(
        name.rsplit_once('.').map(|(_, extension)| extension),
        Some("json" | "jsonc" | "toml" | "yaml" | "yml" | "md" | "txt")
    ) || name == "preferences"
}

fn ensure_owned(component: &Component) -> ProviderResult<()> {
    if component
        .provenance
        .as_ref()
        .is_some_and(|provenance| provenance.adapter_id == ADAPTER_ID)
    {
        Ok(())
    } else {
        Err(schema_error(
            "agent runtime operation received an unowned component",
        ))
    }
}

fn schema_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::SchemaInvalid, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn safe_surface_filter_excludes_runtime_state_and_binaries() {
        assert!(safe_text_path(".omp/agent/config.yml"));
        assert!(safe_text_path(".antigravity/skills/review.md"));
        assert!(!safe_text_path(".omp/agent/sessions/2026.json"));
        assert!(!safe_text_path(".omp/agent/models.db"));
        assert!(!safe_text_path(".omp/agent/keys/provider.json"));
        assert!(!safe_text_path(".omp/agent/plugin.exe"));
    }

    #[test]
    fn runtime_registry_ids_are_stable_and_distinct() {
        let ids = AgentRuntimeKind::ALL
            .into_iter()
            .map(|kind| kind.provider_id())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), AgentRuntimeKind::ALL.len());
    }

    #[test]
    fn empty_known_folders_do_not_invent_runtime_components() {
        let folders = KnownFolderMap::from_entries(BTreeMap::new());
        let (requests, detected) =
            AgentRuntimeAdapter::new(AgentRuntimeKind::Omp).requests(&folders);
        assert!(requests.is_empty());
        assert!(!detected);
    }

    #[test]
    fn omp_collection_ignores_databases_sessions_and_binaries() {
        let root = std::env::temp_dir().join(format!(
            "reforge-agent-runtime-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let agent = root.join(".omp/agent");
        std::fs::create_dir_all(agent.join("sessions")).expect("create fixture directories");
        std::fs::write(agent.join("config.yml"), "theme: dark\n").expect("write config");
        std::fs::write(agent.join("models.db"), b"not portable state").expect("write database");
        std::fs::write(agent.join("sessions/secret.json"), b"not portable session")
            .expect("write session");
        std::fs::write(agent.join("plugin.exe"), b"not a selected binary").expect("write binary");

        let mut entries = BTreeMap::new();
        entries.insert(KnownFolderToken::UserProfile, root.clone());
        let folders = KnownFolderMap::from_entries(entries);
        let adapter = AgentRuntimeAdapter::new(AgentRuntimeKind::Omp);
        let (requests, detected) = adapter.requests(&folders);
        assert!(detected);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path.relative, ".omp/agent/config.yml");

        let collection = collect_artifacts(&folders, &requests).expect("collect safe config");
        assert_eq!(collection.artifacts.len(), 1);
        assert_eq!(
            collection.artifacts[0].source_path.relative,
            ".omp/agent/config.yml"
        );
        assert!(!collection.artifacts.iter().any(|artifact| {
            artifact.source_path.relative.contains("session")
                || artifact.source_path.relative.ends_with("models.db")
                || artifact.source_path.relative.ends_with("plugin.exe")
        }));
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }
}
