//! Read-only discovery for known agent launchers on the current Windows PATH.
//!
//! A launcher is not an install source and is never executed by discovery. The
//! catalog exists so a user can see agent runtimes that have no reviewed
//! configuration adapter yet. Catalog-only components are manual, unselected,
//! and contain no executable or credential artifact.

use std::{ffi::OsStr, fs};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, ManualAction,
    ManualActionState, Operation, OperationId, OperationKind, Portability, Precondition,
    ProviderId, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel, RunId,
    SelectionMetadata, TargetFacts,
};

use crate::providers::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const ADAPTER_ID: &str = "agent-catalog";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROVIDER_ID: &str = "agent-catalog";
const EVIDENCE_ID: &str = "agent-catalog-path";

/// One launcher name from the agent catalog shown in the Orca settings UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCatalogEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub command: &'static str,
}

/// Additional agents are catalogued without pretending that an available
/// command means its configuration or installer is safely portable.
pub const SCREENSHOT_AGENT_CATALOG: &[AgentCatalogEntry] = &[
    AgentCatalogEntry {
        id: "claude-agent-teams",
        display_name: "Claude Agent Teams",
        command: "claude-teams",
    },
    AgentCatalogEntry {
        id: "openclaude",
        display_name: "OpenClaude",
        command: "openclaude",
    },
    AgentCatalogEntry {
        id: "grok",
        display_name: "Grok",
        command: "grok",
    },
    AgentCatalogEntry {
        id: "github-copilot",
        display_name: "GitHub Copilot",
        command: "copilot",
    },
    AgentCatalogEntry {
        id: "mimo-code",
        display_name: "MiMo Code",
        command: "mimo",
    },
    AgentCatalogEntry {
        id: "ante",
        display_name: "Ante",
        command: "ante",
    },
    AgentCatalogEntry {
        id: "trae",
        display_name: "Trae",
        command: "traecli",
    },
    AgentCatalogEntry {
        id: "pi",
        display_name: "Pi",
        command: "pi",
    },
    AgentCatalogEntry {
        id: "prime-agent",
        display_name: "Prime Agent",
        command: "prime-agent",
    },
    AgentCatalogEntry {
        id: "gemini",
        display_name: "Gemini",
        command: "gemini",
    },
    AgentCatalogEntry {
        id: "aider",
        display_name: "Aider",
        command: "aider",
    },
    AgentCatalogEntry {
        id: "goose",
        display_name: "Goose",
        command: "goose",
    },
    AgentCatalogEntry {
        id: "amp",
        display_name: "Amp",
        command: "amp",
    },
    AgentCatalogEntry {
        id: "kilocode",
        display_name: "Kilocode",
        command: "kilo",
    },
    AgentCatalogEntry {
        id: "kiro",
        display_name: "Kiro",
        command: "kiro-cli",
    },
    AgentCatalogEntry {
        id: "charm",
        display_name: "Charm",
        command: "crush",
    },
    AgentCatalogEntry {
        id: "auggie",
        display_name: "Auggie",
        command: "auggie",
    },
    AgentCatalogEntry {
        id: "autohand-code",
        display_name: "Autohand Code",
        command: "autohand",
    },
    AgentCatalogEntry {
        id: "cline",
        display_name: "Cline",
        command: "cline",
    },
    AgentCatalogEntry {
        id: "codebuff",
        display_name: "Codebuff",
        command: "codebuff",
    },
    AgentCatalogEntry {
        id: "command-code",
        display_name: "Command Code",
        command: "command-code",
    },
    AgentCatalogEntry {
        id: "continue",
        display_name: "Continue",
        command: "cn",
    },
    AgentCatalogEntry {
        id: "cursor",
        display_name: "Cursor",
        command: "cursor-agent",
    },
    AgentCatalogEntry {
        id: "droid",
        display_name: "Droid",
        command: "droid",
    },
    AgentCatalogEntry {
        id: "kimi",
        display_name: "Kimi",
        command: "kimi",
    },
    AgentCatalogEntry {
        id: "mistral-vibe",
        display_name: "Mistral Vibe",
        command: "vibe",
    },
    AgentCatalogEntry {
        id: "qwen-code",
        display_name: "Qwen Code",
        command: "qwen",
    },
    AgentCatalogEntry {
        id: "rovo-dev",
        display_name: "Rovo Dev",
        command: "rovo",
    },
    AgentCatalogEntry {
        id: "devin",
        display_name: "Devin",
        command: "devin",
    },
    AgentCatalogEntry {
        id: "openclaw",
        display_name: "OpenClaw",
        command: "openclaw",
    },
];

/// Provider adapter for catalog-only launchers not covered by a configuration
/// adapter. Existing Reforge adapters own Claude, Codex, OpenCode, OMP,
/// Antigravity, Hermes, and Orca, so those commands are intentionally omitted
/// from this fallback catalog to avoid duplicate components.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentCatalogAdapter;

impl AgentCatalogAdapter {
    pub const fn new() -> Self {
        Self
    }

    fn available_entries(path: Option<&OsStr>) -> Vec<&'static AgentCatalogEntry> {
        let Some(path) = path else {
            return Vec::new();
        };
        SCREENSHOT_AGENT_CATALOG
            .iter()
            .filter(|entry| command_available(path, entry.command))
            .collect()
    }

    fn evidence() -> Evidence {
        Evidence {
            id: EvidenceId::new(EVIDENCE_ID).expect("constant agent catalog evidence ID"),
            source: EvidenceSource::Harness,
            locator: "PATH:known-agent-launchers".to_owned(),
            observed_at: Utc::now(),
            summary: "Known agent launcher names were checked without executing commands"
                .to_owned(),
            strength: 35,
            independent_group: "agent-catalog-path".to_owned(),
        }
    }
}

#[async_trait]
impl ProviderAdapter for AgentCatalogAdapter {
    fn id(&self) -> ProviderId {
        ProviderId::new(PROVIDER_ID).expect("constant agent catalog provider ID")
    }

    fn detect(&self, _context: &ProviderContext<'_>) -> DetectionResult {
        let available = !Self::available_entries(std::env::var_os("PATH").as_deref()).is_empty();
        DetectionResult {
            available,
            version: None,
            evidence: vec![Self::evidence()],
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
                "Agent catalog discovery was cancelled",
            )));
        }
        let entries = Self::available_entries(std::env::var_os("PATH").as_deref());
        if entries.is_empty() {
            return Ok(ProviderEnumeration::empty());
        }
        let evidence = Self::evidence();
        let components = entries
            .into_iter()
            .map(|entry| build_component(entry, &evidence))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProviderEnumeration {
            observations: vec![Observation::Components {
                components,
                edges: Vec::new(),
                evidence: vec![evidence],
            }],
            warnings: vec![
                "Agent launcher catalog entries are manual references; no command or executable is copied"
                    .to_owned(),
            ],
        })
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Components { components, .. } = observation else {
            return Err(schema_error(
                "agent catalog received a non-graph observation",
            ));
        };
        if components.is_empty()
            || components.iter().any(|component| {
                component.kind != ComponentKind::Harness
                    || component
                        .provenance
                        .as_ref()
                        .is_none_or(|provenance| provenance.adapter_id != ADAPTER_ID)
                    || !component_is_catalog_only(component)
            })
        {
            return Err(schema_error("agent catalog contains an unowned component"));
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
            .map_err(|_| schema_error("agent catalog operation ID could not be constructed"))?;
        let idempotency_key = format!("agent-catalog-{}", component.id);
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: format!("Review {} installation", component.display_name),
            reason: "The launcher was observed, but Reforge has no trusted installer or portable configuration adapter for it"
                .to_owned(),
            risk: RiskLevel::Medium,
            instructions: vec![
                "Install the agent from its trusted source".to_owned(),
                "Configure it manually on the target Windows PC".to_owned(),
                "Authenticate again; Reforge never restores credentials or sessions".to_owned(),
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
    ) -> ProviderResult<Vec<reforge_domain::VerificationRule>> {
        ensure_owned(component)?;
        Ok(component.verification.clone())
    }
}

fn build_component(
    entry: &AgentCatalogEntry,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    let provider = ProviderId::new(PROVIDER_ID).expect("constant agent catalog provider ID");
    let mut identity = Identity {
        provider_package: Some((provider.clone(), entry.id.to_owned())),
        provider_source: Some(PROVIDER_ID.to_owned()),
        package_family: Some(format!("agent-catalog:{}", entry.id)),
        product_name: Some(entry.display_name.to_owned()),
        executable_name: Some(entry.command.to_owned()),
        publisher: None,
        executable_hash: None,
        install_role: Some("agent-launcher".to_owned()),
        identity_quality: IdentityQuality::Provider,
    };
    let canonical = ComponentId::from_identity(&identity, None)
        .map_err(|_| schema_error("agent catalog identity could not be canonicalized"))?;
    identity.identity_quality = canonical.quality;
    let mut extensions = std::collections::BTreeMap::new();
    extensions.insert(
        "agent_catalog".to_owned(),
        json!({"command": entry.command, "detection": "PATH"}),
    );
    extensions.insert("catalog_only".to_owned(), json!(true));
    Ok(Component {
        id: canonical.id,
        kind: ComponentKind::Harness,
        identity,
        display_name: entry.display_name.to_owned(),
        version: None,
        architecture: None,
        publisher: None,
        provenance: Some(reforge_domain::Provenance {
            provider: Some(provider),
            package_id: Some(entry.id.to_owned()),
            source_url: None,
            observed_version: None,
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: ADAPTER_VERSION.to_owned(),
        }),
        evidence: vec![EvidenceRef {
            id: evidence.id.clone(),
            strength: evidence.strength,
        }],
        confidence: Confidence::Low,
        dependencies: Vec::new(),
        artifacts: Vec::new(),
        restore: RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: Vec::new(),
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "Only the launcher name was observed; configuration and installation are not covered by a reviewed adapter"
                    .to_owned(),
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
            recommended: false,
            score: 0,
            selected_by_default: false,
            sensitive: false,
            size_bytes: 0,
        },
        extensions,
    })
}

fn command_available(path: &OsStr, command: &str) -> bool {
    std::env::split_paths(path)
        .filter(|directory| !directory.as_os_str().is_empty())
        .any(|directory| {
            ["", ".exe", ".cmd", ".bat", ".com", ".ps1"]
                .into_iter()
                .any(|suffix| {
                    let candidate = directory.join(format!("{command}{suffix}"));
                    fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                        metadata.is_file() && !metadata.file_type().is_symlink()
                    })
                })
        })
}

fn component_is_catalog_only(component: &Component) -> bool {
    component
        .extensions
        .get("catalog_only")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

fn ensure_owned(component: &Component) -> ProviderResult<()> {
    if component.kind == ComponentKind::Harness
        && component
            .provenance
            .as_ref()
            .is_some_and(|provenance| provenance.adapter_id == ADAPTER_ID)
        && component_is_catalog_only(component)
    {
        Ok(())
    } else {
        Err(schema_error(
            "agent catalog operation received a foreign component",
        ))
    }
}

fn schema_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::SchemaInvalid, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, fs};

    #[test]
    fn catalog_contains_the_screenshot_available_agents() {
        assert_eq!(SCREENSHOT_AGENT_CATALOG.len(), 30);
        assert!(
            SCREENSHOT_AGENT_CATALOG
                .iter()
                .any(|entry| entry.display_name == "OpenClaw" && entry.command == "openclaw")
        );
        assert!(
            SCREENSHOT_AGENT_CATALOG
                .iter()
                .any(|entry| entry.display_name == "GitHub Copilot" && entry.command == "copilot")
        );
    }

    #[test]
    fn path_catalog_detects_only_regular_non_reparse_launchers() {
        let root = std::env::temp_dir().join(format!(
            "reforge-agent-catalog-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&root).expect("create catalog fixture");
        fs::write(root.join("openclaude.cmd"), b"not executed").expect("write launcher fixture");
        let path = OsString::from(root.as_os_str());
        let detected = AgentCatalogAdapter::available_entries(Some(&path));
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].id, "openclaude");
        fs::remove_dir_all(root).expect("remove catalog fixture");
    }

    #[test]
    fn catalog_component_is_manual_and_not_default_safe() {
        let evidence = AgentCatalogAdapter::evidence();
        let component = build_component(
            SCREENSHOT_AGENT_CATALOG
                .iter()
                .find(|entry| entry.id == "openclaude")
                .expect("catalog entry"),
            &evidence,
        )
        .expect("build catalog component");
        assert_eq!(component.kind, ComponentKind::Harness);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert!(component.artifacts.is_empty());
        assert!(!component.selection.selected_by_default);
        assert!(component_is_catalog_only(&component));
    }
}
