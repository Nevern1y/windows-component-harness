//! Windows registration discovery and manual restore descriptors.
//!
//! This adapter is deliberately observation-only. Registry entries, shortcuts,
//! services, scheduled tasks, and optional features become typed components;
//! none of their command lines, targets outside the token boundary, or
//! registration mutations are exposed as automatic operations.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::Utc;
use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken,
    ManualAction, ManualActionState, Operation, OperationId, OperationKind, Portability,
    Precondition, Provenance, ProviderId, Publisher, RedactionPolicy, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, RiskLevel, RunId, SelectionMetadata, TargetFacts,
    VerificationRule,
};
use reforge_platform_windows::{
    AppxPackageObservation, BuiltinExecutable, DefaultAssociationKind,
    DefaultAssociationObservation, FeatureObservation, RegistryKeyObservation, RegistryQuery,
    RegistryRoot, RegistryScope, RegistryValueData, RegistryView, ScheduledTaskObservation,
    ScheduledTaskState, ServiceObservation, ServiceStartMode, ServiceState, ShellLinkObservation,
    StartupEntryObservation, TaskSnapshot, enumerate_current_user_appx_packages,
    enumerate_default_associations, enumerate_registry_with, enumerate_scheduled_tasks,
    enumerate_services, enumerate_shell_links, enumerate_startup_entries, feature_probe_command,
    parse_feature_output,
};

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "windows-registration";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Read-only adapter for Windows registration and system-state observations.
#[derive(Clone, Debug)]
pub struct WindowsRegistrationAdapter {
    id: ProviderId,
}

impl WindowsRegistrationAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Windows registration provider ID"),
        }
    }
}

impl Default for WindowsRegistrationAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for WindowsRegistrationAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, _context: &ProviderContext<'_>) -> DetectionResult {
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![Evidence {
                id: EvidenceId::new("windows-registration-apis")
                    .expect("constant registration provider evidence ID"),
                source: EvidenceSource::Registry,
                locator: "local:windows-registration-apis".to_owned(),
                observed_at: Utc::now(),
                summary: "Windows registration APIs are available for read-only discovery"
                    .to_owned(),
                strength: 50,
                independent_group: "windows-registration-provider".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        if context.cancellation.is_cancelled() {
            return Err(cancelled_error());
        }

        let known_folders = context.known_folders.clone();
        let native = tokio::task::spawn_blocking(move || NativeSnapshot {
            registry: enumerate_registry_with(&RegistryQuery {
                scopes: vec![RegistryScope::CurrentUser, RegistryScope::LocalMachine],
                views: vec![RegistryView::View32, RegistryView::View64],
                roots: vec![
                    RegistryRoot::Uninstall,
                    RegistryRoot::AppPaths,
                    RegistryRoot::CurrentUserRun,
                ],
            }),
            appx: enumerate_current_user_appx_packages(),
            startup: enumerate_startup_entries(&known_folders),
            services: enumerate_services(),
            tasks: enumerate_scheduled_tasks(),
            shortcuts: enumerate_shell_links(&known_folders),
            default_associations: enumerate_default_associations(),
        })
        .await
        .map_err(|_| operation_error("Windows registration enumeration worker failed"))?;

        if context.cancellation.is_cancelled() {
            return Err(cancelled_error());
        }

        let mut enumeration = ProviderEnumeration::empty();
        enumeration.observations.extend(registry_observations(
            &self.id,
            &native.registry.observations,
        ));
        enumeration
            .observations
            .extend(appx_observations(&self.id, &native.appx.observations));
        enumeration.observations.extend(startup_entry_observations(
            &self.id,
            &native.startup.observations,
        ));
        enumeration.observations.extend(shortcut_observations(
            &self.id,
            &native.shortcuts.observations,
        ));
        enumeration
            .observations
            .extend(default_association_observations(
                &self.id,
                &native.default_associations.observations,
            ));
        enumeration.observations.extend(service_observations(
            &self.id,
            &native.services.observations,
        ));
        enumeration
            .observations
            .extend(task_observations(&self.id, &native.tasks.observations));

        append_native_warnings(&mut enumeration.warnings, &native);

        if context
            .runner
            .builtin_available(BuiltinExecutable::PowerShell)
        {
            let command = feature_probe_command()?;
            let result = context.runner.run(&command, context.cancellation).await?;
            if result.cancelled {
                return Err(cancelled_error());
            }
            if result.timed_out {
                enumeration
                    .warnings
                    .push("Windows optional-feature probe timed out".to_owned());
            } else if result.exit_code != Some(0) {
                enumeration.warnings.push(format!(
                    "Windows optional-feature probe exited without success (code {:?})",
                    result.exit_code
                ));
            } else {
                match parse_feature_output(&result.stdout) {
                    Ok(features) => enumeration
                        .observations
                        .extend(feature_observations(&self.id, &features)),
                    Err(error) => enumeration.warnings.push(error_summary(
                        "Windows optional-feature probe parse failed",
                        &error,
                    )),
                }
            }
        } else {
            enumeration.warnings.push(
                "PowerShell is unavailable; optional-feature observations were skipped".to_owned(),
            );
        }

        enumeration.observations.sort_by_key(observation_sort_key);
        enumeration.warnings.sort();
        enumeration.warnings.dedup();
        Ok(enumeration)
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Registration {
            kind,
            identity,
            evidence,
        } = observation
        else {
            return Err(schema_error(
                "Windows registration adapter received a non-registration observation",
            ));
        };
        if evidence.is_empty() {
            return Err(schema_error(
                "Windows registration observation has no supporting evidence",
            ));
        }
        if identity.provider_package.as_ref().map(|pair| &pair.0) != Some(&self.id)
            || identity.provider_source.as_deref() != Some(PROVIDER_ID)
        {
            return Err(schema_error(
                "Windows registration identity is missing its stable provider source",
            ));
        }
        if !registration_kind(&kind) {
            return Err(schema_error(
                "Windows registration observation has an unsupported component kind",
            ));
        }

        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("Windows registration identity is not canonical"))?;
        let display_name = display_name(&identity);
        let publisher = identity.publisher.clone().map(|name| Publisher {
            name,
            certificate_thumbprint: None,
        });
        let evidence_refs = evidence_refs(&evidence);
        let install_role = identity.install_role.as_deref();
        let requires_elevation = requires_elevation(&kind, install_role);
        let identity_package = identity
            .provider_package
            .as_ref()
            .map(|(_, package)| package.clone());

        let (portability, rationale) = registration_restore_profile(&kind, install_role);
        Ok(vec![Component {
            id: canonical.id,
            kind,
            identity,
            display_name,
            version: None,
            architecture: None,
            publisher,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: identity_package,
                source_url: None,
                observed_version: None,
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs,
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: RestoreStrategy::Manual,
                alternatives: Vec::new(),
                portability,
                requires_elevation,
                requires_user_action: true,
                rationale,
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: None,
                requires_runtime: None,
                requires_elevation,
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
        }])
    }

    fn plan_install(
        &self,
        component: &Component,
        _target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        if component
            .provenance
            .as_ref()
            .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
            || !registration_kind(&component.kind)
        {
            return Err(schema_error(
                "Windows registration plan received a foreign component",
            ));
        }

        let operation_id = OperationId::for_run(run_id, first_ordinal).map_err(|_| {
            schema_error("Windows registration operation ID could not be constructed")
        })?;
        let digest = operation_key(component);
        let action = ManualAction {
            id: digest.clone(),
            component: Some(component.id.clone()),
            title: manual_title(&component.kind, component.identity.install_role.as_deref()),
            reason: manual_reason(&component.kind, component.identity.install_role.as_deref()),
            risk: manual_risk(&component.kind, component.identity.install_role.as_deref()),
            instructions: vec![
                "Review the observed registration in the target before making changes".to_owned(),
                "Use the original vendor or Windows-supported configuration procedure".to_owned(),
                "Do not execute command text or restore service/task registrations from this observation".to_owned(),
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
            idempotency_key: digest,
            verification: Vec::new(),
            requires_elevation: component.restore.requires_elevation,
            non_idempotent: false,
        }])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        if component
            .provenance
            .as_ref()
            .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
            || !registration_kind(&component.kind)
        {
            return Err(schema_error(
                "Windows registration verification received a foreign component",
            ));
        }
        // No registration is recreated or compared through an automatic rule.
        // The manual action remains the only supported restore/verification path.
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct NativeSnapshot {
    registry: reforge_platform_windows::RegistrySnapshot,
    appx: reforge_platform_windows::AppxPackageSnapshot,
    startup: reforge_platform_windows::StartupEntrySnapshot,
    services: reforge_platform_windows::ServiceSnapshot,
    tasks: TaskSnapshot,
    shortcuts: reforge_platform_windows::ShellLinkSnapshot,
    default_associations: reforge_platform_windows::DefaultAssociationSnapshot,
}

fn registry_observations(
    provider: &ProviderId,
    observations: &[RegistryKeyObservation],
) -> Vec<Observation> {
    let mut output = Vec::new();
    for observation in observations {
        match observation.root {
            RegistryRoot::Uninstall => {
                let Some(display) = registry_text(observation, "DisplayName") else {
                    continue;
                };
                let version = registry_text(observation, "DisplayVersion");
                let publisher = registry_text(observation, "Publisher");
                let package = format!(
                    "uninstall:{}:{}:{}",
                    scope_label(observation.scope),
                    view_label(observation.view),
                    observation.key_path
                );
                let mut summary = format!("Uninstall registration: {display}");
                if let Some(version) = version {
                    summary.push_str("; version recorded");
                    summary.push_str(if version.is_empty() {
                        " unavailable"
                    } else {
                        ""
                    });
                }
                output.push(registration_observation(
                    provider,
                    ComponentKind::Application,
                    package,
                    display.clone(),
                    None,
                    publisher,
                    "uninstall-registration",
                    EvidenceSource::Registry,
                    format!(
                        "registry:{}/{}/{}",
                        scope_label(observation.scope),
                        view_label(observation.view),
                        observation.key_path
                    ),
                    summary,
                    80,
                    "registry-uninstall",
                ));
            }
            RegistryRoot::AppPaths => {
                let Some(executable) = registry_key_basename(&observation.key_path) else {
                    continue;
                };
                let package = format!(
                    "app-paths:{}:{}:{}",
                    scope_label(observation.scope),
                    view_label(observation.view),
                    observation.key_path
                );
                let target_recorded = registry_text(observation, "").is_some();
                let summary = if target_recorded {
                    format!("App Paths registration for {executable}; target metadata recorded")
                } else {
                    format!("App Paths registration for {executable}; target metadata unavailable")
                };
                output.push(registration_observation(
                    provider,
                    ComponentKind::PortableBinary,
                    package,
                    executable.clone(),
                    Some(executable),
                    None,
                    "app-paths-registration",
                    EvidenceSource::AppPaths,
                    format!(
                        "registry:{}/{}/{}",
                        scope_label(observation.scope),
                        view_label(observation.view),
                        observation.key_path
                    ),
                    summary,
                    75,
                    "registry-app-paths",
                ));
            }
            RegistryRoot::CurrentUserRun => {
                output.extend(current_user_run_observations(provider, observation));
            }
            RegistryRoot::UserEnvironment | RegistryRoot::SystemEnvironment => {}
        }
    }
    output
}

fn current_user_run_observations(
    provider: &ProviderId,
    observation: &RegistryKeyObservation,
) -> Vec<Observation> {
    let mut seen = BTreeSet::new();
    observation
        .values
        .iter()
        .filter_map(|value| {
            if value.name.trim().is_empty() {
                return None;
            }
            let entry_id = opaque_identifier("startup-run", &value.name);
            if !seen.insert(entry_id.clone()) {
                return None;
            }
            Some(registration_observation(
                provider,
                ComponentKind::Configuration,
                entry_id.clone(),
                "Current-user Run startup entry".to_owned(),
                None,
                None,
                "startup-registry-current-user",
                EvidenceSource::Registry,
                format!("registry:user:{entry_id}"),
                "Current-user Run entry observed; command text is intentionally omitted".to_owned(),
                80,
                "startup-registry-current-user",
            ))
        })
        .collect()
}

fn appx_observations(
    provider: &ProviderId,
    observations: &[AppxPackageObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .filter_map(|observation| {
            let package_name = safe_appx_identifier(&observation.package_name)?;
            let package_family = safe_appx_identifier(&observation.package_family)?;
            let display_name = observation
                .display_name
                .as_deref()
                .and_then(|value| safe_text(value, 512))
                .unwrap_or_else(|| package_name.clone());
            let publisher = observation
                .publisher
                .as_deref()
                .and_then(|value| safe_text(value, 512));
            let mut result = registration_observation(
                provider,
                ComponentKind::Application,
                format!("appx:{package_family}"),
                display_name,
                None,
                publisher,
                "appx-current-user",
                EvidenceSource::Registry,
                format!("appx:{package_family}"),
                "Current-user AppX/MSIX package observed through Windows package metadata"
                    .to_owned(),
                80,
                "appx-current-user",
            );
            if let Observation::Registration { identity, .. } = &mut result {
                identity.package_family = Some(package_family);
            }
            Some(result)
        })
        .collect()
}

fn startup_entry_observations(
    provider: &ProviderId,
    observations: &[StartupEntryObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .map(|observation| {
            let entry_id = opaque_identifier("startup-folder", &observation.source.relative);
            registration_observation(
                provider,
                ComponentKind::Configuration,
                entry_id.clone(),
                "Startup folder entry".to_owned(),
                None,
                None,
                "startup-folder-entry",
                EvidenceSource::FileMetadata,
                format!("startup:{entry_id}"),
                "Startup folder entry observed; file contents and executable behavior are not used"
                    .to_owned(),
                75,
                "startup-folder-entry",
            )
        })
        .collect()
}

fn opaque_identifier(prefix: &str, value: &str) -> String {
    format!("{prefix}:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn safe_appx_identifier(value: &str) -> Option<String> {
    let value = safe_text(value, 512)?;
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        .then_some(value)
}

fn shortcut_observations(
    provider: &ProviderId,
    observations: &[ShellLinkObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .map(|observation| {
            let source_relative = observation.source.relative.clone();
            let is_startup = observation.source.root == KnownFolderToken::Startup;
            let source_identity = if is_startup {
                opaque_identifier("startup-shortcut", &source_relative)
            } else {
                source_relative.clone()
            };
            let install_role = if is_startup {
                "startup-shortcut"
            } else {
                "shortcut-registration"
            };
            let source_name = if is_startup {
                "Startup shortcut".to_owned()
            } else {
                path_basename(&source_relative).unwrap_or_else(|| "shortcut".to_owned())
            };
            let display = observation
                .description
                .as_deref()
                .and_then(|value| safe_text(value, 512))
                .or_else(|| observation.target_name.clone())
                .unwrap_or(source_name.clone());
            let target_name = observation
                .target_name
                .as_deref()
                .and_then(|value| safe_text(value, 512));
            let root = known_folder_label(&observation.source.root);
            let summary = match (&target_name, observation.target_exists) {
                (Some(target), true) => format!("Shortcut target observed: {target}"),
                (Some(target), false) => format!("Shortcut target is missing: {target}"),
                (None, _) => "Shortcut target name is unavailable".to_owned(),
            };
            registration_observation(
                provider,
                ComponentKind::Shell,
                format!("shortcut:{root}:{source_identity}"),
                display,
                target_name,
                None,
                install_role,
                EvidenceSource::Shortcut,
                format!("shortcut:{root}:{source_identity}"),
                summary,
                if observation.target_exists { 80 } else { 55 },
                install_role,
            )
        })
        .collect()
}

fn default_association_observations(
    provider: &ProviderId,
    observations: &[DefaultAssociationObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .filter_map(|observation| {
            let association = safe_association_identifier(&observation.association, 64)?;
            let prog_id = safe_association_identifier(&observation.prog_id, 256)?;
            let kind = default_association_kind_label(observation.kind);
            Some(registration_observation(
                provider,
                ComponentKind::Configuration,
                format!("default-association:{kind}:{association}"),
                format!("Default {association} association"),
                None,
                None,
                "default-association",
                EvidenceSource::Registry,
                format!("default-association:{kind}:{association}"),
                format!("Effective default {kind} association is registered to ProgID {prog_id}"),
                80,
                "default-association-api",
            ))
        })
        .collect()
}

fn service_observations(
    provider: &ProviderId,
    observations: &[ServiceObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .filter_map(|observation| {
            let name = safe_text(&observation.name, 512)?;
            let display = observation
                .display_name
                .as_deref()
                .and_then(|value| safe_text(value, 512))
                .unwrap_or_else(|| name.clone());
            let executable = observation
                .binary_name
                .as_deref()
                .and_then(|value| safe_text(value, 512));
            let summary = format!(
                "Service state={}; start_mode={}; process_id={}",
                service_state_label(observation.state),
                observation
                    .start_mode
                    .map(service_start_mode_label)
                    .unwrap_or("Unavailable"),
                observation
                    .process_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "Unavailable".to_owned())
            );
            Some(registration_observation(
                provider,
                ComponentKind::Service,
                format!("service:{name}"),
                display,
                executable,
                None,
                "service-registration",
                EvidenceSource::Registry,
                format!("scm:{name}"),
                summary,
                80,
                "service-control-manager",
            ))
        })
        .collect()
}

fn task_observations(
    provider: &ProviderId,
    observations: &[ScheduledTaskObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .filter_map(|observation| {
            let path = safe_text(&observation.path, 1024)?;
            let name = safe_text(&observation.name, 512).unwrap_or_else(|| path.clone());
            let summary = format!(
                "Scheduled task state={}; enabled={}; action_count={}",
                task_state_label(observation.state),
                observation
                    .enabled
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "Unavailable".to_owned()),
                observation
                    .action_count
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "Unavailable".to_owned())
            );
            Some(registration_observation(
                provider,
                ComponentKind::ScheduledTask,
                format!("task:{path}"),
                name,
                None,
                None,
                "task-registration",
                EvidenceSource::Registry,
                format!("task-scheduler:{path}"),
                summary,
                80,
                "task-scheduler",
            ))
        })
        .collect()
}

fn feature_observations(
    provider: &ProviderId,
    observations: &[FeatureObservation],
) -> Vec<Observation> {
    observations
        .iter()
        .filter_map(|observation| {
            let name = safe_text(&observation.name, 256)?;
            let summary = format!(
                "Windows feature state={}; restart_required={}",
                observation.state.as_str(),
                observation.restart_required
            );
            Some(registration_observation(
                provider,
                ComponentKind::SystemFeature,
                format!("feature:{name}"),
                name.clone(),
                None,
                None,
                "optional-feature-registration",
                EvidenceSource::PowerShell,
                format!("windows-feature:{name}"),
                summary,
                80,
                "windows-optional-features",
            ))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn registration_observation(
    provider: &ProviderId,
    kind: ComponentKind,
    package: String,
    product_name: String,
    executable_name: Option<String>,
    publisher: Option<String>,
    install_role: &str,
    source: EvidenceSource,
    locator: String,
    summary: String,
    strength: u8,
    independent_group: &str,
) -> Observation {
    let identity = Identity {
        provider_package: Some((provider.clone(), package)),
        provider_source: Some(PROVIDER_ID.to_owned()),
        package_family: None,
        product_name: safe_text(&product_name, 512),
        executable_name: executable_name.and_then(|value| safe_text(&value, 512)),
        publisher: publisher.and_then(|value| safe_text(&value, 512)),
        executable_hash: None,
        install_role: Some(install_role.to_owned()),
        identity_quality: IdentityQuality::Provider,
    };
    Observation::Registration {
        kind,
        identity,
        evidence: vec![make_evidence(
            source,
            locator,
            summary,
            strength,
            independent_group,
        )],
    }
}

fn make_evidence(
    source: EvidenceSource,
    locator: String,
    summary: String,
    strength: u8,
    independent_group: &str,
) -> Evidence {
    let id = evidence_id(&format!("{source:?}"), &locator, &summary);
    Evidence {
        id,
        source,
        locator,
        observed_at: Utc::now(),
        summary,
        strength,
        independent_group: independent_group.to_owned(),
    }
}

fn evidence_id(source: &str, locator: &str, summary: &str) -> EvidenceId {
    let mut hasher = blake3::Hasher::new();
    for value in [source, locator, summary] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    EvidenceId::new(format!(
        "windows-registration-evidence-{}",
        hasher.finalize().to_hex()
    ))
    .expect("hashed registration evidence ID")
}

fn operation_key(component: &Component) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(component.id.as_str().as_bytes());
    format!("windows-registration-manual-{}", hasher.finalize().to_hex())
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
        .and_then(|value| safe_text(&value, 4 * 1024))
}

fn registry_key_basename(value: &str) -> Option<String> {
    value
        .rsplit(['\\', '/'])
        .next()
        .and_then(|name| safe_text(name, 512))
        .filter(|name| !name.is_empty())
}

fn path_basename(value: &str) -> Option<String> {
    value
        .rsplit(['\\', '/'])
        .next()
        .and_then(|name| safe_text(name, 512))
        .filter(|name| !name.is_empty())
}

fn safe_text(value: &str, max_bytes: usize) -> Option<String> {
    RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
}

fn safe_association_identifier(value: &str, max_bytes: usize) -> Option<String> {
    let value = safe_text(value, max_bytes)?;
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        .then_some(value)
}

fn display_name(identity: &Identity) -> String {
    identity
        .product_name
        .clone()
        .or_else(|| identity.executable_name.clone())
        .unwrap_or_else(|| "Windows registration".to_owned())
}

fn evidence_refs(evidence: &[Evidence]) -> Vec<EvidenceRef> {
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

fn confidence_from_evidence(evidence: &[Evidence]) -> Confidence {
    let mut score = evidence
        .iter()
        .fold(0u16, |score, record| {
            score.saturating_add(u16::from(record.strength))
        })
        .min(100);
    let independent_groups: BTreeSet<_> = evidence
        .iter()
        .map(|record| record.independent_group.as_str())
        .collect();
    if independent_groups.len() >= 2 {
        score = score.saturating_add(10).min(100);
    }
    if score >= 90 && independent_groups.len() >= 2 {
        Confidence::Confirmed
    } else if score >= 75 {
        Confidence::High
    } else if score >= 45 {
        Confidence::Medium
    } else if score >= 20 {
        Confidence::Low
    } else {
        Confidence::Unknown
    }
}

fn registration_kind(kind: &ComponentKind) -> bool {
    matches!(
        kind,
        ComponentKind::Application
            | ComponentKind::PortableBinary
            | ComponentKind::Shell
            | ComponentKind::Service
            | ComponentKind::ScheduledTask
            | ComponentKind::SystemFeature
            | ComponentKind::Configuration
    )
}

fn requires_elevation(kind: &ComponentKind, install_role: Option<&str>) -> bool {
    if matches!(
        install_role,
        Some(
            "appx-current-user"
                | "startup-registry-current-user"
                | "startup-folder-entry"
                | "startup-shortcut"
        )
    ) {
        return false;
    }
    matches!(
        kind,
        ComponentKind::Application
            | ComponentKind::PortableBinary
            | ComponentKind::Service
            | ComponentKind::ScheduledTask
            | ComponentKind::SystemFeature
    )
}

fn registration_restore_profile(
    kind: &ComponentKind,
    install_role: Option<&str>,
) -> (Portability, Vec<String>) {
    match install_role {
        Some("appx-current-user") => (
            Portability::UserBound,
            vec![
                "AppX/MSIX package registration is observed for the current user only".to_owned(),
                "Package installation or registration is never performed automatically".to_owned(),
            ],
        ),
        Some("startup-registry-current-user" | "startup-folder-entry" | "startup-shortcut") => (
            Portability::UserBound,
            vec![
                "Current-user startup state is recorded without command text or file contents".to_owned(),
                "Startup behavior is never recreated automatically".to_owned(),
            ],
        ),
        _ => match kind {
            ComponentKind::Service => (
                Portability::MachineBound,
                vec![
                    "Service configuration is observed as system state only".to_owned(),
                    "Automatic service creation or start is prohibited".to_owned(),
                ],
            ),
            ComponentKind::ScheduledTask => (
                Portability::MachineBound,
                vec![
                    "Task Scheduler metadata is observed without executable action text".to_owned(),
                    "Automatic task registration or execution is prohibited".to_owned(),
                ],
            ),
            ComponentKind::SystemFeature => (
                Portability::MachineBound,
                vec![
                    "Windows feature state must be reviewed against target compatibility".to_owned(),
                    "Feature enablement and reboot decisions remain manual".to_owned(),
                ],
            ),
            ComponentKind::Configuration => (
                Portability::UserBound,
                vec![
                    "Effective default application associations are per-user state".to_owned(),
                    "Protected UserChoice data is never written automatically".to_owned(),
                ],
            ),
            ComponentKind::Shell => (
                Portability::PartiallyPortable,
                vec![
                    "Shortcut metadata is retained, but its target is not an executable restore instruction".to_owned(),
                ],
            ),
            _ => (
                Portability::PartiallyPortable,
                vec![
                    "A registration observation has no trusted installer or package source".to_owned(),
                    "Restore remains a reviewed manual action".to_owned(),
                ],
            ),
        },
    }
}

fn manual_title(kind: &ComponentKind, install_role: Option<&str>) -> String {
    match install_role {
        Some("appx-current-user") => "Review current-user AppX/MSIX package".to_owned(),
        Some("startup-registry-current-user" | "startup-folder-entry" | "startup-shortcut") => {
            "Review current-user Windows startup entry".to_owned()
        }
        _ => match kind {
            ComponentKind::Service => "Review Windows service registration".to_owned(),
            ComponentKind::ScheduledTask => "Review scheduled task registration".to_owned(),
            ComponentKind::SystemFeature => "Review Windows optional feature".to_owned(),
            ComponentKind::Configuration => "Review Windows default association".to_owned(),
            ComponentKind::Shell => "Review shortcut registration".to_owned(),
            ComponentKind::PortableBinary => "Review App Paths registration".to_owned(),
            _ => "Review Windows application registration".to_owned(),
        },
    }
}

fn manual_reason(kind: &ComponentKind, install_role: Option<&str>) -> String {
    match install_role {
        Some("appx-current-user") => {
            "AppX/MSIX package state is user-bound and is never restored automatically".to_owned()
        }
        Some("startup-registry-current-user" | "startup-folder-entry" | "startup-shortcut") => {
            "Startup behavior may execute code; the target entry must be reviewed manually".to_owned()
        }
        _ => match kind {
            ComponentKind::Service => {
                "Service configuration is machine-bound and is never recreated automatically".to_owned()
            }
            ComponentKind::ScheduledTask => {
                "Task registration may contain executable behavior and is never recreated automatically"
                    .to_owned()
            }
            ComponentKind::SystemFeature => {
                "Feature changes can require elevation and reboot; target state must be reviewed"
                    .to_owned()
            }
            ComponentKind::Configuration => {
                "Windows protects per-user default associations; target state remains manual".to_owned()
            }
            ComponentKind::Shell => {
                "Shortcut targets are observations, not executable restore instructions".to_owned()
            }
            _ => "The registration has no trusted source package for automatic restore".to_owned(),
        },
    }
}

fn manual_risk(kind: &ComponentKind, install_role: Option<&str>) -> RiskLevel {
    if matches!(
        install_role,
        Some("startup-registry-current-user" | "startup-folder-entry" | "startup-shortcut")
    ) {
        return RiskLevel::High;
    }
    match kind {
        ComponentKind::Service | ComponentKind::ScheduledTask | ComponentKind::SystemFeature => {
            RiskLevel::High
        }
        _ => RiskLevel::Medium,
    }
}

fn observation_sort_key(observation: &Observation) -> String {
    match observation {
        Observation::Registration { identity, .. } => identity
            .provider_package
            .as_ref()
            .map(|(_, package)| package.clone())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn append_native_warnings(warnings: &mut Vec<String>, snapshot: &NativeSnapshot) {
    for error in &snapshot.registry.errors {
        warnings.push(format!(
            "registry {} {} {} {}: {}",
            scope_label(error.scope),
            view_label(error.view),
            root_label(error.root),
            error.key_path,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.appx.errors {
        let package = error
            .package_family
            .as_deref()
            .and_then(safe_appx_identifier)
            .unwrap_or_else(|| "<REDACTED>".to_owned());
        warnings.push(format!(
            "AppX/MSIX package {package} {:?}: {}",
            error.operation,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.startup.errors {
        warnings.push(format!(
            "startup {} {:?}: {}",
            known_folder_label(&error.root),
            error.operation,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.shortcuts.errors {
        let source = error
            .source
            .as_ref()
            .map(|path| {
                let root = known_folder_label(&path.root);
                if path.root == KnownFolderToken::Startup {
                    format!(
                        "{root}:{}",
                        opaque_identifier("startup-shortcut", &path.relative)
                    )
                } else {
                    format!("{root}:{}", path.relative)
                }
            })
            .unwrap_or_else(|| known_folder_label(&error.root));
        warnings.push(format!(
            "shortcut {source} {:?}: {}",
            error.operation,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.default_associations.errors {
        let association = safe_association_identifier(&error.association, 64)
            .unwrap_or_else(|| "<REDACTED>".to_owned());
        warnings.push(format!(
            "default association {} {association} {:?}: {}",
            default_association_kind_label(error.kind),
            error.operation,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.services.errors {
        let name = error
            .service_name
            .as_deref()
            .and_then(|value| safe_text(value, 512))
            .unwrap_or_else(|| "<REDACTED>".to_owned());
        warnings.push(format!(
            "service {name} {:?}: {}",
            error.operation,
            error_summary_text(&error.error)
        ));
    }
    for error in &snapshot.tasks.errors {
        let path = error
            .path
            .as_deref()
            .and_then(|value| safe_text(value, 1024))
            .unwrap_or_else(|| "<REDACTED>".to_owned());
        warnings.push(format!(
            "task {path} {:?}: {}",
            error.operation,
            error_summary_text(&error.error)
        ));
    }
}

fn error_summary(prefix: &str, error: &ErrorEnvelope) -> String {
    format!("{prefix}: {}", error_summary_text(error))
}

fn error_summary_text(error: &ErrorEnvelope) -> String {
    let mut value = error.message.clone();
    if let Some(detail) = &error.technical_detail {
        value.push_str(" — ");
        value.push_str(detail);
    }
    safe_text(&value, 1024).unwrap_or_else(|| "The observation failed safely".to_owned())
}

fn scope_label(scope: RegistryScope) -> &'static str {
    match scope {
        RegistryScope::LocalMachine => "machine",
        RegistryScope::CurrentUser => "user",
    }
}

fn view_label(view: RegistryView) -> &'static str {
    match view {
        RegistryView::View32 => "32",
        RegistryView::View64 => "64",
    }
}

fn root_label(root: RegistryRoot) -> &'static str {
    match root {
        RegistryRoot::Uninstall => "uninstall",
        RegistryRoot::AppPaths => "app-paths",
        RegistryRoot::CurrentUserRun => "current-user-run",
        RegistryRoot::UserEnvironment => "user-environment",
        RegistryRoot::SystemEnvironment => "system-environment",
    }
}

fn known_folder_label(token: &KnownFolderToken) -> String {
    match token {
        KnownFolderToken::UserProfile => "user-profile".to_owned(),
        KnownFolderToken::RoamingAppData => "roaming-app-data".to_owned(),
        KnownFolderToken::LocalAppData => "local-app-data".to_owned(),
        KnownFolderToken::ProgramData => "program-data".to_owned(),
        KnownFolderToken::ProgramFiles => "program-files".to_owned(),
        KnownFolderToken::ProgramFilesX86 => "program-files-x86".to_owned(),
        KnownFolderToken::StartMenu => "start-menu".to_owned(),
        KnownFolderToken::Desktop => "desktop".to_owned(),
        KnownFolderToken::Startup => "startup".to_owned(),
        KnownFolderToken::Documents => "documents".to_owned(),
        KnownFolderToken::UserSelected { id } => format!("user-selected-{id}"),
    }
}

fn service_state_label(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "Stopped",
        ServiceState::StartPending => "StartPending",
        ServiceState::StopPending => "StopPending",
        ServiceState::Running => "Running",
        ServiceState::ContinuePending => "ContinuePending",
        ServiceState::PausePending => "PausePending",
        ServiceState::Paused => "Paused",
        ServiceState::Unknown(_) => "Unknown",
    }
}

fn service_start_mode_label(mode: ServiceStartMode) -> &'static str {
    match mode {
        ServiceStartMode::Boot => "Boot",
        ServiceStartMode::System => "System",
        ServiceStartMode::Automatic => "Automatic",
        ServiceStartMode::Manual => "Manual",
        ServiceStartMode::Disabled => "Disabled",
        ServiceStartMode::Unknown(_) => "Unknown",
    }
}

fn task_state_label(state: ScheduledTaskState) -> &'static str {
    match state {
        ScheduledTaskState::Unknown => "Unknown",
        ScheduledTaskState::Disabled => "Disabled",
        ScheduledTaskState::Queued => "Queued",
        ScheduledTaskState::Ready => "Ready",
        ScheduledTaskState::Running => "Running",
    }
}

fn default_association_kind_label(kind: DefaultAssociationKind) -> &'static str {
    match kind {
        DefaultAssociationKind::UrlProtocol => "url-protocol",
        DefaultAssociationKind::FileExtension => "file-extension",
    }
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Windows registration observation is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Windows registration discovery failed",
        )
        .with_technical_detail(detail),
    )
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "Windows registration discovery was cancelled",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::PathToken;

    fn observation(kind: ComponentKind) -> Observation {
        registration_observation(
            &ProviderId::new(PROVIDER_ID).expect("provider"),
            kind,
            "fixture:registration".to_owned(),
            "Fixture registration".to_owned(),
            None,
            None,
            "fixture-registration",
            EvidenceSource::Registry,
            "fixture:registration".to_owned(),
            "fixture registration state".to_owned(),
            80,
            "fixture",
        )
    }

    #[test]
    fn registration_normalizes_to_manual_component() {
        let adapter = WindowsRegistrationAdapter::new();
        let component = adapter
            .normalize(observation(ComponentKind::Service))
            .expect("service normalization")
            .remove(0);
        assert_eq!(component.kind, ComponentKind::Service);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert_eq!(component.restore.portability, Portability::MachineBound);
        assert!(component.restore.requires_elevation);
        assert_eq!(component.confidence, Confidence::High);
        assert!(component.verification.is_empty());
    }

    #[test]
    fn every_registration_plan_is_an_explicit_manual_action() {
        let adapter = WindowsRegistrationAdapter::new();
        let component = adapter
            .normalize(observation(ComponentKind::ScheduledTask))
            .expect("task normalization")
            .remove(0);
        let run_id = RunId::new(uuid::Uuid::now_v7()).expect("run id");
        let target = TargetFacts {
            host: reforge_domain::HostFacts {
                os_version: "Windows".to_owned(),
                os_build: "fixture".to_owned(),
                architecture: reforge_domain::Architecture::X64,
                elevated: false,
                account_scope: reforge_domain::AccountScope::User,
                sid_fingerprint: None,
                known_folders: Vec::new(),
                drives: Vec::new(),
                free_bytes: Vec::new(),
            },
            installed: Vec::new(),
            providers: Vec::new(),
            runtimes: Vec::new(),
            environment: Vec::new(),
            fingerprint: "fixture-target".to_owned(),
        };
        let operations = adapter
            .plan_install(&component, &target, &run_id, 1)
            .expect("manual task plan");
        assert_eq!(operations.len(), 1);
        assert!(matches!(
            operations[0].kind,
            OperationKind::OpenManualAction { .. }
        ));
        assert!(operations[0].requires_elevation);
        assert!(!operations[0].non_idempotent);
    }

    #[test]
    fn missing_shortcut_target_remains_observable_without_target_command_text() {
        let source = PathToken::new(KnownFolderToken::Desktop, "fixture.lnk").expect("path token");
        let observation = ShellLinkObservation {
            source,
            target: None,
            target_name: Some("missing.exe".to_owned()),
            target_exists: false,
            description: Some("Fixture shortcut".to_owned()),
        };
        let mapped = shortcut_observations(
            &ProviderId::new(PROVIDER_ID).expect("provider"),
            &[observation],
        );
        let Observation::Registration { evidence, .. } = &mapped[0] else {
            panic!("shortcut registration");
        };
        assert_eq!(evidence[0].strength, 55);
        assert!(!evidence[0].summary.contains("C:\\"));
        assert!(!evidence[0].summary.contains("/"));
    }

    #[test]
    fn service_and_task_metadata_stays_non_executable() {
        let provider = ProviderId::new(PROVIDER_ID).expect("provider");
        let services = service_observations(
            &provider,
            &[ServiceObservation {
                name: "FixtureService".to_owned(),
                display_name: Some("Fixture Service".to_owned()),
                state: ServiceState::Running,
                start_mode: Some(ServiceStartMode::Automatic),
                service_type: 0x10,
                process_id: Some(4242),
                binary_name: Some("fixture-service.exe".to_owned()),
            }],
        );
        let Observation::Registration {
            kind,
            identity,
            evidence,
        } = &services[0]
        else {
            panic!("service registration");
        };
        assert_eq!(*kind, ComponentKind::Service);
        assert_eq!(
            identity.executable_name.as_deref(),
            Some("fixture-service.exe")
        );
        assert!(evidence[0].summary.contains("state=Running"));
        assert!(evidence[0].summary.contains("start_mode=Automatic"));
        assert!(evidence[0].summary.contains("process_id=4242"));
        assert!(!evidence[0].summary.contains("C:\\"));

        let tasks = task_observations(
            &provider,
            &[ScheduledTaskObservation {
                name: "Fixture Task".to_owned(),
                path: "\\Fixture\\Task".to_owned(),
                state: ScheduledTaskState::Ready,
                enabled: Some(true),
                action_count: Some(2),
            }],
        );
        let Observation::Registration { kind, evidence, .. } = &tasks[0] else {
            panic!("task registration");
        };
        assert_eq!(*kind, ComponentKind::ScheduledTask);
        assert!(evidence[0].summary.contains("state=Ready"));
        assert!(evidence[0].summary.contains("enabled=true"));
        assert!(evidence[0].summary.contains("action_count=2"));
        assert!(!evidence[0].summary.contains("C:\\"));
    }

    #[test]
    fn default_association_observation_is_manual_per_user_configuration() {
        let adapter = WindowsRegistrationAdapter::new();
        let mapped = default_association_observations(
            &ProviderId::new(PROVIDER_ID).expect("provider"),
            &[DefaultAssociationObservation {
                association: "https".to_owned(),
                kind: DefaultAssociationKind::UrlProtocol,
                prog_id: "MSEdgeHTM".to_owned(),
            }],
        );
        let Observation::Registration { evidence, .. } = &mapped[0] else {
            panic!("default association registration");
        };
        assert!(evidence[0].summary.contains("ProgID MSEdgeHTM"));
        assert!(!evidence[0].summary.contains("C:\\"));

        let component = adapter
            .normalize(mapped.into_iter().next().expect("association observation"))
            .expect("association normalization")
            .remove(0);
        assert_eq!(component.kind, ComponentKind::Configuration);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert_eq!(component.restore.portability, Portability::UserBound);
        assert!(!component.restore.requires_elevation);
        assert!(component.restore.requires_user_action);
    }

    #[test]
    fn appx_observation_is_a_current_user_manual_descriptor() {
        let adapter = WindowsRegistrationAdapter::new();
        let mapped = appx_observations(
            &ProviderId::new(PROVIDER_ID).expect("provider"),
            &[AppxPackageObservation {
                package_name: "Microsoft.WindowsStore".to_owned(),
                package_family: "Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned(),
                display_name: Some("Microsoft Store".to_owned()),
                publisher: Some("Microsoft Corporation".to_owned()),
            }],
        );
        let Observation::Registration {
            identity, evidence, ..
        } = &mapped[0]
        else {
            panic!("AppX registration");
        };
        assert_eq!(
            identity.package_family.as_deref(),
            Some("Microsoft.WindowsStore_8wekyb3d8bbwe")
        );
        assert_eq!(identity.install_role.as_deref(), Some("appx-current-user"));
        assert!(!evidence[0].summary.contains("C:\\"));

        let component = adapter
            .normalize(mapped.into_iter().next().expect("AppX observation"))
            .expect("AppX normalization")
            .remove(0);
        assert_eq!(component.kind, ComponentKind::Application);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert_eq!(component.restore.portability, Portability::UserBound);
        assert!(!component.restore.requires_elevation);
        assert!(component.restore.requires_user_action);
    }

    #[test]
    fn startup_sources_are_opaque_manual_descriptors() {
        let provider = ProviderId::new(PROVIDER_ID).expect("provider");
        let folder_entry = StartupEntryObservation {
            source: PathToken::new(KnownFolderToken::Startup, "personal-launch.cmd")
                .expect("Startup path token"),
        };
        let mapped = startup_entry_observations(&provider, &[folder_entry]);
        let rendered = format!("{:?}", mapped[0]);
        assert!(!rendered.contains("personal-launch.cmd"));
        assert_eq!(
            match &mapped[0] {
                Observation::Registration { identity, .. } => identity.install_role.as_deref(),
                _ => None,
            },
            Some("startup-folder-entry")
        );

        let current_user_run = RegistryKeyObservation {
            scope: RegistryScope::CurrentUser,
            view: RegistryView::View64,
            root: RegistryRoot::CurrentUserRun,
            key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_owned(),
            values: vec![reforge_platform_windows::RegistryValueObservation {
                name: "personal-launch".to_owned(),
                value_type: reforge_platform_windows::RegistryValueType::String,
                data: RegistryValueData::Text(reforge_platform_windows::RegistryTextValue {
                    redacted: Some(r"C:\Users\fixture\private.cmd".to_owned()),
                    normalized: None,
                }),
            }],
        };
        let run_mapped = registry_observations(&provider, &[current_user_run]);
        let rendered = format!("{:?}", run_mapped[0]);
        assert!(!rendered.contains("personal-launch"));
        assert!(!rendered.contains("C:\\Users\\fixture"));

        let adapter = WindowsRegistrationAdapter::new();
        let component = adapter
            .normalize(mapped.into_iter().next().expect("Startup observation"))
            .expect("Startup normalization")
            .remove(0);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert_eq!(component.restore.portability, Portability::UserBound);
        assert!(!component.restore.requires_elevation);
        assert_eq!(
            manual_title(&component.kind, component.identity.install_role.as_deref()),
            "Review current-user Windows startup entry"
        );
    }

    #[test]
    fn access_denials_remain_redacted_warnings() {
        let denied = || {
            ErrorEnvelope::new(ReforgeErrorCode::AccessDenied, "Access denied")
                .with_technical_detail(r"C:\Users\fixture\private")
        };
        let snapshot = NativeSnapshot {
            registry: reforge_platform_windows::RegistrySnapshot::default(),
            appx: reforge_platform_windows::AppxPackageSnapshot {
                observations: Vec::new(),
                errors: vec![reforge_platform_windows::AppxAccessError {
                    package_family: Some("Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned()),
                    operation: reforge_platform_windows::AppxOperation::ReadPackageMetadata,
                    hresult: 0x8007_0005,
                    error: denied(),
                }],
            },
            startup: reforge_platform_windows::StartupEntrySnapshot {
                observations: Vec::new(),
                errors: vec![reforge_platform_windows::StartupAccessError {
                    root: KnownFolderToken::Startup,
                    operation: reforge_platform_windows::StartupOperation::InspectEntry,
                    error: denied(),
                }],
            },
            services: reforge_platform_windows::ServiceSnapshot {
                observations: Vec::new(),
                errors: vec![reforge_platform_windows::ServiceAccessError {
                    service_name: Some("FixtureService".to_owned()),
                    operation: reforge_platform_windows::ServiceOperation::OpenService,
                    win32_code: 5,
                    error: denied(),
                }],
            },
            tasks: TaskSnapshot {
                observations: Vec::new(),
                errors: vec![reforge_platform_windows::TaskAccessError {
                    path: Some("\\Fixture\\Task".to_owned()),
                    operation: reforge_platform_windows::TaskOperation::ReadTask,
                    hresult: 0x8007_0005,
                    error: denied(),
                }],
            },
            shortcuts: reforge_platform_windows::ShellLinkSnapshot::default(),
            default_associations: reforge_platform_windows::DefaultAssociationSnapshot {
                observations: Vec::new(),
                errors: vec![reforge_platform_windows::DefaultAssociationAccessError {
                    association: "https".to_owned(),
                    kind: DefaultAssociationKind::UrlProtocol,
                    operation:
                        reforge_platform_windows::DefaultAssociationOperation::QueryCurrentDefault,
                    hresult: 0x8007_0005,
                    error: denied(),
                }],
            },
        };
        let mut warnings = Vec::new();
        append_native_warnings(&mut warnings, &snapshot);
        let warnings = warnings.join("\n");
        assert!(warnings.contains("service FixtureService OpenService: Access denied"));
        assert!(warnings.contains("task \\Fixture\\Task ReadTask: Access denied"));
        assert!(
            warnings.contains(
                "default association url-protocol https QueryCurrentDefault: Access denied"
            )
        );
        assert!(warnings.contains("AppX/MSIX package Microsoft.WindowsStore_8wekyb3d8bbwe ReadPackageMetadata: Access denied"));
        assert!(warnings.contains("startup startup InspectEntry: Access denied"));
        assert!(!warnings.contains("C:\\Users\\fixture"));
    }

    #[test]
    fn registry_values_ignore_binary_and_secret_shapes() {
        let key = RegistryKeyObservation {
            scope: RegistryScope::CurrentUser,
            view: RegistryView::View64,
            root: RegistryRoot::Uninstall,
            key_path: "Software\\fixture".to_owned(),
            values: vec![
                reforge_platform_windows::RegistryValueObservation {
                    name: "DisplayName".to_owned(),
                    value_type: reforge_platform_windows::RegistryValueType::String,
                    data: RegistryValueData::Text(reforge_platform_windows::RegistryTextValue {
                        redacted: Some("Fixture".to_owned()),
                        normalized: Some("fixture".to_owned()),
                    }),
                },
                reforge_platform_windows::RegistryValueObservation {
                    name: "DisplayIcon".to_owned(),
                    value_type: reforge_platform_windows::RegistryValueType::Binary,
                    data: RegistryValueData::Opaque { byte_len: 12 },
                },
            ],
        };
        let mapped =
            registry_observations(&ProviderId::new(PROVIDER_ID).expect("provider"), &[key]);
        assert_eq!(mapped.len(), 1);
    }
}
