//! Fail-closed target compatibility analysis.

use reforge_domain::{
    Architecture, Blocker, CompatibilityResult, CompatibilityStatus, Component, ComponentId,
    Confirmation, ManualAction, ManualActionState, PackageGraph, PackageManifest, ReforgeErrorCode,
    RiskLevel, TargetFacts,
};

/// Operational reserve retained beyond the selected uncompressed restore size.
pub const MINIMUM_FREE_SPACE_MARGIN_BYTES: u64 = 64 * 1024 * 1024;
/// Additional proportional reserve for staging, backups, and journal writes.
pub const FREE_SPACE_MARGIN_PERCENT: u64 = 10;

#[derive(Clone, Copy, Debug, Default)]
pub struct CompatibilityEngine;

impl CompatibilityEngine {
    pub fn new() -> Self {
        Self
    }

    /// Compare package and component requirements with normalized target facts.
    pub fn evaluate(
        &self,
        manifest: &PackageManifest,
        graph: &PackageGraph,
        required_disk_bytes: u64,
        target: &TargetFacts,
    ) -> CompatibilityResult {
        let mut blockers = Vec::new();
        let mut confirmations = Vec::new();
        let mut warnings = Vec::new();

        if target.host.os_build.trim().is_empty() {
            warnings.push("Target Windows build is unavailable".to_owned());
        }
        if target.host.architecture == Architecture::Unknown {
            warnings.push("Target architecture is unknown".to_owned());
        }

        if let Some(required_os) = manifest.required_os.as_deref() {
            check_os_requirement(required_os, None, target, &mut blockers);
        }
        if let Some(required_architecture) = &manifest.required_architecture {
            check_architecture_requirement(required_architecture, None, target, &mut blockers);
        }

        check_disk_requirement(
            required_disk_bytes,
            target,
            &mut blockers,
            &mut confirmations,
            &mut warnings,
        );

        for component in &graph.components {
            check_component(component, target, &mut blockers, &mut warnings);
        }

        blockers.sort_by(|left, right| {
            left.component
                .cmp(&right.component)
                .then_with(|| left.code.to_string().cmp(&right.code.to_string()))
                .then_with(|| left.reason.cmp(&right.reason))
        });
        blockers.dedup();
        confirmations.sort_by(|left, right| left.id.cmp(&right.id));
        confirmations.dedup();
        warnings.sort();
        warnings.dedup();

        let status = if blockers.is_empty() {
            if confirmations.is_empty() {
                CompatibilityStatus::Ready
            } else {
                CompatibilityStatus::RequiresConfirmation
            }
        } else {
            CompatibilityStatus::Blocked
        };
        CompatibilityResult {
            status,
            blockers,
            confirmations,
            warnings,
        }
    }
}

/// Required bytes including the documented staging/backup margin.
pub fn recommended_free_bytes(required_disk_bytes: u64) -> Option<u64> {
    let proportional = required_disk_bytes.div_ceil(100 / FREE_SPACE_MARGIN_PERCENT);
    required_disk_bytes.checked_add(proportional.max(MINIMUM_FREE_SPACE_MARGIN_BYTES))
}

fn check_component(
    component: &Component,
    target: &TargetFacts,
    blockers: &mut Vec<Blocker>,
    warnings: &mut Vec<String>,
) {
    let requirement = &component.compatibility;
    if let Some(required_os) = requirement.required_os.as_deref() {
        check_os_requirement(required_os, Some(&component.id), target, blockers);
    }
    if let Some(required_architecture) = &requirement.required_architecture {
        check_architecture_requirement(
            required_architecture,
            Some(&component.id),
            target,
            blockers,
        );
    }

    if (requirement.requires_elevation || component.restore.requires_elevation)
        && !target.host.elevated
    {
        blockers.push(manual_blocker(
            ReforgeErrorCode::AccessDenied,
            Some(component.id.clone()),
            "The component requires an elevated restore process",
            "Relaunch Reforge with elevation",
            "Relaunch Reforge as administrator, rescan the target, and review the plan again.",
            RiskLevel::High,
        ));
    }

    if let Some(provider) = &requirement.requires_provider {
        match target.providers.iter().find(|fact| &fact.id == provider) {
            Some(fact) if fact.available => {
                if fact.version.is_none() {
                    warnings.push(format!(
                        "Required provider {} is available but its version is unknown",
                        provider.as_str()
                    ));
                }
            }
            _ => blockers.push(manual_blocker(
                ReforgeErrorCode::ProviderUnavailable,
                Some(component.id.clone()),
                "A required package provider is unavailable on the target",
                "Install or enable the required provider",
                "Install or enable the provider through its documented setup path, then rescan the target.",
                RiskLevel::High,
            )),
        }
    }

    if let Some(runtime) = &requirement.requires_runtime {
        match target.runtimes.iter().find(|fact| &fact.id == runtime) {
            Some(fact) => {
                if fact.version.is_none() {
                    warnings.push(format!(
                        "Required runtime {} is present but its version is unknown",
                        runtime.as_str()
                    ));
                }
                if let Some(architecture) = &fact.architecture
                    && !architecture_matches(architecture, &target.host.architecture)
                {
                    blockers.push(manual_blocker(
                        ReforgeErrorCode::ArchitectureConflict,
                        Some(component.id.clone()),
                        "The required runtime architecture does not match the target",
                        "Install a compatible runtime architecture",
                        "Install a runtime build compatible with the target architecture, then rescan.",
                        RiskLevel::High,
                    ));
                }
            }
            None => blockers.push(manual_blocker(
                ReforgeErrorCode::TargetConflict,
                Some(component.id.clone()),
                "A required runtime is absent from the target",
                "Install the required runtime",
                "Install the exact required runtime through a reviewed provider, then rescan the target.",
                RiskLevel::High,
            )),
        }
    }

    if requirement.requires_wsl {
        check_subsystem_provider(component, "wsl", "WSL", target, blockers, warnings);
    }
    if requirement.requires_docker {
        check_subsystem_provider(component, "docker", "Docker", target, blockers, warnings);
    }
}

fn check_os_requirement(
    required: &str,
    component: Option<&ComponentId>,
    target: &TargetFacts,
    blockers: &mut Vec<Blocker>,
) {
    if os_matches(required, &target.host.os_version) {
        return;
    }
    blockers.push(manual_blocker(
        ReforgeErrorCode::OsConflict,
        component.cloned(),
        "The target operating system does not satisfy a package requirement",
        "Use a compatible Windows target",
        "Move this component to a compatible Windows target or remove it from the restore selection.",
        RiskLevel::High,
    ));
}

fn check_architecture_requirement(
    required: &Architecture,
    component: Option<&ComponentId>,
    target: &TargetFacts,
    blockers: &mut Vec<Blocker>,
) {
    if architecture_matches(required, &target.host.architecture) {
        return;
    }
    blockers.push(manual_blocker(
        ReforgeErrorCode::ArchitectureConflict,
        component.cloned(),
        "The target architecture does not satisfy a package requirement",
        "Use a compatible target architecture",
        "Move this component to a compatible target architecture or remove it from the restore selection.",
        RiskLevel::High,
    ));
}

fn check_disk_requirement(
    required: u64,
    target: &TargetFacts,
    blockers: &mut Vec<Blocker>,
    confirmations: &mut Vec<Confirmation>,
    warnings: &mut Vec<String>,
) {
    if required == 0 {
        if target.host.free_bytes.is_empty() {
            warnings.push("Target free-space facts are unavailable".to_owned());
        }
        return;
    }
    let Some(available) = target.host.free_bytes.iter().map(|fact| fact.bytes).max() else {
        blockers.push(manual_blocker(
            ReforgeErrorCode::InsufficientDisk,
            None,
            "Target free space could not be verified",
            "Verify target free space",
            "Verify free space on the destination volume and rescan before restoring data.",
            RiskLevel::High,
        ));
        return;
    };
    if available < required {
        blockers.push(manual_blocker(
            ReforgeErrorCode::InsufficientDisk,
            None,
            "Target free space is smaller than the selected restore size",
            "Free disk space or reduce the selection",
            "Free space on the destination volume or remove large items from the restore selection.",
            RiskLevel::High,
        ));
        return;
    }
    let Some(recommended) = recommended_free_bytes(required) else {
        blockers.push(manual_blocker(
            ReforgeErrorCode::InsufficientDisk,
            None,
            "Required disk-space calculation overflowed",
            "Reduce the restore selection",
            "Reduce the selected restore size and generate the plan again.",
            RiskLevel::High,
        ));
        return;
    };
    if available < recommended {
        confirmations.push(Confirmation {
            id: "confirm_low_disk_margin".to_owned(),
            component: None,
            reason: "Target has the required bytes but not the staging and backup margin"
                .to_owned(),
            risk: RiskLevel::High,
        });
    }
}

fn check_subsystem_provider(
    component: &Component,
    provider_id: &str,
    label: &str,
    target: &TargetFacts,
    blockers: &mut Vec<Blocker>,
    warnings: &mut Vec<String>,
) {
    let available = target
        .providers
        .iter()
        .find(|fact| fact.id.as_str() == provider_id);
    match available {
        Some(fact) if fact.available => {
            if fact.version.is_none() {
                warnings.push(format!(
                    "Required {label} prerequisite is available but its version is unknown"
                ));
            }
        }
        _ => blockers.push(manual_blocker(
            ReforgeErrorCode::ProviderUnavailable,
            Some(component.id.clone()),
            &format!("Required {label} support is unavailable on the target"),
            &format!("Install or enable {label}"),
            &format!(
                "Install or enable {label} through its documented setup path, then rescan the target."
            ),
            RiskLevel::High,
        )),
    }
}

fn os_matches(required: &str, observed: &str) -> bool {
    let required = required.trim().to_ascii_lowercase();
    let observed = observed.trim().to_ascii_lowercase();
    if required.is_empty() || observed.is_empty() {
        return false;
    }
    if required == "windows" {
        return observed.starts_with("windows ")
            || observed == "windows"
            || observed
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.');
    }
    observed == required
        || observed
            .strip_prefix(&required)
            .is_some_and(|suffix| suffix.starts_with(' '))
}

fn architecture_matches(required: &Architecture, observed: &Architecture) -> bool {
    matches!(required, Architecture::Neutral)
        || (required != &Architecture::Unknown
            && observed != &Architecture::Unknown
            && required == observed)
}

fn manual_blocker(
    code: ReforgeErrorCode,
    component: Option<ComponentId>,
    reason: &str,
    title: &str,
    instruction: &str,
    risk: RiskLevel,
) -> Blocker {
    let component_suffix = component.as_ref().map(|id| id.as_str()).unwrap_or("target");
    Blocker {
        code,
        component: component.clone(),
        reason: reason.to_owned(),
        required_action: Some(ManualAction {
            id: format!("compatibility:{component_suffix}:{}", action_slug(title)),
            component,
            title: title.to_owned(),
            reason: reason.to_owned(),
            risk,
            instructions: vec![instruction.to_owned()],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: false,
            acknowledged_at: None,
            verification: None,
        }),
    }
}

fn action_slug(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
