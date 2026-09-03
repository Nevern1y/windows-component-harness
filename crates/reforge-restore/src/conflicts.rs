//! Deterministic conflict construction and safe default resolutions.

use reforge_domain::{ComponentId, Conflict, ConflictKind, ConflictResolution};

/// One conflict plus whether it blocks planning until the source selection or
/// target prerequisite changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedConflict {
    pub conflict: Conflict,
    pub blocks_planning: bool,
}

/// Build one stable conflict using the normative defaults from section 19.3.
pub(crate) fn classify_conflict(
    component: Option<ComponentId>,
    kind: ConflictKind,
    source_summary: impl Into<String>,
    target_summary: impl Into<String>,
    suffix: &str,
    version_direction: Option<VersionDirection>,
) -> ClassifiedConflict {
    let (resolution, requires_confirmation, blocks_planning) = match kind {
        ConflictKind::AlreadySatisfied => (ConflictResolution::Skip, false, false),
        ConflictKind::VersionDifference => match version_direction {
            Some(VersionDirection::TargetNewer) => (ConflictResolution::Skip, false, false),
            Some(VersionDirection::TargetOlder) => (ConflictResolution::Install, true, false),
            None => (ConflictResolution::PreserveTarget, true, false),
        },
        ConflictKind::ConfigDifference => (ConflictResolution::Merge, true, false),
        ConflictKind::DataCollision => (ConflictResolution::Manual, true, false),
        ConflictKind::SecretCollision => (ConflictResolution::PreserveTarget, true, false),
        ConflictKind::PortCollision => (ConflictResolution::Manual, true, false),
        ConflictKind::PathCollision => (ConflictResolution::Merge, false, false),
        ConflictKind::DependencyConflict
        | ConflictKind::ArchitectureConflict
        | ConflictKind::UnsupportedTarget => (ConflictResolution::Manual, false, true),
    };
    let component_key = component
        .as_ref()
        .map(ComponentId::as_str)
        .unwrap_or("target");
    let kind_key = conflict_kind_key(&kind);
    let suffix = safe_suffix(suffix);
    ClassifiedConflict {
        conflict: Conflict {
            id: format!("conflict:{component_key}:{kind_key}:{suffix}"),
            component,
            kind,
            source_summary: source_summary.into(),
            target_summary: target_summary.into(),
            resolution,
            requires_confirmation,
        },
        blocks_planning,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VersionDirection {
    TargetNewer,
    TargetOlder,
}

fn conflict_kind_key(kind: &ConflictKind) -> &'static str {
    match kind {
        ConflictKind::AlreadySatisfied => "already-satisfied",
        ConflictKind::VersionDifference => "version-difference",
        ConflictKind::ConfigDifference => "config-difference",
        ConflictKind::DataCollision => "data-collision",
        ConflictKind::SecretCollision => "secret-collision",
        ConflictKind::PathCollision => "path-collision",
        ConflictKind::PortCollision => "port-collision",
        ConflictKind::DependencyConflict => "dependency-conflict",
        ConflictKind::ArchitectureConflict => "architecture-conflict",
        ConflictKind::UnsupportedTarget => "unsupported-target",
    }
}

fn safe_suffix(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(128));
    let mut previous_dash = false;
    for byte in value.bytes().take(128) {
        let character = if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            byte.to_ascii_lowercase() as char
        } else {
            '-'
        };
        if character == '-' {
            if output.is_empty() || previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        output.push(character);
    }
    if output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        "default".to_owned()
    } else {
        output
    }
}
