//! Deterministic, typed operation construction and DAG ordering.
//!
//! This module contains the planner's internal operation representation.  It
//! never accepts command text or executable paths: callers can only construct
//! values from the closed domain [`OperationKind`] enum.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use reforge_domain::{
    ComponentId, KnownFolderToken, ObjectIndex, Operation, OperationId, OperationKind, PathToken,
    Precondition, ReforgeErrorCode, TargetFacts, VerificationRule, VersionValue,
};
use reforge_package::canonicalize;

use crate::RestoreResult;

/// The reviewed execution phase for a typed operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum OperationPhase {
    ProviderBootstrap,
    RuntimeBootstrap,
    PackageInstall,
    FileRestore,
    EnvironmentRestore,
    SubsystemRestore,
    ApplicationRestore,
    Manual,
    Verify,
}

impl OperationPhase {
    fn rank(self) -> u8 {
        match self {
            Self::ProviderBootstrap => 0,
            Self::RuntimeBootstrap => 1,
            Self::PackageInstall => 2,
            Self::FileRestore => 3,
            Self::EnvironmentRestore => 4,
            Self::SubsystemRestore => 5,
            Self::ApplicationRestore => 6,
            Self::Manual => 7,
            Self::Verify => 8,
        }
    }
}

/// Evaluate the target and package facts required before one operation may run.
///
/// A false result is intentionally not treated as success: the executor turns
/// it into a coded conflict or user-action error and leaves the operation
/// journaled rather than guessing at a recovery path.
pub(crate) fn precondition_satisfied(
    precondition: &Precondition,
    target: &TargetFacts,
    object_index: &ObjectIndex,
    approved_actions: &BTreeSet<String>,
) -> bool {
    match precondition {
        Precondition::Always => true,
        Precondition::TargetFingerprint { fingerprint } => target.fingerprint == *fingerprint,
        Precondition::ComponentAbsent { component } => !target_component_present(target, component),
        Precondition::ComponentVersion { component, minimum } => {
            if !target_component_present(target, component) {
                return false;
            }
            let Some(minimum) = minimum else {
                return true;
            };
            target_component_version(target, component)
                .is_some_and(|actual| version_at_least(actual, minimum))
        }
        Precondition::ArtifactPresent { object } => {
            object_index.objects.iter().any(|entry| &entry.id == object)
        }
        Precondition::ManualApproval { action } => approved_actions.contains(action),
    }
}

fn target_component_present(target: &TargetFacts, component: &ComponentId) -> bool {
    target.runtimes.iter().any(|fact| &fact.id == component)
        || target.installed.iter().any(|fact| {
            ComponentId::from_identity(&fact.identity, fact.publisher.as_ref())
                .is_ok_and(|identity| identity.id == *component)
        })
}

fn target_component_version<'a>(
    target: &'a TargetFacts,
    component: &ComponentId,
) -> Option<&'a VersionValue> {
    if target.runtimes.iter().any(|fact| &fact.id == component) {
        return target
            .runtimes
            .iter()
            .find(|fact| &fact.id == component)
            .and_then(|fact| fact.version.as_ref());
    }
    target.installed.iter().find_map(|fact| {
        let identity = ComponentId::from_identity(&fact.identity, fact.publisher.as_ref()).ok()?;
        (identity.id == *component)
            .then_some(fact.version.as_ref())
            .flatten()
    })
}

fn version_at_least(actual: &VersionValue, minimum: &VersionValue) -> bool {
    let actual_text = actual
        .normalized
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&actual.raw);
    let minimum_text = minimum
        .normalized
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&minimum.raw);
    if actual_text == minimum_text {
        return true;
    }
    let Some(actual_parts) = numeric_version_parts(actual_text) else {
        return false;
    };
    let Some(minimum_parts) = numeric_version_parts(minimum_text) else {
        return false;
    };
    let count = actual_parts.len().max(minimum_parts.len());
    for index in 0..count {
        let actual_part = actual_parts.get(index).copied().unwrap_or(0);
        let minimum_part = minimum_parts.get(index).copied().unwrap_or(0);
        match actual_part.cmp(&minimum_part) {
            Ordering::Less => return false,
            Ordering::Greater => return true,
            Ordering::Equal => {}
        }
    }
    true
}

fn numeric_version_parts(value: &str) -> Option<Vec<u128>> {
    let mut parts = Vec::new();
    for part in value.split('.') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        parts.push(part.parse().ok()?);
    }
    Some(parts)
}

/// A not-yet-numbered operation.  Prerequisites use stable logical keys until
/// operation IDs are assigned for the supplied run.
#[derive(Clone, Debug)]
pub(crate) struct OperationSpec {
    pub(crate) key: String,
    pub(crate) component: ComponentId,
    pub(crate) kind: OperationKind,
    pub(crate) phase: OperationPhase,
    pub(crate) prerequisites: BTreeSet<String>,
    pub(crate) precondition: Precondition,
    pub(crate) idempotency_key: String,
    pub(crate) verification: Vec<VerificationRule>,
    pub(crate) requires_elevation: bool,
    pub(crate) non_idempotent: bool,
}

impl OperationSpec {
    pub(crate) fn new(
        component: ComponentId,
        kind: OperationKind,
        phase: OperationPhase,
        precondition: Precondition,
        verification: Vec<VerificationRule>,
        requires_elevation: bool,
        non_idempotent: bool,
    ) -> RestoreResult<Self> {
        let idempotency_key = derive_idempotency_key(&component, &kind)?;
        Ok(Self {
            key: idempotency_key.clone(),
            component,
            kind,
            phase,
            prerequisites: BTreeSet::new(),
            precondition,
            idempotency_key,
            verification,
            requires_elevation,
            non_idempotent,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_shared(
        component: ComponentId,
        namespace: &str,
        kind: OperationKind,
        phase: OperationPhase,
        precondition: Precondition,
        verification: Vec<VerificationRule>,
        requires_elevation: bool,
        non_idempotent: bool,
    ) -> RestoreResult<Self> {
        let idempotency_key = derive_shared_idempotency_key(namespace, &kind)?;
        Ok(Self {
            key: idempotency_key.clone(),
            component,
            kind,
            phase,
            prerequisites: BTreeSet::new(),
            precondition,
            idempotency_key,
            verification,
            requires_elevation,
            non_idempotent,
        })
    }

    pub(crate) fn add_prerequisite(&mut self, key: impl Into<String>) {
        self.prerequisites.insert(key.into());
    }

    fn sort_key(&self, operation_id: Option<&OperationId>) -> (u8, String, String, String, String) {
        (
            self.phase.rank(),
            self.component.to_string(),
            operation_kind_key(&self.kind).to_owned(),
            normalized_destination(&self.kind),
            operation_id
                .map(ToString::to_string)
                .unwrap_or_else(|| self.idempotency_key.clone()),
        )
    }
}

/// Return a stable, human-readable operation-kind key for the planner tie
/// breaker.  The numeric prefix follows the default execution phases.
pub(crate) fn operation_kind_key(kind: &OperationKind) -> &'static str {
    match kind {
        OperationKind::EnsureProvider { .. } => "00.ensure_provider",
        OperationKind::EnsureRuntime { .. } => "01.ensure_runtime",
        OperationKind::InstallPackage { .. } => "02.install_package",
        OperationKind::WriteFile { .. } => "03.write_file",
        OperationKind::MergeJson { .. } => "03.merge_json",
        OperationKind::MergeToml { .. } => "03.merge_toml",
        OperationKind::SetUserEnvironment { .. } => "04.set_user_environment",
        OperationKind::AppendUserPath { .. } => "04.append_user_path",
        OperationKind::ImportWsl { .. } => "05.import_wsl",
        OperationKind::RestoreDockerImage { .. } => "05.restore_docker_image",
        OperationKind::RestoreDockerVolume { .. } => "05.restore_docker_volume",
        OperationKind::InstallVsCodeExtension { .. } => "06.install_vscode_extension",
        OperationKind::RegisterMcp { .. } => "06.register_mcp",
        OperationKind::OpenManualAction { .. } => "07.open_manual_action",
        OperationKind::RequireReboot { .. } => "07.require_reboot",
        OperationKind::Verify { .. } => "08.verify",
    }
}

pub(crate) fn default_phase(kind: &OperationKind) -> OperationPhase {
    match kind {
        OperationKind::EnsureProvider { .. } => OperationPhase::ProviderBootstrap,
        OperationKind::EnsureRuntime { .. } => OperationPhase::RuntimeBootstrap,
        OperationKind::InstallPackage { .. } => OperationPhase::PackageInstall,
        OperationKind::WriteFile { .. }
        | OperationKind::MergeJson { .. }
        | OperationKind::MergeToml { .. } => OperationPhase::FileRestore,
        OperationKind::SetUserEnvironment { .. } | OperationKind::AppendUserPath { .. } => {
            OperationPhase::EnvironmentRestore
        }
        OperationKind::ImportWsl { .. }
        | OperationKind::RestoreDockerImage { .. }
        | OperationKind::RestoreDockerVolume { .. } => OperationPhase::SubsystemRestore,
        OperationKind::InstallVsCodeExtension { .. } | OperationKind::RegisterMcp { .. } => {
            OperationPhase::ApplicationRestore
        }
        OperationKind::OpenManualAction { .. } | OperationKind::RequireReboot { .. } => {
            OperationPhase::Manual
        }
        OperationKind::Verify { .. } => OperationPhase::Verify,
    }
}

/// The normalized destination used by the stable planner tie-breaker.
pub(crate) fn normalized_destination(kind: &OperationKind) -> String {
    match kind {
        OperationKind::EnsureProvider { provider } => format!("provider:{}", provider),
        OperationKind::InstallPackage {
            provider, package, ..
        } => {
            format!("package:{provider}:{}", safe_key_text(&package.id))
        }
        OperationKind::EnsureRuntime { runtime } => {
            format!("runtime:{}", safe_key_text(&runtime.id))
        }
        OperationKind::WriteFile { destination, .. }
        | OperationKind::MergeJson { destination, .. }
        | OperationKind::MergeToml { destination, .. } => path_key(destination),
        OperationKind::SetUserEnvironment { name, .. } => {
            format!("environment:{}", safe_key_text(name))
        }
        OperationKind::AppendUserPath { entries } => {
            let mut values: Vec<_> = entries.iter().map(path_key).collect();
            values.sort();
            format!("path:{}", values.join("|"))
        }
        OperationKind::ImportWsl { distro, .. } => {
            format!("wsl:{}", safe_key_text(&distro.distribution))
        }
        OperationKind::RestoreDockerImage { image, .. } => {
            format!(
                "docker-image:{}:{}",
                safe_key_text(&image.repository),
                image.tag.as_deref().map(safe_key_text).unwrap_or_default()
            )
        }
        OperationKind::RestoreDockerVolume { volume, .. } => {
            format!("docker-volume:{}", safe_key_text(&volume.name))
        }
        OperationKind::InstallVsCodeExtension { id, profile, .. } => format!(
            "vscode-extension:{}:{}",
            safe_key_text(id),
            profile.as_deref().map(safe_key_text).unwrap_or_default()
        ),
        OperationKind::RegisterMcp { server } => format!(
            "mcp:{}:{}",
            safe_key_text(&server.name),
            path_key(&server.source_config.source_path)
        ),
        OperationKind::OpenManualAction { action } => {
            format!("manual:{}", safe_key_text(&action.id))
        }
        OperationKind::RequireReboot { reason } => {
            format!("reboot:{}", safe_key_text(reason))
        }
        OperationKind::Verify { rule } => verification_destination(rule),
    }
}

/// Return the tokenized write path for operations that mutate a file.
pub(crate) fn write_destination(kind: &OperationKind) -> Option<&PathToken> {
    match kind {
        OperationKind::WriteFile { destination, .. }
        | OperationKind::MergeJson { destination, .. }
        | OperationKind::MergeToml { destination, .. } => Some(destination),
        _ => None,
    }
}

/// Add deterministic ordering for all overlapping file/merge destinations.
///
/// The executor is allowed to run only non-overlapping writes concurrently.
/// The MVP is serial, but the plan itself must still carry an explicit order so
/// a later scheduler cannot turn an ambiguous package into a race.
pub(crate) fn order_overlapping_writes(
    specs: &mut BTreeMap<String, OperationSpec>,
) -> RestoreResult<()> {
    let mut keys: Vec<_> = specs.keys().cloned().collect();
    keys.sort_by(|left, right| {
        let left_spec = specs.get(left).expect("operation key exists");
        let right_spec = specs.get(right).expect("operation key exists");
        left_spec.sort_key(None).cmp(&right_spec.sort_key(None))
    });

    for (left_index, left_key) in keys.iter().enumerate() {
        let Some(left_path) = specs
            .get(left_key)
            .and_then(|spec| write_destination(&spec.kind))
            .cloned()
        else {
            continue;
        };
        for right_key in keys.iter().skip(left_index + 1) {
            let Some(right_path) = specs
                .get(right_key)
                .and_then(|spec| write_destination(&spec.kind))
                .cloned()
            else {
                continue;
            };
            if paths_overlap(&left_path, &right_path) {
                specs
                    .get_mut(right_key)
                    .expect("operation key exists")
                    .add_prerequisite(left_key.clone());
            }
        }
    }
    Ok(())
}

/// Convert logical operation specs into a stable topological order and assign
/// run-scoped operation IDs only after the candidate order is deterministic.
pub(crate) fn topological_order(
    mut specs: BTreeMap<String, OperationSpec>,
    run_id: &reforge_domain::RunId,
    first_ordinal: u64,
) -> RestoreResult<Vec<Operation>> {
    let mut ordered_keys: Vec<_> = specs.keys().cloned().collect();
    ordered_keys.sort_by(|left, right| {
        let left_spec = specs.get(left).expect("operation key exists");
        let right_spec = specs.get(right).expect("operation key exists");
        left_spec.sort_key(None).cmp(&right_spec.sort_key(None))
    });

    let mut id_by_key = BTreeMap::new();
    for (index, key) in ordered_keys.iter().enumerate() {
        let ordinal = first_ordinal
            .checked_add(u64::try_from(index).map_err(|_| {
                crate::restore_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "restore operation ordinal conversion overflowed",
                    None,
                    None,
                    None,
                    None,
                )
            })?)
            .ok_or_else(|| {
                crate::restore_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "restore operation ordinal overflowed",
                    None,
                    None,
                    None,
                    None,
                )
            })?;
        let operation_id = OperationId::for_run(run_id, ordinal).map_err(|_| {
            crate::restore_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore operation ID could not be constructed",
                None,
                None,
                None,
                None,
            )
        })?;
        id_by_key.insert(key.clone(), operation_id);
    }

    let mut indices = BTreeMap::new();
    for (index, key) in ordered_keys.iter().enumerate() {
        indices.insert(key.clone(), index);
    }

    let mut indegree = vec![0usize; ordered_keys.len()];
    let mut dependents = vec![Vec::<usize>::new(); ordered_keys.len()];
    for (index, key) in ordered_keys.iter().enumerate() {
        let spec = specs.get(key).expect("operation key exists");
        for prerequisite in &spec.prerequisites {
            let Some(&prerequisite_index) = indices.get(prerequisite) else {
                return Err(crate::restore_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "restore operation prerequisite does not exist",
                    None,
                    None,
                    None,
                    None,
                ));
            };
            indegree[index] = indegree[index].checked_add(1).ok_or_else(|| {
                crate::restore_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "restore operation prerequisite count overflowed",
                    None,
                    None,
                    None,
                    None,
                )
            })?;
            dependents[prerequisite_index].push(index);
        }
    }

    let mut ready = BTreeSet::<(u8, String, String, String, String, usize)>::new();
    for (index, key) in ordered_keys.iter().enumerate() {
        if indegree[index] == 0 {
            let spec = specs.get(key).expect("operation key exists");
            let operation_id = id_by_key.get(key).expect("operation ID exists");
            let sort_key = spec.sort_key(Some(operation_id));
            ready.insert((
                sort_key.0, sort_key.1, sort_key.2, sort_key.3, sort_key.4, index,
            ));
        }
    }

    let mut result = Vec::with_capacity(ordered_keys.len());
    while let Some((_, _, _, _, _, index)) = ready.pop_first() {
        let key = &ordered_keys[index];
        let spec = specs.remove(key).expect("operation spec exists");
        let operation_id = id_by_key.get(key).expect("operation ID exists").clone();
        let prerequisites = spec
            .prerequisites
            .iter()
            .map(|prerequisite| {
                id_by_key
                    .get(prerequisite)
                    .expect("prerequisite ID exists")
                    .clone()
            })
            .collect();
        let idempotency_key = scoped_idempotency_key(run_id, &spec.idempotency_key);
        result.push(Operation {
            id: operation_id,
            component: spec.component,
            kind: spec.kind,
            prerequisites,
            precondition: spec.precondition,
            idempotency_key,
            verification: spec.verification,
            requires_elevation: spec.requires_elevation,
            non_idempotent: spec.non_idempotent,
        });

        for dependent in dependents[index].iter().copied() {
            indegree[dependent] = indegree[dependent]
                .checked_sub(1)
                .expect("positive indegree");
            if indegree[dependent] == 0 {
                let dependent_key = &ordered_keys[dependent];
                let dependent_spec = specs
                    .get(dependent_key)
                    .expect("unprocessed operation spec exists");
                let operation_id = id_by_key.get(dependent_key).expect("operation ID exists");
                let sort_key = dependent_spec.sort_key(Some(operation_id));
                ready.insert((
                    sort_key.0, sort_key.1, sort_key.2, sort_key.3, sort_key.4, dependent,
                ));
            }
        }
    }

    if result.len() != ordered_keys.len() {
        return Err(crate::restore_error(
            ReforgeErrorCode::DependencyCycle,
            "restore operation prerequisites contain a cycle",
            None,
            None,
            None,
            None,
        ));
    }
    Ok(result)
}
fn scoped_idempotency_key(run_id: &reforge_domain::RunId, logical_key: &str) -> String {
    let suffix = logical_key
        .strip_prefix("restore-v1:")
        .unwrap_or(logical_key);
    format!("restore-v1:{run_id}:{suffix}")
}

fn derive_idempotency_key(component: &ComponentId, kind: &OperationKind) -> RestoreResult<String> {
    let digest = canonicalize(kind)
        .map_err(|_| {
            crate::restore_error(
                ReforgeErrorCode::SchemaInvalid,
                "restore operation kind could not be canonicalized",
                None,
                Some(component.clone()),
                None,
                None,
            )
        })?
        .object_id()
        .as_str()
        .to_owned();
    Ok(format!("restore-v1:{component}:{digest}"))
}

fn derive_shared_idempotency_key(namespace: &str, kind: &OperationKind) -> RestoreResult<String> {
    let digest = canonicalize(kind)
        .map_err(|_| {
            crate::restore_error(
                ReforgeErrorCode::SchemaInvalid,
                "shared restore operation kind could not be canonicalized",
                None,
                None,
                None,
                None,
            )
        })?
        .object_id()
        .as_str()
        .to_owned();
    Ok(format!("restore-v1:{namespace}:{digest}"))
}

fn path_key(path: &PathToken) -> String {
    format!(
        "{}:{}",
        folder_key(&path.root),
        path.relative.to_ascii_lowercase()
    )
}

fn folder_key(folder: &KnownFolderToken) -> String {
    match folder {
        KnownFolderToken::UserProfile => "user_profile".to_owned(),
        KnownFolderToken::RoamingAppData => "roaming_app_data".to_owned(),
        KnownFolderToken::LocalAppData => "local_app_data".to_owned(),
        KnownFolderToken::ProgramData => "program_data".to_owned(),
        KnownFolderToken::ProgramFiles => "program_files".to_owned(),
        KnownFolderToken::ProgramFilesX86 => "program_files_x86".to_owned(),
        KnownFolderToken::StartMenu => "start_menu".to_owned(),
        KnownFolderToken::Desktop => "desktop".to_owned(),
        KnownFolderToken::Startup => "startup".to_owned(),
        KnownFolderToken::Documents => "documents".to_owned(),
        KnownFolderToken::UserSelected { id } => format!("user_selected:{}", safe_key_text(id)),
    }
}

fn verification_destination(rule: &VerificationRule) -> String {
    match rule {
        VerificationRule::File { destination, .. }
        | VerificationRule::FileVersion { destination, .. }
        | VerificationRule::ConfigParses { destination, .. }
        | VerificationRule::McpRegistration {
            config: destination,
            ..
        }
        | VerificationRule::BrowserArtifact {
            profile: destination,
        } => path_key(destination),
        VerificationRule::ProviderIdentity { provider, package } => {
            format!("provider:{}:{}", provider, safe_key_text(&package.id))
        }
        VerificationRule::Environment { scope, name, .. } => {
            format!("environment:{scope:?}:{}", safe_key_text(name))
        }
        VerificationRule::WslState { distro, .. } => format!("wsl:{}", safe_key_text(distro)),
        VerificationRule::DockerObject { kind, identity } => {
            format!("docker:{kind:?}:{}", safe_key_text(identity))
        }
        VerificationRule::SecureTarget { secret } => format!("secure-target:{secret}"),
    }
}

fn safe_key_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '_'
            } else {
                character
            }
        })
        .take(256)
        .collect()
}

fn paths_overlap(left: &PathToken, right: &PathToken) -> bool {
    if left.root != right.root {
        return false;
    }
    let left = left.relative.to_ascii_lowercase();
    let right = right.relative.to_ascii_lowercase();
    left == right
        || (!left.is_empty() && right.starts_with(&(left.clone() + "/")))
        || (!right.is_empty() && left.starts_with(&(right.clone() + "/")))
}
