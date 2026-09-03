//! Complete, deterministic source/target comparison without filesystem guesses.

use std::{cmp::Ordering, collections::BTreeSet};

use reforge_domain::{
    Architecture, ArtifactId, ArtifactPolicy, Component, ComponentId, ComponentKind, ConfigScope,
    Conflict, ConflictKind, ConflictResolution, DependencyEdge, EnvironmentFact, InstalledFact,
    ObjectId, PackageGraph, PathToken, Portability, ReforgeErrorCode, RestoreStrategy, RuntimeFact,
    SafeValueRef, TargetFacts, VerificationRule, VersionValue,
};

use crate::conflicts::{ClassifiedConflict, VersionDirection, classify_conflict};

/// Planner disposition after applying safe conflict defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentDisposition {
    Install,
    Skip,
    Merge,
    PreserveTarget,
    Manual,
    Blocked,
}

/// Per-component comparison result consumed by the planner and report builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentDiff {
    pub component: ComponentId,
    pub disposition: ComponentDisposition,
    pub target_present: bool,
    pub conflict_ids: Vec<String>,
}

/// State that must be retained before a user-approved mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupTarget {
    Artifact {
        artifact: ArtifactId,
        path: PathToken,
    },
    Environment {
        scope: ConfigScope,
        name: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRequirement {
    pub component: ComponentId,
    pub target: BackupTarget,
    pub reason: String,
}

/// Full source/target comparison. Target-only facts are explicitly retained;
/// no diff output can express deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDiff {
    pub components: Vec<ComponentDiff>,
    pub conflicts: Vec<Conflict>,
    pub blocking_conflict_ids: Vec<String>,
    pub backup_requirements: Vec<BackupRequirement>,
    pub preserved_target: Vec<InstalledFact>,
    pub preserved_runtimes: Vec<RuntimeFact>,
    pub preserved_environment: Vec<EnvironmentFact>,
    pub warnings: Vec<String>,
}

impl TargetDiff {
    pub fn is_blocked(&self) -> bool {
        !self.blocking_conflict_ids.is_empty()
    }

    pub fn component(&self, id: &ComponentId) -> Option<&ComponentDiff> {
        self.components
            .binary_search_by(|entry| entry.component.cmp(id))
            .ok()
            .map(|index| &self.components[index])
    }
}
/// Case-insensitively deduplicate PATH entries while retaining target order
/// and appending only source entries that the target does not already contain.
pub fn merge_path_entries(target: &[String], source: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for entry in target.iter().chain(source) {
        let candidate = entry.trim();
        if candidate.is_empty() {
            continue;
        }
        if seen.insert(candidate.to_lowercase()) {
            merged.push(entry.clone());
        }
    }
    merged
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DiffEngine;

impl DiffEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn compare(
        &self,
        graph: &PackageGraph,
        target: &TargetFacts,
    ) -> crate::RestoreResult<TargetDiff> {
        validate_inputs(graph, target)?;

        let mut components: Vec<_> = graph.components.iter().collect();
        components.sort_by(|left, right| left.id.cmp(&right.id));

        let mut used_installed = BTreeSet::new();
        let mut used_runtimes = BTreeSet::new();
        let mut used_environment = BTreeSet::new();
        let mut states = Vec::with_capacity(components.len());
        let mut conflicts = Vec::<ClassifiedConflict>::new();
        let mut backups = Vec::new();

        for component in components {
            let target_present = match component.kind {
                ComponentKind::Runtime => {
                    compare_runtime(component, target, &mut used_runtimes, &mut conflicts)
                }
                ComponentKind::EnvironmentVariable => compare_environment(
                    component,
                    target,
                    &mut used_environment,
                    &mut conflicts,
                    &mut backups,
                ),
                ComponentKind::SecretReference => {
                    compare_secret(component, target, &mut used_environment, &mut conflicts)
                }
                _ => compare_installed(component, target, &mut used_installed, &mut conflicts),
            };

            compare_architecture(component, target, &mut conflicts);
            compare_supported_state(component, &mut conflicts);
            compare_artifacts(component, target_present, &mut conflicts, &mut backups);

            states.push(PendingComponentDiff {
                component: component.id.clone(),
                target_present,
            });
        }

        add_dependency_conflicts(graph, &states, &mut conflicts);

        conflicts.sort_by(|left, right| left.conflict.id.cmp(&right.conflict.id));
        conflicts.dedup_by(|left, right| left.conflict.id == right.conflict.id);
        backups.sort_by_key(backup_key);
        backups.dedup();

        let warnings = diff_warnings(&conflicts);
        let final_conflicts: Vec<_> = conflicts
            .iter()
            .map(|classified| classified.conflict.clone())
            .collect();
        let blocking_conflict_ids: Vec<String> = conflicts
            .iter()
            .filter(|classified| classified.blocks_planning)
            .map(|classified| classified.conflict.id.clone())
            .collect();
        let component_diffs = states
            .into_iter()
            .map(|pending| {
                let component_conflicts: Vec<_> = final_conflicts
                    .iter()
                    .filter(|conflict| conflict.component.as_ref() == Some(&pending.component))
                    .collect();
                let conflict_ids = component_conflicts
                    .iter()
                    .map(|conflict| conflict.id.clone())
                    .collect();
                let disposition = disposition(
                    pending.target_present,
                    &component_conflicts,
                    &blocking_conflict_ids,
                );
                ComponentDiff {
                    component: pending.component,
                    disposition,
                    target_present: pending.target_present,
                    conflict_ids,
                }
            })
            .collect();

        Ok(TargetDiff {
            components: component_diffs,
            conflicts: final_conflicts,
            blocking_conflict_ids,
            backup_requirements: backups,
            preserved_target: target
                .installed
                .iter()
                .enumerate()
                .filter(|(index, _)| !used_installed.contains(index))
                .map(|(_, fact)| fact.clone())
                .collect(),
            preserved_runtimes: target
                .runtimes
                .iter()
                .enumerate()
                .filter(|(index, _)| !used_runtimes.contains(index))
                .map(|(_, fact)| fact.clone())
                .collect(),
            preserved_environment: target
                .environment
                .iter()
                .enumerate()
                .filter(|(index, _)| !used_environment.contains(index))
                .map(|(_, fact)| fact.clone())
                .collect(),
            warnings,
        })
    }
}
const MAX_DIFF_COMPONENTS: usize = 250_000;
const MAX_DIFF_EDGES: usize = 1_000_000;
const MAX_DIFF_ARTIFACTS: usize = 1_000_000;

fn validate_inputs(graph: &PackageGraph, target: &TargetFacts) -> crate::RestoreResult<()> {
    if graph.components.len() > MAX_DIFF_COMPONENTS {
        return Err(diff_error(
            "package graph exceeds the reviewed component bound",
        ));
    }
    let embedded_edges = graph
        .components
        .iter()
        .try_fold(0usize, |count, component| {
            count.checked_add(component.dependencies.len())
        })
        .ok_or_else(|| diff_error("package graph edge count overflow"))?;
    let total_edges = graph
        .edges
        .len()
        .checked_add(embedded_edges)
        .ok_or_else(|| diff_error("package graph edge count overflow"))?;
    if total_edges > MAX_DIFF_EDGES {
        return Err(diff_error("package graph exceeds the reviewed edge bound"));
    }

    let mut component_ids = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_count = 0usize;
    for component in &graph.components {
        if !component_ids.insert(component.id.clone()) {
            return Err(diff_error("package graph contains duplicate component IDs"));
        }
        artifact_count = artifact_count
            .checked_add(component.artifacts.len())
            .ok_or_else(|| diff_error("package graph artifact count overflow"))?;
        if artifact_count > MAX_DIFF_ARTIFACTS {
            return Err(diff_error(
                "package graph exceeds the reviewed artifact bound",
            ));
        }
        for artifact in &component.artifacts {
            if !artifact_ids.insert(artifact.id.clone()) {
                return Err(diff_error("package graph contains duplicate artifact IDs"));
            }
            artifact
                .source_path
                .validate()
                .map_err(|_| diff_error("package graph contains an invalid artifact path"))?;
        }
    }
    for edge in graph.edges.iter().chain(
        graph
            .components
            .iter()
            .flat_map(|component| component.dependencies.iter()),
    ) {
        if !component_ids.contains(&edge.from) || !component_ids.contains(&edge.to) {
            return Err(diff_error(
                "package graph edge references a missing component",
            ));
        }
    }

    let mut environment_keys = BTreeSet::new();
    for fact in &target.environment {
        let name = normalize_environment_name(&fact.name)
            .ok_or_else(|| diff_error("target contains an invalid environment variable name"))?;
        if let Some(hash) = &fact.value_hash {
            ObjectId::new(hash.clone())
                .map_err(|_| diff_error("target contains an invalid environment value hash"))?;
        }
        if !environment_keys.insert((scope_rank(&fact.scope), name)) {
            return Err(diff_error("target contains duplicate environment facts"));
        }
    }
    Ok(())
}

fn diff_error(message: &str) -> Box<reforge_domain::ErrorEnvelope> {
    crate::restore_error(
        ReforgeErrorCode::SchemaInvalid,
        message,
        None,
        None,
        None,
        None,
    )
}

fn diff_warnings(conflicts: &[ClassifiedConflict]) -> Vec<String> {
    conflicts
        .iter()
        .filter(|classified| !classified.blocks_planning)
        .filter(|classified| classified.conflict.kind != ConflictKind::AlreadySatisfied)
        .map(|classified| {
            format!(
                "{} requires {:?}",
                classified.conflict.id, classified.conflict.resolution
            )
        })
        .collect()
}

#[derive(Clone, Debug)]
struct PendingComponentDiff {
    component: ComponentId,
    target_present: bool,
}

fn compare_installed(
    component: &Component,
    target: &TargetFacts,
    used: &mut BTreeSet<usize>,
    conflicts: &mut Vec<ClassifiedConflict>,
) -> bool {
    let matches: Vec<_> = target
        .installed
        .iter()
        .enumerate()
        .filter(|(_, fact)| identity_matches(component, fact))
        .collect();
    match matches.as_slice() {
        [] => false,
        [(index, fact)] => {
            used.insert(*index);
            compare_version_and_source(component, fact, conflicts);
            true
        }
        _ => {
            for (index, _) in &matches {
                used.insert(*index);
            }
            conflicts.push(classify_conflict(
                Some(component.id.clone()),
                ConflictKind::UnsupportedTarget,
                source_identity_summary(component),
                "multiple target identities match the source component",
                "ambiguous-identity",
                None,
            ));
            true
        }
    }
}

fn compare_runtime(
    component: &Component,
    target: &TargetFacts,
    used: &mut BTreeSet<usize>,
    conflicts: &mut Vec<ClassifiedConflict>,
) -> bool {
    let Some((index, fact)) = target
        .runtimes
        .iter()
        .enumerate()
        .find(|(_, fact)| fact.id == component.id)
    else {
        return false;
    };
    used.insert(index);
    compare_versions(
        &component.id,
        component.version.as_ref(),
        fact.version.as_ref(),
        conflicts,
    );
    if let (Some(source), Some(observed)) = (&component.architecture, &fact.architecture)
        && !architecture_matches(source, observed)
    {
        conflicts.push(classify_conflict(
            Some(component.id.clone()),
            ConflictKind::ArchitectureConflict,
            architecture_summary(source),
            architecture_summary(observed),
            "runtime",
            None,
        ));
    }
    true
}

fn compare_environment(
    component: &Component,
    target: &TargetFacts,
    used: &mut BTreeSet<usize>,
    conflicts: &mut Vec<ClassifiedConflict>,
    backups: &mut Vec<BackupRequirement>,
) -> bool {
    let Some(name) = environment_name(component) else {
        conflicts.push(classify_conflict(
            Some(component.id.clone()),
            ConflictKind::UnsupportedTarget,
            "source environment variable has no normalized name",
            "target comparison unavailable",
            "environment-name",
            None,
        ));
        return false;
    };
    let expected_scope = environment_scope(component);
    let Some((index, fact)) =
        target.environment.iter().enumerate().find(|(_, fact)| {
            fact.scope == expected_scope && fact.name.eq_ignore_ascii_case(&name)
        })
    else {
        return false;
    };
    used.insert(index);
    let hashes_equal = environment_expected_hash(component)
        .as_deref()
        .zip(fact.value_hash.as_deref())
        .is_some_and(|(source, target)| source == target);
    let kind = if hashes_equal {
        ConflictKind::AlreadySatisfied
    } else if name.eq_ignore_ascii_case("PATH") {
        ConflictKind::PathCollision
    } else if is_port_name(&name) {
        ConflictKind::PortCollision
    } else {
        ConflictKind::ConfigDifference
    };
    let classified = classify_conflict(
        Some(component.id.clone()),
        kind,
        format!("source environment variable {}", safe_label(&name)),
        format!("target environment variable {}", safe_label(&fact.name)),
        &name,
        None,
    );
    if !hashes_equal
        && matches!(
            classified.conflict.kind,
            ConflictKind::ConfigDifference | ConflictKind::PathCollision
        )
    {
        backups.push(BackupRequirement {
            component: component.id.clone(),
            target: BackupTarget::Environment {
                scope: fact.scope.clone(),
                name: fact.name.clone(),
            },
            reason: "Preserve the target environment value before merge".to_owned(),
        });
    }
    conflicts.push(classified);
    true
}

fn compare_secret(
    component: &Component,
    target: &TargetFacts,
    used: &mut BTreeSet<usize>,
    conflicts: &mut Vec<ClassifiedConflict>,
) -> bool {
    let Some(name) = environment_name(component) else {
        return false;
    };
    let expected_scope = environment_scope(component);
    let Some((index, fact)) =
        target.environment.iter().enumerate().find(|(_, fact)| {
            fact.scope == expected_scope && fact.name.eq_ignore_ascii_case(&name)
        })
    else {
        return false;
    };
    used.insert(index);
    conflicts.push(classify_conflict(
        Some(component.id.clone()),
        ConflictKind::SecretCollision,
        format!("source secret reference {}", safe_label(&name)),
        format!("target already defines {}", safe_label(&fact.name)),
        &name,
        None,
    ));
    true
}

fn compare_version_and_source(
    component: &Component,
    target: &InstalledFact,
    conflicts: &mut Vec<ClassifiedConflict>,
) {
    compare_versions(
        &component.id,
        component.version.as_ref(),
        target.version.as_ref(),
        conflicts,
    );

    if let (Some(source), Some(observed)) = (
        normalized_source(component),
        normalized_installed_source(target),
    ) && source != observed
    {
        conflicts.push(classify_conflict(
            Some(component.id.clone()),
            ConflictKind::UnsupportedTarget,
            format!("source package channel {}", safe_label(&source)),
            format!("target package channel {}", safe_label(&observed)),
            "source-channel",
            None,
        ));
    }
}

fn compare_versions(
    component: &ComponentId,
    source: Option<&VersionValue>,
    target: Option<&VersionValue>,
    conflicts: &mut Vec<ClassifiedConflict>,
) {
    match version_relation(source, target) {
        VersionRelation::Same => conflicts.push(classify_conflict(
            Some(component.clone()),
            ConflictKind::AlreadySatisfied,
            version_summary("source", source),
            version_summary("target", target),
            "identity-version",
            None,
        )),
        VersionRelation::TargetNewer => conflicts.push(classify_conflict(
            Some(component.clone()),
            ConflictKind::VersionDifference,
            version_summary("source", source),
            version_summary("target", target),
            "target-newer",
            Some(VersionDirection::TargetNewer),
        )),
        VersionRelation::TargetOlder => conflicts.push(classify_conflict(
            Some(component.clone()),
            ConflictKind::VersionDifference,
            version_summary("source", source),
            version_summary("target", target),
            "target-older",
            Some(VersionDirection::TargetOlder),
        )),
        VersionRelation::DifferentUnknown => conflicts.push(classify_conflict(
            Some(component.clone()),
            ConflictKind::VersionDifference,
            version_summary("source", source),
            version_summary("target", target),
            "unranked",
            None,
        )),
    }
}

fn compare_architecture(
    component: &Component,
    target: &TargetFacts,
    conflicts: &mut Vec<ClassifiedConflict>,
) {
    let required = component
        .compatibility
        .required_architecture
        .as_ref()
        .or(component.architecture.as_ref());
    let Some(required) = required else {
        return;
    };
    if architecture_matches(required, &target.host.architecture) {
        return;
    }
    conflicts.push(classify_conflict(
        Some(component.id.clone()),
        ConflictKind::ArchitectureConflict,
        architecture_summary(required),
        architecture_summary(&target.host.architecture),
        "target",
        None,
    ));
}

fn compare_supported_state(component: &Component, conflicts: &mut Vec<ClassifiedConflict>) {
    if component.kind == ComponentKind::Unknown
        || matches!(
            component.restore.primary,
            RestoreStrategy::MachineBound | RestoreStrategy::Unknown
        )
        || (!matches!(component.restore.primary, RestoreStrategy::Manual)
            && matches!(
                component.restore.portability,
                Portability::Unsupported | Portability::MachineBound | Portability::Unknown
            ))
    {
        conflicts.push(classify_conflict(
            Some(component.id.clone()),
            ConflictKind::UnsupportedTarget,
            "source component has no automatic portable restore contract",
            "target state must be handled manually",
            "restore-contract",
            None,
        ));
    }
}

fn compare_artifacts(
    component: &Component,
    target_present: bool,
    conflicts: &mut Vec<ClassifiedConflict>,
    backups: &mut Vec<BackupRequirement>,
) {
    for artifact in component.artifacts.iter().filter(|artifact| {
        !(matches!(
            component.kind,
            ComponentKind::EnvironmentVariable | ComponentKind::SecretReference
        ) && artifact.policy == ArtifactPolicy::SecretReference)
    }) {
        let (kind, backup, suffix) = match artifact.policy {
            ArtifactPolicy::Config => (ConflictKind::ConfigDifference, true, "config"),
            ArtifactPolicy::Data
            | ArtifactPolicy::Export
            | ArtifactPolicy::PortableBinary
            | ArtifactPolicy::LargeOptIn => (ConflictKind::DataCollision, true, "data"),
            ArtifactPolicy::SecretReference => (ConflictKind::SecretCollision, false, "secret"),
            ArtifactPolicy::Manual => (ConflictKind::UnsupportedTarget, false, "manual"),
        };
        if target_present {
            conflicts.push(classify_conflict(
                Some(component.id.clone()),
                kind,
                format!("selected artifact {}", artifact.id.as_str()),
                "matching target component may already own the destination",
                &format!("{suffix}-{}", artifact.id.as_str()),
                None,
            ));
        }
        if backup {
            backups.push(BackupRequirement {
                component: component.id.clone(),
                target: BackupTarget::Artifact {
                    artifact: artifact.id.clone(),
                    path: artifact.source_path.clone(),
                },
                reason: if target_present {
                    "Back up an existing target artifact before an approved change".to_owned()
                } else {
                    "Guard the destination and back it up if it exists before writing".to_owned()
                },
            });
        }
    }
}

fn add_dependency_conflicts(
    graph: &PackageGraph,
    states: &[PendingComponentDiff],
    conflicts: &mut Vec<ClassifiedConflict>,
) {
    let component_ids: BTreeSet<_> = states.iter().map(|state| state.component.clone()).collect();
    let mut blocked: BTreeSet<_> = conflicts
        .iter()
        .filter(|conflict| conflict.blocks_planning)
        .filter_map(|conflict| conflict.conflict.component.clone())
        .collect();
    let mut required_edges = graph
        .edges
        .iter()
        .chain(
            graph
                .components
                .iter()
                .flat_map(|component| component.dependencies.iter()),
        )
        .filter(|edge| edge.required)
        .collect::<Vec<_>>();
    required_edges.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.to.cmp(&right.to))
            .then_with(|| dependency_kind_rank(&left.kind).cmp(&dependency_kind_rank(&right.kind)))
    });
    required_edges.dedup_by(|left, right| {
        left.from == right.from && left.to == right.to && left.kind == right.kind
    });

    loop {
        let mut changed = false;
        for edge in &required_edges {
            if !component_ids.contains(&edge.from)
                || !component_ids.contains(&edge.to)
                || blocked.contains(&edge.to)
            {
                let conflict = dependency_conflict(edge);
                if !conflicts
                    .iter()
                    .any(|existing| existing.conflict.id == conflict.conflict.id)
                {
                    conflicts.push(conflict);
                }
                changed |= blocked.insert(edge.from.clone());
            }
        }
        if !changed {
            break;
        }
    }
}

fn dependency_kind_rank(kind: &reforge_domain::DependencyKind) -> u8 {
    use reforge_domain::DependencyKind;

    match kind {
        DependencyKind::RequiredRuntime => 0,
        DependencyKind::RequiredPackage => 1,
        DependencyKind::InstalledThrough => 2,
        DependencyKind::Configures => 3,
        DependencyKind::UsesSecret => 4,
        DependencyKind::OptionalFeature => 5,
        DependencyKind::ProvidesExecutable => 6,
        DependencyKind::Contains => 7,
        DependencyKind::RestoresBefore => 8,
        DependencyKind::VerifiesWith => 9,
        DependencyKind::RelatedOnly => 10,
    }
}
fn dependency_conflict(edge: &DependencyEdge) -> ClassifiedConflict {
    classify_conflict(
        Some(edge.from.clone()),
        ConflictKind::DependencyConflict,
        format!("component requires {}", edge.to.as_str()),
        "required dependency is unavailable or blocked",
        edge.to.as_str(),
        None,
    )
}

fn disposition(
    target_present: bool,
    conflicts: &[&Conflict],
    blocking_ids: &[String],
) -> ComponentDisposition {
    if conflicts
        .iter()
        .any(|conflict| blocking_ids.binary_search(&conflict.id).is_ok())
    {
        return ComponentDisposition::Blocked;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.resolution == ConflictResolution::Manual)
    {
        return ComponentDisposition::Manual;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.resolution == ConflictResolution::PreserveTarget)
    {
        return ComponentDisposition::PreserveTarget;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.resolution == ConflictResolution::Merge)
    {
        return ComponentDisposition::Merge;
    }
    if conflicts
        .iter()
        .any(|conflict| conflict.resolution == ConflictResolution::Install)
    {
        return ComponentDisposition::Install;
    }
    if target_present {
        ComponentDisposition::Skip
    } else {
        ComponentDisposition::Install
    }
}

fn identity_matches(source: &Component, target: &InstalledFact) -> bool {
    if let (Some((source_provider, source_package)), Some((target_provider, target_package))) = (
        source.identity.provider_package.as_ref(),
        target.identity.provider_package.as_ref(),
    ) && source_provider == target_provider
        && normalized(source.identity.provider_source.as_deref())
            == normalized(target.identity.provider_source.as_deref())
        && normalized(Some(source_package)) == normalized(Some(target_package))
        && source.identity.provider_source.is_some()
        && target.identity.provider_source.is_some()
    {
        return true;
    }

    let source_publisher = component_publisher(source);
    let target_publisher = installed_publisher(target);
    if let (
        Some(source_family),
        Some(target_family),
        Some(source_publisher),
        Some(target_publisher),
    ) = (
        normalized(source.identity.package_family.as_deref()),
        normalized(target.identity.package_family.as_deref()),
        source_publisher.clone(),
        target_publisher.clone(),
    ) && source_family == target_family
        && source_publisher == target_publisher
    {
        return true;
    }

    if let (
        Some(source_product),
        Some(target_product),
        Some(source_certificate),
        Some(target_certificate),
    ) = (
        normalized(source.identity.product_name.as_deref()),
        normalized(target.identity.product_name.as_deref()),
        source
            .publisher
            .as_ref()
            .and_then(|publisher| normalized(publisher.certificate_thumbprint.as_deref())),
        target
            .publisher
            .as_ref()
            .and_then(|publisher| normalized(publisher.certificate_thumbprint.as_deref())),
    ) && source_product == target_product
        && source_certificate == target_certificate
    {
        return true;
    }

    if let (
        Some(source_product),
        Some(target_product),
        Some(source_publisher),
        Some(target_publisher),
        Some(source_role),
        Some(target_role),
    ) = (
        normalized(source.identity.product_name.as_deref()),
        normalized(target.identity.product_name.as_deref()),
        source_publisher,
        target_publisher,
        normalized(source.identity.install_role.as_deref()),
        normalized(target.identity.install_role.as_deref()),
    ) && source_product == target_product
        && source_publisher == target_publisher
        && source_role == target_role
    {
        return true;
    }

    matches!(
        (
            normalized_executable(source.identity.executable_name.as_deref()),
            normalized_executable(target.identity.executable_name.as_deref()),
            normalized(source.identity.executable_hash.as_deref()),
            normalized(target.identity.executable_hash.as_deref()),
        ),
        (Some(source_executable), Some(target_executable), Some(source_hash), Some(target_hash))
            if source_executable == target_executable && source_hash == target_hash
    )
}

fn component_publisher(component: &Component) -> Option<String> {
    component
        .publisher
        .as_ref()
        .and_then(|publisher| normalized(Some(&publisher.name)))
        .or_else(|| normalized(component.identity.publisher.as_deref()))
}

fn installed_publisher(fact: &InstalledFact) -> Option<String> {
    fact.publisher
        .as_ref()
        .and_then(|publisher| normalized(Some(&publisher.name)))
        .or_else(|| normalized(fact.identity.publisher.as_deref()))
}

fn normalized_source(component: &Component) -> Option<String> {
    normalized(component.identity.provider_source.as_deref()).or_else(|| {
        component
            .provenance
            .as_ref()
            .and_then(|provenance| normalized(Some(&provenance.adapter_id)))
    })
}

fn normalized_installed_source(fact: &InstalledFact) -> Option<String> {
    normalized(fact.identity.provider_source.as_deref()).or_else(|| {
        fact.provenance
            .as_ref()
            .and_then(|provenance| normalized(Some(&provenance.adapter_id)))
    })
}

fn source_identity_summary(component: &Component) -> String {
    if let Some((provider, package)) = &component.identity.provider_package {
        return format!(
            "source identity {}/{}",
            provider.as_str(),
            safe_label(package)
        );
    }
    format!("source component {}", component.id.as_str())
}

fn environment_name(component: &Component) -> Option<String> {
    component
        .verification
        .iter()
        .find_map(|rule| match rule {
            VerificationRule::Environment { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .or(component.identity.product_name.as_deref())
        .or_else(|| {
            component
                .identity
                .provider_package
                .as_ref()
                .map(|(_, name)| name.as_str())
        })
        .and_then(normalize_environment_name)
}

fn environment_scope(component: &Component) -> ConfigScope {
    component
        .verification
        .iter()
        .find_map(|rule| match rule {
            VerificationRule::Environment { scope, .. } => Some(scope.clone()),
            _ => None,
        })
        .or_else(|| {
            component
                .artifacts
                .first()
                .map(|artifact| artifact.scope.clone())
        })
        .unwrap_or(ConfigScope::User)
}

fn environment_expected_hash(component: &Component) -> Option<String> {
    component.verification.iter().find_map(|rule| match rule {
        VerificationRule::Environment {
            expected: SafeValueRef::LiteralNonSecret(value),
            ..
        } => Some(ObjectId::from_content(value.as_bytes()).as_str().to_owned()),
        _ => None,
    })
}

fn normalize_environment_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 32 * 1024
        || value.contains(['\0', '='])
        || value.chars().any(char::is_control)
    {
        None
    } else {
        Some(value.to_uppercase())
    }
}

fn scope_rank(scope: &ConfigScope) -> u8 {
    match scope {
        ConfigScope::Process => 0,
        ConfigScope::User => 1,
        ConfigScope::System => 2,
        ConfigScope::Project => 3,
        ConfigScope::Managed => 4,
    }
}

fn normalized_executable(value: Option<&str>) -> Option<String> {
    normalized(value).and_then(|value| {
        value
            .rsplit(['/', '\\'])
            .next()
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn is_port_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("PORT") || name.to_ascii_uppercase().ends_with("_PORT")
}

fn normalized(value: Option<&str>) -> Option<String> {
    let value = value?.trim().to_lowercase();
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        None
    } else {
        Some(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VersionRelation {
    Same,
    TargetNewer,
    TargetOlder,
    DifferentUnknown,
}

fn version_relation(
    source: Option<&VersionValue>,
    target: Option<&VersionValue>,
) -> VersionRelation {
    let source = source.and_then(version_text);
    let target = target.and_then(version_text);
    match (&source, &target) {
        (None, None) => return VersionRelation::Same,
        (Some(source), Some(target)) if source == target => return VersionRelation::Same,
        (None, Some(_)) => return VersionRelation::TargetNewer,
        (Some(_), None) => return VersionRelation::DifferentUnknown,
        (Some(_), Some(_)) => {}
    }
    let (Some(source), Some(target)) = (source, target) else {
        return VersionRelation::DifferentUnknown;
    };
    match compare_version_text(&source, &target) {
        Some(Ordering::Equal) => VersionRelation::Same,
        Some(Ordering::Less) => VersionRelation::TargetNewer,
        Some(Ordering::Greater) => VersionRelation::TargetOlder,
        None => VersionRelation::DifferentUnknown,
    }
}

fn compare_version_text(source: &str, target: &str) -> Option<Ordering> {
    let source = numeric_version(source)?;
    let target = numeric_version(target)?;
    Some(compare_numeric_versions(&source, &target))
}

fn version_text(version: &VersionValue) -> Option<String> {
    normalized(version.normalized.as_deref().or(Some(version.raw.as_str())))
}

fn numeric_version(value: &str) -> Option<Vec<u64>> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let segments: Vec<_> = value.split('.').collect();
    if segments.is_empty() || segments.len() > 16 {
        return None;
    }
    segments
        .into_iter()
        .map(|segment| {
            if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
                None
            } else {
                segment.parse().ok()
            }
        })
        .collect()
}

fn compare_numeric_versions(source: &[u64], target: &[u64]) -> Ordering {
    let length = source.len().max(target.len());
    (0..length)
        .map(|index| {
            source
                .get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&target.get(index).copied().unwrap_or(0))
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

fn version_summary(label: &str, version: Option<&VersionValue>) -> String {
    let value = version
        .and_then(version_text)
        .map(|value| safe_label(&value))
        .unwrap_or_else(|| "unknown".to_owned());
    format!("{label} version {value}")
}

fn architecture_matches(source: &Architecture, target: &Architecture) -> bool {
    matches!(source, Architecture::Neutral)
        || (source != &Architecture::Unknown
            && target != &Architecture::Unknown
            && source == target)
}

fn architecture_summary(architecture: &Architecture) -> String {
    match architecture {
        Architecture::X86 => "x86 architecture",
        Architecture::X64 => "x64 architecture",
        Architecture::Arm64 => "arm64 architecture",
        Architecture::Neutral => "architecture-neutral",
        Architecture::Unknown => "unknown architecture",
    }
    .to_owned()
}

fn safe_label(value: &str) -> String {
    let value: String = value
        .chars()
        .take(128)
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '-' | '_' | '+' | ':' | '/')
        })
        .collect();
    if value.is_empty() {
        "unavailable".to_owned()
    } else {
        value
    }
}

fn backup_key(requirement: &BackupRequirement) -> (String, String) {
    let target = match &requirement.target {
        BackupTarget::Artifact { artifact, path } => {
            format!(
                "artifact:{}:{:?}:{}",
                artifact.as_str(),
                path.root,
                path.relative
            )
        }
        BackupTarget::Environment { scope, name } => {
            format!("environment:{scope:?}:{name}")
        }
    };
    (requirement.component.as_str().to_owned(), target)
}
