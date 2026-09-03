//! Selection and recommendation wire types.
//!
//! Recommendation records are explanations, not authorization. A caller must
//! still apply the selection policy before it includes artifacts or schedules a
//! restore operation.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
    ArtifactId, ArtifactPolicy, ArtifactRef, Component, ComponentGraph, ComponentId, ComponentKind,
    DependencyEdge, DependencyKind, ErrorEnvelope, LargeDataSelectionPolicy, ReforgeErrorCode,
    RestoreStrategy, SecretSelectionPolicy, SelectionClosure, SelectionInput, SelectionPolicy,
    UnknownBinarySelectionPolicy,
};

const DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SELECTED_COMPONENTS: usize = 250_000;
const MAX_SELECTED_ARTIFACTS: usize = 1_000_000;
const MAX_SELECTION_WARNINGS: usize = 4_096;

/// The deterministic recommendation result for one component.
#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecommendationScore {
    pub component: ComponentId,
    pub score: i16,
    pub recommended: bool,
    pub chips: Vec<ExplanationChip>,
}

/// One explainable score contribution or safety override.
#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExplanationChip {
    pub code: String,
    pub label: String,
    pub delta: i16,
}

/// Resolve a user selection into the immutable snapshot consumed by packaging.
///
/// Required dependencies are closed transitively and optional dependencies are
/// retained as warnings rather than silently included. Artifact inclusion is
/// policy-driven: ordinary configuration/data/export artifacts are included by
/// default, while secrets, large data, manual artifacts, and portable binaries
/// require an explicit artifact selection. The returned value is a frozen
/// decision record; changing the input requires calling this function again.
pub fn build_selection_closure(
    graph: &ComponentGraph,
    input: &SelectionInput,
) -> Result<SelectionClosure, Box<ErrorEnvelope>> {
    let components = index_components(graph)?;
    let artifacts = index_artifacts(graph)?;
    let adjacency = index_edges(graph);
    let explicit_artifacts = index_artifact_selection(input, &artifacts)?;

    if input.components.len() > MAX_SELECTED_COMPONENTS {
        return Err(selection_error(
            ReforgeErrorCode::SecurityPolicy,
            "The selection exceeds the reviewed component limit",
            None,
        ));
    }

    let roots = user_selected_components(input, &components)?;
    let mut selected_components = roots.clone();
    let mut auto_added_dependencies = BTreeSet::new();
    let mut pending = roots.iter().cloned().collect::<Vec<_>>();

    while let Some(source) = pending.pop() {
        let Some(edges) = adjacency.get(&source) else {
            continue;
        };
        for edge in edges {
            if !edge.required {
                continue;
            }
            if !components.contains_key(&edge.to) {
                return Err(selection_error(
                    ReforgeErrorCode::SelectionIncomplete,
                    "A required dependency is unavailable in the inventory",
                    Some(source),
                ));
            }
            if selected_components.insert(edge.to.clone()) {
                if selected_components.len() > MAX_SELECTED_COMPONENTS {
                    return Err(selection_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "The dependency closure exceeds the reviewed component limit",
                        Some(source.clone()),
                    ));
                }
                auto_added_dependencies.insert(edge.to.clone());
                pending.push(edge.to.clone());
            }
        }
    }

    let mut warnings = BTreeSet::new();
    for dependency in &auto_added_dependencies {
        push_warning(
            &mut warnings,
            format!("Required dependency was automatically added: {dependency}"),
        )?;
    }
    expose_optional_edges(&adjacency, &selected_components, &components, &mut warnings)?;

    for component_id in &selected_components {
        let component = components
            .get(component_id)
            .expect("selected component IDs are indexed");
        validate_component_policy(component, &input.policy, &mut warnings)?;
    }

    for selection in &input.artifacts {
        if selection.include
            && artifacts
                .get(&selection.artifact)
                .is_some_and(|(owner, _)| !selected_components.contains(owner))
        {
            return Err(selection_error(
                ReforgeErrorCode::SelectionIncomplete,
                "An artifact is selected without selecting its owning component",
                artifacts
                    .get(&selection.artifact)
                    .map(|(owner, _)| (*owner).clone()),
            ));
        }
    }

    let mut selected_artifacts = BTreeSet::new();
    let mut total_bytes = 0u64;
    for component_id in &selected_components {
        let component = components
            .get(component_id)
            .expect("selected component IDs are indexed");
        let mut component_artifacts = component.artifacts.iter().collect::<Vec<_>>();
        component_artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        for artifact in component_artifacts {
            let explicit = explicit_artifacts.get(&artifact.id).copied();
            let include = explicit.unwrap_or_else(|| default_artifact_selection(artifact));
            if !include {
                continue;
            }
            artifact.source_path.validate().map_err(|_| {
                selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "A selected artifact has an invalid tokenized path",
                    Some(component_id.clone()),
                )
            })?;
            validate_artifact_policy(
                component,
                artifact,
                explicit.is_some(),
                &input.policy,
                &mut warnings,
            )?;
            total_bytes = total_bytes
                .checked_add(artifact.size_bytes)
                .ok_or_else(|| {
                    selection_error(
                        ReforgeErrorCode::SecurityPolicy,
                        "Selected artifact sizes overflow the reviewed limit",
                        Some(component_id.clone()),
                    )
                })?;
            selected_artifacts.insert(artifact.id.clone());
            if selected_artifacts.len() > MAX_SELECTED_ARTIFACTS {
                return Err(selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "The selection exceeds the reviewed artifact limit",
                    Some(component_id.clone()),
                ));
            }
        }
    }

    if input
        .policy
        .max_bytes
        .is_some_and(|maximum| total_bytes > maximum)
    {
        return Err(selection_error(
            ReforgeErrorCode::SecurityPolicy,
            "Selected artifacts exceed the configured size limit",
            None,
        ));
    }

    Ok(SelectionClosure {
        selected_components: selected_components.into_iter().collect(),
        selected_artifacts: selected_artifacts.into_iter().collect(),
        auto_added_dependencies: auto_added_dependencies.into_iter().collect(),
        total_bytes,
        warnings: warnings.into_iter().collect(),
    })
}

fn index_components(
    graph: &ComponentGraph,
) -> Result<BTreeMap<ComponentId, &Component>, Box<ErrorEnvelope>> {
    let mut components = BTreeMap::new();
    for component in &graph.components {
        if components.insert(component.id.clone(), component).is_some() {
            return Err(selection_error(
                ReforgeErrorCode::SchemaInvalid,
                "The inventory contains duplicate component IDs",
                Some(component.id.clone()),
            ));
        }
    }
    Ok(components)
}

fn index_artifacts(
    graph: &ComponentGraph,
) -> Result<BTreeMap<ArtifactId, (&ComponentId, &ArtifactRef)>, Box<ErrorEnvelope>> {
    let mut artifacts = BTreeMap::new();
    for component in &graph.components {
        for artifact in &component.artifacts {
            if artifacts
                .insert(artifact.id.clone(), (&component.id, artifact))
                .is_some()
            {
                return Err(selection_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "The inventory contains duplicate artifact IDs",
                    Some(component.id.clone()),
                ));
            }
        }
    }
    Ok(artifacts)
}

fn index_edges(graph: &ComponentGraph) -> BTreeMap<ComponentId, Vec<DependencyEdge>> {
    let mut indexed = BTreeMap::<ComponentId, Vec<DependencyEdge>>::new();
    let mut seen = BTreeSet::<(ComponentId, ComponentId, u8, bool)>::new();
    for edge in graph.edges.iter().chain(
        graph
            .components
            .iter()
            .flat_map(|component| component.dependencies.iter()),
    ) {
        let key = (
            edge.from.clone(),
            edge.to.clone(),
            dependency_kind_order(&edge.kind),
            edge.required,
        );
        if seen.insert(key) {
            indexed
                .entry(edge.from.clone())
                .or_default()
                .push(edge.clone());
        }
    }
    for edges in indexed.values_mut() {
        edges.sort_by(|left, right| {
            left.to
                .cmp(&right.to)
                .then_with(|| {
                    dependency_kind_order(&left.kind).cmp(&dependency_kind_order(&right.kind))
                })
                .then_with(|| left.required.cmp(&right.required))
        });
    }
    indexed
}

fn index_artifact_selection(
    input: &SelectionInput,
    artifacts: &BTreeMap<ArtifactId, (&ComponentId, &ArtifactRef)>,
) -> Result<BTreeMap<ArtifactId, bool>, Box<ErrorEnvelope>> {
    let mut indexed = BTreeMap::new();
    for selection in &input.artifacts {
        if !artifacts.contains_key(&selection.artifact) {
            return Err(selection_error(
                ReforgeErrorCode::SelectionIncomplete,
                "The selection references an unavailable artifact",
                None,
            ));
        }
        if indexed
            .insert(selection.artifact.clone(), selection.include)
            .is_some()
        {
            return Err(selection_error(
                ReforgeErrorCode::SelectionIncomplete,
                "The selection contains a duplicate artifact decision",
                artifacts
                    .get(&selection.artifact)
                    .map(|(owner, _)| (*owner).clone()),
            ));
        }
    }
    Ok(indexed)
}

fn user_selected_components(
    input: &SelectionInput,
    components: &BTreeMap<ComponentId, &Component>,
) -> Result<BTreeSet<ComponentId>, Box<ErrorEnvelope>> {
    let mut selected = BTreeSet::new();
    for component in &input.components {
        if !components.contains_key(component) {
            return Err(selection_error(
                ReforgeErrorCode::SelectionIncomplete,
                "The selection references an unavailable component",
                None,
            ));
        }
        if !selected.insert(component.clone()) {
            return Err(selection_error(
                ReforgeErrorCode::SelectionIncomplete,
                "The selection contains a duplicate component decision",
                Some(component.clone()),
            ));
        }
    }
    Ok(selected)
}

fn expose_optional_edges(
    adjacency: &BTreeMap<ComponentId, Vec<DependencyEdge>>,
    selected: &BTreeSet<ComponentId>,
    components: &BTreeMap<ComponentId, &Component>,
    warnings: &mut BTreeSet<String>,
) -> Result<(), Box<ErrorEnvelope>> {
    for source in selected {
        let Some(edges) = adjacency.get(source) else {
            continue;
        };
        for edge in edges.iter().filter(|edge| !edge.required) {
            let state = if components.contains_key(&edge.to) {
                "available but not selected"
            } else {
                "unavailable in the inventory"
            };
            if !selected.contains(&edge.to) {
                push_warning(
                    warnings,
                    format!("Optional dependency {state}: {}", edge.to),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_component_policy(
    component: &Component,
    policy: &SelectionPolicy,
    warnings: &mut BTreeSet<String>,
) -> Result<(), Box<ErrorEnvelope>> {
    if component.selection.sensitive || component.kind == ComponentKind::SecretReference {
        match policy.secrets {
            SecretSelectionPolicy::Exclude => {
                return Err(selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "Sensitive components require explicit vault selection",
                    Some(component.id.clone()),
                ));
            }
            SecretSelectionPolicy::VaultExplicit => push_warning(
                warnings,
                format!(
                    "Sensitive component requires explicit vault handling: {}",
                    component.id
                ),
            )?,
        }
    }

    if is_unknown_binary(component) {
        match policy.unknown_binaries {
            UnknownBinarySelectionPolicy::Exclude => {
                return Err(selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "Unknown binaries require explicit portable-binary selection",
                    Some(component.id.clone()),
                ));
            }
            UnknownBinarySelectionPolicy::PortableBinaryExplicit => {
                if !has_safe_binary_hash(component) {
                    return Err(selection_error(
                        ReforgeErrorCode::SelectionIncomplete,
                        "Portable-binary selection requires an executable hash",
                        Some(component.id.clone()),
                    ));
                }
                if !has_source_report(component) {
                    push_warning(
                        warnings,
                        format!(
                            "Portable binary source is unknown; review before restore: {}",
                            component.id
                        ),
                    )?;
                }
                if !has_signature_report(component) {
                    push_warning(
                        warnings,
                        format!(
                            "Portable binary signature is unverified; review before restore: {}",
                            component.id
                        ),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_artifact_policy(
    component: &Component,
    artifact: &ArtifactRef,
    explicitly_selected: bool,
    policy: &SelectionPolicy,
    warnings: &mut BTreeSet<String>,
) -> Result<(), Box<ErrorEnvelope>> {
    let secret = artifact.policy == ArtifactPolicy::SecretReference
        || component.selection.sensitive
        || component.kind == ComponentKind::SecretReference;
    if secret {
        match policy.secrets {
            SecretSelectionPolicy::Exclude => {
                return Err(selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "Secret artifacts require explicit vault selection",
                    Some(component.id.clone()),
                ));
            }
            SecretSelectionPolicy::VaultExplicit => push_warning(
                warnings,
                format!("Secret artifact requires vault handling: {}", artifact.id),
            )?,
        }
    }

    let large = artifact.policy == ArtifactPolicy::LargeOptIn
        || artifact.size_bytes > DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES;
    if large {
        match policy.large_data {
            LargeDataSelectionPolicy::Exclude => {
                return Err(selection_error(
                    ReforgeErrorCode::SecurityPolicy,
                    "Large artifacts require explicit size confirmation",
                    Some(component.id.clone()),
                ));
            }
            LargeDataSelectionPolicy::RequireConfirmation => {
                if !explicitly_selected {
                    return Err(selection_error(
                        ReforgeErrorCode::SelectionIncomplete,
                        "Large artifacts require an explicit selection decision",
                        Some(component.id.clone()),
                    ));
                }
                push_warning(
                    warnings,
                    format!("Large artifact explicitly confirmed: {}", artifact.id),
                )?;
            }
        }
    }

    if artifact.policy == ArtifactPolicy::Manual {
        push_warning(
            warnings,
            format!("Artifact requires manual restore review: {}", artifact.id),
        )?;
    }
    Ok(())
}

fn default_artifact_selection(artifact: &ArtifactRef) -> bool {
    if artifact.policy == ArtifactPolicy::LargeOptIn
        || artifact.policy == ArtifactPolicy::SecretReference
        || artifact.policy == ArtifactPolicy::PortableBinary
        || artifact.policy == ArtifactPolicy::Manual
        || artifact.size_bytes > DEFAULT_LARGE_ARTIFACT_THRESHOLD_BYTES
    {
        return false;
    }
    matches!(
        artifact.policy,
        ArtifactPolicy::Config | ArtifactPolicy::Data | ArtifactPolicy::Export
    )
}

fn is_unknown_binary(component: &Component) -> bool {
    component.kind == ComponentKind::PortableBinary
        || component.restore.primary == RestoreStrategy::PortableBinary
        || component
            .artifacts
            .iter()
            .any(|artifact| artifact.policy == ArtifactPolicy::PortableBinary)
        || (component.kind == ComponentKind::Unknown
            && (component.identity.executable_name.is_some()
                || component.identity.executable_hash.is_some()))
}

fn has_safe_binary_hash(component: &Component) -> bool {
    component
        .identity
        .executable_hash
        .as_deref()
        .is_some_and(|hash| {
            !hash.is_empty()
                && hash.len() <= 512
                && hash.trim() == hash
                && !hash.chars().any(char::is_control)
        })
}

fn has_source_report(component: &Component) -> bool {
    component.provenance.as_ref().is_some_and(|provenance| {
        provenance.source_url.is_some()
            || provenance.package_id.is_some()
            || provenance.provider.is_some()
    }) || component.identity.provider_source.is_some()
        || component.identity.provider_package.is_some()
}

fn has_signature_report(component: &Component) -> bool {
    component
        .publisher
        .as_ref()
        .and_then(|publisher| publisher.certificate_thumbprint.as_deref())
        .is_some_and(|thumbprint| !thumbprint.trim().is_empty())
}

fn push_warning(
    warnings: &mut BTreeSet<String>,
    warning: String,
) -> Result<(), Box<ErrorEnvelope>> {
    if warning.is_empty() || warning.len() > 512 || warning.chars().any(char::is_control) {
        return Err(selection_error(
            ReforgeErrorCode::SecurityPolicy,
            "Selection warning is outside the reviewed grammar",
            None,
        ));
    }
    warnings.insert(warning);
    if warnings.len() > MAX_SELECTION_WARNINGS {
        return Err(selection_error(
            ReforgeErrorCode::SecurityPolicy,
            "The selection warning limit was exceeded",
            None,
        ));
    }
    Ok(())
}

fn dependency_kind_order(kind: &DependencyKind) -> u8 {
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

fn selection_error(
    code: ReforgeErrorCode,
    message: &str,
    component: Option<ComponentId>,
) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(code, message).with_ids(component, None))
}
