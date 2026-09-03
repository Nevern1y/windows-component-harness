//! Restore-plan construction from trusted package state and target analysis.
//!
//! The planner is deliberately data-only.  It translates closed domain facts
//! into allowlisted [`OperationKind`] values, assigns stable IDs, and refuses
//! to produce a plan when trust, compatibility, selection, or dependency
//! invariants are not satisfied.

use std::collections::{BTreeMap, BTreeSet};

use reforge_domain::selection::build_selection_closure;
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, CompatibilityResult, Component, ComponentId,
    ComponentKind, ConfigScope, Conflict, ConflictKind, ConflictResolution, ContentType,
    DependencyEdge, DependencyKind, DockerImageSpec, DockerVolumeSpec, FileMode, KnownFolderToken,
    ManualAction, ManualActionState, McpServerSpec, MergePolicy, ObjectIndex, OperationKind,
    PackageGraph, PackageInstallPolicy, PackageSpec, PathToken, Precondition, ProviderId,
    ReforgeErrorCode, RestoreMode, RestorePlan, RestoreStrategy, RiskLevel, RunId, SafeValueRef,
    SelectionClosure, TrustState, VerificationRule, WslSpec, validate_restore_plan,
};
use reforge_package::{InspectedPackage, require_plan_approval};

use crate::diff::{ComponentDisposition, TargetDiff};
use crate::operations::{
    OperationPhase, OperationSpec, default_phase, order_overlapping_writes, topological_order,
};
use crate::{RestoreResult, restore_error};

const PLAN_FORMAT_VERSION: u16 = 1;
const MAX_PLAN_COMPONENTS: usize = 250_000;
const MAX_PLAN_ARTIFACTS: usize = 1_000_000;
const MAX_PLAN_OPERATIONS: usize = 1_000_000;
const MAX_PLAN_WARNINGS: usize = 4_096;
const MAX_MANUAL_TEXT_BYTES: usize = 1_024;

/// Immutable inputs consumed by [`RestorePlanner`].
#[derive(Clone, Debug)]
pub struct PlannerInput {
    pub run_id: reforge_domain::RunId,
    pub package_id: String,
    pub mode: RestoreMode,
    pub target_fingerprint: String,
    pub graph: PackageGraph,
    pub selection: SelectionClosure,
    pub trust: TrustState,
    pub target_diff: TargetDiff,
    pub compatibility: CompatibilityResult,
    pub object_index: ObjectIndex,
}

/// Explicit name for callers that prefer the plan-oriented terminology.
pub type RestorePlanInput = PlannerInput;

impl PlannerInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: reforge_domain::RunId,
        package_id: impl Into<String>,
        mode: RestoreMode,
        target_fingerprint: impl Into<String>,
        graph: PackageGraph,
        selection: SelectionClosure,
        trust: TrustState,
        target_diff: TargetDiff,
        compatibility: CompatibilityResult,
        object_index: ObjectIndex,
    ) -> Self {
        Self {
            run_id,
            package_id: package_id.into(),
            mode,
            target_fingerprint: target_fingerprint.into(),
            graph,
            selection,
            trust,
            target_diff,
            compatibility,
            object_index,
        }
    }

    /// Build planner input directly from a package reader result.  Selection is
    /// re-evaluated from the package's immutable selection input so a caller
    /// cannot accidentally plan a package with a changed policy decision.
    /// The target fingerprint is supplied by the target scanner, never inferred
    /// from package contents.
    pub fn from_package(
        package: &InspectedPackage,
        run_id: reforge_domain::RunId,
        mode: RestoreMode,
        target_fingerprint: impl Into<String>,
        target_diff: TargetDiff,
        compatibility: CompatibilityResult,
    ) -> RestoreResult<Self> {
        let selection = build_selection_closure(&package.graph, &package.selection)?;
        Ok(Self {
            run_id,
            package_id: package.manifest.package_id.clone(),
            mode,
            target_fingerprint: target_fingerprint.into(),
            graph: package.graph.clone(),
            selection,
            trust: package.trust.clone(),
            target_diff,
            compatibility,
            object_index: package.object_index.clone(),
        })
    }
}

/// Deterministic restore DAG planner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlanner {
    first_ordinal: u64,
    mcp_servers: BTreeMap<ComponentId, McpServerSpec>,
}

impl RestorePlanner {
    pub fn new() -> Self {
        Self {
            first_ordinal: 0,
            mcp_servers: BTreeMap::new(),
        }
    }

    /// Set the first operation ordinal reserved for this planner invocation.
    pub fn with_first_ordinal(mut self, first_ordinal: u64) -> Self {
        self.first_ordinal = first_ordinal;
        self
    }

    /// Supply normalized MCP records from the trusted discovery adapter.
    ///
    /// The planner never interprets `Component::extensions` as operations;
    /// callers must provide the adapter's typed `McpServerSpec` values.
    pub fn with_mcp_servers(mut self, mcp_servers: BTreeMap<ComponentId, McpServerSpec>) -> Self {
        self.mcp_servers = mcp_servers;
        self
    }

    pub fn first_ordinal(self) -> u64 {
        self.first_ordinal
    }

    /// Validate trust and compatibility, close the selected graph, construct
    /// typed operations, and return a stable topological plan.
    pub fn plan(&self, input: PlannerInput) -> RestoreResult<RestorePlan> {
        require_plan_approval(&input.trust)?;
        validate_plan_input(&input)?;

        let graph = GraphIndex::build(&input.graph)?;
        validate_mcp_specs(&graph, &self.mcp_servers, &input.object_index)?;
        let (selected_components, selected_artifacts, mut warnings) =
            close_selection(&graph, &input.selection, &self.mcp_servers)?;
        validate_dependency_cycles(&graph, &selected_components, &self.mcp_servers)?;
        validate_target_inputs(&input, &selected_components)?;

        warnings.extend(input.selection.warnings.iter().cloned());
        warnings.extend(input.target_diff.warnings.iter().cloned());
        warnings.extend(input.compatibility.warnings.iter().cloned());
        let warnings = normalize_warnings(warnings)?;

        let mut specs = BTreeMap::<String, OperationSpec>::new();
        let mut manual_actions = BTreeMap::<String, ManualAction>::new();
        let mut manual_operation_keys = BTreeMap::<String, String>::new();
        let mut confirmation_keys = BTreeMap::<ComponentId, Vec<String>>::new();
        seed_compatibility_confirmations(
            &input.compatibility,
            &selected_components,
            &input.run_id,
            &mut specs,
            &mut manual_actions,
            &mut manual_operation_keys,
            &mut confirmation_keys,
        )?;
        seed_conflict_confirmations(
            &input.target_diff,
            &selected_components,
            &input.run_id,
            &mut specs,
            &mut manual_actions,
            &mut manual_operation_keys,
            &mut confirmation_keys,
        )?;

        let mut provider_operation_keys = BTreeMap::<ProviderId, String>::new();
        let mut component_mutations = BTreeMap::<ComponentId, Vec<String>>::new();
        let mut component_all_operations = BTreeMap::<ComponentId, Vec<String>>::new();
        let mut component_readiness = BTreeMap::<ComponentId, Option<String>>::new();

        for component_id in &selected_components {
            let component = graph
                .components
                .get(component_id)
                .expect("selected component is indexed");
            let diff = component_diff(&input.target_diff, component_id).expect("validated diff");
            let built = build_component_operations(
                component,
                &input.run_id,
                diff,
                &selected_artifacts,
                &graph.artifacts,
                &confirmation_keys,
                &mut specs,
                &mut manual_actions,
                &mut manual_operation_keys,
                &mut provider_operation_keys,
                &self.mcp_servers,
            )?;
            component_readiness.insert(component_id.clone(), built.readiness_key.clone());
            component_mutations.insert(component_id.clone(), built.mutation_keys.clone());
            component_all_operations.insert(component_id.clone(), built.mutation_keys);
        }

        add_verification_operations(
            &graph,
            &selected_components,
            &component_mutations,
            &component_readiness,
            &mut component_all_operations,
            &mut specs,
        )?;
        add_dependency_prerequisites(
            &graph,
            &selected_components,
            &component_readiness,
            &component_all_operations,
            &self.mcp_servers,
            &mut specs,
        )?;

        if specs.len() > MAX_PLAN_OPERATIONS {
            return Err(planner_error(
                ReforgeErrorCode::SecurityPolicy,
                "restore plan exceeds the reviewed operation limit",
            ));
        }
        order_overlapping_writes(&mut specs)?;
        let operations = topological_order(specs, &input.run_id, self.first_ordinal)?;

        let conflicts = relevant_conflicts(&input.target_diff.conflicts, &selected_components);
        let manual_actions: Vec<_> = manual_actions.into_values().collect();
        let plan = RestorePlan {
            format_version: PLAN_FORMAT_VERSION,
            run_id: input.run_id,
            package_id: input.package_id,
            mode: input.mode,
            target_fingerprint: input.target_fingerprint,
            selected_components: selected_components.into_iter().collect(),
            operations,
            conflicts,
            manual_actions,
            warnings,
        };

        validate_restore_plan(&plan, &input.object_index)
            .map_err(|error| restore_error(error.code, error.message, None, None, None, None))?;
        Ok(plan)
    }
}

impl Default for RestorePlanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience entry point for callers that do not need planner state.
pub fn plan_restore(input: PlannerInput) -> RestoreResult<RestorePlan> {
    RestorePlanner::new().plan(input)
}

struct GraphIndex<'a> {
    components: BTreeMap<ComponentId, &'a Component>,
    artifacts: BTreeMap<ArtifactId, (&'a ComponentId, &'a ArtifactRef)>,
    outgoing: BTreeMap<ComponentId, Vec<DependencyEdge>>,
}

impl<'a> GraphIndex<'a> {
    fn build(graph: &'a PackageGraph) -> RestoreResult<Self> {
        let mut components = BTreeMap::new();
        let mut artifacts = BTreeMap::new();
        for component in &graph.components {
            if components.insert(component.id.clone(), component).is_some() {
                return Err(planner_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "package graph contains duplicate component IDs",
                ));
            }
            for artifact in &component.artifacts {
                artifact.source_path.validate().map_err(|_| {
                    planner_error(
                        ReforgeErrorCode::InvalidPath,
                        "package graph contains an invalid artifact path",
                    )
                })?;
                if artifacts
                    .insert(artifact.id.clone(), (&component.id, artifact))
                    .is_some()
                {
                    return Err(planner_error(
                        ReforgeErrorCode::SchemaInvalid,
                        "package graph contains duplicate artifact IDs",
                    ));
                }
            }
        }

        let mut outgoing = BTreeMap::<ComponentId, Vec<DependencyEdge>>::new();
        let mut seen = BTreeSet::<(ComponentId, ComponentId, String, bool)>::new();
        for edge in graph.edges.iter().chain(
            graph
                .components
                .iter()
                .flat_map(|component| component.dependencies.iter()),
        ) {
            if !components.contains_key(&edge.from) || !components.contains_key(&edge.to) {
                return Err(planner_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "package graph edge references a missing component",
                ));
            }
            let key = (
                edge.from.clone(),
                edge.to.clone(),
                dependency_kind_key(&edge.kind).to_owned(),
                edge.required,
            );
            if seen.insert(key) {
                outgoing
                    .entry(edge.from.clone())
                    .or_default()
                    .push(edge.clone());
            }
        }
        for edges in outgoing.values_mut() {
            edges.sort_by(|left, right| {
                left.to
                    .cmp(&right.to)
                    .then_with(|| {
                        dependency_kind_key(&left.kind).cmp(dependency_kind_key(&right.kind))
                    })
                    .then_with(|| left.required.cmp(&right.required))
            });
        }
        Ok(Self {
            components,
            artifacts,
            outgoing,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ComponentOperations {
    mutation_keys: Vec<String>,
    readiness_key: Option<String>,
}

fn validate_plan_input(input: &PlannerInput) -> RestoreResult<()> {
    if input.package_id.trim().is_empty()
        || input.package_id.len() > 256
        || input.package_id.chars().any(char::is_control)
    {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "restore plan package ID is invalid",
        ));
    }
    if input.target_fingerprint.trim().is_empty()
        || input.target_fingerprint.len() > 512
        || input.target_fingerprint.chars().any(char::is_control)
    {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "restore plan target fingerprint is invalid",
        ));
    }
    if input.graph.components.len() > MAX_PLAN_COMPONENTS {
        return Err(planner_error(
            ReforgeErrorCode::SecurityPolicy,
            "package graph exceeds the reviewed planner component limit",
        ));
    }
    if input.selection.selected_components.len() > MAX_PLAN_COMPONENTS {
        return Err(planner_error(
            ReforgeErrorCode::SecurityPolicy,
            "selection exceeds the reviewed planner component limit",
        ));
    }
    if input.selection.selected_artifacts.len() > MAX_PLAN_ARTIFACTS {
        return Err(planner_error(
            ReforgeErrorCode::SecurityPolicy,
            "selection exceeds the reviewed planner artifact limit",
        ));
    }
    let status_has_blockers = !input.compatibility.blockers.is_empty();
    let status_has_confirmations = !input.compatibility.confirmations.is_empty();
    let status_is_consistent = match input.compatibility.status {
        reforge_domain::CompatibilityStatus::Ready => {
            !status_has_blockers && !status_has_confirmations
        }
        reforge_domain::CompatibilityStatus::RequiresConfirmation => {
            !status_has_blockers && status_has_confirmations
        }
        reforge_domain::CompatibilityStatus::Blocked => status_has_blockers,
    };
    if !status_is_consistent {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "compatibility result status does not match its blockers and confirmations",
        ));
    }
    Ok(())
}

fn validate_mcp_specs(
    graph: &GraphIndex<'_>,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
    object_index: &ObjectIndex,
) -> RestoreResult<()> {
    for (component_id, server) in mcp_servers {
        let Some(component) = graph.components.get(component_id) else {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record references a missing component",
            ));
        };
        if component.kind != ComponentKind::McpServer {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record references a non-MCP component",
            ));
        }
        if server.name.trim().is_empty()
            || server.name.len() > MAX_MANUAL_TEXT_BYTES
            || server.name.chars().any(char::is_control)
            || server.transport == reforge_domain::McpTransport::Unknown
        {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record has an invalid or unsupported transport identity",
            ));
        }
        server.source_config.source_path.validate().map_err(|_| {
            planner_error(
                ReforgeErrorCode::InvalidPath,
                "typed MCP record contains an invalid source path",
            )
        })?;
        if server.source_config.policy != ArtifactPolicy::Config {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record source must be a non-secret config artifact",
            ));
        }
        let Some(source_artifact) = component
            .artifacts
            .iter()
            .find(|artifact| artifact.id == server.source_config.id)
        else {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record source artifact is not owned by its component",
            ));
        };
        if source_artifact.source_path != server.source_config.source_path {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record source path conflicts with its component artifact",
            ));
        }
        let Some(object) = &server.source_config.object else {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record source artifact has no content object",
            ));
        };
        if !object_index.objects.iter().any(|entry| &entry.id == object) {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "typed MCP record source object is absent from the package index",
            ));
        }
    }
    Ok(())
}

fn close_selection(
    graph: &GraphIndex<'_>,
    selection: &SelectionClosure,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
) -> RestoreResult<(BTreeSet<ComponentId>, BTreeSet<ArtifactId>, Vec<String>)> {
    let mut selected = BTreeSet::new();
    for component in &selection.selected_components {
        if !selected.insert(component.clone()) {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selection contains duplicate component IDs",
            ));
        }
        if !graph.components.contains_key(component) {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selection references an unavailable component",
            ));
        }
    }

    let mut pending: Vec<_> = selected.iter().cloned().collect();
    let mut auto_added = BTreeSet::new();
    while let Some(source) = pending.pop() {
        if let Some(edges) = graph.outgoing.get(&source) {
            for edge in edges.iter().filter(|edge| edge.required) {
                if selected.insert(edge.to.clone()) {
                    auto_added.insert(edge.to.clone());
                    pending.push(edge.to.clone());
                }
            }
        }
        let runtime = graph
            .components
            .get(&source)
            .and_then(|component| component.compatibility.requires_runtime.clone());
        if let Some(runtime) = runtime {
            if !graph.components.contains_key(&runtime) {
                return Err(planner_error(
                    ReforgeErrorCode::SelectionIncomplete,
                    "a required runtime is unavailable in the package graph",
                ));
            }
            if selected.insert(runtime.clone()) {
                auto_added.insert(runtime.clone());
                pending.push(runtime);
            }
        }
        if let Some(server) = mcp_servers.get(&source) {
            if let Some(runtime) = &server.required_runtime {
                queue_required_component(
                    graph,
                    &mut selected,
                    &mut auto_added,
                    &mut pending,
                    runtime.clone(),
                    "a required MCP runtime is unavailable in the package graph",
                )?;
            }
            if let Some(package) = &server.required_package {
                let package_component = graph.components.iter().find_map(|(id, component)| {
                    component
                        .identity
                        .provider_package
                        .as_ref()
                        .filter(|(provider, package_id)| {
                            provider == &package.provider && package_id == &package.id
                        })
                        .map(|_| id.clone())
                });
                let Some(package_component) = package_component else {
                    return Err(planner_error(
                        ReforgeErrorCode::SelectionIncomplete,
                        "a required MCP package is unavailable in the package graph",
                    ));
                };
                queue_required_component(
                    graph,
                    &mut selected,
                    &mut auto_added,
                    &mut pending,
                    package_component,
                    "a required MCP package is unavailable in the package graph",
                )?;
            }
        }
    }

    let mut selected_artifacts = BTreeSet::new();
    for artifact in &selection.selected_artifacts {
        if !selected_artifacts.insert(artifact.clone()) {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selection contains duplicate artifact IDs",
            ));
        }
        let Some((owner, _)) = graph.artifacts.get(artifact) else {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selection references an unavailable artifact",
            ));
        };
        if !selected.contains(*owner) {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selected artifact belongs to an unselected component",
            ));
        }
    }
    for component_id in &selected {
        if let Some(server) = mcp_servers.get(component_id)
            && !selected_artifacts.contains(&server.source_config.id)
        {
            return Err(planner_error(
                ReforgeErrorCode::SelectionIncomplete,
                "selected MCP component does not include its normalized source artifact",
            ));
        }
    }

    for component_id in &selected {
        if graph
            .components
            .get(component_id)
            .expect("selected component is indexed")
            .verification
            .is_empty()
        {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "selected component has no verification rule",
            ));
        }
    }

    let warnings = auto_added
        .into_iter()
        .map(|component| format!("Required dependency was automatically added: {component}"))
        .collect();
    Ok((selected, selected_artifacts, warnings))
}
fn queue_required_component(
    graph: &GraphIndex<'_>,
    selected: &mut BTreeSet<ComponentId>,
    auto_added: &mut BTreeSet<ComponentId>,
    pending: &mut Vec<ComponentId>,
    component: ComponentId,
    missing_message: &str,
) -> RestoreResult<()> {
    if !graph.components.contains_key(&component) {
        return Err(planner_error(
            ReforgeErrorCode::SelectionIncomplete,
            missing_message,
        ));
    }
    if selected.insert(component.clone()) {
        auto_added.insert(component.clone());
        pending.push(component);
    }
    Ok(())
}

fn validate_dependency_cycles(
    graph: &GraphIndex<'_>,
    selected: &BTreeSet<ComponentId>,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
) -> RestoreResult<()> {
    let mut indegree = selected
        .iter()
        .map(|component| (component.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = BTreeMap::<ComponentId, Vec<ComponentId>>::new();
    let mut pairs = BTreeSet::<(ComponentId, ComponentId)>::new();

    for source in selected {
        if let Some(edges) = graph.outgoing.get(source) {
            for edge in edges.iter().filter(|edge| {
                (edge.required || edge.kind == DependencyKind::RestoresBefore)
                    && edge.kind != DependencyKind::VerifiesWith
                    && selected.contains(&edge.to)
            }) {
                pairs.insert((source.clone(), edge.to.clone()));
            }
        }
        if let Some(runtime) = graph
            .components
            .get(source)
            .and_then(|component| component.compatibility.requires_runtime.clone())
            && selected.contains(&runtime)
        {
            pairs.insert((source.clone(), runtime));
        }
        if let Some(server) = mcp_servers.get(source) {
            if let Some(runtime) = &server.required_runtime
                && selected.contains(runtime)
            {
                pairs.insert((source.clone(), runtime.clone()));
            }
            if let Some(package) = &server.required_package
                && let Some(package_component) =
                    graph.components.iter().find_map(|(id, component)| {
                        component
                            .identity
                            .provider_package
                            .as_ref()
                            .filter(|(provider, package_id)| {
                                provider == &package.provider && package_id == &package.id
                            })
                            .map(|_| id.clone())
                    })
                && selected.contains(&package_component)
            {
                pairs.insert((source.clone(), package_component));
            }
        }
    }

    for (source, dependency) in pairs {
        let entry = indegree
            .get_mut(&source)
            .expect("selected source has an indegree entry");
        *entry = entry.checked_add(1).ok_or_else(|| {
            planner_error(
                ReforgeErrorCode::SecurityPolicy,
                "dependency prerequisite count overflowed",
            )
        })?;
        dependents.entry(dependency).or_default().push(source);
    }

    let mut ready: BTreeSet<ComponentId> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(component, _)| component.clone())
        .collect();
    let mut processed = 0usize;
    while let Some(component) = ready.pop_first() {
        processed += 1;
        if let Some(children) = dependents.get(&component) {
            for child in children {
                let count = indegree
                    .get_mut(child)
                    .expect("selected child has an indegree entry");
                *count = count.checked_sub(1).expect("positive dependency indegree");
                if *count == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if processed != selected.len() {
        return Err(planner_error(
            ReforgeErrorCode::DependencyCycle,
            "selected package dependencies contain a restore cycle",
        ));
    }
    Ok(())
}

fn validate_target_inputs(
    input: &PlannerInput,
    selected: &BTreeSet<ComponentId>,
) -> RestoreResult<()> {
    for component in selected {
        if component_diff(&input.target_diff, component).is_none() {
            return Err(planner_error(
                ReforgeErrorCode::SchemaInvalid,
                "target diff is missing a selected component",
            ));
        }
    }

    let relevant_conflict_ids: BTreeSet<_> = input
        .target_diff
        .conflicts
        .iter()
        .filter(|conflict| {
            conflict
                .component
                .as_ref()
                .is_none_or(|component| selected.contains(component))
        })
        .map(|conflict| conflict.id.as_str())
        .collect();
    if input
        .target_diff
        .blocking_conflict_ids
        .iter()
        .any(|id| relevant_conflict_ids.contains(id.as_str()))
    {
        return Err(planner_error(
            ReforgeErrorCode::TargetConflict,
            "target conflicts block restore planning",
        ));
    }

    let relevant_blocker = input.compatibility.blockers.iter().any(|blocker| {
        blocker
            .component
            .as_ref()
            .is_none_or(|component| selected.contains(component))
    });
    if relevant_blocker {
        return Err(planner_error(
            ReforgeErrorCode::TargetConflict,
            "target compatibility blocks restore planning",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_component_operations(
    component: &Component,
    run_id: &RunId,
    diff: &crate::diff::ComponentDiff,
    selected_artifacts: &BTreeSet<ArtifactId>,
    artifacts: &BTreeMap<ArtifactId, (&ComponentId, &ArtifactRef)>,
    confirmation_keys: &BTreeMap<ComponentId, Vec<String>>,
    specs: &mut BTreeMap<String, OperationSpec>,
    manual_actions: &mut BTreeMap<String, ManualAction>,
    manual_operation_keys: &mut BTreeMap<String, String>,
    provider_operation_keys: &mut BTreeMap<ProviderId, String>,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
) -> RestoreResult<ComponentOperations> {
    if matches!(
        diff.disposition,
        ComponentDisposition::Skip | ComponentDisposition::PreserveTarget
    ) {
        return Ok(ComponentOperations::default());
    }

    if diff.disposition == ComponentDisposition::Blocked {
        return Err(planner_error(
            ReforgeErrorCode::TargetConflict,
            "a selected component is blocked by the target diff",
        ));
    }

    let mut result = ComponentOperations::default();
    let requires_manual = diff.disposition == ComponentDisposition::Manual
        || matches!(
            component.restore.primary,
            RestoreStrategy::Manual
                | RestoreStrategy::MachineBound
                | RestoreStrategy::Unknown
                | RestoreStrategy::SecretExportable
        )
        || component.kind == ComponentKind::SecretReference
        || component.kind == ComponentKind::SystemFeature
        || (component.kind == ComponentKind::McpServer && !mcp_servers.contains_key(&component.id));

    if requires_manual {
        let action = component_manual_action(component, "component")?;
        if let Some(key) = add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        )? {
            result.mutation_keys.push(key.clone());
            result.readiness_key = Some(key);
        }
        return Ok(result);
    }

    let mut primary_provider = None;
    if diff.disposition == ComponentDisposition::Install
        && let Some((kind, phase, precondition, verification, requires_elevation, provider)) =
            primary_operation(component, diff)?
    {
        let mut spec = OperationSpec::new(
            component.id.clone(),
            kind,
            phase,
            precondition,
            verification,
            requires_elevation,
            false,
        )?;
        primary_provider = provider;
        add_confirmation_prerequisites(&mut spec, component, confirmation_keys);
        let key = insert_spec(specs, spec)?;
        result.mutation_keys.push(key.clone());
        result.readiness_key = Some(key);
    }

    let mut component_artifacts: Vec<_> = selected_artifacts
        .iter()
        .filter_map(|artifact_id| {
            artifacts
                .get(artifact_id)
                .filter(|(owner, _)| **owner == component.id)
                .map(|(_, artifact)| *artifact)
        })
        .collect();
    component_artifacts.sort_by(|left, right| left.id.cmp(&right.id));

    if let Some(provider) = primary_provider {
        let provider_key = ensure_provider(
            provider,
            component.id.clone(),
            specs,
            provider_operation_keys,
        )?;
        let primary_key = result
            .mutation_keys
            .first()
            .expect("primary operation was inserted")
            .clone();
        specs
            .get_mut(&primary_key)
            .expect("primary operation exists")
            .add_prerequisite(provider_key);
    }

    for artifact in component_artifacts {
        if let Some(key) = add_artifact_operation(
            component,
            run_id,
            diff,
            artifact,
            confirmation_keys,
            specs,
            manual_actions,
            manual_operation_keys,
            provider_operation_keys,
        )? {
            if result.readiness_key.is_none() {
                result.readiness_key = Some(key.clone());
            }
            result.mutation_keys.push(key);
        }
    }
    if component.kind == ComponentKind::McpServer
        && let Some(server) = mcp_servers.get(&component.id)
    {
        let mut spec = OperationSpec::new(
            component.id.clone(),
            OperationKind::RegisterMcp {
                server: server.clone(),
            },
            OperationPhase::ApplicationRestore,
            if diff.target_present {
                Precondition::Always
            } else {
                Precondition::ComponentAbsent {
                    component: component.id.clone(),
                }
            },
            component.verification.clone(),
            false,
            false,
        )?;
        for prerequisite in &result.mutation_keys {
            spec.add_prerequisite(prerequisite.clone());
        }
        add_confirmation_prerequisites(&mut spec, component, confirmation_keys);
        let key = insert_spec(specs, spec)?;
        result.mutation_keys.push(key.clone());
        result.readiness_key = Some(key);
    }

    if component.restore.primary == RestoreStrategy::ReauthRequired {
        let action = component_manual_action(component, "reauth")?;
        if let Some(key) = add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        )? {
            result.mutation_keys.push(key);
        }
    }

    if result.mutation_keys.is_empty() {
        let action = component_manual_action(component, "unsupported")?;
        if let Some(key) = add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        )? {
            result.mutation_keys.push(key.clone());
            result.readiness_key = Some(key);
        }
    }
    Ok(result)
}

#[allow(clippy::type_complexity)]
fn primary_operation(
    component: &Component,
    diff: &crate::diff::ComponentDiff,
) -> RestoreResult<
    Option<(
        OperationKind,
        OperationPhase,
        Precondition,
        Vec<VerificationRule>,
        bool,
        Option<ProviderId>,
    )>,
> {
    let precondition = if diff.target_present {
        Precondition::Always
    } else {
        Precondition::ComponentAbsent {
            component: component.id.clone(),
        }
    };
    match component.kind {
        ComponentKind::EnvironmentVariable => {
            let Some(VerificationRule::Environment {
                scope: ConfigScope::User,
                name,
                expected: SafeValueRef::LiteralNonSecret(value),
            }) = component
                .verification
                .iter()
                .find(|rule| matches!(rule, VerificationRule::Environment { .. }))
            else {
                return Ok(None);
            };
            if name.is_empty()
                || name.len() > 256
                || name.contains('=')
                || name.chars().any(char::is_control)
                || name.eq_ignore_ascii_case("PATH")
                || value.chars().any(char::is_control)
            {
                return Ok(None);
            }
            Ok(Some((
                OperationKind::SetUserEnvironment {
                    name: name.clone(),
                    value: SafeValueRef::LiteralNonSecret(value.clone()),
                },
                OperationPhase::EnvironmentRestore,
                precondition,
                component.verification.clone(),
                false,
                None,
            )))
        }
        ComponentKind::Runtime => {
            if !matches!(
                component.restore.primary,
                RestoreStrategy::Reinstall | RestoreStrategy::Partial
            ) {
                return Ok(None);
            }
            let id = component.display_name.trim();
            if id.is_empty() || id.chars().any(char::is_control) {
                return Ok(None);
            }
            Ok(Some((
                OperationKind::EnsureRuntime {
                    runtime: reforge_domain::RuntimeSpec {
                        id: bounded_text(id),
                        version: component
                            .version
                            .as_ref()
                            .map(|version| bounded_text(&version.raw)),
                        architecture: component.architecture.clone(),
                    },
                },
                OperationPhase::RuntimeBootstrap,
                precondition,
                component.verification.clone(),
                component.restore.requires_elevation,
                component.compatibility.requires_provider.clone(),
            )))
        }
        ComponentKind::Package | ComponentKind::Application | ComponentKind::Tool => {
            if component.restore.primary != RestoreStrategy::Reinstall {
                return Ok(None);
            }
            let Some(package) = provider_identity(component)? else {
                return Ok(None);
            };
            let provider = package.provider.clone();
            Ok(Some((
                OperationKind::InstallPackage {
                    provider: provider.clone(),
                    package,
                    policy: PackageInstallPolicy {
                        accept_source_agreements: false,
                        accept_package_agreements: false,
                        silent: false,
                        allow_reboot: false,
                    },
                },
                OperationPhase::PackageInstall,
                precondition,
                component.verification.clone(),
                component.restore.requires_elevation,
                Some(provider),
            )))
        }
        ComponentKind::Extension => {
            if !matches!(
                component.restore.primary,
                RestoreStrategy::Reinstall | RestoreStrategy::Partial
            ) {
                return Ok(None);
            }
            let extension_id = component
                .provenance
                .as_ref()
                .and_then(|provenance| provenance.package_id.as_deref())
                .or_else(|| {
                    component
                        .identity
                        .provider_package
                        .as_ref()
                        .map(|(_, package)| package.as_str())
                });
            let Some(extension_id) = extension_id else {
                return Ok(None);
            };
            if extension_id.trim().is_empty()
                || extension_id.len() > 256
                || extension_id.chars().any(char::is_control)
            {
                return Ok(None);
            }
            Ok(Some((
                OperationKind::InstallVsCodeExtension {
                    id: extension_id.to_owned(),
                    version: component
                        .version
                        .as_ref()
                        .map(|version| bounded_text(&version.raw)),
                    profile: None,
                },
                OperationPhase::ApplicationRestore,
                precondition,
                component.verification.clone(),
                component.restore.requires_elevation,
                None,
            )))
        }
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn add_artifact_operation(
    component: &Component,
    run_id: &RunId,
    diff: &crate::diff::ComponentDiff,
    artifact: &ArtifactRef,
    confirmation_keys: &BTreeMap<ComponentId, Vec<String>>,
    specs: &mut BTreeMap<String, OperationSpec>,
    manual_actions: &mut BTreeMap<String, ManualAction>,
    manual_operation_keys: &mut BTreeMap<String, String>,
    provider_operation_keys: &mut BTreeMap<ProviderId, String>,
) -> RestoreResult<Option<String>> {
    if matches!(
        artifact.policy,
        ArtifactPolicy::Manual | ArtifactPolicy::SecretReference
    ) || component.kind == ComponentKind::SecretReference
    {
        let action = artifact_manual_action(component, artifact)?;
        return add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        );
    }

    artifact.source_path.validate().map_err(|_| {
        planner_error(
            ReforgeErrorCode::InvalidPath,
            "selected artifact contains an invalid destination path",
        )
    })?;
    if matches!(
        artifact.source_path.root,
        KnownFolderToken::ProgramData
            | KnownFolderToken::ProgramFiles
            | KnownFolderToken::ProgramFilesX86
    ) {
        let action = artifact_manual_action(component, artifact)?;
        return add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        );
    }

    let Some(object) = artifact.object.clone() else {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "selected artifact has no content object",
        ));
    };

    let special = match component.kind {
        ComponentKind::WslDistribution
            if matches!(
                artifact.policy,
                ArtifactPolicy::LargeOptIn | ArtifactPolicy::Export
            ) =>
        {
            Some(OperationKind::ImportWsl {
                distro: WslSpec {
                    distribution: bounded_text(&component.display_name),
                    wsl_version: component
                        .version
                        .as_ref()
                        .and_then(|version| version.raw.parse::<u8>().ok()),
                },
                object: object.clone(),
            })
        }
        ComponentKind::DockerImage => Some(OperationKind::RestoreDockerImage {
            image: docker_image_spec(component),
            object: object.clone(),
        }),
        ComponentKind::DockerVolume => Some(OperationKind::RestoreDockerVolume {
            volume: DockerVolumeSpec {
                name: bounded_text(&component.display_name),
                driver: None,
            },
            object: object.clone(),
        }),
        _ => None,
    };

    if special.is_some() && diff.target_present {
        let action = artifact_manual_action(component, artifact)?;
        return add_manual_action_operation(
            action,
            component.id.clone(),
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        );
    }

    let (kind, phase, verification) = if let Some(kind) = special {
        (
            kind,
            OperationPhase::SubsystemRestore,
            subsystem_verification(component, artifact),
        )
    } else if matches!(artifact.policy, ArtifactPolicy::Config)
        && matches!(
            artifact.content_type,
            ContentType::Json | ContentType::Jsonc
        )
    {
        (
            OperationKind::MergeJson {
                destination: artifact.source_path.clone(),
                object: object.clone(),
                policy: if diff.target_present {
                    MergePolicy::ManualOnConflict
                } else {
                    MergePolicy::PreserveUnknown
                },
            },
            OperationPhase::FileRestore,
            artifact_verification(component, artifact, true, object.clone()),
        )
    } else if matches!(artifact.policy, ArtifactPolicy::Config)
        && artifact.content_type == ContentType::Toml
    {
        (
            OperationKind::MergeToml {
                destination: artifact.source_path.clone(),
                object: object.clone(),
                policy: if diff.target_present {
                    MergePolicy::ManualOnConflict
                } else {
                    MergePolicy::PreserveUnknown
                },
            },
            OperationPhase::FileRestore,
            artifact_verification(component, artifact, true, object.clone()),
        )
    } else {
        if diff.target_present
            && matches!(
                artifact.policy,
                ArtifactPolicy::Config
                    | ArtifactPolicy::Data
                    | ArtifactPolicy::Export
                    | ArtifactPolicy::PortableBinary
                    | ArtifactPolicy::LargeOptIn
            )
            && artifact.policy != ArtifactPolicy::Config
        {
            let action = artifact_manual_action(component, artifact)?;
            return add_manual_action_operation(
                action,
                component.id.clone(),
                run_id,
                specs,
                manual_actions,
                manual_operation_keys,
            );
        }
        (
            OperationKind::WriteFile {
                destination: artifact.source_path.clone(),
                object: object.clone(),
                mode: if diff.target_present {
                    FileMode::PreserveTarget
                } else {
                    FileMode::CreateOnly
                },
            },
            OperationPhase::FileRestore,
            artifact_verification(component, artifact, false, object.clone()),
        )
    };

    let mut spec = OperationSpec::new(
        component.id.clone(),
        kind.clone(),
        phase,
        Precondition::ArtifactPresent { object },
        verification,
        false,
        false,
    )?;
    add_confirmation_prerequisites(&mut spec, component, confirmation_keys);
    let key = insert_spec(specs, spec)?;

    if let Some(provider) = artifact_provider(component, &kind)? {
        let provider_key = ensure_provider(
            provider,
            component.id.clone(),
            specs,
            provider_operation_keys,
        )?;
        specs
            .get_mut(&key)
            .expect("artifact operation exists")
            .add_prerequisite(provider_key);
    }
    Ok(Some(key))
}

fn add_dependency_prerequisites(
    graph: &GraphIndex<'_>,
    selected: &BTreeSet<ComponentId>,
    readiness: &BTreeMap<ComponentId, Option<String>>,
    all_operations: &BTreeMap<ComponentId, Vec<String>>,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
    specs: &mut BTreeMap<String, OperationSpec>,
) -> RestoreResult<()> {
    let pairs = dependency_pairs(graph, selected, mcp_servers);
    for (source, dependency) in pairs {
        let Some(dependency_key) = readiness.get(&dependency).and_then(Clone::clone) else {
            continue;
        };
        let Some(source_operations) = all_operations.get(&source) else {
            continue;
        };
        for operation_key in source_operations {
            specs
                .get_mut(operation_key)
                .expect("component operation exists")
                .add_prerequisite(dependency_key.clone());
        }
    }
    Ok(())
}

fn add_verification_operations(
    graph: &GraphIndex<'_>,
    selected: &BTreeSet<ComponentId>,
    mutations: &BTreeMap<ComponentId, Vec<String>>,
    readiness: &BTreeMap<ComponentId, Option<String>>,
    all_operations: &mut BTreeMap<ComponentId, Vec<String>>,
    specs: &mut BTreeMap<String, OperationSpec>,
) -> RestoreResult<()> {
    for component_id in selected {
        let component = graph
            .components
            .get(component_id)
            .expect("selected component is indexed");
        let mut rules = component
            .verification
            .iter()
            .map(|rule| {
                let key = reforge_package::canonicalize(rule)
                    .map(|canonical| canonical.object_id().as_str().to_owned())
                    .map_err(|_| {
                        planner_error(
                            ReforgeErrorCode::SchemaInvalid,
                            "verification rule could not be canonicalized",
                        )
                    });
                key.map(|key| (key, rule.clone()))
            })
            .collect::<RestoreResult<Vec<_>>>()?;
        rules.sort_by(|left, right| left.0.cmp(&right.0));
        rules.dedup_by(|left, right| left.0 == right.0);

        for (_, rule) in rules {
            let mut spec = OperationSpec::new(
                component.id.clone(),
                OperationKind::Verify { rule },
                default_phase(&OperationKind::Verify {
                    rule: component
                        .verification
                        .first()
                        .cloned()
                        .expect("verification rule exists"),
                }),
                Precondition::Always,
                Vec::new(),
                false,
                false,
            )?;
            if let Some(component_mutations) = mutations.get(component_id) {
                for mutation in component_mutations {
                    spec.add_prerequisite(mutation.clone());
                }
            }
            if mutations.get(component_id).is_none_or(Vec::is_empty)
                && readiness.get(component_id).and_then(Clone::clone).is_some()
            {
                spec.add_prerequisite(
                    readiness
                        .get(component_id)
                        .and_then(Clone::clone)
                        .expect("readiness key exists"),
                );
            }
            let key = insert_spec(specs, spec)?;
            all_operations
                .entry(component_id.clone())
                .or_default()
                .push(key);
        }
    }
    Ok(())
}

fn dependency_pairs(
    graph: &GraphIndex<'_>,
    selected: &BTreeSet<ComponentId>,
    mcp_servers: &BTreeMap<ComponentId, McpServerSpec>,
) -> BTreeSet<(ComponentId, ComponentId)> {
    let mut pairs = BTreeSet::new();
    for source in selected {
        if let Some(edges) = graph.outgoing.get(source) {
            for edge in edges.iter().filter(|edge| {
                (edge.required || edge.kind == DependencyKind::RestoresBefore)
                    && edge.kind != DependencyKind::VerifiesWith
                    && selected.contains(&edge.to)
            }) {
                pairs.insert((source.clone(), edge.to.clone()));
            }
        }
        if let Some(runtime) = graph
            .components
            .get(source)
            .and_then(|component| component.compatibility.requires_runtime.clone())
            && selected.contains(&runtime)
        {
            pairs.insert((source.clone(), runtime));
        }
        if let Some(server) = mcp_servers.get(source) {
            if let Some(runtime) = &server.required_runtime
                && selected.contains(runtime)
            {
                pairs.insert((source.clone(), runtime.clone()));
            }
            if let Some(package) = &server.required_package
                && let Some(package_component) =
                    graph.components.iter().find_map(|(id, component)| {
                        component
                            .identity
                            .provider_package
                            .as_ref()
                            .filter(|(provider, package_id)| {
                                provider == &package.provider && package_id == &package.id
                            })
                            .map(|_| id.clone())
                    })
                && selected.contains(&package_component)
            {
                pairs.insert((source.clone(), package_component));
            }
        }
    }
    pairs
}

fn ensure_provider(
    provider: ProviderId,
    owner: ComponentId,
    specs: &mut BTreeMap<String, OperationSpec>,
    provider_operation_keys: &mut BTreeMap<ProviderId, String>,
) -> RestoreResult<String> {
    if let Some(key) = provider_operation_keys.get(&provider) {
        return Ok(key.clone());
    }
    let kind = OperationKind::EnsureProvider {
        provider: provider.clone(),
    };
    let spec = OperationSpec::new_shared(
        owner,
        "provider",
        kind,
        OperationPhase::ProviderBootstrap,
        Precondition::Always,
        Vec::new(),
        false,
        false,
    )?;
    let key = insert_spec(specs, spec)?;
    provider_operation_keys.insert(provider, key.clone());
    Ok(key)
}

fn insert_spec(
    specs: &mut BTreeMap<String, OperationSpec>,
    spec: OperationSpec,
) -> RestoreResult<String> {
    let key = spec.key.clone();
    if specs.insert(key.clone(), spec).is_some() {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "restore planner derived duplicate operation identity",
        ));
    }
    Ok(key)
}

fn add_manual_action_operation(
    mut action: ManualAction,
    owner: ComponentId,
    run_id: &RunId,
    specs: &mut BTreeMap<String, OperationSpec>,
    manual_actions: &mut BTreeMap<String, ManualAction>,
    manual_operation_keys: &mut BTreeMap<String, String>,
) -> RestoreResult<Option<String>> {
    action.id = format!("manual-action:{run_id}:{}", action.id);
    if let Some(existing) = manual_actions.get(&action.id)
        && existing != &action
    {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "restore planner derived conflicting manual actions",
        ));
    }
    manual_actions.insert(action.id.clone(), action.clone());
    if let Some(key) = manual_operation_keys.get(&action.id) {
        return Ok(Some(key.clone()));
    }
    let spec = OperationSpec::new(
        owner,
        OperationKind::OpenManualAction {
            action: action.clone(),
        },
        OperationPhase::Manual,
        Precondition::Always,
        action.verification.clone().into_iter().collect(),
        action.risk == RiskLevel::High || action.risk == RiskLevel::Critical,
        false,
    )?;
    let key = insert_spec(specs, spec)?;
    manual_operation_keys.insert(action.id, key.clone());
    Ok(Some(key))
}

fn add_confirmation_prerequisites(
    spec: &mut OperationSpec,
    component: &Component,
    confirmation_keys: &BTreeMap<ComponentId, Vec<String>>,
) {
    if let Some(keys) = confirmation_keys.get(&component.id) {
        for key in keys {
            spec.add_prerequisite(key.clone());
        }
    }
}

fn seed_compatibility_confirmations(
    compatibility: &CompatibilityResult,
    selected: &BTreeSet<ComponentId>,
    run_id: &RunId,
    specs: &mut BTreeMap<String, OperationSpec>,
    manual_actions: &mut BTreeMap<String, ManualAction>,
    manual_operation_keys: &mut BTreeMap<String, String>,
    confirmation_keys: &mut BTreeMap<ComponentId, Vec<String>>,
) -> RestoreResult<()> {
    let owner = selected.iter().next().cloned();
    for confirmation in &compatibility.confirmations {
        let action = ManualAction {
            id: format!(
                "compatibility-confirmation:{}",
                bounded_text(&confirmation.id)
            ),
            component: confirmation.component.clone(),
            title: "Confirm target compatibility".to_owned(),
            reason: bounded_text(&confirmation.reason),
            risk: confirmation.risk.clone(),
            instructions: vec![
                "Review the target compatibility warning before restore".to_owned(),
                "Continue only after confirming the target can accept this change".to_owned(),
            ],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: false,
            acknowledged_at: None,
            verification: None,
        };
        let action_owner = confirmation
            .component
            .clone()
            .or_else(|| owner.clone())
            .ok_or_else(|| {
                planner_error(
                    ReforgeErrorCode::SelectionIncomplete,
                    "a global compatibility confirmation has no selected component owner",
                )
            })?;
        let key = add_manual_action_operation(
            action,
            action_owner,
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        )?;
        if let Some(key) = key {
            if let Some(component) = &confirmation.component {
                confirmation_keys
                    .entry(component.clone())
                    .or_default()
                    .push(key);
            } else {
                for component in selected {
                    confirmation_keys
                        .entry(component.clone())
                        .or_default()
                        .push(key.clone());
                }
            }
        }
    }
    Ok(())
}

fn seed_conflict_confirmations(
    target_diff: &TargetDiff,
    selected: &BTreeSet<ComponentId>,
    run_id: &RunId,
    specs: &mut BTreeMap<String, OperationSpec>,
    manual_actions: &mut BTreeMap<String, ManualAction>,
    manual_operation_keys: &mut BTreeMap<String, String>,
    confirmation_keys: &mut BTreeMap<ComponentId, Vec<String>>,
) -> RestoreResult<()> {
    let owner = selected.iter().next().cloned();
    for conflict in relevant_conflicts(&target_diff.conflicts, selected) {
        if !conflict.requires_confirmation && conflict.resolution != ConflictResolution::Manual {
            continue;
        }
        let action = conflict_manual_action(&conflict);
        let action_owner = conflict
            .component
            .clone()
            .or_else(|| owner.clone())
            .ok_or_else(|| {
                planner_error(
                    ReforgeErrorCode::SelectionIncomplete,
                    "a global conflict confirmation has no selected component owner",
                )
            })?;
        let key = add_manual_action_operation(
            action,
            action_owner,
            run_id,
            specs,
            manual_actions,
            manual_operation_keys,
        )?;
        if let Some(key) = key {
            if let Some(component) = conflict.component {
                confirmation_keys.entry(component).or_default().push(key);
            } else {
                for component in selected {
                    confirmation_keys
                        .entry(component.clone())
                        .or_default()
                        .push(key.clone());
                }
            }
        }
    }
    for keys in confirmation_keys.values_mut() {
        keys.sort();
        keys.dedup();
    }
    Ok(())
}

fn component_manual_action(component: &Component, suffix: &str) -> RestoreResult<ManualAction> {
    let reason = if component.restore.rationale.is_empty() {
        "The component has no reviewed automatic restore contract".to_owned()
    } else {
        component
            .restore
            .rationale
            .iter()
            .map(|reason| bounded_text(reason))
            .collect::<Vec<_>>()
            .join("; ")
    };
    Ok(ManualAction {
        id: format!("component-manual:{}:{suffix}", component.id),
        component: Some(component.id.clone()),
        title: format!("Review {} restore", bounded_text(&component.display_name)),
        reason,
        risk: component_risk(component),
        instructions: vec![
            "Review the component source, target scope, and portability evidence".to_owned(),
            "Do not execute command text or scripts from package metadata".to_owned(),
            "Complete the restore through the documented application or provider path".to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: component.verification.first().cloned(),
    })
}

fn artifact_manual_action(
    component: &Component,
    artifact: &ArtifactRef,
) -> RestoreResult<ManualAction> {
    Ok(ManualAction {
        id: format!("artifact-manual:{}:{}", component.id, artifact.id),
        component: Some(component.id.clone()),
        title: "Review artifact restore".to_owned(),
        reason: if artifact.policy == ArtifactPolicy::SecretReference {
            "The artifact is secret-bearing and requires an approved secure target".to_owned()
        } else {
            "The artifact cannot be restored automatically without risking target data or an unreviewed privileged write".to_owned()
        },
        risk: if artifact.policy == ArtifactPolicy::SecretReference {
            RiskLevel::Critical
        } else {
            RiskLevel::High
        },
        instructions: vec![
            format!(
                "Review the tokenized destination {}",
                path_display(&artifact.source_path)
            ),
            "Confirm backup and collision handling before changing the target".to_owned(),
            "Use a documented application import or secure credential target when required"
                .to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    })
}

fn conflict_manual_action(conflict: &Conflict) -> ManualAction {
    ManualAction {
        id: format!("conflict-confirmation:{}", bounded_text(&conflict.id)),
        component: conflict.component.clone(),
        title: format!("Review {} conflict", conflict_kind_label(&conflict.kind)),
        reason: format!(
            "{} requires explicit target confirmation before restore",
            conflict_kind_label(&conflict.kind)
        ),
        risk: conflict_risk(&conflict.kind),
        instructions: vec![
            "Review the source and target state in the conflict preview".to_owned(),
            "Confirm the selected merge, install, preserve, or manual decision".to_owned(),
            "Verify that the target backup requirement is satisfied before continuing".to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

fn provider_identity(component: &Component) -> RestoreResult<Option<PackageSpec>> {
    let verification_packages: Vec<_> = component
        .verification
        .iter()
        .filter_map(|rule| match rule {
            VerificationRule::ProviderIdentity { package, .. } => Some(package.clone()),
            _ => None,
        })
        .collect();
    if verification_packages.len() > 1 {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "component contains multiple provider package identities",
        ));
    }

    let typed_identity = component.identity.provider_package.clone().or_else(|| {
        component.provenance.as_ref().and_then(|provenance| {
            provenance
                .provider
                .clone()
                .zip(provenance.package_id.clone())
        })
    });
    let Some((provider, package_id)) = typed_identity else {
        return Ok(verification_packages.into_iter().next());
    };
    if let Some(package) = verification_packages.first()
        && (package.provider != provider || package.id != package_id)
    {
        return Err(planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "component provider identity conflicts with its verification rule",
        ));
    }

    let version = component
        .version
        .as_ref()
        .map(|version| bounded_text(&version.raw))
        .filter(|version| !version.is_empty());
    let provenance = component.provenance.as_ref();
    Ok(Some(PackageSpec {
        provider,
        id: bounded_text(&package_id),
        version,
        source_name: component.identity.provider_source.clone(),
        source_identifier: None,
        source: provenance.and_then(|provenance| provenance.source_url.clone()),
        architecture: component.architecture.clone(),
        installer_hash: None,
    }))
}

fn artifact_verification(
    component: &Component,
    artifact: &ArtifactRef,
    merge: bool,
    object: reforge_domain::ObjectId,
) -> Vec<VerificationRule> {
    if let Some(rule) = component.verification.iter().find(|rule| match rule {
        VerificationRule::File { destination, .. }
        | VerificationRule::FileVersion { destination, .. }
        | VerificationRule::ConfigParses { destination, .. } => {
            destination == &artifact.source_path
        }
        _ => false,
    }) {
        return vec![rule.clone()];
    }
    if merge {
        vec![VerificationRule::ConfigParses {
            destination: artifact.source_path.clone(),
            content_type: artifact.content_type.clone(),
        }]
    } else {
        vec![VerificationRule::File {
            destination: artifact.source_path.clone(),
            object: Some(object),
        }]
    }
}

fn subsystem_verification(component: &Component, artifact: &ArtifactRef) -> Vec<VerificationRule> {
    let rules: Vec<_> = component
        .verification
        .iter()
        .filter(|rule| {
            matches!(
                rule,
                VerificationRule::WslState { .. } | VerificationRule::DockerObject { .. }
            )
        })
        .cloned()
        .collect();
    if rules.is_empty() {
        vec![VerificationRule::File {
            destination: artifact.source_path.clone(),
            object: artifact.object.clone(),
        }]
    } else {
        rules
    }
}

fn artifact_provider(
    component: &Component,
    kind: &OperationKind,
) -> RestoreResult<Option<ProviderId>> {
    if let OperationKind::InstallPackage { provider, .. } = kind {
        return Ok(Some(provider.clone()));
    }
    if matches!(
        kind,
        OperationKind::ImportWsl { .. }
            | OperationKind::RestoreDockerImage { .. }
            | OperationKind::RestoreDockerVolume { .. }
    ) {
        return if matches!(kind, OperationKind::ImportWsl { .. }) {
            Ok(Some(provider_id("wsl")?))
        } else {
            Ok(Some(provider_id("docker")?))
        };
    }
    if let Some(provider) = &component.compatibility.requires_provider {
        return Ok(Some(provider.clone()));
    }
    if component.compatibility.requires_wsl {
        return Ok(Some(provider_id("wsl")?));
    }
    if component.compatibility.requires_docker {
        return Ok(Some(provider_id("docker")?));
    }
    Ok(None)
}

fn docker_image_spec(component: &Component) -> DockerImageSpec {
    let identity = component
        .identity
        .provider_package
        .as_ref()
        .map(|(_, package)| package.as_str())
        .unwrap_or(component.display_name.as_str());
    let value = identity.strip_prefix("image:").unwrap_or(identity);
    let image_id = value.strip_prefix("sha256:").map(|_| bounded_text(value));
    // Docker discovery keys an image by immutable ID when present, while the
    // component display name retains its source repository and tag.
    let reference = image_id
        .as_ref()
        .map_or(value, |_| component.display_name.as_str());
    let (repository, tag) = split_docker_image_reference(reference);
    DockerImageSpec {
        repository,
        tag,
        image_id,
    }
}

fn split_docker_image_reference(reference: &str) -> (String, Option<String>) {
    let reference = bounded_text(reference);
    let path_start = reference.rfind('/').map_or(0, |position| position + 1);
    let Some(separator) = reference
        .rfind(':')
        .filter(|position| *position >= path_start)
    else {
        return (reference, None);
    };
    (
        bounded_text(&reference[..separator]),
        Some(bounded_text(&reference[separator + 1..])),
    )
}

fn component_diff<'a>(
    target_diff: &'a TargetDiff,
    id: &ComponentId,
) -> Option<&'a crate::diff::ComponentDiff> {
    target_diff
        .components
        .iter()
        .find(|diff| &diff.component == id)
}

fn relevant_conflicts(conflicts: &[Conflict], selected: &BTreeSet<ComponentId>) -> Vec<Conflict> {
    let mut relevant: Vec<_> = conflicts
        .iter()
        .filter(|conflict| {
            conflict
                .component
                .as_ref()
                .is_none_or(|component| selected.contains(component))
        })
        .cloned()
        .collect();
    relevant.sort_by(|left, right| left.id.cmp(&right.id));
    relevant
}

fn normalize_warnings(mut warnings: Vec<String>) -> RestoreResult<Vec<String>> {
    warnings.retain(|warning| !warning.trim().is_empty());
    warnings = warnings
        .into_iter()
        .map(|warning| bounded_text(&warning))
        .collect();
    warnings.sort();
    warnings.dedup();
    if warnings.len() > MAX_PLAN_WARNINGS {
        return Err(planner_error(
            ReforgeErrorCode::SecurityPolicy,
            "restore plan produces too many warnings",
        ));
    }
    Ok(warnings)
}

fn dependency_kind_key(kind: &DependencyKind) -> &'static str {
    match kind {
        DependencyKind::RequiredRuntime => "required_runtime",
        DependencyKind::RequiredPackage => "required_package",
        DependencyKind::InstalledThrough => "installed_through",
        DependencyKind::Configures => "configures",
        DependencyKind::UsesSecret => "uses_secret",
        DependencyKind::OptionalFeature => "optional_feature",
        DependencyKind::ProvidesExecutable => "provides_executable",
        DependencyKind::Contains => "contains",
        DependencyKind::RestoresBefore => "restores_before",
        DependencyKind::VerifiesWith => "verifies_with",
        DependencyKind::RelatedOnly => "related_only",
    }
}

fn risk_for_component(component: &Component) -> RiskLevel {
    match component.kind {
        ComponentKind::SecretReference => RiskLevel::Critical,
        ComponentKind::SystemFeature
        | ComponentKind::Service
        | ComponentKind::ScheduledTask
        | ComponentKind::PortableBinary => RiskLevel::High,
        _ => RiskLevel::Medium,
    }
}

fn component_risk(component: &Component) -> RiskLevel {
    if component.restore.requires_elevation || component.compatibility.requires_elevation {
        RiskLevel::High
    } else {
        risk_for_component(component)
    }
}

fn conflict_risk(kind: &ConflictKind) -> RiskLevel {
    match kind {
        ConflictKind::SecretCollision => RiskLevel::Critical,
        ConflictKind::DataCollision
        | ConflictKind::PortCollision
        | ConflictKind::ArchitectureConflict
        | ConflictKind::UnsupportedTarget => RiskLevel::High,
        _ => RiskLevel::Medium,
    }
}

fn conflict_kind_label(kind: &ConflictKind) -> &'static str {
    match kind {
        ConflictKind::AlreadySatisfied => "already satisfied",
        ConflictKind::VersionDifference => "version",
        ConflictKind::ConfigDifference => "configuration",
        ConflictKind::DataCollision => "data",
        ConflictKind::SecretCollision => "secret",
        ConflictKind::PathCollision => "PATH",
        ConflictKind::PortCollision => "port",
        ConflictKind::DependencyConflict => "dependency",
        ConflictKind::ArchitectureConflict => "architecture",
        ConflictKind::UnsupportedTarget => "unsupported target",
    }
}

fn path_display(path: &PathToken) -> String {
    format!("{:?}/{}", path.root, path.relative)
}

fn bounded_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_MANUAL_TEXT_BYTES));
    for character in value.chars() {
        if output.len() >= MAX_MANUAL_TEXT_BYTES {
            break;
        }
        output.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    output.trim().to_owned()
}

fn provider_id(value: &str) -> RestoreResult<ProviderId> {
    ProviderId::new(value).map_err(|_| {
        planner_error(
            ReforgeErrorCode::SchemaInvalid,
            "planner could not construct a built-in provider identifier",
        )
    })
}

fn planner_error(
    code: ReforgeErrorCode,
    message: impl Into<String>,
) -> Box<reforge_domain::ErrorEnvelope> {
    restore_error(code, message, None, None, None, None)
}
