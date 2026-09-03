//! Verification of selected restore components from target facts and journaled evidence.
//!
//! The verifier is deliberately fail-closed.  A component is reported even when
//! its definition or operation evidence is missing, and a terminal operation
//! failure always wins over a matching success observation.  Values crossing
//! the report boundary are redacted before the report is returned.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use reforge_domain::{
    Component, ComponentId, ComponentKind, ComponentReport, ConfigScope, ContentType,
    ErrorEnvelope, InstalledFact, ManualAction, ManualActionState, ObjectId, OperationId,
    OperationKind, OperationState, PackageGraph, PackageSpec, PathToken, ReportCounts,
    ReportStatus, RestoreDescriptor, RestorePlan, RestoreReport, RestoreStrategy, SafeValueRef,
    TargetFacts, VerificationEvidence, VerificationRule, VersionValue, redaction::RedactionPolicy,
};
use serde_json::Value;

use crate::{RestoreResult, journal::JournalOperation, restore_error};

/// The canonical report format version emitted by this verifier.
pub const REPORT_FORMAT_VERSION: u16 = 1;

/// Inputs required to build a final restore report.
///
/// `components` is the complete package graph, while `selected_components`
/// identifies the exact closure being reported.  Keeping those collections
/// separate lets the verifier emit a failure for a selected ID that is absent
/// from a malformed graph instead of silently dropping it.
pub struct VerificationInput<'a> {
    pub target: &'a TargetFacts,
    pub operations: &'a [JournalOperation],
    pub components: &'a [Component],
    pub selected_components: &'a [ComponentId],
    pub manual_actions: &'a [ManualAction],
    pub warnings: &'a [String],
    pub run_id: reforge_domain::RunId,
    pub package_id: String,
    pub elapsed_ms: u64,
    pub bytes_written: u64,
}

impl<'a> VerificationInput<'a> {
    /// Construct a report request with no additional actions or warnings.
    pub fn new(
        target: &'a TargetFacts,
        operations: &'a [JournalOperation],
        components: &'a [Component],
        selected_components: &'a [ComponentId],
        run_id: reforge_domain::RunId,
        package_id: impl Into<String>,
    ) -> Self {
        Self {
            target,
            operations,
            components,
            selected_components,
            manual_actions: &[],
            warnings: &[],
            run_id,
            package_id: package_id.into(),
            elapsed_ms: 0,
            bytes_written: 0,
        }
    }

    /// Build inputs directly from an approved plan and its package graph.
    pub fn from_plan(
        target: &'a TargetFacts,
        plan: &'a RestorePlan,
        graph: &'a PackageGraph,
        operations: &'a [JournalOperation],
    ) -> Self {
        Self {
            target,
            operations,
            components: &graph.components,
            selected_components: &plan.selected_components,
            manual_actions: &plan.manual_actions,
            warnings: &plan.warnings,
            run_id: plan.run_id.clone(),
            package_id: plan.package_id.clone(),
            elapsed_ms: 0,
            bytes_written: 0,
        }
    }

    /// Include the plan's manual-action queue in the report.
    pub fn with_manual_actions(mut self, actions: &'a [ManualAction]) -> Self {
        self.manual_actions = actions;
        self
    }

    /// Include bounded caller warnings in the report.
    pub fn with_warnings(mut self, warnings: &'a [String]) -> Self {
        self.warnings = warnings;
        self
    }

    /// Attach executor metrics to the report.
    pub fn with_metrics(mut self, elapsed_ms: u64, bytes_written: u64) -> Self {
        self.elapsed_ms = elapsed_ms;
        self.bytes_written = bytes_written;
        self
    }
}

/// Stateless verification engine for final restore reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerificationEngine;

impl VerificationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Verify every selected component and return a redacted report.
    pub fn verify(&self, input: &VerificationInput<'_>) -> RestoreResult<RestoreReport> {
        build_report(input)
    }

    /// Descriptive alias for callers that prefer report-oriented naming.
    pub fn build_report(&self, input: &VerificationInput<'_>) -> RestoreResult<RestoreReport> {
        self.verify(input)
    }

    /// Verify an execution result against a plan and package graph.
    pub fn verify_plan(
        &self,
        target: &TargetFacts,
        plan: &RestorePlan,
        graph: &PackageGraph,
        operations: &[JournalOperation],
    ) -> RestoreResult<RestoreReport> {
        let input = VerificationInput::from_plan(target, plan, graph, operations);
        self.verify(&input)
    }
}

/// Convenience entry point for one-shot report construction.
pub fn verify_restore(input: &VerificationInput<'_>) -> RestoreResult<RestoreReport> {
    VerificationEngine::new().verify(input)
}

fn build_report(input: &VerificationInput<'_>) -> RestoreResult<RestoreReport> {
    let component_index = index_components(input.components)?;
    let selected = unique_selected_components(input.selected_components)?;
    let mut reports = Vec::with_capacity(selected.len());

    for component_id in input.selected_components {
        let report = match component_index.get(component_id) {
            Some(component) => build_component_report(
                component,
                input,
                input
                    .operations
                    .iter()
                    .filter(|operation| operation.operation.component == *component_id)
                    .collect(),
                input
                    .manual_actions
                    .iter()
                    .filter(|action| action.component.as_ref() == Some(component_id))
                    .collect(),
            )?,
            None => missing_component_report(component_id),
        };
        reports.push(report);
    }

    let mut warnings = input.warnings.to_vec();
    if input.selected_components.is_empty() {
        warnings.push("UNVERIFIED: no components were selected for restore".to_owned());
    }
    for component_id in input.selected_components {
        if !component_index.contains_key(component_id) {
            warnings.push(format!(
                "UNVERIFIED: selected component {component_id} is missing from the package graph"
            ));
        }
    }

    // The selected set is the report boundary.  Operations outside it may be
    // dependency work or caller-owned data, so they are not allowed to create
    // a phantom component report or alter selected-component status.
    let status = aggregate_statuses(reports.iter().map(|report| &report.status))
        .unwrap_or(ReportStatus::Failed);
    let counts = report_counts(&reports);
    let report = RestoreReport {
        format_version: REPORT_FORMAT_VERSION,
        run_id: input.run_id.clone(),
        package_id: input.package_id.clone(),
        status,
        counts,
        components: reports
            .into_iter()
            .map(|report| ComponentReport {
                component: report.component,
                status: report.status,
                evidence: report.evidence,
                manual_actions: report.manual_actions,
                warnings: report.warnings,
            })
            .collect(),
        manual_actions: input.manual_actions.to_vec(),
        warnings,
        elapsed_ms: input.elapsed_ms,
        bytes_written: input.bytes_written,
    };

    Ok(redact_restore_report(report))
}

fn index_components(components: &[Component]) -> RestoreResult<BTreeMap<ComponentId, &Component>> {
    let mut index = BTreeMap::new();
    for component in components {
        if let Some(previous) = index.insert(component.id.clone(), component)
            && previous != component
        {
            return Err(schema_error(
                "package graph contains conflicting definitions for one component",
            ));
        }
    }
    Ok(index)
}

fn unique_selected_components(selected: &[ComponentId]) -> RestoreResult<BTreeSet<ComponentId>> {
    let mut unique = BTreeSet::new();
    for component in selected {
        if !unique.insert(component.clone()) {
            return Err(schema_error(
                "restore report selection contains duplicate component IDs",
            ));
        }
    }
    Ok(unique)
}

fn missing_component_report(component: &ComponentId) -> ComponentReportParts {
    ComponentReportParts {
        component: component.clone(),
        status: ReportStatus::Failed,
        evidence: Vec::new(),
        manual_actions: Vec::new(),
        warnings: vec![
            "UNVERIFIED: selected component has no package definition or verification rule"
                .to_owned(),
        ],
    }
}

struct ComponentReportParts {
    component: ComponentId,
    status: ReportStatus,
    evidence: Vec<VerificationEvidence>,
    manual_actions: Vec<String>,
    warnings: Vec<String>,
}

fn build_component_report(
    component: &Component,
    input: &VerificationInput<'_>,
    operations: Vec<&JournalOperation>,
    actions: Vec<&ManualAction>,
) -> RestoreResult<ComponentReportParts> {
    let mut rules = component.verification.clone();
    for action in &actions {
        if let Some(rule) = &action.verification {
            push_unique_rule(&mut rules, rule.clone());
        }
    }
    for operation in &operations {
        for rule in &operation.operation.verification {
            push_unique_rule(&mut rules, rule.clone());
        }
        if let OperationKind::Verify { rule } = &operation.operation.kind {
            push_unique_rule(&mut rules, rule.clone());
        }
    }

    let manual_action_ids = actions
        .iter()
        .map(|action| action.id.clone())
        .collect::<Vec<_>>();
    let lifecycle = operation_lifecycle(&operations);
    let manual_lifecycle = manual_action_lifecycle(&actions);
    let mut evidence = Vec::with_capacity(rules.len());
    let mut warnings = Vec::new();

    if rules.is_empty() {
        warnings.push("UNVERIFIED: selected component has no verification rule".to_owned());
    } else {
        for rule in &rules {
            validate_rule_shape(rule)?;
            let evaluation = evaluate_rule(
                rule,
                component,
                input.target,
                &operations,
                &actions,
                lifecycle,
            );
            if matches!(
                evaluation.status,
                ReportStatus::Failed
                    | ReportStatus::Unsupported
                    | ReportStatus::WaitingForUser
                    | ReportStatus::ReauthRequired
                    | ReportStatus::RebootRequired
            ) {
                push_unique_warning(&mut warnings, evaluation.summary.clone());
            }
            evidence.push(VerificationEvidence {
                rule: rule.clone(),
                status: evaluation.status,
                summary: evaluation.summary,
                observed_at: evaluation.observed_at,
            });
        }
    }

    let status = if rules.is_empty() {
        ReportStatus::Failed
    } else {
        let rule_status = aggregate_statuses(evidence.iter().map(|entry| &entry.status))
            .unwrap_or(ReportStatus::Failed);
        combine_component_status(rule_status, lifecycle, manual_lifecycle)
    };

    if matches!(status, ReportStatus::Failed | ReportStatus::Unsupported) && warnings.is_empty() {
        warnings.push("UNVERIFIED: component was not fully proven".to_owned());
    }

    ComponentReportParts {
        component: component.id.clone(),
        status,
        evidence,
        manual_actions: manual_action_ids,
        warnings,
    }
    .into_result()
}

impl ComponentReportParts {
    fn into_result(self) -> RestoreResult<Self> {
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleStatus {
    Failed,
    ReauthRequired,
    RebootRequired,
    WaitingForUser,
    Skipped,
}

fn operation_lifecycle(operations: &[&JournalOperation]) -> Option<LifecycleStatus> {
    let by_id = operations
        .iter()
        .map(|operation| (operation.id.clone(), *operation))
        .collect::<BTreeMap<_, _>>();
    let mut blocked_cache = BTreeMap::<OperationId, Option<LifecycleStatus>>::new();
    let mut visiting = BTreeSet::new();
    let mut has_reauth = false;
    let mut has_reboot = false;
    let mut has_waiting = false;
    let mut has_skipped = false;
    let mut has_incomplete = false;

    for operation in operations {
        match operation.state {
            OperationState::Failed | OperationState::Interrupted | OperationState::Cancelled => {
                return Some(LifecycleStatus::Failed);
            }
            OperationState::Pending | OperationState::Running => {
                match blocked_by_unresolved_prerequisite(
                    operation,
                    &by_id,
                    &mut blocked_cache,
                    &mut visiting,
                ) {
                    Some(LifecycleStatus::Failed) => return Some(LifecycleStatus::Failed),
                    Some(LifecycleStatus::ReauthRequired) => has_reauth = true,
                    Some(LifecycleStatus::RebootRequired) => has_reboot = true,
                    Some(LifecycleStatus::WaitingForUser) => has_waiting = true,
                    Some(LifecycleStatus::Skipped) | None => has_incomplete = true,
                }
            }
            OperationState::WaitingForReboot => has_reboot = true,
            OperationState::WaitingForUser => {
                if operation_requires_reauth(operation) {
                    has_reauth = true;
                } else {
                    has_waiting = true;
                }
            }
            OperationState::Skipped => has_skipped = true,
            OperationState::Completed => {}
        }
    }

    if has_incomplete {
        Some(LifecycleStatus::Failed)
    } else if has_reauth {
        Some(LifecycleStatus::ReauthRequired)
    } else if has_reboot {
        Some(LifecycleStatus::RebootRequired)
    } else if has_waiting {
        Some(LifecycleStatus::WaitingForUser)
    } else if has_skipped
        && operations
            .iter()
            .all(|operation| matches!(operation.state, OperationState::Skipped))
    {
        Some(LifecycleStatus::Skipped)
    } else {
        None
    }
}

fn blocked_by_unresolved_prerequisite(
    operation: &JournalOperation,
    by_id: &BTreeMap<OperationId, &JournalOperation>,
    cache: &mut BTreeMap<OperationId, Option<LifecycleStatus>>,
    visiting: &mut BTreeSet<OperationId>,
) -> Option<LifecycleStatus> {
    if let Some(status) = cache.get(&operation.id) {
        return *status;
    }
    if !visiting.insert(operation.id.clone()) {
        // A planner cycle is invalid; fail closed rather than classifying it
        // as user work that can be resumed safely.
        return Some(LifecycleStatus::Failed);
    }

    let status = operation
        .operation
        .prerequisites
        .iter()
        .find_map(|prerequisite| {
            let prerequisite = by_id.get(prerequisite)?;
            match prerequisite.state {
                OperationState::Failed
                | OperationState::Interrupted
                | OperationState::Cancelled => Some(LifecycleStatus::Failed),
                OperationState::WaitingForReboot => Some(LifecycleStatus::RebootRequired),
                OperationState::WaitingForUser => {
                    Some(if operation_requires_reauth(prerequisite) {
                        LifecycleStatus::ReauthRequired
                    } else {
                        LifecycleStatus::WaitingForUser
                    })
                }
                OperationState::Pending | OperationState::Running => {
                    blocked_by_unresolved_prerequisite(prerequisite, by_id, cache, visiting)
                }
                OperationState::Completed | OperationState::Skipped => None,
            }
        });
    visiting.remove(&operation.id);
    cache.insert(operation.id.clone(), status);
    status
}

fn manual_action_lifecycle(actions: &[&ManualAction]) -> Option<LifecycleStatus> {
    let mut has_reauth = false;
    let mut has_waiting = false;
    let mut has_skipped = false;
    for action in actions {
        match action.state {
            ManualActionState::Pending | ManualActionState::Acknowledged => {
                if action
                    .verification
                    .as_ref()
                    .is_some_and(rule_requires_reauth)
                {
                    has_reauth = true;
                } else {
                    has_waiting = true;
                }
            }
            ManualActionState::Skipped => has_skipped = true,
            ManualActionState::Completed => {}
        }
    }
    if has_reauth {
        Some(LifecycleStatus::ReauthRequired)
    } else if has_waiting {
        Some(LifecycleStatus::WaitingForUser)
    } else if has_skipped {
        Some(LifecycleStatus::Skipped)
    } else {
        None
    }
}

fn combine_component_status(
    rule_status: ReportStatus,
    lifecycle: Option<LifecycleStatus>,
    manual_lifecycle: Option<LifecycleStatus>,
) -> ReportStatus {
    if matches!(rule_status, ReportStatus::Failed) {
        return ReportStatus::Failed;
    }

    let lifecycle =
        [lifecycle, manual_lifecycle]
            .into_iter()
            .flatten()
            .fold(None, |current, next| {
                Some(match (current, next) {
                    (Some(LifecycleStatus::Failed), _) | (_, LifecycleStatus::Failed) => {
                        LifecycleStatus::Failed
                    }
                    (Some(LifecycleStatus::ReauthRequired), _)
                    | (_, LifecycleStatus::ReauthRequired) => LifecycleStatus::ReauthRequired,
                    (Some(LifecycleStatus::RebootRequired), _)
                    | (_, LifecycleStatus::RebootRequired) => LifecycleStatus::RebootRequired,
                    (Some(LifecycleStatus::WaitingForUser), _)
                    | (_, LifecycleStatus::WaitingForUser) => LifecycleStatus::WaitingForUser,
                    (Some(LifecycleStatus::Skipped), _) | (_, LifecycleStatus::Skipped) => {
                        LifecycleStatus::Skipped
                    }
                })
            });

    match lifecycle {
        Some(LifecycleStatus::Failed) => ReportStatus::Failed,
        Some(LifecycleStatus::ReauthRequired) => ReportStatus::ReauthRequired,
        Some(LifecycleStatus::RebootRequired) => ReportStatus::RebootRequired,
        Some(LifecycleStatus::WaitingForUser) => ReportStatus::WaitingForUser,
        Some(LifecycleStatus::Skipped) if matches!(rule_status, ReportStatus::AlreadyPresent) => {
            ReportStatus::AlreadyPresent
        }
        Some(LifecycleStatus::Skipped) if matches!(rule_status, ReportStatus::Verified) => {
            ReportStatus::PartiallyVerified
        }
        Some(LifecycleStatus::Skipped) => ReportStatus::Skipped,
        None => rule_status,
    }
}

struct RuleEvaluation {
    status: ReportStatus,
    summary: String,
    observed_at: DateTime<Utc>,
}

fn evaluate_rule(
    rule: &VerificationRule,
    component: &Component,
    target: &TargetFacts,
    operations: &[&JournalOperation],
    actions: &[&ManualAction],
    lifecycle: Option<LifecycleStatus>,
) -> RuleEvaluation {
    let relevant = relevant_operations(rule, operations);
    let observed_at = observed_at(&relevant);

    // A failed operation is never hidden by an independently matching target
    // fact or by a successful sibling operation.
    if matches!(lifecycle, Some(LifecycleStatus::Failed)) {
        return failed_evaluation(
            observed_at,
            "UNVERIFIED: a selected component operation failed or did not reach a terminal state",
        );
    }

    for operation in &relevant {
        match operation.state {
            OperationState::WaitingForUser => {
                return RuleEvaluation {
                    status: if operation_requires_reauth(operation) {
                        ReportStatus::ReauthRequired
                    } else {
                        ReportStatus::WaitingForUser
                    },
                    summary: if operation_requires_reauth(operation) {
                        "UNVERIFIED: reauthentication or secret binding is required".to_owned()
                    } else {
                        "UNVERIFIED: user action is required before verification can finish"
                            .to_owned()
                    },
                    observed_at,
                };
            }
            OperationState::WaitingForReboot => {
                return RuleEvaluation {
                    status: ReportStatus::RebootRequired,
                    summary: "UNVERIFIED: reboot is required before verification can finish"
                        .to_owned(),
                    observed_at,
                };
            }
            OperationState::Pending | OperationState::Running => {
                return failed_evaluation(
                    observed_at,
                    "UNVERIFIED: operation did not reach a terminal state",
                );
            }
            OperationState::Failed | OperationState::Interrupted | OperationState::Cancelled => {
                return failed_evaluation(observed_at, "UNVERIFIED: operation failed");
            }
            OperationState::Completed | OperationState::Skipped => {}
        }
    }

    if let Some(operation) = relevant.iter().find(|operation| {
        matches!(
            operation.state,
            OperationState::Completed | OperationState::Skipped
        ) && operation_proves(rule, operation)
    }) {
        let already_present = operation.state == OperationState::Skipped;
        return RuleEvaluation {
            status: if already_present {
                ReportStatus::AlreadyPresent
            } else {
                ReportStatus::Verified
            },
            summary: verified_summary(rule, already_present),
            observed_at: operation
                .ended_at
                .or(operation.started_at)
                .unwrap_or(observed_at),
        };
    }

    // A target fact proves only fact categories that the target scanner owns.
    // File/config/browser checks require operation evidence because TargetFacts
    // intentionally does not contain arbitrary filesystem state.
    if relevant.is_empty() && target_satisfies(rule, target) {
        return RuleEvaluation {
            status: ReportStatus::AlreadyPresent,
            summary: already_present_summary(rule),
            observed_at,
        };
    }

    let pending_manual_action = actions.iter().any(|action| {
        action
            .verification
            .as_ref()
            .is_some_and(|candidate| candidate == rule)
            && matches!(
                action.state,
                ManualActionState::Pending | ManualActionState::Acknowledged
            )
    });
    if rule_requires_reauth(rule) {
        return RuleEvaluation {
            status: ReportStatus::ReauthRequired,
            summary: "UNVERIFIED: secure target proof or secret binding is required".to_owned(),
            observed_at,
        };
    }
    if pending_manual_action {
        return RuleEvaluation {
            status: ReportStatus::WaitingForUser,
            summary: "UNVERIFIED: user action is required before verification can finish"
                .to_owned(),
            observed_at,
        };
    }

    if relevant.is_empty() && unsupported_restore(&component.restore) {
        return RuleEvaluation {
            status: ReportStatus::Unsupported,
            summary: "UNVERIFIED: no automatic restore operation supports this verification rule"
                .to_owned(),
            observed_at,
        };
    }

    failed_evaluation(
        observed_at,
        if relevant.is_empty() {
            "UNVERIFIED: no matching verification evidence was recorded"
        } else {
            "UNVERIFIED: recorded evidence did not prove the requested rule"
        },
    )
}

fn failed_evaluation(observed_at: DateTime<Utc>, summary: &str) -> RuleEvaluation {
    RuleEvaluation {
        status: ReportStatus::Failed,
        summary: summary.to_owned(),
        observed_at,
    }
}

fn observed_at(operations: &[&JournalOperation]) -> DateTime<Utc> {
    operations
        .iter()
        .filter_map(|operation| operation.ended_at.or(operation.started_at))
        .max()
        .unwrap_or_else(Utc::now)
}

fn relevant_operations<'a>(
    rule: &VerificationRule,
    operations: &[&'a JournalOperation],
) -> Vec<&'a JournalOperation> {
    operations
        .iter()
        .copied()
        .filter(|operation| operation_matches_rule(operation, rule))
        .collect()
}

fn operation_matches_rule(operation: &JournalOperation, rule: &VerificationRule) -> bool {
    if operation
        .operation
        .verification
        .iter()
        .any(|candidate| candidate == rule)
    {
        return true;
    }
    if let OperationKind::Verify { rule: candidate } = &operation.operation.kind
        && candidate == rule
    {
        return true;
    }

    match rule {
        VerificationRule::ProviderIdentity { provider, package } => {
            matches!(
                &operation.operation.kind,
                OperationKind::InstallPackage {
                    provider: operation_provider,
                    package: operation_package,
                    ..
                } if operation_provider == provider && operation_package == package
            )
        }
        VerificationRule::File { destination, .. }
        | VerificationRule::FileVersion { destination, .. }
        | VerificationRule::BrowserArtifact {
            profile: destination,
        } => operation_destination(&operation.operation.kind)
            .is_some_and(|candidate| candidate == destination),
        VerificationRule::ConfigParses {
            destination,
            content_type,
        } => match content_type {
            ContentType::Json | ContentType::Jsonc => matches!(
                &operation.operation.kind,
                OperationKind::MergeJson {
                    destination: candidate,
                    ..
                } if candidate == destination
            ),
            ContentType::Toml => matches!(
                &operation.operation.kind,
                OperationKind::MergeToml {
                    destination: candidate,
                    ..
                } if candidate == destination
            ),
            _ => false,
        },
        VerificationRule::Environment { scope, name, .. } => {
            let scope_matches = matches!(scope, ConfigScope::User)
                && matches!(
                    &operation.operation.kind,
                    OperationKind::SetUserEnvironment {
                        name: candidate,
                        ..
                    } if candidate.eq_ignore_ascii_case(name)
                );
            let path_matches = matches!(scope, ConfigScope::User)
                && name.eq_ignore_ascii_case("PATH")
                && matches!(
                    &operation.operation.kind,
                    OperationKind::AppendUserPath { .. }
                );
            scope_matches || path_matches
        }
        VerificationRule::McpRegistration { name, config } => matches!(
            &operation.operation.kind,
            OperationKind::RegisterMcp { server }
                if server.name == *name && server.source_config.source_path == *config
        ),
        VerificationRule::WslState { distro, version } => matches!(
            &operation.operation.kind,
            OperationKind::ImportWsl { distro: candidate, .. }
                if candidate.distribution == *distro
                    && version_matches_text(candidate.wsl_version.map(|value| value.to_string()).as_deref(), version.as_deref())
        ),
        VerificationRule::DockerObject { kind, identity } => {
            docker_operation_matches(&operation.operation.kind, kind, identity)
        }
        VerificationRule::SecureTarget { .. } => matches!(
            &operation.operation.kind,
            OperationKind::OpenManualAction { action }
                if action.verification.as_ref() == Some(rule)
        ),
    }
}

fn operation_destination(kind: &OperationKind) -> Option<&PathToken> {
    match kind {
        OperationKind::WriteFile { destination, .. }
        | OperationKind::MergeJson { destination, .. }
        | OperationKind::MergeToml { destination, .. } => Some(destination),
        OperationKind::RegisterMcp { server } => Some(&server.source_config.source_path),
        _ => None,
    }
}

fn docker_operation_matches(
    kind: &OperationKind,
    expected_kind: &ComponentKind,
    identity: &str,
) -> bool {
    match (expected_kind, kind) {
        (ComponentKind::DockerImage, OperationKind::RestoreDockerImage { image, .. }) => {
            image.image_id.as_deref() == Some(identity)
                || (image.image_id.is_none() && image_reference(image) == identity)
        }
        (ComponentKind::DockerVolume, OperationKind::RestoreDockerVolume { volume, .. }) => {
            volume.name == identity
        }
        _ => false,
    }
}

fn image_reference(image: &reforge_domain::DockerImageSpec) -> String {
    match image.tag.as_deref() {
        Some(tag) => format!("{}:{tag}", image.repository),
        None => image.repository.clone(),
    }
}

fn operation_proves(rule: &VerificationRule, operation: &JournalOperation) -> bool {
    let payloads = operation_payloads(operation);
    match rule {
        VerificationRule::ProviderIdentity { provider, package } => {
            payloads.iter().any(|payload| {
                let kind_ok = field_str(payload, "kind").is_some_and(|value| {
                    value.eq_ignore_ascii_case("provider_package")
                        || value.eq_ignore_ascii_case("target_package")
                });
                kind_ok
                    && field_str(payload, "provider")
                        .is_some_and(|value| value == provider.as_str())
                    && field_str(payload, "package_id").is_some_and(|value| value == package.id)
                    && package
                        .version
                        .as_deref()
                        .is_none_or(|expected| field_str(payload, "version") == Some(expected))
                    && package.installer_hash.is_none()
            })
        }
        VerificationRule::File { object, .. } => file_proof(&payloads, object.as_ref()),
        VerificationRule::FileVersion {
            version, publisher, ..
        } => file_version_proof(&payloads, version.as_ref(), publisher.as_ref()),
        VerificationRule::ConfigParses { content_type, .. } => {
            config_kind_proof(&payloads, content_type) && file_proof(&payloads, None)
        }
        VerificationRule::Environment {
            scope,
            name,
            expected,
        } => environment_proof(&payloads, scope, name, expected),
        VerificationRule::McpRegistration { name, .. } => payloads.iter().any(|payload| {
            field_str(payload, "server") == Some(name.as_str())
                && field_bool(payload, "verified") == Some(true)
                && field_bool(payload, "reauth_required") != Some(true)
        }),
        VerificationRule::WslState { distro, version } => payloads.iter().any(|payload| {
            field_str(payload, "kind").is_some_and(|value| value == "wsl_distribution")
                && field_str(payload, "distribution") == Some(distro.as_str())
                && version_matches_text(field_str(payload, "wsl_version"), version.as_deref())
                && field_bool(payload, "verified") == Some(true)
        }),
        VerificationRule::DockerObject { kind, identity } => {
            docker_payload_proof(&payloads, kind, identity)
        }
        VerificationRule::BrowserArtifact { .. } => file_proof(&payloads, None),
        VerificationRule::SecureTarget { secret } => payloads.iter().any(|payload| {
            (field_bool(payload, "secure_target") == Some(true)
                || field_bool(payload, "secure_adapter") == Some(true))
                && field_str(payload, "secret").is_none_or(|value| value == secret.as_str())
        }),
    }
}

fn operation_payloads(operation: &JournalOperation) -> Vec<&Value> {
    let mut payloads = Vec::new();
    let Some(result) = operation.result.as_ref() else {
        return payloads;
    };
    payloads.push(result);
    if let Some(inner) = result.get("result")
        && !inner.is_null()
    {
        payloads.push(inner);
    }
    if let Some(evidence) = result.get("evidence").and_then(Value::as_array) {
        payloads.extend(evidence);
    }
    payloads
}

fn file_proof(payloads: &[&Value], object: Option<&ObjectId>) -> bool {
    payloads.iter().any(|payload| {
        let Some(_bytes) = field_u64(payload, "bytes") else {
            return false;
        };
        let Some(digest) = field_str(payload, "blake3") else {
            return false;
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        object.is_none_or(|expected| {
            field_str(payload, "object") == Some(expected.as_str())
                || expected
                    .as_str()
                    .strip_prefix("obj_")
                    .is_some_and(|expected_digest| digest.eq_ignore_ascii_case(expected_digest))
        })
    })
}

fn file_version_proof(
    payloads: &[&Value],
    expected_version: Option<&VersionValue>,
    expected_publisher: Option<&reforge_domain::Publisher>,
) -> bool {
    let version_ok = expected_version.is_none_or(|expected| {
        payloads.iter().any(|payload| {
            field_str(payload, "version").is_some_and(|actual| {
                actual == expected.raw || expected.normalized.as_deref() == Some(actual)
            })
        })
    });
    let publisher_ok = expected_publisher.is_none_or(|expected| {
        payloads.iter().any(|payload| {
            let name = field_str(payload, "publisher").or_else(|| {
                payload
                    .get("publisher")
                    .and_then(|value| value.get("name"))
                    .and_then(Value::as_str)
            });
            let thumbprint = payload
                .get("publisher")
                .and_then(|value| value.get("certificate_thumbprint"))
                .and_then(Value::as_str)
                .or_else(|| field_str(payload, "certificate_thumbprint"));
            name == Some(expected.name.as_str())
                && expected
                    .certificate_thumbprint
                    .as_deref()
                    .is_none_or(|required| thumbprint == Some(required))
        })
    });
    let has_metadata = expected_version.is_some()
        || expected_publisher.is_some()
        || payloads.iter().any(|payload| {
            field_str(payload, "version").is_some()
                || payload
                    .get("publisher")
                    .is_some_and(|value| !value.is_null())
        });
    version_ok && publisher_ok && has_metadata
}

fn config_kind_proof(payloads: &[&Value], content_type: &ContentType) -> bool {
    let expected = match content_type {
        ContentType::Json | ContentType::Jsonc => "json",
        ContentType::Toml => "toml",
        _ => return false,
    };
    payloads.iter().any(|payload| {
        field_str(payload, "kind").is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

fn environment_proof(
    payloads: &[&Value],
    scope: &ConfigScope,
    name: &str,
    expected: &SafeValueRef,
) -> bool {
    if !matches!(scope, ConfigScope::User) {
        return false;
    }
    let expected_hash = match expected {
        SafeValueRef::LiteralNonSecret(value) => {
            Some(ObjectId::from_content(value.as_bytes()).as_str().to_owned())
        }
        SafeValueRef::EnvironmentReference { .. }
        | SafeValueRef::SecretReference { .. }
        | SafeValueRef::RedactedUnknown => None,
    };
    payloads.iter().any(|payload| {
        field_str(payload, "name").is_some_and(|actual| actual.eq_ignore_ascii_case(name))
            && expected_hash
                .as_deref()
                .is_some_and(|hash| field_str(payload, "value_hash") == Some(hash))
    })
}

fn docker_payload_proof(payloads: &[&Value], kind: &ComponentKind, identity: &str) -> bool {
    let expected_kind = match kind {
        ComponentKind::DockerImage => "docker_image",
        ComponentKind::DockerVolume => "docker_volume",
        ComponentKind::DockerContext => "docker_context",
        _ => return false,
    };
    payloads.iter().any(|payload| {
        if field_str(payload, "kind") != Some(expected_kind)
            || field_bool(payload, "verified") != Some(true)
        {
            return false;
        }
        let actual = match kind {
            ComponentKind::DockerImage => {
                field_str(payload, "image_id").or_else(|| field_str(payload, "reference"))
            }
            ComponentKind::DockerVolume => field_str(payload, "name"),
            ComponentKind::DockerContext => {
                field_str(payload, "name").or_else(|| field_str(payload, "context"))
            }
            _ => None,
        };
        actual == Some(identity)
    })
}

fn target_satisfies(rule: &VerificationRule, target: &TargetFacts) -> bool {
    match rule {
        VerificationRule::ProviderIdentity { provider, package } => target
            .installed
            .iter()
            .any(|fact| installed_package_matches(fact, provider, package)),
        VerificationRule::Environment {
            scope,
            name,
            expected,
        } => target_environment_matches(target, scope, name, expected),
        VerificationRule::WslState { distro, version } => {
            target_wsl_matches(target, distro, version)
        }
        VerificationRule::DockerObject { kind, identity } => {
            target_docker_matches(target, kind, identity)
        }
        VerificationRule::File { .. }
        | VerificationRule::FileVersion { .. }
        | VerificationRule::ConfigParses { .. }
        | VerificationRule::McpRegistration { .. }
        | VerificationRule::BrowserArtifact { .. }
        | VerificationRule::SecureTarget { .. } => false,
    }
}

fn installed_package_matches(
    fact: &InstalledFact,
    provider: &reforge_domain::ProviderId,
    package: &PackageSpec,
) -> bool {
    let Some((actual_provider, actual_id)) = fact.identity.provider_package.as_ref() else {
        return false;
    };
    actual_provider == provider
        && actual_id == &package.id
        && package.installer_hash.is_none()
        && package.version.as_deref().is_none_or(|expected| {
            fact.version.as_ref().is_some_and(|actual| {
                actual.raw == expected || actual.normalized.as_deref() == Some(expected)
            })
        })
        && source_matches(&fact.identity, package)
}

fn source_matches(identity: &reforge_domain::Identity, package: &PackageSpec) -> bool {
    let Some(observed) = identity.provider_source.as_deref() else {
        return package.source_identifier.is_none()
            && package.source.is_none()
            && package.source_name.is_none();
    };
    if matches!(package.provider.as_str(), "npm" | "pnpm" | "yarn" | "bun")
        && package.source_identifier.is_none()
        && package.source_name.is_none()
    {
        return observed == "global";
    }
    let mut expected = Vec::with_capacity(6);
    if let Some(identifier) = package.source_identifier.as_deref() {
        expected.push(identifier.to_owned());
        expected.push(format!("identifier:{identifier}"));
    }
    if let Some(source) = package.source.as_ref() {
        expected.push(source.to_string());
        expected.push(format!("url:{source}"));
    }
    if let Some(name) = package.source_name.as_deref() {
        expected.push(name.to_owned());
        expected.push(format!("kind:{name}"));
    }
    expected.is_empty() || expected.iter().any(|value| value == observed)
}

fn target_environment_matches(
    target: &TargetFacts,
    scope: &ConfigScope,
    name: &str,
    expected: &SafeValueRef,
) -> bool {
    let Some(destination) = target
        .environment
        .iter()
        .find(|fact| &fact.scope == scope && fact.name.eq_ignore_ascii_case(name))
    else {
        return false;
    };
    match expected {
        SafeValueRef::LiteralNonSecret(value) => {
            destination.value_hash.as_deref()
                == Some(ObjectId::from_content(value.as_bytes()).as_str())
        }
        SafeValueRef::EnvironmentReference { name: source } => {
            target
                .environment
                .iter()
                .find(|fact| &fact.scope == scope && fact.name.eq_ignore_ascii_case(source))
                .and_then(|fact| fact.value_hash.as_deref())
                == destination.value_hash.as_deref()
        }
        SafeValueRef::SecretReference { .. } | SafeValueRef::RedactedUnknown => false,
    }
}

fn target_wsl_matches(target: &TargetFacts, distro: &str, version: &Option<String>) -> bool {
    target.installed.iter().any(|fact| {
        if !matches!(
            fact.kind,
            ComponentKind::WslDistribution | ComponentKind::SystemFeature
        ) {
            return false;
        }
        let identity_matches =
            fact.identity
                .provider_package
                .as_ref()
                .is_some_and(|(_, package)| {
                    package == distro
                        || package == &format!("distribution:{distro}")
                        || package == &format!("feature:{distro}")
                })
                || fact
                    .identity
                    .product_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(distro));
        identity_matches
            && version.as_deref().is_none_or(|expected| {
                fact.version.as_ref().is_some_and(|actual| {
                    actual.raw == expected || actual.normalized.as_deref() == Some(expected)
                })
            })
    })
}

fn target_docker_matches(target: &TargetFacts, kind: &ComponentKind, identity: &str) -> bool {
    target.installed.iter().any(|fact| {
        if fact.kind != *kind {
            return false;
        }
        fact.identity
            .provider_package
            .as_ref()
            .is_some_and(|(provider, package)| {
                provider.as_str() == "docker"
                    && (package == identity
                        || package == &format!("{}:{identity}", docker_kind_label(kind)))
            })
    })
}

fn docker_kind_label(kind: &ComponentKind) -> &'static str {
    match kind {
        ComponentKind::DockerImage => "image",
        ComponentKind::DockerVolume => "volume",
        ComponentKind::DockerContext => "context",
        _ => "unknown",
    }
}

fn version_matches_text(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| actual == Some(expected))
}

fn rule_requires_reauth(rule: &VerificationRule) -> bool {
    match rule {
        VerificationRule::Environment { expected, .. } => matches!(
            expected,
            SafeValueRef::SecretReference { .. } | SafeValueRef::RedactedUnknown
        ),
        VerificationRule::SecureTarget { .. } => true,
        _ => false,
    }
}

fn operation_requires_reauth(operation: &JournalOperation) -> bool {
    if operation_payloads(operation)
        .iter()
        .any(|payload| field_bool(payload, "reauth_required") == Some(true))
    {
        return true;
    }
    match &operation.operation.kind {
        OperationKind::SetUserEnvironment { value, .. } => safe_value_requires_secret(value),
        OperationKind::RegisterMcp { server } => {
            server
                .environment
                .iter()
                .any(|binding| safe_value_requires_secret(&binding.value))
                || server
                    .endpoint
                    .as_ref()
                    .is_some_and(endpoint_requires_secret)
                || server
                    .cwd
                    .as_ref()
                    .is_some_and(working_directory_requires_secret)
        }
        OperationKind::OpenManualAction { action } => action
            .verification
            .as_ref()
            .is_some_and(rule_requires_reauth),
        _ => false,
    }
}

fn endpoint_requires_secret(endpoint: &reforge_domain::McpEndpoint) -> bool {
    matches!(
        endpoint,
        reforge_domain::McpEndpoint::SecretReference { .. }
    )
}

fn working_directory_requires_secret(directory: &reforge_domain::McpWorkingDirectory) -> bool {
    matches!(
        directory,
        reforge_domain::McpWorkingDirectory::SecretReference { .. }
    )
}

fn safe_value_requires_secret(value: &SafeValueRef) -> bool {
    matches!(value, SafeValueRef::SecretReference { .. })
}

fn unsupported_restore(restore: &RestoreDescriptor) -> bool {
    matches!(
        restore.primary,
        RestoreStrategy::Manual
            | RestoreStrategy::MachineBound
            | RestoreStrategy::Unknown
            | RestoreStrategy::Partial
    ) || matches!(
        restore.portability,
        reforge_domain::Portability::Unsupported
    )
}

fn verified_summary(rule: &VerificationRule, already_present: bool) -> String {
    if already_present {
        return already_present_summary(rule);
    }
    match rule {
        VerificationRule::ProviderIdentity { .. } => {
            "provider package identity was verified".to_owned()
        }
        VerificationRule::File { .. } => "file content was verified by BLAKE3 evidence".to_owned(),
        VerificationRule::FileVersion { .. } => {
            "file version and publisher metadata were verified".to_owned()
        }
        VerificationRule::ConfigParses { .. } => "configuration was parsed and verified".to_owned(),
        VerificationRule::Environment { .. } => {
            "environment value hash was verified without exposing its value".to_owned()
        }
        VerificationRule::McpRegistration { .. } => {
            "MCP registration was verified without exposing secret values".to_owned()
        }
        VerificationRule::WslState { .. } => "WSL state was verified".to_owned(),
        VerificationRule::DockerObject { .. } => "Docker object identity was verified".to_owned(),
        VerificationRule::BrowserArtifact { .. } => {
            "browser portable artifact was verified".to_owned()
        }
        VerificationRule::SecureTarget { .. } => {
            "secure target adapter reported verification".to_owned()
        }
    }
}

fn already_present_summary(rule: &VerificationRule) -> String {
    match rule {
        VerificationRule::ProviderIdentity { .. } => {
            "target already contains the verified provider package".to_owned()
        }
        VerificationRule::Environment { .. } => {
            "target already contains the verified environment value hash".to_owned()
        }
        VerificationRule::WslState { .. } => {
            "target already contains the requested WSL state".to_owned()
        }
        VerificationRule::DockerObject { .. } => {
            "target already contains the requested Docker object".to_owned()
        }
        _ => "target already satisfied this verification rule".to_owned(),
    }
}

fn validate_rule_shape(rule: &VerificationRule) -> RestoreResult<()> {
    match rule {
        VerificationRule::File { destination, .. }
        | VerificationRule::FileVersion { destination, .. }
        | VerificationRule::ConfigParses { destination, .. }
        | VerificationRule::BrowserArtifact {
            profile: destination,
        }
        | VerificationRule::McpRegistration {
            config: destination,
            ..
        } => {
            destination.validate().map_err(|_| {
                schema_error("verification rule contains an invalid tokenized path")
            })?;
        }
        VerificationRule::Environment { name, .. } if name.is_empty() => {
            return Err(schema_error(
                "verification rule contains an empty environment name",
            ));
        }
        VerificationRule::WslState { distro, .. } if distro.is_empty() => {
            return Err(schema_error(
                "verification rule contains an empty WSL identity",
            ));
        }
        VerificationRule::DockerObject { identity, .. } if identity.is_empty() => {
            return Err(schema_error(
                "verification rule contains an empty Docker identity",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn push_unique_rule(rules: &mut Vec<VerificationRule>, rule: VerificationRule) {
    if !rules.iter().any(|candidate| candidate == &rule) {
        rules.push(rule);
    }
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.iter().any(|candidate| candidate == &warning) {
        warnings.push(warning);
    }
}

fn aggregate_statuses<'a>(
    statuses: impl IntoIterator<Item = &'a ReportStatus>,
) -> Option<ReportStatus> {
    let statuses = statuses.into_iter().cloned().collect::<Vec<_>>();
    if statuses.contains(&ReportStatus::Failed) {
        return Some(ReportStatus::Failed);
    }
    // A report-level lifecycle blocker must remain actionable even when
    // independent selected components were verified. This also preserves the
    // CLI's documented manual/reboot exit states rather than collapsing them
    // into a generic partial result.
    if statuses.contains(&ReportStatus::ReauthRequired) {
        return Some(ReportStatus::ReauthRequired);
    }
    if statuses.contains(&ReportStatus::RebootRequired) {
        return Some(ReportStatus::RebootRequired);
    }
    if statuses.contains(&ReportStatus::WaitingForUser) {
        return Some(ReportStatus::WaitingForUser);
    }
    let first = statuses.first()?.clone();
    if statuses.iter().all(|status| *status == first) {
        Some(first)
    } else {
        Some(ReportStatus::PartiallyVerified)
    }
}
fn report_counts(reports: &[ComponentReportParts]) -> ReportCounts {
    let mut counts = ReportCounts {
        verified: 0,
        partial: 0,
        already_present: 0,
        waiting_for_user: 0,
        reauth_required: 0,
        reboot_required: 0,
        unsupported: 0,
        failed: 0,
    };
    for report in reports {
        match report.status {
            ReportStatus::Verified => counts.verified += 1,
            ReportStatus::PartiallyVerified | ReportStatus::Skipped => counts.partial += 1,
            ReportStatus::AlreadyPresent => counts.already_present += 1,
            ReportStatus::WaitingForUser => counts.waiting_for_user += 1,
            ReportStatus::ReauthRequired => counts.reauth_required += 1,
            ReportStatus::RebootRequired => counts.reboot_required += 1,
            ReportStatus::Unsupported => counts.unsupported += 1,
            ReportStatus::Failed => counts.failed += 1,
        }
    }
    counts
}

/// Redact all free-form report text while preserving typed IDs and rules.
pub fn redact_restore_report(mut report: RestoreReport) -> RestoreReport {
    let policy = RedactionPolicy::default();
    report.package_id = redact_text(&policy, &report.package_id);
    report.warnings = report
        .warnings
        .iter()
        .map(|warning| redact_text(&policy, warning))
        .collect();
    for component in &mut report.components {
        component.warnings = component
            .warnings
            .iter()
            .map(|warning| redact_text(&policy, warning))
            .collect();
        component.manual_actions = component
            .manual_actions
            .iter()
            .map(|action| redact_text(&policy, action))
            .collect();
        for evidence in &mut component.evidence {
            evidence.summary = redact_text(&policy, &evidence.summary);
        }
    }
    for action in &mut report.manual_actions {
        action.title = redact_text(&policy, &action.title);
        action.reason = redact_text(&policy, &action.reason);
        action.instructions = action
            .instructions
            .iter()
            .map(|instruction| redact_text(&policy, instruction))
            .collect();
    }
    report
}

fn redact_text(policy: &RedactionPolicy, value: &str) -> String {
    policy
        .redact_text(value)
        .unwrap_or_else(|| "<REDACTED>".to_owned())
}

fn field_str<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn field_bool(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn field_u64(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn schema_error(message: &str) -> Box<ErrorEnvelope> {
    restore_error(
        reforge_domain::ReforgeErrorCode::SchemaInvalid,
        message,
        None,
        None,
        None,
        Some("restore-verification"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{
        AccountScope, Architecture, Compatibility, ComponentKind, Confidence, Identity,
        IdentityQuality, KnownFolderToken, OperationId, RestoreDescriptor, SelectionMetadata,
    };

    fn run_id() -> reforge_domain::RunId {
        reforge_domain::RunId::try_from("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".to_owned())
            .expect("run ID")
    }

    fn component_id(index: u8) -> ComponentId {
        ComponentId::new(format!(
            "cmp_{}",
            char::from(b'a' + index).to_string().repeat(52)
        ))
        .expect("component ID")
    }

    fn target() -> TargetFacts {
        TargetFacts {
            host: reforge_domain::HostFacts {
                os_version: "Windows".to_owned(),
                os_build: "test".to_owned(),
                architecture: Architecture::X64,
                elevated: false,
                account_scope: AccountScope::User,
                sid_fingerprint: None,
                known_folders: vec![
                    PathToken::new(KnownFolderToken::UserProfile, "").expect("root token"),
                ],
                drives: Vec::new(),
                free_bytes: Vec::new(),
            },
            installed: Vec::new(),
            providers: Vec::new(),
            runtimes: Vec::new(),
            environment: Vec::new(),
            fingerprint: "target_test".to_owned(),
        }
    }

    fn component(
        id: ComponentId,
        rules: Vec<VerificationRule>,
        strategy: RestoreStrategy,
    ) -> Component {
        Component {
            id,
            kind: ComponentKind::Configuration,
            identity: Identity {
                provider_package: None,
                provider_source: None,
                package_family: None,
                product_name: Some("test".to_owned()),
                executable_name: None,
                publisher: None,
                executable_hash: None,
                install_role: None,
                identity_quality: IdentityQuality::Local,
            },
            display_name: "test".to_owned(),
            version: None,
            architecture: None,
            publisher: None,
            provenance: None,
            evidence: Vec::new(),
            confidence: Confidence::Confirmed,
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: strategy,
                alternatives: Vec::new(),
                portability: reforge_domain::Portability::Portable,
                requires_elevation: false,
                requires_user_action: false,
                rationale: Vec::new(),
            },
            compatibility: Compatibility {
                required_os: None,
                required_architecture: None,
                requires_provider: None,
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: rules,
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: 0,
            },
            extensions: BTreeMap::new(),
        }
    }

    fn operation(
        component: &ComponentId,
        kind: OperationKind,
        verification: Vec<VerificationRule>,
        result: Value,
        state: OperationState,
    ) -> JournalOperation {
        let operation_id = OperationId::for_run(&run_id(), 1).expect("operation ID");
        let operation = reforge_domain::Operation {
            id: operation_id.clone(),
            component: component.clone(),
            kind,
            prerequisites: Vec::new(),
            precondition: reforge_domain::Precondition::Always,
            idempotency_key: "verification-test".to_owned(),
            verification,
            requires_elevation: false,
            non_idempotent: false,
        };
        JournalOperation {
            id: operation_id,
            run_id: run_id(),
            operation,
            state,
            attempt: 1,
            started_at: None,
            ended_at: None,
            result: Some(result),
            error: None,
            backup: None,
        }
    }

    fn file_result(object: &ObjectId) -> Value {
        serde_json::json!({
            "result": {"changed": true},
            "evidence": [{
                "bytes": 4,
                "blake3": object.as_str().strip_prefix("obj_").expect("object digest")
            }]
        })
    }

    #[test]
    fn file_rule_is_verified_from_bounded_hash_evidence() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let rule = VerificationRule::File {
            destination: path.clone(),
            object: Some(object.clone()),
        };
        let component_id = component_id(0);
        let component = component(
            component_id.clone(),
            vec![rule.clone()],
            RestoreStrategy::ConfigPortable,
        );
        let op = operation(
            &component_id,
            OperationKind::WriteFile {
                destination: path,
                object: object.clone(),
                mode: reforge_domain::FileMode::Replace,
            },
            vec![rule],
            file_result(&object),
            OperationState::Completed,
        );
        let _selected = vec![component_id];
        let operations = vec![op];
        let components = vec![component];
        let target_facts = target();
        let input = VerificationInput::new(
            &target_facts,
            &operations,
            &components,
            &_selected,
            run_id(),
            "package",
        );
        let report = verify_restore(&input).expect("report");
        assert_eq!(report.status, ReportStatus::Verified);
        assert_eq!(report.counts.verified, 1);
    }

    #[test]
    fn a_failed_sibling_operation_cannot_be_hidden_by_successful_evidence() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let rule = VerificationRule::File {
            destination: path.clone(),
            object: Some(object.clone()),
        };
        let component_id = component_id(1);
        let component = component(
            component_id.clone(),
            vec![rule.clone()],
            RestoreStrategy::ConfigPortable,
        );
        let success = operation(
            &component_id,
            OperationKind::WriteFile {
                destination: path.clone(),
                object: object.clone(),
                mode: reforge_domain::FileMode::Replace,
            },
            vec![rule.clone()],
            file_result(&object),
            OperationState::Completed,
        );
        let mut failure = success.clone();
        failure.id = OperationId::for_run(&run_id(), 2).expect("operation ID");
        failure.operation.id = failure.id.clone();
        failure.state = OperationState::Failed;
        failure.result = None;
        failure.error = Some(ErrorEnvelope::new(
            reforge_domain::ReforgeErrorCode::OperationFailed,
            "failed",
        ));
        let selected = vec![component_id];
        let operations = vec![success, failure];
        let components = vec![component];
        let target_facts = target();
        let input = VerificationInput::new(
            &target_facts,
            &operations,
            &components,
            &selected,
            run_id(),
            "package",
        );
        let report = verify_restore(&input).expect("report");
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.counts.failed, 1);
    }

    #[test]
    fn missing_selection_is_failed_and_report_text_is_redacted() {
        let selected = vec![component_id(2)];
        let components: Vec<Component> = Vec::new();
        let operations: Vec<JournalOperation> = Vec::new();
        let warnings = vec!["api_key=hidden C:\\Users\\Alice\\secret.txt".to_owned()];
        let target_facts = target();
        let input = VerificationInput::new(
            &target_facts,
            &operations,
            &components,
            &selected,
            run_id(),
            "package",
        )
        .with_warnings(&warnings);
        let report = verify_restore(&input).expect("report");
        let encoded = serde_json::to_string(&report).expect("report JSON");
        assert_eq!(report.status, ReportStatus::Failed);
        assert!(encoded.contains("<REDACTED>"));
        assert!(!encoded.contains("hidden"));
        assert!(!encoded.contains("Alice"));
    }
    #[test]
    fn every_verification_rule_category_requires_typed_positive_evidence() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let provider = reforge_domain::ProviderId::new("winget").expect("provider");
        let package = PackageSpec {
            provider: provider.clone(),
            id: "Git.Git".to_owned(),
            version: Some("2.0.0".to_owned()),
            source_name: None,
            source_identifier: None,
            source: None,
            architecture: None,
            installer_hash: None,
        };
        let expected_value = SafeValueRef::LiteralNonSecret("enabled".to_owned());
        let secret = component_id(9);
        let cases = vec![
            (
                VerificationRule::ProviderIdentity { provider, package },
                serde_json::json!({
                    "kind": "provider_package",
                    "provider": "winget",
                    "package_id": "Git.Git",
                    "version": "2.0.0"
                }),
            ),
            (
                VerificationRule::File {
                    destination: path.clone(),
                    object: Some(object.clone()),
                },
                file_result(&object),
            ),
            (
                VerificationRule::FileVersion {
                    destination: path.clone(),
                    version: Some(VersionValue {
                        raw: "1.2.3".to_owned(),
                        normalized: None,
                    }),
                    publisher: Some(reforge_domain::Publisher {
                        name: "Acme".to_owned(),
                        certificate_thumbprint: Some("thumb".to_owned()),
                    }),
                },
                serde_json::json!({
                    "version": "1.2.3",
                    "publisher": {
                        "name": "Acme",
                        "certificate_thumbprint": "thumb"
                    }
                }),
            ),
            (
                VerificationRule::ConfigParses {
                    destination: path.clone(),
                    content_type: ContentType::Json,
                },
                serde_json::json!({
                    "kind": "json",
                    "bytes": 2,
                    "blake3": object.as_str().strip_prefix("obj_").expect("digest")
                }),
            ),
            (
                VerificationRule::Environment {
                    scope: ConfigScope::User,
                    name: "FEATURE_FLAG".to_owned(),
                    expected: expected_value,
                },
                serde_json::json!({
                    "name": "FEATURE_FLAG",
                    "value_hash": ObjectId::from_content(b"enabled").as_str()
                }),
            ),
            (
                VerificationRule::McpRegistration {
                    name: "filesystem".to_owned(),
                    config: path.clone(),
                },
                serde_json::json!({
                    "server": "filesystem",
                    "verified": true,
                    "reauth_required": false
                }),
            ),
            (
                VerificationRule::WslState {
                    distro: "Ubuntu".to_owned(),
                    version: Some("2".to_owned()),
                },
                serde_json::json!({
                    "kind": "wsl_distribution",
                    "distribution": "Ubuntu",
                    "wsl_version": "2",
                    "verified": true
                }),
            ),
            (
                VerificationRule::DockerObject {
                    kind: ComponentKind::DockerImage,
                    identity: "sha256:abc".to_owned(),
                },
                serde_json::json!({
                    "kind": "docker_image",
                    "image_id": "sha256:abc",
                    "verified": true
                }),
            ),
            (
                VerificationRule::BrowserArtifact {
                    profile: path.clone(),
                },
                file_result(&object),
            ),
            (
                VerificationRule::SecureTarget {
                    secret: secret.clone(),
                },
                serde_json::json!({
                    "secure_target": true,
                    "secret": secret.as_str()
                }),
            ),
        ];

        let component = component(component_id(0), Vec::new(), RestoreStrategy::ConfigPortable);
        for (rule, result) in cases {
            let operation = operation(
                &component.id,
                OperationKind::Verify { rule: rule.clone() },
                Vec::new(),
                result,
                OperationState::Completed,
            );
            assert!(
                operation_proves(&rule, &operation),
                "positive evidence did not prove {rule:?}"
            );
        }
    }

    #[test]
    fn missing_typed_markers_are_not_verification_evidence() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let config_rule = VerificationRule::ConfigParses {
            destination: path.clone(),
            content_type: ContentType::Json,
        };
        let wsl_rule = VerificationRule::WslState {
            distro: "Ubuntu".to_owned(),
            version: Some("2".to_owned()),
        };
        let config_operation = operation(
            &component_id(0),
            OperationKind::Verify {
                rule: config_rule.clone(),
            },
            Vec::new(),
            serde_json::json!({
                "bytes": 2,
                "blake3": object.as_str().strip_prefix("obj_").expect("digest")
            }),
            OperationState::Completed,
        );
        let wsl_operation = operation(
            &component_id(0),
            OperationKind::Verify {
                rule: wsl_rule.clone(),
            },
            Vec::new(),
            serde_json::json!({
                "kind": "wsl_distribution",
                "distribution": "Ubuntu",
                "wsl_version": "2"
            }),
            OperationState::Completed,
        );
        assert!(!operation_proves(&config_rule, &config_operation));
        assert!(!operation_proves(&wsl_rule, &wsl_operation));
    }

    #[test]
    fn mixed_rule_results_are_partial_and_counted() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let file_rule = VerificationRule::File {
            destination: path.clone(),
            object: Some(object.clone()),
        };
        let unsupported_rule = VerificationRule::DockerObject {
            kind: ComponentKind::DockerImage,
            identity: "sha256:missing".to_owned(),
        };
        let component_id = component_id(0);
        let component = component(
            component_id.clone(),
            vec![file_rule.clone(), unsupported_rule],
            RestoreStrategy::Manual,
        );
        let operation = operation(
            &component_id,
            OperationKind::WriteFile {
                destination: path,
                object: object.clone(),
                mode: reforge_domain::FileMode::Replace,
            },
            vec![file_rule],
            file_result(&object),
            OperationState::Completed,
        );
        let selected = vec![component_id];
        let report = verify_restore(&VerificationInput::new(
            &target(),
            &[operation],
            &[component],
            &selected,
            run_id(),
            "package",
        ))
        .expect("report");
        assert_eq!(report.status, ReportStatus::PartiallyVerified);
        assert_eq!(report.counts.partial, 1);
        assert_eq!(report.counts.failed, 0);
        assert!(
            report.components[0]
                .evidence
                .iter()
                .any(|evidence| { evidence.status == ReportStatus::Verified })
        );
        assert!(
            report.components[0]
                .evidence
                .iter()
                .any(|evidence| { evidence.status == ReportStatus::Unsupported })
        );
    }

    #[test]
    fn pending_manual_action_is_waiting_for_user() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let rule = VerificationRule::ConfigParses {
            destination: path,
            content_type: ContentType::Json,
        };
        let component_id = component_id(0);
        let component = component(
            component_id.clone(),
            vec![rule.clone()],
            RestoreStrategy::ConfigPortable,
        );
        let action = ManualAction {
            id: "action_config".to_owned(),
            component: Some(component_id.clone()),
            title: "Review config".to_owned(),
            reason: "manual review".to_owned(),
            risk: reforge_domain::RiskLevel::Medium,
            instructions: vec!["Review the file".to_owned()],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: Some(rule),
        };
        let selected = vec![component_id];
        let actions = vec![action];
        let report = verify_restore(
            &VerificationInput::new(&target(), &[], &[component], &selected, run_id(), "package")
                .with_manual_actions(&actions),
        )
        .expect("report");
        assert_eq!(report.status, ReportStatus::WaitingForUser);
        assert_eq!(report.counts.waiting_for_user, 1);
    }

    #[test]
    fn mixed_selected_report_preserves_manual_blocker_status() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let verified_id = component_id(0);
        let waiting_id = component_id(1);
        let verified_rule = VerificationRule::File {
            destination: path.clone(),
            object: Some(object.clone()),
        };
        let waiting_rule = VerificationRule::ConfigParses {
            destination: path.clone(),
            content_type: ContentType::Json,
        };
        let verified_component = component(
            verified_id.clone(),
            vec![verified_rule.clone()],
            RestoreStrategy::ConfigPortable,
        );
        let waiting_component = component(
            waiting_id.clone(),
            vec![waiting_rule.clone()],
            RestoreStrategy::ConfigPortable,
        );
        let operation = operation(
            &verified_id,
            OperationKind::WriteFile {
                destination: path,
                object: object.clone(),
                mode: reforge_domain::FileMode::Replace,
            },
            vec![verified_rule],
            file_result(&object),
            OperationState::Completed,
        );
        let actions = vec![ManualAction {
            id: "action_waiting".to_owned(),
            component: Some(waiting_id.clone()),
            title: "Review configuration".to_owned(),
            reason: "A user decision is required".to_owned(),
            risk: reforge_domain::RiskLevel::Medium,
            instructions: vec!["Review the configuration merge".to_owned()],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: Some(waiting_rule),
        }];
        let selected = vec![verified_id, waiting_id];
        let report = verify_restore(
            &VerificationInput::new(
                &target(),
                &[operation],
                &[verified_component, waiting_component],
                &selected,
                run_id(),
                "package",
            )
            .with_manual_actions(&actions),
        )
        .expect("report");

        assert_eq!(report.status, ReportStatus::WaitingForUser);
        assert_eq!(report.counts.verified, 1);
        assert_eq!(report.counts.waiting_for_user, 1);
        assert_eq!(report.counts.failed, 0);
    }

    #[test]
    fn report_counts_keep_failure_visible_in_mixed_selected_components() {
        let path = PathToken::new(KnownFolderToken::UserProfile, "settings.json").expect("path");
        let object = ObjectId::from_content(b"test");
        let verified_id = component_id(0);
        let failed_id = component_id(1);
        let verified_component = component(
            verified_id.clone(),
            vec![VerificationRule::File {
                destination: path.clone(),
                object: Some(object.clone()),
            }],
            RestoreStrategy::ConfigPortable,
        );
        let failed_component = component(
            failed_id.clone(),
            vec![VerificationRule::File {
                destination: path.clone(),
                object: Some(ObjectId::from_content(b"different")),
            }],
            RestoreStrategy::ConfigPortable,
        );
        let operation = operation(
            &verified_id,
            OperationKind::WriteFile {
                destination: path,
                object: object.clone(),
                mode: reforge_domain::FileMode::Replace,
            },
            verified_component.verification.clone(),
            file_result(&object),
            OperationState::Completed,
        );
        let selected = vec![verified_id, failed_id];
        let report = verify_restore(&VerificationInput::new(
            &target(),
            &[operation],
            &[verified_component, failed_component],
            &selected,
            run_id(),
            "package",
        ))
        .expect("report");
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.counts.verified, 1);
        assert_eq!(report.counts.failed, 1);
    }
}
