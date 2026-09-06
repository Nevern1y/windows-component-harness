//! Typed, journal-gated restore execution with conservative resume behavior.
//!
//! The executor is deliberately unaware of provider-specific command details.
//! A handler owns one closed [`OperationKind`] branch and receives only the
//! validated operation plus bounded target/package context. The journal is the
//! source of truth for approval and operation state.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::Arc,
};

use async_trait::async_trait;
use reforge_domain::{
    ErrorEnvelope, FileManifest, ManualActionState, ObjectEntry, ObjectId, ObjectIndex, Operation,
    OperationId, OperationKind, OperationState, Precondition, RestorePlan, RunId, RunStatus,
    TargetFacts, validate_restore_plan,
};
use reforge_platform_windows::CancellationToken;
use serde_json::{Map, Value, json};

use crate::{
    RestoreResult,
    journal::{Journal, JournalOperation},
    manual_actions::{ManualActionQueue, operation_blocker_action, operation_blocker_action_id},
    operations::precondition_satisfied,
    restore_error,
};

/// Result category returned by a typed operation handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDisposition {
    /// The handler committed the operation and its verification facts.
    Completed,
    /// The handler determined that no mutation was necessary.
    Skipped,
    /// The operation requires an explicit user action before the run can move on.
    WaitingForUser,
    /// The operation requires a reboot before the run can move on.
    WaitingForReboot,
    /// The operation observed cancellation before it could report a commit.
    Cancelled,
}

/// Structured handler output persisted at the operation boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationOutcome {
    pub disposition: OperationDisposition,
    pub result: Option<Value>,
    pub evidence: Vec<Value>,
    pub backup: Option<Value>,
}

impl OperationOutcome {
    pub fn completed(result: Option<Value>) -> Self {
        Self {
            disposition: OperationDisposition::Completed,
            result,
            evidence: Vec::new(),
            backup: None,
        }
    }

    pub fn skipped(result: Option<Value>) -> Self {
        Self {
            disposition: OperationDisposition::Skipped,
            result,
            evidence: Vec::new(),
            backup: None,
        }
    }

    pub fn waiting_for_user(result: Option<Value>) -> Self {
        Self {
            disposition: OperationDisposition::WaitingForUser,
            result,
            evidence: Vec::new(),
            backup: None,
        }
    }

    pub fn waiting_for_reboot(result: Option<Value>) -> Self {
        Self {
            disposition: OperationDisposition::WaitingForReboot,
            result,
            evidence: Vec::new(),
            backup: None,
        }
    }

    pub fn cancelled(result: Option<Value>) -> Self {
        Self {
            disposition: OperationDisposition::Cancelled,
            result,
            evidence: Vec::new(),
            backup: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = Value>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    pub fn with_backup(mut self, backup: Value) -> Self {
        self.backup = Some(backup);
        self
    }
}

/// Evidence returned by a handler's idempotency check.
#[derive(Clone, Debug, PartialEq)]
pub enum OperationSatisfaction {
    NotSatisfied,
    Satisfied {
        result: Option<Value>,
        evidence: Vec<Value>,
    },
}

impl OperationSatisfaction {
    pub fn satisfied(result: Option<Value>) -> Self {
        Self::Satisfied {
            result,
            evidence: Vec::new(),
        }
    }

    pub fn with_evidence(self, evidence: impl IntoIterator<Item = Value>) -> Self {
        match self {
            Self::NotSatisfied => Self::NotSatisfied,
            Self::Satisfied {
                result,
                evidence: mut current,
            } => {
                current.extend(evidence);
                Self::Satisfied {
                    result,
                    evidence: current,
                }
            }
        }
    }
}

/// Read-only package object access made available to handlers.
pub trait ObjectSource: Send + Sync {
    /// Copy one already-inspected, content-verified object to the destination.
    fn copy_verified_object(
        &self,
        object: &ObjectId,
        output: &mut dyn Write,
    ) -> RestoreResult<ObjectEntry>;
}

/// Backup boundary used by handlers before a destructive replacement.
pub trait BackupHook: Send + Sync {
    /// Create and describe a backup for this operation, if one is required.
    /// The returned JSON crosses the journal boundary and is redacted there.
    fn prepare_backup(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
    ) -> RestoreResult<Option<Value>>;
}

/// Immutable facts and narrowly-scoped capabilities supplied to one handler.
pub struct ExecutionContext<'a> {
    pub target: &'a TargetFacts,
    pub object_index: &'a ObjectIndex,
    pub file_manifests: Option<&'a BTreeMap<ObjectId, FileManifest>>,
    pub object_source: Option<&'a dyn ObjectSource>,
    pub backup_hook: Option<&'a dyn BackupHook>,
}

impl<'a> ExecutionContext<'a> {
    pub fn new(target: &'a TargetFacts, object_index: &'a ObjectIndex) -> Self {
        Self {
            target,
            object_index,
            file_manifests: None,
            object_source: None,
            backup_hook: None,
        }
    }

    pub fn with_object_source(mut self, source: &'a dyn ObjectSource) -> Self {
        self.object_source = Some(source);
        self
    }

    pub fn with_file_manifests(
        mut self,
        file_manifests: &'a BTreeMap<ObjectId, FileManifest>,
    ) -> Self {
        self.file_manifests = Some(file_manifests);
        self
    }

    pub fn with_backup_hook(mut self, hook: &'a dyn BackupHook) -> Self {
        self.backup_hook = Some(hook);
        self
    }
}

/// Handler boundary for one or more fixed domain operation kinds.
#[async_trait]
pub trait OperationHandler: Send + Sync {
    /// Return true only for the closed operation kind branches this handler owns.
    fn handles(&self, kind: &OperationKind) -> bool;

    /// Recheck whether the requested effect is already present on the target.
    /// The default is conservative: an unimplemented check never skips work.
    async fn is_satisfied(
        &self,
        _operation: &Operation,
        _context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        Ok(OperationSatisfaction::NotSatisfied)
    }

    /// Execute one typed operation without accepting command text or paths from
    /// the package as imperative instructions.
    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome>;
}

/// Durable result of one executor invocation.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionReport {
    pub run_id: RunId,
    pub status: RunStatus,
    pub operations: Vec<JournalOperation>,
}

impl Eq for ExecutionReport {}

/// Serial, journal-backed restore executor.
pub struct Executor {
    journal: Journal,
    handlers: Vec<Arc<dyn OperationHandler>>,
}

impl Executor {
    pub fn new(journal: Journal) -> Self {
        Self {
            journal,
            handlers: Vec::new(),
        }
    }

    pub fn with_handlers(
        journal: Journal,
        handlers: impl IntoIterator<Item = Arc<dyn OperationHandler>>,
    ) -> Self {
        Self {
            journal,
            handlers: handlers.into_iter().collect(),
        }
    }

    pub fn register_handler<H>(&mut self, handler: H)
    where
        H: OperationHandler + 'static,
    {
        self.handlers.push(Arc::new(handler));
    }

    pub fn register_handler_arc(&mut self, handler: Arc<dyn OperationHandler>) {
        self.handlers.push(handler);
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Execute an approved plan serially and resume only operations whose
    /// current journal state and target facts still permit a safe retry.
    pub async fn execute(
        &self,
        plan: &RestorePlan,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<ExecutionReport> {
        self.execute_with_progress(plan, context, cancellation, |_, _, _, _| {})
            .await
    }

    /// Execute a plan while reporting durable operation-state boundaries.
    pub async fn execute_with_progress<F>(
        &self,
        plan: &RestorePlan,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
        progress: F,
    ) -> RestoreResult<ExecutionReport>
    where
        F: Fn(&Operation, OperationState, u64, u64) + Send + Sync,
    {
        self.journal.require_approved(&plan.run_id)?;
        let mut states = self.validate_execution(plan, context)?;
        let mut waiting_for_user = false;
        let total = u64::try_from(plan.operations.len()).unwrap_or(u64::MAX);
        let mut completed = 0u64;
        for operation in &plan.operations {
            let persisted = states.get(&operation.id).cloned().ok_or_else(|| {
                execution_error(
                    operation,
                    reforge_domain::ReforgeErrorCode::SchemaInvalid,
                    "journal operation is missing from the execution set",
                )
            })?;

            if matches!(
                persisted.state,
                OperationState::Completed | OperationState::Skipped
            ) {
                completed = completed.saturating_add(1);
                progress(operation, persisted.state, completed, total);
                continue;
            }
            let mut acknowledged_blocker_action = None;

            if let Some((action_id, action_state)) =
                self.blocked_operation_action_state(&plan.run_id, operation, &persisted)?
            {
                match action_state {
                    ManualActionState::Pending => {
                        waiting_for_user = true;
                        progress(operation, OperationState::WaitingForUser, completed, total);
                        continue;
                    }
                    ManualActionState::Skipped => {
                        let updated = self.journal.transition_operation(
                            &plan.run_id,
                            &operation.id,
                            OperationState::Skipped,
                            Some(outcome_payload(
                                Some(json!({
                                    "manual_action_id": action_id,
                                    "state": "SKIPPED",
                                })),
                                Vec::new(),
                                Some("SKIPPED_BY_USER"),
                            )),
                            None,
                            None,
                        )?;
                        states.insert(operation.id.clone(), updated);
                        completed = completed.saturating_add(1);
                        progress(operation, OperationState::Skipped, completed, total);
                        continue;
                    }
                    ManualActionState::Acknowledged => {
                        acknowledged_blocker_action = Some(action_id);
                    }
                    ManualActionState::Completed => {}
                }
            }

            if !prerequisites_complete(operation, &states) {
                if has_waiting_for_user_prerequisite(operation, &states) {
                    waiting_for_user = true;
                    continue;
                }
                let error = execution_error(
                    operation,
                    reforge_domain::ReforgeErrorCode::OperationFailed,
                    "operation prerequisites are not complete",
                );
                return Err(self.persist_failure(&plan.run_id, operation, error, None));
            }

            if cancellation.is_cancelled() {
                return self.cancelled_report(&plan.run_id).await;
            }

            let approved_actions = self.approved_manual_actions(&plan.run_id)?;
            if !precondition_satisfied(
                &operation.precondition,
                context.target,
                context.object_index,
                &approved_actions,
            ) {
                let error = precondition_error(operation);
                return Err(self.persist_failure(&plan.run_id, operation, error, None));
            }

            if operation.non_idempotent
                && (!matches!(persisted.state, OperationState::Pending) || persisted.attempt > 0)
            {
                let error = execution_error(
                    operation,
                    reforge_domain::ReforgeErrorCode::SecurityPolicy,
                    "non-idempotent operation cannot be retried without a new approval boundary",
                );
                return Err(self.persist_blocked_retry(&plan.run_id, operation, error));
            }

            if let Some(action_id) = acknowledged_blocker_action.take()
                && let Err(error) =
                    ManualActionQueue::new(self.journal.clone()).complete(&plan.run_id, &action_id)
            {
                return Err(self.persist_failure(&plan.run_id, operation, error, None));
            }

            if matches!(&operation.kind, OperationKind::Verify { .. }) {
                let running = match self
                    .journal
                    .mark_operation_running(&plan.run_id, &operation.id)
                {
                    Ok(running) => running,
                    Err(error) => {
                        let error = correlate_error(operation, &error);
                        return Err(self.persist_failure(&plan.run_id, operation, error, None));
                    }
                };
                states.insert(operation.id.clone(), running);
                progress(operation, OperationState::Running, completed, total);
                if cancellation.is_cancelled() {
                    return self.cancelled_operation_report(plan, &mut states, operation, None);
                }

                let recorded = states.values().collect::<Vec<_>>();
                let verification = recorded
                    .iter()
                    .copied()
                    .find(|record| record.id == operation.id)
                    .expect("running verification operation is journaled");
                let proof = match crate::verification::operation_verification_proof(
                    verification,
                    context.target,
                    &recorded,
                ) {
                    Ok(Some(proof)) => proof,
                    Ok(None) => {
                        let error = execution_error(
                            operation,
                            reforge_domain::ReforgeErrorCode::OperationFailed,
                            "verification rule was not proven by target facts or typed prerequisite evidence",
                        );
                        return Err(self.persist_failure(&plan.run_id, operation, error, None));
                    }
                    Err(error) => {
                        let error = correlate_error(operation, &error);
                        return Err(self.persist_failure(&plan.run_id, operation, error, None));
                    }
                };
                let result = Some(outcome_payload(
                    Some(serde_json::json!({
                        "verification_checked": true,
                        "source": proof,
                    })),
                    Vec::new(),
                    None,
                ));
                let updated = self.journal.transition_operation(
                    &plan.run_id,
                    &operation.id,
                    OperationState::Completed,
                    result,
                    None,
                    None,
                )?;
                states.insert(operation.id.clone(), updated);
                completed = completed.saturating_add(1);
                progress(operation, OperationState::Completed, completed, total);
                continue;
            }

            let handler = match self.handler_for(&operation.kind) {
                Ok(handler) => handler,
                Err(error) => {
                    return Err(self.persist_failure(&plan.run_id, operation, error, None));
                }
            };

            let satisfaction = match handler.is_satisfied(operation, context, cancellation).await {
                Ok(satisfaction) => satisfaction,
                Err(error) => {
                    let error = correlate_error(operation, &error);
                    return Err(self.persist_failure(&plan.run_id, operation, error, None));
                }
            };
            if cancellation.is_cancelled() {
                return self.cancelled_report(&plan.run_id).await;
            }
            if let OperationSatisfaction::Satisfied { result, evidence } = satisfaction {
                let result = Some(outcome_payload(
                    result,
                    evidence,
                    Some("SKIPPED_ALREADY_SATISFIED"),
                ));
                let updated = self.journal.transition_operation(
                    &plan.run_id,
                    &operation.id,
                    OperationState::Skipped,
                    result,
                    None,
                    None,
                )?;
                states.insert(operation.id.clone(), updated);
                completed = completed.saturating_add(1);
                progress(operation, OperationState::Skipped, completed, total);
                continue;
            }
            let running = match self
                .journal
                .mark_operation_running(&plan.run_id, &operation.id)
            {
                Ok(running) => running,
                Err(error) => {
                    let error = correlate_error(operation, &error);
                    return Err(self.persist_failure(&plan.run_id, operation, error, None));
                }
            };
            let attempt = running.attempt;
            states.insert(operation.id.clone(), running);
            progress(operation, OperationState::Running, completed, total);
            let hook_backup = match context.backup_hook {
                Some(hook) => match hook.prepare_backup(operation, context) {
                    Ok(backup) => backup,
                    Err(error) => {
                        let error = correlate_error(operation, &error);
                        return Err(self.persist_failure(&plan.run_id, operation, error, None));
                    }
                },
                None => None,
            };
            if cancellation.is_cancelled() {
                return self.cancelled_operation_report(plan, &mut states, operation, hook_backup);
            }

            let outcome = match handler.execute(operation, context, cancellation).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    let error = correlate_error(operation, &error);
                    if cancellation.is_cancelled()
                        || error.code == reforge_domain::ReforgeErrorCode::Cancelled
                    {
                        return self.cancelled_operation_report(
                            plan,
                            &mut states,
                            operation,
                            hook_backup,
                        );
                    }
                    if error.code == reforge_domain::ReforgeErrorCode::Interrupted {
                        let updated = self.journal.transition_operation(
                            &plan.run_id,
                            &operation.id,
                            OperationState::Interrupted,
                            None,
                            Some((*error).clone()),
                            hook_backup,
                        )?;
                        states.insert(operation.id.clone(), updated);
                        let run = self
                            .journal
                            .set_run_status(&plan.run_id, RunStatus::Interrupted)?;
                        return Err(if run.status == RunStatus::Interrupted {
                            error
                        } else {
                            execution_error(
                                operation,
                                reforge_domain::ReforgeErrorCode::Interrupted,
                                "restore run was interrupted",
                            )
                        });
                    }
                    return Err(self.persist_failure(&plan.run_id, operation, error, hook_backup));
                }
            };

            if outcome.disposition == OperationDisposition::WaitingForUser
                && !matches!(&operation.kind, OperationKind::OpenManualAction { .. })
                && let Err(error) = self.queue_blocked_operation_action(
                    &plan.run_id,
                    operation,
                    attempt,
                    outcome.result.as_ref(),
                )
            {
                return Err(self.persist_failure(&plan.run_id, operation, error, hook_backup));
            }

            let backup = combine_backup(hook_backup, outcome.backup);
            let result = Some(outcome_payload(
                outcome.result,
                outcome.evidence,
                match outcome.disposition {
                    OperationDisposition::Completed => None,
                    OperationDisposition::Skipped => Some("SKIPPED_BY_HANDLER"),
                    OperationDisposition::WaitingForUser => Some("WAITING_FOR_USER"),
                    OperationDisposition::WaitingForReboot => Some("WAITING_FOR_REBOOT"),
                    OperationDisposition::Cancelled => Some("CANCELLED"),
                },
            ));
            let (state, error) = match outcome.disposition {
                OperationDisposition::Completed => (OperationState::Completed, None),
                OperationDisposition::Skipped => (OperationState::Skipped, None),
                OperationDisposition::WaitingForUser => (OperationState::WaitingForUser, None),
                OperationDisposition::WaitingForReboot => (
                    OperationState::WaitingForReboot,
                    Some(correlated_code_error(
                        operation,
                        reforge_domain::ReforgeErrorCode::RebootRequired,
                        "operation requires a reboot before resume",
                    )),
                ),
                OperationDisposition::Cancelled => (
                    OperationState::Cancelled,
                    Some(correlated_code_error(
                        operation,
                        reforge_domain::ReforgeErrorCode::Cancelled,
                        "restore operation was cancelled",
                    )),
                ),
            };
            let progress_state = state.clone();
            let updated = self.journal.transition_operation(
                &plan.run_id,
                &operation.id,
                state,
                result,
                error.map(|error| *error),
                backup,
            )?;
            states.insert(operation.id.clone(), updated);
            if matches!(
                progress_state,
                OperationState::Completed | OperationState::Skipped
            ) {
                completed = completed.saturating_add(1);
            }
            progress(operation, progress_state, completed, total);
            match outcome.disposition {
                OperationDisposition::Completed | OperationDisposition::Skipped => {}
                OperationDisposition::WaitingForUser => {
                    let may_continue = match &operation.kind {
                        OperationKind::OpenManualAction { action } => {
                            action.independent_operations_may_continue
                        }
                        _ => true,
                    };
                    if !may_continue {
                        let run = self
                            .journal
                            .set_run_status(&plan.run_id, RunStatus::WaitingForUser)?;
                        return self.report(&plan.run_id, run.status);
                    }
                    waiting_for_user = true;
                }
                OperationDisposition::WaitingForReboot => {
                    let run = self
                        .journal
                        .set_run_status(&plan.run_id, RunStatus::WaitingForReboot)?;
                    return self.report(&plan.run_id, run.status);
                }
                OperationDisposition::Cancelled => {
                    let run = self
                        .journal
                        .set_run_status(&plan.run_id, RunStatus::Cancelled)?;
                    return self.report(&plan.run_id, run.status);
                }
            }
        }

        let status = if waiting_for_user
            || states
                .values()
                .any(|operation| operation.state == OperationState::WaitingForUser)
        {
            RunStatus::WaitingForUser
        } else {
            RunStatus::Completed
        };
        let run = self.journal.set_run_status(&plan.run_id, status)?;
        self.report(&plan.run_id, run.status)
    }

    /// Alias that makes the plan-oriented API explicit for callers.
    pub async fn execute_plan(
        &self,
        plan: &RestorePlan,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<ExecutionReport> {
        self.execute(plan, context, cancellation).await
    }

    fn validate_execution(
        &self,
        plan: &RestorePlan,
        context: &ExecutionContext<'_>,
    ) -> RestoreResult<BTreeMap<OperationId, JournalOperation>> {
        if context.target.fingerprint != plan.target_fingerprint {
            return Err(restore_error(
                reforge_domain::ReforgeErrorCode::TargetConflict,
                "current target fingerprint does not match the approved plan",
                None,
                None,
                None,
                Some("restore-target-fingerprint"),
            ));
        }
        let operation_prefix = format!("op_{}_", plan.run_id);
        if plan
            .operations
            .iter()
            .any(|operation| !operation.id.as_str().starts_with(&operation_prefix))
        {
            return Err(restore_error(
                reforge_domain::ReforgeErrorCode::SchemaInvalid,
                "restore operation ID does not belong to the plan run",
                None,
                None,
                None,
                Some("restore-operation-scope"),
            ));
        }
        validate_restore_plan(plan, context.object_index).map_err(|error| {
            restore_error(
                error.code,
                error.message,
                None,
                None,
                None,
                Some("restore-plan-validation"),
            )
        })?;

        let run = self.journal.get_run(&plan.run_id)?.ok_or_else(|| {
            restore_error(
                reforge_domain::ReforgeErrorCode::OperationFailed,
                "journal run was not found",
                None,
                None,
                None,
                None,
            )
        })?;
        if run.package_id != plan.package_id || run.mode != plan.mode {
            return Err(restore_error(
                reforge_domain::ReforgeErrorCode::SchemaInvalid,
                "journal run metadata does not match the approved plan",
                None,
                None,
                None,
                Some("restore-plan-journal-mismatch"),
            ));
        }
        if run.target_fingerprint != plan.target_fingerprint {
            return Err(restore_error(
                reforge_domain::ReforgeErrorCode::TargetConflict,
                "journal target fingerprint does not match the approved plan",
                None,
                None,
                None,
                Some("restore-target-fingerprint"),
            ));
        }

        let persisted = self.journal.list_operations(&plan.run_id)?;
        if persisted.len() != plan.operations.len() {
            return Err(restore_error(
                reforge_domain::ReforgeErrorCode::SchemaInvalid,
                "journal operation set does not match the approved plan",
                None,
                None,
                None,
                Some("restore-operation-set"),
            ));
        }
        let expected: BTreeMap<_, _> = plan
            .operations
            .iter()
            .map(|operation| (operation.id.clone(), operation))
            .collect();
        let mut states = BTreeMap::new();
        for persisted_operation in persisted {
            let Some(expected_operation) = expected.get(&persisted_operation.id) else {
                return Err(restore_error(
                    reforge_domain::ReforgeErrorCode::SchemaInvalid,
                    "journal contains an operation absent from the approved plan",
                    None,
                    None,
                    None,
                    Some("restore-operation-set"),
                ));
            };
            if &persisted_operation.operation != *expected_operation {
                return Err(restore_error(
                    reforge_domain::ReforgeErrorCode::SecurityPolicy,
                    "journal operation input differs from the approved plan",
                    None,
                    Some(expected_operation.component.clone()),
                    Some(expected_operation.id.clone()),
                    Some("restore-operation-integrity"),
                ));
            }
            if states
                .insert(persisted_operation.id.clone(), persisted_operation)
                .is_some()
            {
                return Err(restore_error(
                    reforge_domain::ReforgeErrorCode::SchemaInvalid,
                    "journal operation IDs are not unique",
                    None,
                    None,
                    None,
                    Some("restore-operation-set"),
                ));
            }
        }
        Ok(states)
    }

    fn handler_for(&self, kind: &OperationKind) -> RestoreResult<&dyn OperationHandler> {
        let mut selected = None;
        for handler in &self.handlers {
            if !handler.handles(kind) {
                continue;
            }
            if selected.is_some() {
                return Err(restore_error(
                    reforge_domain::ReforgeErrorCode::SecurityPolicy,
                    "multiple handlers claim one operation kind",
                    None,
                    None,
                    None,
                    Some("restore-handler-routing"),
                ));
            }
            selected = Some(handler.as_ref());
        }
        selected.ok_or_else(|| {
            restore_error(
                reforge_domain::ReforgeErrorCode::OperationFailed,
                "no typed handler is registered for the operation kind",
                None,
                None,
                None,
                Some("restore-handler-missing"),
            )
        })
    }

    fn approved_manual_actions(&self, run_id: &RunId) -> RestoreResult<BTreeSet<String>> {
        Ok(self
            .journal
            .list_manual_actions(run_id)?
            .into_iter()
            .filter(|action| {
                matches!(
                    action.state,
                    ManualActionState::Acknowledged | ManualActionState::Completed
                )
            })
            .map(|action| action.id)
            .collect())
    }

    fn blocked_operation_action_state(
        &self,
        run_id: &RunId,
        operation: &Operation,
        persisted: &JournalOperation,
    ) -> RestoreResult<Option<(String, ManualActionState)>> {
        if persisted.state != OperationState::WaitingForUser
            || matches!(&operation.kind, OperationKind::OpenManualAction { .. })
        {
            return Ok(None);
        }
        let action_id = operation_blocker_action_id(operation, persisted.attempt);
        Ok(ManualActionQueue::new(self.journal.clone())
            .get(run_id, &action_id)?
            .map(|action| (action_id, action.state)))
    }

    fn queue_blocked_operation_action(
        &self,
        run_id: &RunId,
        operation: &Operation,
        attempt: u32,
        outcome: Option<&Value>,
    ) -> RestoreResult<()> {
        let action = operation_blocker_action(operation, attempt, outcome);
        ManualActionQueue::new(self.journal.clone()).create(run_id, &action)?;
        Ok(())
    }

    fn persist_failure(
        &self,
        run_id: &RunId,
        operation: &Operation,
        error: Box<ErrorEnvelope>,
        backup: Option<Value>,
    ) -> Box<ErrorEnvelope> {
        let error = correlate_error(operation, &error);
        if let Err(journal_error) = self.journal.transition_operation(
            run_id,
            &operation.id,
            OperationState::Failed,
            None,
            Some((*error).clone()),
            backup,
        ) {
            return journal_error;
        }
        match self.journal.set_run_status(run_id, RunStatus::Failed) {
            Ok(_) => error,
            Err(journal_error) => journal_error,
        }
    }

    fn persist_blocked_retry(
        &self,
        run_id: &RunId,
        operation: &Operation,
        error: Box<ErrorEnvelope>,
    ) -> Box<ErrorEnvelope> {
        let error = correlate_error(operation, &error);
        if let Err(journal_error) = self.journal.transition_operation(
            run_id,
            &operation.id,
            OperationState::Failed,
            Some(json!({"reason": "NON_IDEMPOTENT_RETRY_BLOCKED"})),
            Some((*error).clone()),
            None,
        ) {
            return journal_error;
        }
        match self
            .journal
            .set_run_status(run_id, RunStatus::WaitingForUser)
        {
            Ok(_) => error,
            Err(journal_error) => journal_error,
        }
    }

    async fn cancelled_report(&self, run_id: &RunId) -> RestoreResult<ExecutionReport> {
        let run = self.journal.set_run_status(run_id, RunStatus::Cancelled)?;
        self.report(run_id, run.status)
    }

    fn cancelled_operation_report(
        &self,
        plan: &RestorePlan,
        states: &mut BTreeMap<OperationId, JournalOperation>,
        operation: &Operation,
        backup: Option<Value>,
    ) -> RestoreResult<ExecutionReport> {
        let error = correlated_code_error(
            operation,
            reforge_domain::ReforgeErrorCode::Cancelled,
            "restore operation was cancelled",
        );
        let updated = self.journal.transition_operation(
            &plan.run_id,
            &operation.id,
            OperationState::Cancelled,
            Some(outcome_payload(
                Some(json!({"reason": "CANCELLED"})),
                Vec::new(),
                Some("CANCELLED"),
            )),
            Some(*error),
            backup,
        )?;
        states.insert(operation.id.clone(), updated);
        let run = self
            .journal
            .set_run_status(&plan.run_id, RunStatus::Cancelled)?;
        self.report(&plan.run_id, run.status)
    }

    fn report(&self, run_id: &RunId, status: RunStatus) -> RestoreResult<ExecutionReport> {
        Ok(ExecutionReport {
            run_id: run_id.clone(),
            status,
            operations: self.journal.list_operations(run_id)?,
        })
    }
}

fn prerequisites_complete(
    operation: &Operation,
    states: &BTreeMap<OperationId, JournalOperation>,
) -> bool {
    operation.prerequisites.iter().all(|prerequisite| {
        states.get(prerequisite).is_some_and(|operation| {
            matches!(
                operation.state,
                OperationState::Completed | OperationState::Skipped
            )
        })
    })
}

fn has_waiting_for_user_prerequisite(
    operation: &Operation,
    states: &BTreeMap<OperationId, JournalOperation>,
) -> bool {
    operation.prerequisites.iter().any(|prerequisite| {
        states
            .get(prerequisite)
            .is_some_and(|persisted| persisted.state == OperationState::WaitingForUser)
    })
}

fn precondition_error(operation: &Operation) -> Box<ErrorEnvelope> {
    let (code, message) = match &operation.precondition {
        Precondition::ManualApproval { .. } => (
            reforge_domain::ReforgeErrorCode::UserActionRequired,
            "operation requires an acknowledged manual action",
        ),
        Precondition::ArtifactPresent { .. } => (
            reforge_domain::ReforgeErrorCode::PackageNotFound,
            "required package object is unavailable",
        ),
        _ => (
            reforge_domain::ReforgeErrorCode::TargetConflict,
            "operation precondition no longer holds on the target",
        ),
    };
    correlated_code_error(operation, code, message)
}

fn execution_error(
    operation: &Operation,
    code: reforge_domain::ReforgeErrorCode,
    message: &str,
) -> Box<ErrorEnvelope> {
    correlated_code_error(operation, code, message)
}

fn correlated_code_error(
    operation: &Operation,
    code: reforge_domain::ReforgeErrorCode,
    message: &str,
) -> Box<ErrorEnvelope> {
    restore_error(
        code,
        message,
        None,
        Some(operation.component.clone()),
        Some(operation.id.clone()),
        None,
    )
}

fn correlate_error(operation: &Operation, error: &ErrorEnvelope) -> Box<ErrorEnvelope> {
    let mut error = error.clone();
    error.component = Some(operation.component.clone());
    error.operation = Some(operation.id.clone());
    Box::new(error)
}

fn outcome_payload(result: Option<Value>, evidence: Vec<Value>, reason: Option<&str>) -> Value {
    let mut payload = Map::new();
    payload.insert("result".to_owned(), result.unwrap_or(Value::Null));
    payload.insert("evidence".to_owned(), Value::Array(evidence));
    if let Some(reason) = reason {
        payload.insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    Value::Object(payload)
}

fn combine_backup(first: Option<Value>, second: Option<Value>) -> Option<Value> {
    match (first, second) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(first), Some(second)) => Some(json!({
            "executor": first,
            "handler": second,
        })),
    }
}
