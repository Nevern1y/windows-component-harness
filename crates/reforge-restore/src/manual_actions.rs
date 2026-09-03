//! Durable user-action handling and the explicit secret restore boundary.
//!
//! Manual actions are persisted through [`Journal`] and are safe to replay:
//! acknowledgement, completion, and skipping are monotonic transitions.  The
//! secret gate keeps decrypted records inside this module until a target
//! adapter has proved its policy; reports and manual actions contain only IDs
//! and redacted metadata, never secret bytes.

use std::collections::BTreeSet;

use async_trait::async_trait;
use reforge_domain::{
    ComponentId, ErrorEnvelope, ManualAction, ManualActionState, Operation, OperationKind,
    OperationState, ReforgeErrorCode, RiskLevel, RunId, VerificationRule,
};
use reforge_package::{
    EncryptedVault, SecretRecord, SecretSelection, SecretString, SecretTarget, VaultDocument,
};
use reforge_platform_windows::CancellationToken;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    RestoreResult,
    executor::{OperationHandler, OperationOutcome, OperationSatisfaction},
    journal::{Journal, JournalManualAction},
    restore_error,
};

const MAX_MANUAL_TEXT_BYTES: usize = 1_024;
const MAX_MANUAL_INSTRUCTIONS: usize = 256;

/// Durable queue for actions that cannot be completed automatically.
///
/// The journal remains the source of truth.  `create` is an idempotent ensure:
/// re-planning or resuming a run returns the existing row when its immutable
/// display fields match, while a same-ID conflict is rejected.
#[derive(Clone)]
pub struct ManualActionQueue {
    journal: Journal,
}

impl ManualActionQueue {
    /// Bind a queue to an existing restore journal.
    pub fn new(journal: Journal) -> Self {
        Self { journal }
    }

    /// Return the backing journal for executor/application integration.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Ensure one safe action exists in the run and return its durable row.
    pub fn create(
        &self,
        run_id: &RunId,
        action: &ManualAction,
    ) -> RestoreResult<JournalManualAction> {
        let action = normalize_manual_action(action)?;
        if let Some(existing) = self.get(run_id, &action.id)? {
            return self.ensure_matches(&existing, &action);
        }

        match self.journal.add_manual_action(run_id, &action) {
            Ok(created) => Ok(created),
            Err(error) => {
                // A concurrent creator may have won the insert race.  Read
                // again before returning a duplicate-key failure so retries
                // remain idempotent without weakening conflict detection.
                if let Some(existing) = self.get(run_id, &action.id)? {
                    self.ensure_matches(&existing, &action)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Read one durable action by run and stable action ID.
    pub fn get(
        &self,
        run_id: &RunId,
        action_id: &str,
    ) -> RestoreResult<Option<JournalManualAction>> {
        let action_id = safe_action_id(action_id)?;
        Ok(self
            .journal
            .list_manual_actions(run_id)?
            .into_iter()
            .find(|action| action.id == action_id))
    }

    /// List all durable actions in deterministic ID order.
    pub fn list(&self, run_id: &RunId) -> RestoreResult<Vec<JournalManualAction>> {
        self.journal.list_manual_actions(run_id)
    }

    /// List actions still waiting for the user to acknowledge them.
    pub fn pending(&self, run_id: &RunId) -> RestoreResult<Vec<JournalManualAction>> {
        Ok(self
            .list(run_id)?
            .into_iter()
            .filter(|action| action.state == ManualActionState::Pending)
            .collect())
    }

    /// List actions that are not in a terminal completed/skipped state.
    pub fn unresolved(&self, run_id: &RunId) -> RestoreResult<Vec<JournalManualAction>> {
        Ok(self
            .list(run_id)?
            .into_iter()
            .filter(|action| {
                !matches!(
                    action.state,
                    ManualActionState::Completed | ManualActionState::Skipped
                )
            })
            .collect())
    }

    /// Persist that the user has acknowledged an action.
    pub fn acknowledge(
        &self,
        run_id: &RunId,
        action_id: &str,
    ) -> RestoreResult<JournalManualAction> {
        self.transition(run_id, action_id, ManualActionState::Acknowledged)
    }

    /// Persist that the user intentionally skipped an action.
    pub fn skip(&self, run_id: &RunId, action_id: &str) -> RestoreResult<JournalManualAction> {
        self.transition(run_id, action_id, ManualActionState::Skipped)
    }

    /// Persist that the action was completed and is ready for verification.
    pub fn complete(&self, run_id: &RunId, action_id: &str) -> RestoreResult<JournalManualAction> {
        self.transition(run_id, action_id, ManualActionState::Completed)
    }

    /// Return whether an action state authorizes its operation to proceed.
    pub fn is_acknowledged(state: &ManualActionState) -> bool {
        matches!(
            state,
            ManualActionState::Acknowledged
                | ManualActionState::Completed
                | ManualActionState::Skipped
        )
    }

    fn transition(
        &self,
        run_id: &RunId,
        action_id: &str,
        state: ManualActionState,
    ) -> RestoreResult<JournalManualAction> {
        let action_id = safe_action_id(action_id)?;
        self.journal
            .set_manual_action_state(run_id, &action_id, state)
    }

    fn ensure_matches(
        &self,
        existing: &JournalManualAction,
        action: &ManualAction,
    ) -> RestoreResult<JournalManualAction> {
        if existing.id == action.id
            && existing.title == action.title
            && existing.reason == action.reason
            && existing.risk == action.risk
            && existing.instructions == action.instructions
        {
            Ok(existing.clone())
        } else {
            Err(queue_error(
                ReforgeErrorCode::SecurityPolicy,
                "manual action identity is already bound to different instructions",
            ))
        }
    }
}

/// Return the deterministic action ID for one user-blocked operation attempt.
///
/// Attempts are part of the identity so acknowledgement is bound to exactly
/// the retry the user reviewed. A subsequent blocked retry creates a new,
/// pending action rather than silently reusing a stale acknowledgement.
pub(crate) fn operation_blocker_action_id(operation: &Operation, attempt: u32) -> String {
    format!("operation-blocker:{}:{attempt}", operation.id)
}

/// Build a redacted manual action for a runtime operation blocker.
///
/// Handlers may return target/provider diagnostics in their result payload.
/// Only a bounded, redacted `reason` is copied into the queue; malformed or
/// unsafe diagnostics fall back to static text rather than crossing the user
/// action boundary.
pub(crate) fn operation_blocker_action(
    operation: &Operation,
    attempt: u32,
    outcome: Option<&Value>,
) -> ManualAction {
    let reason = outcome
        .and_then(|outcome| outcome.get("reason"))
        .and_then(Value::as_str)
        .and_then(|reason| safe_manual_text(reason, "operation blocker reason").ok())
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| {
            "The operation requires a documented user action before it can be retried.".to_owned()
        });
    ManualAction {
        id: operation_blocker_action_id(operation, attempt),
        component: Some(operation.component.clone()),
        title: "Resolve restore blocker".to_owned(),
        reason,
        risk: RiskLevel::High,
        instructions: vec![
            "Review the redacted operation result and resolve the documented blocker."
                .to_owned(),
            "Acknowledge this action only after the target, provider, source, lock, reauthentication, or policy condition is resolved."
                .to_owned(),
            "Resume the existing run; Reforge will recheck the operation before continuing."
                .to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    }
}

/// Operation handler for the closed manual-action and reboot operation kinds.
///
/// An acknowledged manual action completes its operation on the next resume;
/// a skipped action becomes a skipped operation.  A reboot operation pauses
/// once and is considered satisfied by an explicit subsequent resume, without
/// executing any package-supplied command.
pub struct ManualActionHandler {
    queue: ManualActionQueue,
}

impl ManualActionHandler {
    /// Construct the handler against the journal used by the executor.
    pub fn new(journal: Journal) -> Self {
        Self {
            queue: ManualActionQueue::new(journal),
        }
    }

    /// Construct a handler from an existing queue.
    pub fn from_queue(queue: ManualActionQueue) -> Self {
        Self { queue }
    }

    /// Return the queue used by this handler for UI/CLI acknowledgements.
    pub fn queue(&self) -> &ManualActionQueue {
        &self.queue
    }
}

#[async_trait]
impl OperationHandler for ManualActionHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::OpenManualAction { .. } | OperationKind::RequireReboot { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        _context: &crate::ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        match &operation.kind {
            OperationKind::OpenManualAction { .. } => {
                let persisted = self.load_action(operation)?;
                if persisted.state == ManualActionState::Skipped {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "manual_action_id": persisted.id,
                        "status": "SKIPPED",
                    }))))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
            OperationKind::RequireReboot { .. } => {
                let run_id = operation_run_id(operation)?;
                let persisted = self
                    .queue
                    .journal()
                    .get_operation(&run_id, &operation.id)?
                    .ok_or_else(|| {
                        operation_error(operation, "reboot operation is missing from journal")
                    })?;
                if persisted.state == OperationState::WaitingForReboot {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "status": "REBOOT_RESUME_ACKNOWLEDGED",
                    }))))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
            _ => Err(operation_error(
                operation,
                "manual-action handler received an unsupported operation kind",
            )),
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        _context: &crate::ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "cancelled": true,
            }))));
        }

        match &operation.kind {
            OperationKind::OpenManualAction { .. } => {
                let persisted = self.load_action(operation)?;
                match persisted.state {
                    ManualActionState::Pending => {
                        Ok(OperationOutcome::waiting_for_user(Some(json!({
                            "manual_action_id": persisted.id,
                            "state": "PENDING",
                        }))))
                    }
                    ManualActionState::Acknowledged => {
                        let run_id = operation_run_id(operation)?;
                        let completed = self.queue.complete(&run_id, &persisted.id)?;
                        Ok(OperationOutcome::completed(Some(json!({
                            "manual_action_id": completed.id,
                            "state": manual_state_label(&completed.state),
                        }))))
                    }
                    ManualActionState::Completed => Ok(OperationOutcome::completed(Some(json!({
                        "manual_action_id": persisted.id,
                        "state": manual_state_label(&persisted.state),
                    })))),
                    ManualActionState::Skipped => Ok(OperationOutcome::skipped(Some(json!({
                        "manual_action_id": persisted.id,
                        "state": manual_state_label(&persisted.state),
                    })))),
                }
            }
            OperationKind::RequireReboot { .. } => Ok(OperationOutcome::waiting_for_reboot(Some(
                json!({"reboot_required": true}),
            ))),
            _ => Err(operation_error(
                operation,
                "manual-action handler received an unsupported operation kind",
            )),
        }
    }
}

impl ManualActionHandler {
    fn load_action(&self, operation: &Operation) -> RestoreResult<JournalManualAction> {
        let OperationKind::OpenManualAction { action } = &operation.kind else {
            return Err(operation_error(
                operation,
                "manual-action handler received a non-action operation",
            ));
        };
        let expected = normalize_manual_action(action)?;
        let run_id = operation_run_id(operation)?;
        let persisted = self.queue.get(&run_id, &expected.id)?.ok_or_else(|| {
            operation_error(operation, "manual action is missing from the journal")
        })?;
        if persisted.title != expected.title
            || persisted.reason != expected.reason
            || persisted.risk != expected.risk
            || persisted.instructions != expected.instructions
        {
            return Err(operation_error(
                operation,
                "journal manual action differs from the approved operation",
            ));
        }
        Ok(persisted)
    }
}

/// Adapter boundary for restoring one already-decrypted secret record.
///
/// The gate invokes `secure_target_policy_proven` before passing a record to
/// `restore_secret`.  Implementations must write only to the supplied secure
/// target and must not retain, serialize, log, or return the value.
pub trait SecretRestoreAdapter {
    /// Prove that this adapter's target handling is secure for this target.
    fn secure_target_policy_proven(&self, target: &SecretTarget) -> bool;

    /// Restore a record at the adapter boundary.  The record contains a
    /// zeroizing value and is dropped by the gate after this call returns.
    fn restore_secret(&mut self, record: &SecretRecord) -> RestoreResult<()>;
}

/// Redacted result of a secret restore attempt.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SecretRestoreReport {
    /// Component IDs whose values were handed to a proven secure adapter.
    pub restored: Vec<ComponentId>,
    /// Manual actions created for targets that were not proven secure.
    pub manual_actions: Vec<ManualAction>,
    /// Safe warnings explaining why no plaintext value was written.
    pub warnings: Vec<String>,
}

/// Explicit vault decryption and secure-target gate.
#[derive(Clone)]
pub struct SecretRestoreGate {
    queue: ManualActionQueue,
}

impl SecretRestoreGate {
    /// Construct a gate backed by the run journal.
    pub fn new(journal: Journal) -> Self {
        Self {
            queue: ManualActionQueue::new(journal),
        }
    }

    /// Construct a gate from an existing manual-action queue.
    pub fn from_queue(queue: ManualActionQueue) -> Self {
        Self { queue }
    }

    /// Return the queue used for insecure-target actions.
    pub fn queue(&self) -> &ManualActionQueue {
        &self.queue
    }

    /// Decrypt and restore only explicitly selected records using a passphrase.
    pub fn restore_with_passphrase(
        &self,
        run_id: &RunId,
        vault: &EncryptedVault,
        selection: &SecretSelection,
        passphrase: SecretString,
        adapter: &mut dyn SecretRestoreAdapter,
    ) -> RestoreResult<SecretRestoreReport> {
        if selection.is_empty() {
            return Err(secret_error(
                ReforgeErrorCode::VaultRequired,
                "At least one secret must be explicitly selected for restore",
            ));
        }
        let document = vault.decrypt_with_passphrase(passphrase).map_err(|_| {
            secret_error(
                ReforgeErrorCode::VaultDecryptFailed,
                "Unable to decrypt the selected secret vault",
            )
        })?;
        self.restore_document(run_id, document, selection, adapter)
    }

    /// Decrypt and restore only explicitly selected records using a recovery identity.
    pub fn restore_with_recovery_identity(
        &self,
        run_id: &RunId,
        vault: &EncryptedVault,
        selection: &SecretSelection,
        recovery_identity: &SecretString,
        adapter: &mut dyn SecretRestoreAdapter,
    ) -> RestoreResult<SecretRestoreReport> {
        if selection.is_empty() {
            return Err(secret_error(
                ReforgeErrorCode::VaultRequired,
                "At least one secret must be explicitly selected for restore",
            ));
        }
        let document = vault
            .decrypt_with_recovery_identity(recovery_identity)
            .map_err(|_| {
                secret_error(
                    ReforgeErrorCode::VaultDecryptFailed,
                    "Unable to decrypt the selected secret vault",
                )
            })?;
        self.restore_document(run_id, document, selection, adapter)
    }

    fn restore_document(
        &self,
        run_id: &RunId,
        document: VaultDocument,
        selection: &SecretSelection,
        adapter: &mut dyn SecretRestoreAdapter,
    ) -> RestoreResult<SecretRestoreReport> {
        // Validate the entire explicit selection before handing any value to
        // an adapter, preventing a malformed selection from causing a partial
        // secret restore.
        let available: BTreeSet<_> = document
            .records
            .iter()
            .map(|record| record.id.clone())
            .collect();
        if selection.iter().any(|id| !available.contains(id)) {
            return Err(secret_error(
                ReforgeErrorCode::VaultRequired,
                "An explicitly selected secret is absent from the vault",
            ));
        }

        let mut report = SecretRestoreReport::default();
        for record in document.records {
            if !selection.contains(&record.id) {
                continue;
            }

            if !secure_target_proven(&record.target, adapter) {
                let action = secret_target_action(run_id, &record);
                let persisted = self.queue.create(run_id, &action)?;
                let mut action = action;
                action.state = persisted.state;
                action.acknowledged_at = persisted.acknowledged_at;
                report.warnings.push(format!(
                    "Secret {} has no proven secure target; no plaintext value was written",
                    record.id
                ));
                report.manual_actions.push(action);
                continue;
            }

            adapter.restore_secret(&record).map_err(|_| {
                secret_error(
                    ReforgeErrorCode::OperationFailed,
                    "The secure secret target adapter could not restore the selected secret",
                )
            })?;
            report.restored.push(record.id.clone());
        }
        Ok(report)
    }
}

fn secure_target_proven(target: &SecretTarget, adapter: &dyn SecretRestoreAdapter) -> bool {
    !matches!(target, SecretTarget::Manual) && adapter.secure_target_policy_proven(target)
}

fn secret_target_action(run_id: &RunId, record: &SecretRecord) -> ManualAction {
    ManualAction {
        id: format!("manual-action:{run_id}:secret-target:{}", record.id),
        component: Some(record.id.clone()),
        title: "Review secret restore target".to_owned(),
        reason: "The selected secret target is plaintext or has no proven secure adapter policy"
            .to_owned(),
        risk: reforge_domain::RiskLevel::Critical,
        instructions: vec![
            "Choose an adapter-specific secure target before restoring this secret".to_owned(),
            "Resume the restore after the secure target is available".to_owned(),
        ],
        docs_url: None,
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: Some(VerificationRule::SecureTarget {
            secret: record.id.clone(),
        }),
    }
}

fn normalize_manual_action(action: &ManualAction) -> RestoreResult<ManualAction> {
    if action.instructions.len() > MAX_MANUAL_INSTRUCTIONS {
        return Err(queue_error(
            ReforgeErrorCode::SecurityPolicy,
            "manual action has too many instructions",
        ));
    }
    let mut normalized = action.clone();
    normalized.id = safe_action_id(&action.id)?;
    normalized.title = safe_manual_text(&action.title, "manual action title")?;
    normalized.reason = safe_manual_text(&action.reason, "manual action reason")?;
    normalized.instructions = action
        .instructions
        .iter()
        .map(|instruction| safe_manual_text(instruction, "manual action instruction"))
        .collect::<RestoreResult<Vec<_>>>()?;
    Ok(normalized)
}

fn safe_manual_text(value: &str, field: &str) -> RestoreResult<String> {
    let safe = reforge_domain::RedactionPolicy::default()
        .redact_text(value)
        .ok_or_else(|| {
            queue_error(
                ReforgeErrorCode::SecurityPolicy,
                "manual action text is unsafe",
            )
        })?;
    if safe.is_empty() || safe.len() > MAX_MANUAL_TEXT_BYTES || safe.chars().any(char::is_control) {
        return Err(queue_error(
            ReforgeErrorCode::SchemaInvalid,
            &format!("{field} is invalid"),
        ));
    }
    Ok(safe)
}

fn safe_action_id(value: &str) -> RestoreResult<String> {
    let safe = safe_manual_text(value, "manual action ID")?;
    if safe != value {
        return Err(queue_error(
            ReforgeErrorCode::SecurityPolicy,
            "manual action ID contains sensitive text",
        ));
    }
    Ok(safe)
}

fn operation_run_id(operation: &Operation) -> RestoreResult<RunId> {
    let Some(remainder) = operation.id.as_str().strip_prefix("op_") else {
        return Err(operation_error(operation, "operation ID has no run prefix"));
    };
    let Some((run, _ordinal)) = remainder.rsplit_once('_') else {
        return Err(operation_error(
            operation,
            "operation ID has no run component",
        ));
    };
    RunId::try_from(run.to_owned())
        .map_err(|_| operation_error(operation, "operation ID contains an invalid run"))
}

fn manual_state_label(state: &ManualActionState) -> &'static str {
    match state {
        ManualActionState::Pending => "PENDING",
        ManualActionState::Acknowledged => "ACKNOWLEDGED",
        ManualActionState::Completed => "COMPLETED",
        ManualActionState::Skipped => "SKIPPED",
    }
}

fn queue_error(code: ReforgeErrorCode, message: &str) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, Some("manual-action-queue"))
}

fn secret_error(code: ReforgeErrorCode, message: &str) -> Box<ErrorEnvelope> {
    restore_error(code, message, None, None, None, Some("secret-restore"))
}

fn operation_error(operation: &Operation, message: &str) -> Box<ErrorEnvelope> {
    restore_error(
        ReforgeErrorCode::OperationFailed,
        message,
        None,
        Some(operation.component.clone()),
        Some(operation.id.clone()),
        Some("manual-action-operation"),
    )
}
