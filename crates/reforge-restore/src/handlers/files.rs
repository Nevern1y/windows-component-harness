//! Reparse-safe atomic `WriteFile` restore handler.

use std::{fs, sync::Arc};

use async_trait::async_trait;
use reforge_domain::{FileMode, Operation, OperationKind, ReforgeErrorCode};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use serde_json::json;

use super::{
    DEFAULT_MAX_OBJECT_BYTES, atomic_write, io_error, operation_error, read_existing_file,
    read_verified_artifact, reject_protected_root, resolve_destination, target_attributes,
    validate_artifact,
};
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

/// Handler for generic tokenized file replacement.
#[derive(Clone, Debug)]
pub struct FileRestoreHandler {
    roots: KnownFolderMap,
    max_object_bytes: u64,
}

impl FileRestoreHandler {
    pub fn new(roots: KnownFolderMap) -> Self {
        Self {
            roots,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }

    pub fn with_max_object_bytes(mut self, max_object_bytes: u64) -> RestoreResult<Self> {
        if max_object_bytes == 0 {
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "file handler object limit must be nonzero",
            ));
        }
        self.max_object_bytes = max_object_bytes;
        Ok(self)
    }

    pub fn roots(&self) -> &KnownFolderMap {
        &self.roots
    }

    fn destination(&self, operation: &Operation) -> RestoreResult<super::ResolvedDestination> {
        let OperationKind::WriteFile { destination, .. } = &operation.kind else {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "file handler received an unsupported operation kind",
            ));
        };
        reject_protected_root(destination)?;
        resolve_destination(&self.roots, destination)
    }
}

#[async_trait]
impl OperationHandler for FileRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::WriteFile { .. })
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        if cancellation.is_cancelled() {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let destination = self.destination(operation)?;
        let OperationKind::WriteFile { object, .. } = &operation.kind else {
            unreachable!("handles restricts file operations");
        };
        let expected = validate_artifact(context, object, self.max_object_bytes)?;
        let Some((bytes, _metadata)) = read_existing_file(&destination, self.max_object_bytes)?
        else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        if !expected.matches_bytes(&bytes) {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let digest = *blake3::hash(&bytes).as_bytes();
        Ok(OperationSatisfaction::satisfied(Some(json!({
            "destination": destination.relative.as_str(),
            "bytes": bytes.len(),
            "blake3": blake3::Hash::from_bytes(digest).to_hex().to_string(),
        })))
        .with_evidence([verified_file_evidence(
            destination.relative.as_str(),
            object,
            bytes.len() as u64,
            digest,
        )]))
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "reason": "cancelled before file commit",
            }))));
        }
        let destination = self.destination(operation)?;
        let OperationKind::WriteFile { object, mode, .. } = &operation.kind else {
            unreachable!("handles restricts file operations");
        };
        let metadata = match fs::symlink_metadata(&destination.absolute) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(operation_error(
                        ReforgeErrorCode::TargetConflict,
                        "file restore destination is not a regular file",
                    ));
                }
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error("inspect file restore destination", &error)),
        };
        if matches!(mode, FileMode::CreateOnly) && metadata.is_some() {
            return Err(operation_error(
                ReforgeErrorCode::TargetConflict,
                "create-only file restore destination already exists",
            ));
        }
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "reason": "cancelled before object read",
            }))));
        }
        let artifact = read_verified_artifact(context, object, self.max_object_bytes)?;
        let attributes = if matches!(mode, FileMode::PreserveTarget) {
            target_attributes(metadata.as_ref())
        } else {
            Default::default()
        };
        let replaced = atomic_write(&destination, &artifact, attributes)?;
        let digest = artifact.digest();
        let mut outcome = OperationOutcome::completed(Some(json!({
            "changed": true,
            "destination": destination.relative.as_str(),
            "bytes": artifact.bytes().len(),
        })))
        .with_evidence([verified_file_evidence(
            destination.relative.as_str(),
            object,
            artifact.bytes().len() as u64,
            digest,
        )]);
        if let Some(backup) = replaced.backup {
            outcome = outcome.with_backup(json!({
                "path": backup.path.as_str(),
                "original_bytes": backup.original_bytes,
                "original_attributes": {
                    "read_only": backup.original_attributes.read_only,
                    "hidden": backup.original_attributes.hidden,
                    "archive": backup.original_attributes.archive,
                    "not_content_indexed": backup.original_attributes.not_content_indexed,
                }
            }));
        }
        Ok(outcome)
    }
}

fn verified_file_evidence(
    destination: &str,
    object: &reforge_domain::ObjectId,
    bytes: u64,
    digest: [u8; 32],
) -> serde_json::Value {
    json!({
        "destination": destination,
        "object_id": object.as_str(),
        "bytes": bytes,
        "blake3": blake3::Hash::from_bytes(digest).to_hex().to_string(),
    })
}

/// Keep the handler object cheap to pass through future registries.
pub type SharedFileRestoreHandler = Arc<FileRestoreHandler>;
