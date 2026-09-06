//! Docker image and volume restore handlers.
//!
//! Docker is reached only through the reviewed built-in executable and typed
//! argv.  Image archives are loaded and then inspected by immutable identity;
//! volume archives are extracted with a pinned, locally available helper image
//! and never trigger a network pull.

use std::{ffi::OsString, sync::Arc, time::Duration};

use async_trait::async_trait;
use reforge_domain::{
    ComponentKind, ContentType, DockerImageSpec, DockerVolumeSpec, Operation, OperationKind,
    ReforgeErrorCode, TargetFacts,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, TrustedExecutable,
};
use serde_json::{Value, json};

use super::{ProviderProcessBridge, stage_subsystem_artifact, subsystem_capacity_waiting};
use crate::handlers::operation_error;
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

const PROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const LOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const VOLUME_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const MAX_REPOSITORY_BYTES: usize = 512;
const MAX_TAG_BYTES: usize = 128;
const MAX_IMAGE_ID_BYTES: usize = 80;
const MAX_VOLUME_NAME_BYTES: usize = 255;
const HELPER_IMAGE_REFERENCE: &str = "busybox:1.36.1";

/// Restores Docker images and volumes from reviewed archive objects.
pub struct DockerRestoreHandler {
    bridge: Arc<dyn ProviderProcessBridge>,
}

impl DockerRestoreHandler {
    /// Use the real shell-free Windows process runner.
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(reforge_platform_windows::ProcessRunner::new()),
        }
    }

    /// Use a caller-supplied process boundary for deterministic tests and
    /// offline environments.
    pub fn with_bridge<B>(bridge: Arc<B>) -> Self
    where
        B: ProviderProcessBridge + 'static,
    {
        Self { bridge }
    }

    /// Use an already-erased process boundary.
    pub fn from_bridge(bridge: Arc<dyn ProviderProcessBridge>) -> Self {
        Self { bridge }
    }

    async fn execute_image(
        &self,
        image: &DockerImageSpec,
        object: &reforge_domain::ObjectId,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        validate_image(image)?;
        if cancellation.is_cancelled() {
            return Ok(cancelled_image(image));
        }
        if target_contains_image(context.target, image) {
            return Ok(OperationOutcome::skipped(Some(json!({
                "subsystem": "docker",
                "kind": "image",
                "reference": image_reference(image),
                "already_present": true,
            }))));
        }
        if !provider_available(context.target)
            || !self.bridge.builtin_available(BuiltinExecutable::Docker)
        {
            return Ok(waiting_for_docker(
                "docker.exe is unavailable or the Docker provider is not ready",
            ));
        }
        if let Some(outcome) = subsystem_capacity_waiting(context, object, "docker")? {
            return Ok(outcome);
        }

        let Some(staged) =
            stage_subsystem_artifact(context, object, ContentType::Archive, cancellation)?
        else {
            return Ok(cancelled_image(image));
        };
        let archive = archive_argument(&staged)?;
        if cancellation.is_cancelled() {
            return Ok(cancelled_image(image));
        }
        let load = self
            .bridge
            .run(
                &docker_command(["load", "--input", archive.as_str()], LOAD_TIMEOUT)?,
                cancellation,
            )
            .await?;
        if load.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_image(image));
        }
        if !process_succeeded(&load) {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "Docker image load failed",
            ));
        }

        if cancellation.is_cancelled() {
            return Ok(cancelled_image(image));
        }
        let reference = image_reference(image);
        let verification = self
            .bridge
            .run(
                &docker_command(
                    [
                        "image",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        reference.as_str(),
                    ],
                    VERIFY_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if verification.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_image(image));
        }
        if !process_succeeded(&verification) || !docker_image_verified(&verification.stdout, image)
        {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "Docker image load could not be verified by immutable identity",
            ));
        }

        Ok(OperationOutcome::completed(Some(json!({
            "subsystem": "docker",
            "kind": "image",
            "reference": reference,
            "image_id": image.image_id,
            "restored": true,
        })))
        .with_evidence([json!({
            "kind": "docker_image",
            "reference": image_reference(image),
            "image_id": image.image_id,
            "object": object.as_str(),
            "verified": true,
        })]))
    }

    async fn execute_volume(
        &self,
        volume: &DockerVolumeSpec,
        object: &reforge_domain::ObjectId,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        validate_volume(volume)?;
        if cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !provider_available(context.target)
            || !self.bridge.builtin_available(BuiltinExecutable::Docker)
        {
            return Ok(waiting_for_docker(
                "docker.exe is unavailable or the Docker provider is not ready",
            ));
        }
        if target_contains_volume(context.target, volume) {
            return Ok(waiting_for_docker(
                "the target volume already exists and its data cannot be replaced automatically",
            ));
        }
        if let Some(outcome) = subsystem_capacity_waiting(context, object, "docker")? {
            return Ok(outcome);
        }

        if cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        let daemon = self
            .bridge
            .run(
                &docker_command(["info", "--format", "{{.ServerVersion}}"], VERIFY_TIMEOUT)?,
                cancellation,
            )
            .await?;
        if daemon.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !process_succeeded(&daemon) {
            return Ok(waiting_for_docker("the Docker daemon is not ready"));
        }

        let helper = self
            .bridge
            .run(
                &docker_command(
                    [
                        "image",
                        "inspect",
                        "--format",
                        "{{.Id}}",
                        HELPER_IMAGE_REFERENCE,
                    ],
                    VERIFY_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if helper.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !process_succeeded(&helper) {
            return Ok(waiting_for_docker(
                "the pinned local archive helper image is unavailable; pull it explicitly before retrying",
            ));
        }
        let Some(helper_id) = immutable_image_id(&helper.stdout) else {
            return Ok(waiting_for_docker(
                "the pinned local archive helper image has no immutable image ID; inspect or replace it before retrying",
            ));
        };

        let volume_inspect = self
            .bridge
            .run(
                &docker_command(
                    [
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        volume.name.as_str(),
                    ],
                    VERIFY_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if volume_inspect.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if volume_inspect.timed_out || volume_inspect.exit_code.is_none() {
            return Ok(waiting_for_docker(
                "the target volume could not be inspected safely",
            ));
        }
        if volume_inspect.exit_code == Some(0) {
            return Ok(waiting_for_docker(
                "the target volume already exists and its data cannot be replaced automatically",
            ));
        }

        let Some(staged) =
            stage_subsystem_artifact(context, object, ContentType::Archive, cancellation)?
        else {
            return Ok(cancelled_volume(volume));
        };
        let archive = archive_argument(&staged)?;
        let mut create_args = vec![OsString::from("volume"), OsString::from("create")];
        if let Some(driver) = volume.driver.as_deref() {
            create_args.push(OsString::from("--driver"));
            create_args.push(OsString::from(driver));
        }
        create_args.push(OsString::from("--name"));
        create_args.push(OsString::from(&volume.name));

        if cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        let created = self
            .bridge
            .run(&docker_command(create_args, VOLUME_TIMEOUT)?, cancellation)
            .await?;
        if created.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !process_succeeded(&created) {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "Docker volume creation failed",
            ));
        }

        let mount_volume = format!("type=volume,source={},destination=/restore", volume.name);
        let mount_archive = format!(
            "type=bind,source={},destination=/restore.tar,readonly",
            archive
        );
        let restore = self
            .bridge
            .run(
                &docker_command(
                    [
                        "run",
                        "--rm",
                        "--pull=never",
                        "--mount",
                        mount_volume.as_str(),
                        "--mount",
                        mount_archive.as_str(),
                        helper_id.as_str(),
                        "tar",
                        "-xf",
                        "/restore.tar",
                        "-C",
                        "/restore",
                    ],
                    VOLUME_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if restore.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !process_succeeded(&restore) {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "Docker volume archive extraction failed",
            ));
        }

        let verification = self
            .bridge
            .run(
                &docker_command(
                    [
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        volume.name.as_str(),
                    ],
                    VERIFY_TIMEOUT,
                )?,
                cancellation,
            )
            .await?;
        if verification.cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_volume(volume));
        }
        if !process_succeeded(&verification)
            || !docker_volume_verified(&verification.stdout, volume)
        {
            return Err(operation_error(
                ReforgeErrorCode::VerificationFailed,
                "Docker volume restore could not be verified",
            ));
        }

        Ok(OperationOutcome::completed(Some(json!({
            "subsystem": "docker",
            "kind": "volume",
            "name": volume.name,
            "driver": volume.driver,
            "restored": true,
        })))
        .with_evidence([json!({
            "kind": "docker_volume",
            "name": volume.name,
            "driver": volume.driver,
            "object": object.as_str(),
            "verified": true,
        })]))
    }
}

impl Default for DockerRestoreHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OperationHandler for DockerRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::RestoreDockerImage { .. } | OperationKind::RestoreDockerVolume { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        _cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        match &operation.kind {
            OperationKind::RestoreDockerImage { image, .. } => {
                validate_image(image)?;
                if target_contains_image(context.target, image) {
                    Ok(OperationSatisfaction::satisfied(Some(json!({
                        "subsystem": "docker",
                        "kind": "image",
                        "reference": image_reference(image),
                        "already_present": true,
                    })))
                    .with_evidence([json!({
                        "kind": "docker_image",
                        "reference": image_reference(image),
                        "image_id": image.image_id,
                        "verified": true,
                    })]))
                } else {
                    Ok(OperationSatisfaction::NotSatisfied)
                }
            }
            OperationKind::RestoreDockerVolume { volume, .. } => {
                validate_volume(volume)?;
                // A volume name proves existence, not that its archive data is
                // complete.  Reapplying an unverified archive is unsafe.
                Ok(OperationSatisfaction::NotSatisfied)
            }
            _ => Ok(OperationSatisfaction::NotSatisfied),
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        match &operation.kind {
            OperationKind::RestoreDockerImage { image, object } => {
                self.execute_image(image, object, context, cancellation)
                    .await
            }
            OperationKind::RestoreDockerVolume { volume, object } => {
                self.execute_volume(volume, object, context, cancellation)
                    .await
            }
            _ => Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "Docker handler received an unsupported operation kind",
            )),
        }
    }
}

fn validate_image(image: &DockerImageSpec) -> RestoreResult<()> {
    if !valid_reference_part(&image.repository, MAX_REPOSITORY_BYTES, true)
        || image.repository.starts_with('.')
        || image.repository.ends_with('.')
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "Docker image repository is invalid",
        ));
    }
    if let Some(tag) = image.tag.as_deref()
        && (tag.is_empty()
            || tag.len() > MAX_TAG_BYTES
            || !tag.chars().enumerate().all(|(index, character)| {
                character.is_ascii_alphanumeric()
                    || (index > 0 && matches!(character, '_' | '.' | '-'))
            }))
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "Docker image tag is invalid",
        ));
    }
    if let Some(image_id) = image.image_id.as_deref() {
        let valid = image_id.len() == 71
            && image_id.starts_with("sha256:")
            && image_id[7..].bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid || image_id.len() > MAX_IMAGE_ID_BYTES {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "Docker image identity is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_volume(volume: &DockerVolumeSpec) -> RestoreResult<()> {
    if !valid_reference_part(&volume.name, MAX_VOLUME_NAME_BYTES, false) {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "Docker volume name is invalid",
        ));
    }
    if let Some(driver) = volume.driver.as_deref()
        && !valid_reference_part(driver, MAX_VOLUME_NAME_BYTES, true)
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "Docker volume driver is invalid",
        ));
    }
    Ok(())
}

fn valid_reference_part(value: &str, max_bytes: usize, allow_separator: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '.' | '-')
                || (allow_separator && matches!(character, '/' | ':'))
        })
}

fn image_reference(image: &DockerImageSpec) -> String {
    match image.tag.as_deref() {
        Some(tag) => format!("{}:{tag}", image.repository),
        None => image.repository.clone(),
    }
}

fn docker_command(
    args: impl IntoIterator<Item = impl Into<OsString>>,
    timeout: Duration,
) -> RestoreResult<CommandSpec> {
    CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::Docker),
        args,
        timeout,
        PROCESS_OUTPUT_BYTES,
    )
}

fn process_succeeded(result: &ProcessResult) -> bool {
    !result.timed_out && !result.cancelled && result.exit_code == Some(0)
}

fn provider_available(target: &TargetFacts) -> bool {
    target
        .providers
        .iter()
        .any(|fact| fact.id.as_str() == "docker" && fact.available)
}

fn target_contains_image(target: &TargetFacts, image: &DockerImageSpec) -> bool {
    let expected = image.image_id.as_deref().map_or_else(
        || format!("image:{}", image_reference(image)),
        |image_id| format!("image:{image_id}"),
    );
    target.installed.iter().any(|fact| {
        fact.kind == ComponentKind::DockerImage
            && fact.identity.provider_source.as_deref() == Some("image")
            && fact
                .identity
                .provider_package
                .as_ref()
                .is_some_and(|(provider, package)| {
                    provider.as_str() == "docker" && package == &expected
                })
    })
}

fn target_contains_volume(target: &TargetFacts, volume: &DockerVolumeSpec) -> bool {
    target.installed.iter().any(|fact| {
        fact.kind == ComponentKind::DockerVolume
            && fact.identity.provider_source.as_deref() == Some("volume")
            && fact
                .identity
                .provider_package
                .as_ref()
                .is_some_and(|(provider, package)| {
                    provider.as_str() == "docker" && package == &format!("volume:{}", volume.name)
                })
    })
}

fn archive_argument(staged: &super::StagedSubsystemObject) -> RestoreResult<String> {
    let archive = staged.path.to_string_lossy().into_owned();
    if archive.is_empty() || archive.contains(',') || archive.contains('\0') {
        return Err(operation_error(
            ReforgeErrorCode::SecurityPolicy,
            "the temporary archive path cannot be represented safely as a Docker mount",
        ));
    }
    Ok(archive)
}

fn immutable_image_id(stdout: &str) -> Option<String> {
    let image_id = stdout.trim();
    let valid = image_id.len() == 71
        && image_id.starts_with("sha256:")
        && image_id[7..].bytes().all(|byte| byte.is_ascii_hexdigit());
    valid.then(|| image_id.to_owned())
}

fn docker_image_verified(stdout: &str, image: &DockerImageSpec) -> bool {
    if stdout.len() > PROCESS_OUTPUT_BYTES {
        return false;
    }
    let documents = parse_json_documents(stdout);
    let reference = image_reference(image);
    let repository_prefix = format!("{}:", image.repository);
    let mut identity_verified = image.image_id.is_none();
    let mut reference_verified = image.tag.is_none() && image.image_id.is_some();
    for document in documents {
        let Some(object) = document.as_object() else {
            continue;
        };
        if let Some(expected_id) = image.image_id.as_deref()
            && object.get("Id").and_then(Value::as_str) == Some(expected_id)
        {
            identity_verified = true;
        }
        if let Some(tags) = object.get("RepoTags").and_then(Value::as_array) {
            for tag in tags.iter().filter_map(Value::as_str) {
                let tag_matches = (image.tag.is_some() && tag == reference)
                    || (image.tag.is_none()
                        && (tag == image.repository || tag.starts_with(&repository_prefix)));
                if tag_matches {
                    reference_verified = true;
                }
            }
        }
    }
    identity_verified && reference_verified
}

fn docker_volume_verified(stdout: &str, volume: &DockerVolumeSpec) -> bool {
    if stdout.len() > PROCESS_OUTPUT_BYTES {
        return false;
    }
    let json_matches = parse_json_documents(stdout).iter().any(|document| {
        document.as_object().is_some_and(|object| {
            object.get("Name").and_then(Value::as_str) == Some(volume.name.as_str())
                && volume.driver.as_deref().is_none_or(|driver| {
                    object.get("Driver").and_then(Value::as_str) == Some(driver)
                })
        })
    });
    json_matches
        || (volume.driver.is_none() && stdout.lines().any(|line| line.trim() == volume.name))
}

fn parse_json_documents(stdout: &str) -> Vec<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return match value {
            Value::Array(values) => values,
            value => vec![value],
        };
    }
    trimmed
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .flat_map(|value| match value {
            Value::Array(values) => values,
            value => vec![value],
        })
        .collect()
}

fn waiting_for_docker(reason: &'static str) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "subsystem": "docker",
        "manual_action_required": true,
        "reason": reason,
    })))
}

fn cancelled_image(image: &DockerImageSpec) -> OperationOutcome {
    OperationOutcome::cancelled(Some(json!({
        "subsystem": "docker",
        "kind": "image",
        "reference": image_reference(image),
        "cancelled": true,
    })))
}

fn cancelled_volume(volume: &DockerVolumeSpec) -> OperationOutcome {
    OperationOutcome::cancelled(Some(json!({
        "subsystem": "docker",
        "kind": "volume",
        "name": volume.name,
        "cancelled": true,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_docker_references_without_shell_metacharacters() {
        assert!(
            validate_image(&DockerImageSpec {
                repository: "ghcr.io/contoso/editor".to_owned(),
                tag: Some("1.2.3".to_owned()),
                image_id: Some(format!("sha256:{}", "a".repeat(64))),
            })
            .is_ok()
        );
        assert!(
            validate_image(&DockerImageSpec {
                repository: "--privileged".to_owned(),
                tag: None,
                image_id: None,
            })
            .is_err()
        );
        assert!(
            validate_volume(&DockerVolumeSpec {
                name: "workspace-data".to_owned(),
                driver: Some("local".to_owned()),
            })
            .is_ok()
        );
        assert!(
            validate_volume(&DockerVolumeSpec {
                name: "../../escape".to_owned(),
                driver: None,
            })
            .is_err()
        );
    }

    #[test]
    fn verifies_image_identity_and_tag_from_inspect_json() {
        let image = DockerImageSpec {
            repository: "ghcr.io/contoso/editor".to_owned(),
            tag: Some("1.2.3".to_owned()),
            image_id: Some(format!("sha256:{}", "b".repeat(64))),
        };
        let output = format!(
            r#"{{"Id":"{}","RepoTags":["ghcr.io/contoso/editor:1.2.3"]}}"#,
            image.image_id.as_deref().expect("test image id")
        );
        assert!(docker_image_verified(&output, &image));
        assert!(!docker_image_verified(
            &output.replace("1.2.3", "9.9.9"),
            &image
        ));
    }

    #[test]
    fn verifies_volume_identity_and_recorded_driver_from_inspect_json() {
        let volume = DockerVolumeSpec {
            name: "workspace-data".to_owned(),
            driver: Some("local".to_owned()),
        };
        assert!(docker_volume_verified(
            r#"{"Name":"workspace-data","Driver":"local"}"#,
            &volume
        ));
        assert!(!docker_volume_verified(
            r#"{"Name":"workspace-data","Driver":"other"}"#,
            &volume
        ));
        assert!(!docker_volume_verified("workspace-data", &volume));

        let unrecorded_driver = DockerVolumeSpec {
            name: "workspace-data".to_owned(),
            driver: None,
        };
        assert!(docker_volume_verified("workspace-data", &unrecorded_driver));
        assert!(!docker_volume_verified(
            r#"{"Name":"other"}"#,
            &unrecorded_driver
        ));
    }
}
