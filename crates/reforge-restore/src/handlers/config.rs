//! Safe JSON/JSONC and TOML merge restore handler.

use std::str::FromStr;

use async_trait::async_trait;
use reforge_domain::{ContentType, MergePolicy, Operation, OperationKind, ReforgeErrorCode};
use reforge_platform_windows::{
    AtomicWriteSpec, CancellationToken, KnownFolderMap, atomic_replace,
};
use serde_json::{Map, Value, json};

use super::{
    DEFAULT_MAX_OBJECT_BYTES, content_type_allowed, operation_error, read_existing_file,
    read_verified_object, reject_protected_root, resolve_destination, target_attributes,
    verified_evidence,
};
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

/// Handler for the explicitly supported JSON/JSONC/TOML merge policies.
#[derive(Clone, Debug)]
pub struct ConfigRestoreHandler {
    roots: KnownFolderMap,
    max_object_bytes: u64,
}

impl ConfigRestoreHandler {
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
                "config handler object limit must be nonzero",
            ));
        }
        self.max_object_bytes = max_object_bytes;
        Ok(self)
    }

    pub fn roots(&self) -> &KnownFolderMap {
        &self.roots
    }

    fn destination(&self, operation: &Operation) -> RestoreResult<super::ResolvedDestination> {
        let destination = match &operation.kind {
            OperationKind::MergeJson { destination, .. }
            | OperationKind::MergeToml { destination, .. } => destination,
            _ => {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "config handler received an unsupported operation kind",
                ));
            }
        };
        reject_protected_root(destination)?;
        resolve_destination(&self.roots, destination)
    }
}

#[async_trait]
impl OperationHandler for ConfigRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        _context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        if cancellation.is_cancelled() {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let destination = self.destination(operation)?;
        let Some((bytes, _metadata)) = read_existing_file(&destination, self.max_object_bytes)?
        else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        match operation.kind {
            OperationKind::MergeJson { .. } => {
                parse_json_config(&bytes, "target JSON configuration")?;
            }
            OperationKind::MergeToml { .. } => {
                parse_toml_config(&bytes, "target TOML configuration")?;
            }
            _ => unreachable!("handles restricts config operations"),
        }
        // A merge's desired result depends on both the package object and the
        // current target.  The executor therefore performs the complete merge
        // instead of guessing that a parseable target is already satisfied.
        Ok(OperationSatisfaction::NotSatisfied)
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "reason": "cancelled before config merge",
            }))));
        }
        let destination = self.destination(operation)?;
        let existing = read_existing_file(&destination, self.max_object_bytes)?;
        let (object, policy, kind) = match &operation.kind {
            OperationKind::MergeJson { object, policy, .. } => (object, policy, ConfigKind::Json),
            OperationKind::MergeToml { object, policy, .. } => (object, policy, ConfigKind::Toml),
            _ => unreachable!("handles restricts config operations"),
        };
        let (entry, source_bytes) = read_verified_object(context, object, self.max_object_bytes)?;
        match kind {
            ConfigKind::Json => {
                content_type_allowed(&entry, [ContentType::Json, ContentType::Jsonc])?;
                let source = parse_json_config(&source_bytes, "package JSON configuration")?;
                let target = existing
                    .as_ref()
                    .map(|(bytes, _)| parse_json_config(bytes, "target JSON configuration"))
                    .transpose()?
                    .unwrap_or_else(|| Value::Object(Map::new()));
                let (merged, waiting) = merge_json_document(target.clone(), source, policy);
                if waiting {
                    return Ok(OperationOutcome::waiting_for_user(Some(json!({
                        "changed": false,
                        "reason": "configuration conflict requires review",
                        "destination": destination.relative.as_str(),
                    }))));
                }
                if merged == target {
                    return Ok(OperationOutcome::skipped(Some(json!({
                        "changed": false,
                        "destination": destination.relative.as_str(),
                        "reason": "merge produced no changes",
                    }))));
                }
                let bytes = serde_json::to_vec_pretty(&merged).map_err(|_| {
                    operation_error(
                        ReforgeErrorCode::OperationFailed,
                        "merged JSON configuration could not be serialized",
                    )
                })?;
                self.commit(
                    &destination,
                    &bytes,
                    existing.as_ref().map(|(_, metadata)| metadata),
                    "json",
                )
            }
            ConfigKind::Toml => {
                content_type_allowed(&entry, [ContentType::Toml])?;
                let source = parse_toml_config(&source_bytes, "package TOML configuration")?;
                let target = existing
                    .as_ref()
                    .map(|(bytes, _)| parse_toml_config(bytes, "target TOML configuration"))
                    .transpose()?
                    .unwrap_or_default();
                let (merged, waiting) = merge_toml_document(target.clone(), source, policy);
                if waiting {
                    return Ok(OperationOutcome::waiting_for_user(Some(json!({
                        "changed": false,
                        "reason": "configuration conflict requires review",
                        "destination": destination.relative.as_str(),
                    }))));
                }
                if merged == target {
                    return Ok(OperationOutcome::skipped(Some(json!({
                        "changed": false,
                        "destination": destination.relative.as_str(),
                        "reason": "merge produced no changes",
                    }))));
                }
                let bytes = toml::to_string_pretty(&merged)
                    .map(|text| text.into_bytes())
                    .map_err(|_| {
                        operation_error(
                            ReforgeErrorCode::OperationFailed,
                            "merged TOML configuration could not be serialized",
                        )
                    })?;
                self.commit(
                    &destination,
                    &bytes,
                    existing.as_ref().map(|(_, metadata)| metadata),
                    "toml",
                )
            }
        }
    }
}

impl ConfigRestoreHandler {
    fn commit(
        &self,
        destination: &super::ResolvedDestination,
        bytes: &[u8],
        existing: Option<&std::fs::Metadata>,
        kind: &str,
    ) -> RestoreResult<OperationOutcome> {
        let digest = *blake3::hash(bytes).as_bytes();
        let replaced = atomic_replace(
            &destination.root,
            &destination.relative,
            std::io::Cursor::new(bytes),
            AtomicWriteSpec {
                expected_bytes: bytes.len() as u64,
                expected_blake3: digest,
                attributes: target_attributes(existing),
            },
        )?;
        let mut outcome = OperationOutcome::completed(Some(json!({
            "changed": true,
            "kind": kind,
            "destination": destination.relative.as_str(),
            "bytes": bytes.len(),
        })))
        .with_evidence([verified_evidence(
            destination.relative.as_str(),
            bytes.len() as u64,
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

#[derive(Clone, Copy)]
enum ConfigKind {
    Json,
    Toml,
}

fn parse_json_config(bytes: &[u8], context: &str) -> RestoreResult<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is not UTF-8"),
        )
    })?;
    let sanitized = strip_jsonc(text)?;
    let value: Value = serde_json::from_slice(&sanitized).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is malformed or unsupported"),
        )
    })?;
    if !value.is_object() {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} must contain a top-level object"),
        ));
    }
    Ok(value)
}

fn parse_toml_config(bytes: &[u8], context: &str) -> RestoreResult<toml::Table> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is not UTF-8"),
        )
    })?;
    let value = toml::Table::from_str(text).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is malformed or unsupported"),
        )
    })?;
    Ok(value)
}

fn strip_jsonc(text: &str) -> RestoreResult<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            let start = index;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "JSONC block comment is unterminated",
                ));
            }
            index += 2;
            if start == index {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "JSONC block comment is invalid",
                ));
            }
            continue;
        }
        if byte == b',' {
            let mut lookahead = index + 1;
            while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
                lookahead += 1;
            }
            if matches!(bytes.get(lookahead), Some(b']' | b'}')) {
                index += 1;
                continue;
            }
        }
        output.push(byte);
        index += 1;
    }
    if in_string || escaped {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "JSONC string is unterminated",
        ));
    }
    Ok(output)
}

fn merge_json_document(mut target: Value, source: Value, policy: &MergePolicy) -> (Value, bool) {
    let target_object = target.as_object_mut().expect("parser returns objects");
    let source_object = source.as_object().expect("parser returns objects");
    if matches!(policy, MergePolicy::ManualOnConflict)
        && json_has_conflict(&Value::Object(target_object.clone()), &source)
    {
        return (target, true);
    }
    for (key, value) in source_object {
        match policy {
            MergePolicy::PreserveUnknown | MergePolicy::ManualOnConflict => merge_json_preserving(
                target_object.entry(key.clone()).or_insert(Value::Null),
                value,
            ),
            MergePolicy::ReplaceKnownKeys => {
                target_object.insert(key.clone(), value.clone());
            }
            MergePolicy::AppendUnique => merge_json_append(
                target_object.entry(key.clone()).or_insert(Value::Null),
                value,
            ),
        }
    }
    (target, false)
}

fn merge_json_preserving(target: &mut Value, source: &Value) {
    if let Value::Object(target_object) = target
        && let Value::Object(source_object) = source
    {
        for (key, value) in source_object {
            merge_json_preserving(
                target_object.entry(key.clone()).or_insert(Value::Null),
                value,
            );
        }
        return;
    }
    *target = source.clone();
}

fn merge_json_append(target: &mut Value, source: &Value) {
    match (target, source) {
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                merge_json_append(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (Value::Array(target), Value::Array(source)) => {
            for value in source {
                if !target.contains(value) {
                    target.push(value.clone());
                }
            }
        }
        (target, source) => *target = source.clone(),
    }
}

fn json_has_conflict(target: &Value, source: &Value) -> bool {
    let (Value::Object(target), Value::Object(source)) = (target, source) else {
        return target != source;
    };
    source.iter().any(|(key, source_value)| {
        target
            .get(key)
            .is_some_and(|target_value| json_has_conflict(target_value, source_value))
    })
}

fn merge_toml_document(
    mut target: toml::Table,
    source: toml::Table,
    policy: &MergePolicy,
) -> (toml::Table, bool) {
    if matches!(policy, MergePolicy::ManualOnConflict) && toml_has_conflict(&target, &source) {
        return (target, true);
    }
    for (key, value) in source {
        match policy {
            MergePolicy::PreserveUnknown | MergePolicy::ManualOnConflict => merge_toml_preserving(
                target
                    .entry(key)
                    .or_insert(toml::Value::String(String::new())),
                value,
            ),
            MergePolicy::ReplaceKnownKeys => {
                target.insert(key, value);
            }
            MergePolicy::AppendUnique => merge_toml_append(
                target
                    .entry(key)
                    .or_insert(toml::Value::String(String::new())),
                value,
            ),
        }
    }
    (target, false)
}

fn merge_toml_preserving(target: &mut toml::Value, source: toml::Value) {
    if let toml::Value::Table(target_table) = target
        && let toml::Value::Table(source_table) = &source
    {
        for (key, value) in source_table {
            merge_toml_preserving(
                target_table
                    .entry(key.clone())
                    .or_insert(toml::Value::String(String::new())),
                value.clone(),
            );
        }
        return;
    }
    *target = source;
}

fn merge_toml_append(target: &mut toml::Value, source: toml::Value) {
    match (target, source) {
        (toml::Value::Table(target), toml::Value::Table(source)) => {
            for (key, value) in source {
                merge_toml_append(
                    target
                        .entry(key)
                        .or_insert(toml::Value::String(String::new())),
                    value,
                );
            }
        }
        (toml::Value::Array(target), toml::Value::Array(source)) => {
            for value in source {
                if !target.contains(&value) {
                    target.push(value);
                }
            }
        }
        (target, source) => *target = source,
    }
}

fn toml_has_conflict(target: &toml::Table, source: &toml::Table) -> bool {
    source.iter().any(|(key, source_value)| {
        target
            .get(key)
            .is_some_and(|target_value| match (target_value, source_value) {
                (toml::Value::Table(target), toml::Value::Table(source)) => {
                    toml_has_conflict(target, source)
                }
                _ => target_value != source_value,
            })
    })
}
