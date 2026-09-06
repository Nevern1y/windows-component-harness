//! Restore handlers for AI harness MCP configuration.
//!
//! The package object is used only as a verified source-shape witness.  MCP
//! values are rebuilt from the normalized [`McpServerSpec`], so raw package
//! configuration (and especially secret literals) never crosses the write
//! boundary.

use std::io::Cursor;

use async_trait::async_trait;
use reforge_domain::{
    ArtifactPolicy, ContentType, EnvBinding, McpEndpoint, McpServerSpec, McpTransport,
    McpWorkingDirectory, Operation, OperationKind, ReforgeErrorCode, SafeValueRef,
};
use reforge_platform_windows::{
    AtomicWriteSpec, CancellationToken, KnownFolderMap, atomic_replace,
};
use serde_json::{Map, Value, json};

use super::{
    DEFAULT_MAX_OBJECT_BYTES, operation_error, read_existing_file, read_verified_artifact,
    reject_protected_root, resolve_destination, target_attributes, validate_artifact,
    verified_evidence,
};
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

const MAX_MCP_VALUE_BYTES: usize = 64 * 1024;
const MAX_MCP_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAX_SOURCE_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Restore a normalized MCP registration without copying raw configuration.
#[derive(Clone, Debug)]
pub struct HarnessRestoreHandler {
    roots: KnownFolderMap,
    max_object_bytes: u64,
}

impl HarnessRestoreHandler {
    /// Construct a handler bound to the current target's known-folder map.
    pub fn new(roots: KnownFolderMap) -> Self {
        Self {
            roots,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }

    /// Use an already validated object limit for deterministic callers/tests.
    pub fn with_max_object_bytes(mut self, max_object_bytes: u64) -> RestoreResult<Self> {
        if max_object_bytes == 0 || max_object_bytes > MAX_SOURCE_DOCUMENT_BYTES {
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "MCP handler object limit is outside the reviewed bound",
            ));
        }
        self.max_object_bytes = max_object_bytes;
        Ok(self)
    }

    /// Return the target roots used for token resolution.
    pub fn roots(&self) -> &KnownFolderMap {
        &self.roots
    }

    fn destination(&self, server: &McpServerSpec) -> RestoreResult<super::ResolvedDestination> {
        reject_protected_root(&server.source_config.source_path)?;
        resolve_destination(&self.roots, &server.source_config.source_path)
    }

    fn validate_source_reference(
        &self,
        context: &ExecutionContext<'_>,
        server: &McpServerSpec,
    ) -> RestoreResult<()> {
        validate_safe_text(&server.name, 256, "MCP server name")?;
        if server.source_config.policy != ArtifactPolicy::Config {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "MCP source artifact is not a non-secret config artifact",
            ));
        }
        let Some(object) = &server.source_config.object else {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "MCP source artifact has no content object",
            ));
        };
        let artifact = validate_artifact(context, object, self.max_object_bytes)?;
        if artifact.size_bytes() > MAX_SOURCE_DOCUMENT_BYTES {
            return Err(operation_error(
                ReforgeErrorCode::SecurityPolicy,
                "MCP source configuration exceeds the reviewed size bound",
            ));
        }
        if !compatible_content_type(&server.source_config.content_type, artifact.content_type()) {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "MCP source artifact content type conflicts with its inspected file metadata",
            ));
        }
        Ok(())
    }

    fn parse_target(
        &self,
        destination: &super::ResolvedDestination,
        content_type: &ContentType,
    ) -> RestoreResult<Option<ParsedTarget>> {
        let Some((bytes, metadata)) = read_existing_file(destination, self.max_object_bytes)?
        else {
            return Ok(None);
        };
        let parsed = match content_type {
            ContentType::Json | ContentType::Jsonc => ParsedTarget::Json {
                value: parse_json_document(&bytes, "target MCP JSON configuration")?,
                metadata,
            },
            ContentType::Toml => ParsedTarget::Toml {
                value: parse_toml_document(&bytes, "target MCP TOML configuration")?,
                metadata,
            },
            _ => {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "MCP configuration must be JSON, JSONC, or TOML",
                ));
            }
        };
        Ok(Some(parsed))
    }

    fn write_json(
        &self,
        destination: &super::ResolvedDestination,
        existing: Option<&ParsedTarget>,
        server: &McpServerSpec,
        source_container: &str,
        safe: &SafeServer,
    ) -> RestoreResult<OperationOutcome> {
        let (mut document, metadata) = match existing {
            Some(ParsedTarget::Json { value, metadata }) => (value.clone(), Some(metadata)),
            Some(ParsedTarget::Toml { .. }) => {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "target MCP configuration format does not match the source",
                ));
            }
            None => (Value::Object(Map::new()), None),
        };
        let root = document.as_object_mut().ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "target MCP JSON configuration must contain a top-level object",
            )
        })?;
        let container = choose_container(root, source_container);
        let servers = root
            .entry(container.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        let servers = servers.as_object_mut().ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "target MCP server container must be an object",
            )
        })?;
        merge_safe_server_json(servers, server, safe)?;
        let bytes = serde_json::to_vec_pretty(&document).map_err(|_| {
            operation_error(
                ReforgeErrorCode::OperationFailed,
                "normalized MCP JSON configuration could not be serialized",
            )
        })?;
        self.commit(destination, &bytes, metadata, server, safe, "json")
    }

    fn write_toml(
        &self,
        destination: &super::ResolvedDestination,
        existing: Option<&ParsedTarget>,
        server: &McpServerSpec,
        source_container: &str,
        safe: &SafeServer,
    ) -> RestoreResult<OperationOutcome> {
        let (mut document, metadata) = match existing {
            Some(ParsedTarget::Toml { value, metadata }) => (value.clone(), Some(metadata)),
            Some(ParsedTarget::Json { .. }) => {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "target MCP configuration format does not match the source",
                ));
            }
            None => (toml::Table::new(), None),
        };
        let container = choose_container_toml(&document, source_container);
        let servers = document
            .entry(container.to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let servers = servers.as_table_mut().ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "target MCP server container must be a TOML table",
            )
        })?;
        merge_safe_server_toml(servers, server, safe)?;
        let bytes = toml::to_string_pretty(&document)
            .map(|text| text.into_bytes())
            .map_err(|_| {
                operation_error(
                    ReforgeErrorCode::OperationFailed,
                    "normalized MCP TOML configuration could not be serialized",
                )
            })?;
        self.commit(destination, &bytes, metadata, server, safe, "toml")
    }

    fn commit(
        &self,
        destination: &super::ResolvedDestination,
        bytes: &[u8],
        metadata: Option<&std::fs::Metadata>,
        server: &McpServerSpec,
        safe: &SafeServer,
        format: &str,
    ) -> RestoreResult<OperationOutcome> {
        if metadata.is_some()
            && let Some((current, _)) = read_existing_file(destination, self.max_object_bytes)?
            && current == bytes
        {
            let digest = *blake3::hash(bytes).as_bytes();
            let mut outcome = OperationOutcome::skipped(Some(json!({
                "changed": false,
                "format": format,
                "server": server.name,
                "destination": destination.relative.as_str(),
                "secret_references": safe.secret_references,
                "reauth_required": safe.reauth_required,
                "reason": if safe.reauth_required {
                    "normalized MCP registration is present; bind the referenced secret or sign in before use"
                } else {
                    "normalized MCP registration is already present"
                },
            })))
            .with_evidence([verified_evidence(
                destination.relative.as_str(),
                bytes.len() as u64,
                digest,
            )]);
            if safe.reauth_required {
                outcome.disposition = crate::OperationDisposition::WaitingForUser;
            }
            return Ok(outcome);
        }
        let digest = *blake3::hash(bytes).as_bytes();
        let replaced = atomic_replace(
            &destination.root,
            &destination.relative,
            Cursor::new(bytes),
            AtomicWriteSpec {
                expected_bytes: bytes.len() as u64,
                expected_blake3: digest,
                attributes: target_attributes(metadata),
            },
        )?;
        let mut outcome = OperationOutcome::completed(Some(json!({
            "changed": true,
            "format": format,
            "server": server.name,
            "destination": destination.relative.as_str(),
            "secret_references": safe.secret_references,
            "reauth_required": safe.reauth_required,
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
                },
            }));
        }
        if safe.reauth_required {
            outcome.disposition = crate::OperationDisposition::WaitingForUser;
            outcome.result = Some(json!({
                "changed": true,
                "format": format,
                "server": server.name,
                "destination": destination.relative.as_str(),
                "secret_references": safe.secret_references,
                "reauth_required": true,
                "manual_action_required": true,
                "reason": "secret-bearing MCP values were not written; sign in or bind the referenced environment/vault values",
            }));
        }
        Ok(outcome)
    }
}

#[async_trait]
impl OperationHandler for HarnessRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(kind, OperationKind::RegisterMcp { .. })
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
        let OperationKind::RegisterMcp { server } = &operation.kind else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        self.validate_source_reference(context, server)?;
        if server_has_secret_or_unknown(server)
            || server.required_runtime.is_some()
            || server.required_package.is_some()
        {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let destination = self.destination(server)?;
        let Some(existing) = self.parse_target(&destination, &server.source_config.content_type)?
        else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        let safe = safe_server(server, &self.roots)?;
        if safe.reauth_required || safe.blocking_secret {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        let matches = match &existing {
            ParsedTarget::Json { value, .. } => json_server_matches(value, server, &safe.value),
            ParsedTarget::Toml { value, .. } => toml_server_matches(value, server, &safe.value),
        };
        if matches {
            Ok(OperationSatisfaction::satisfied(Some(json!({
                "changed": false,
                "server": server.name,
                "destination": destination.relative.as_str(),
                "reason": "normalized MCP registration is already present",
            })))
            .with_evidence([json!({
                "destination": destination.relative.as_str(),
                "server": server.name,
                "verified": true,
            })]))
        } else {
            Ok(OperationSatisfaction::NotSatisfied)
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "cancelled": true,
            }))));
        }
        let OperationKind::RegisterMcp { server } = &operation.kind else {
            return Err(operation_error(
                ReforgeErrorCode::OperationFailed,
                "MCP handler received an unsupported operation kind",
            ));
        };
        self.validate_source_reference(context, server)?;
        let destination = self.destination(server)?;
        let Some(object) = &server.source_config.object else {
            return Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "MCP source artifact has no content object",
            ));
        };
        let source = read_verified_artifact(context, object, self.max_object_bytes)?;
        let source_document = parse_source_document(source.bytes(), source.content_type().clone())?;
        let source_container =
            source_container_for(&source_document, &server.name).ok_or_else(|| {
                operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "normalized MCP server is absent from its source configuration",
                )
            })?;
        if let Some(runtime) = &server.required_runtime
            && !context
                .target
                .runtimes
                .iter()
                .any(|fact| &fact.id == runtime)
        {
            return Ok(waiting_for_manual(
                "required MCP runtime is not present on the target",
                server,
                &destination,
            ));
        }
        if let Some(package) = &server.required_package
            && !target_has_package(context, package)
        {
            return Ok(waiting_for_manual(
                "required MCP package is not present at the recorded identity and version",
                server,
                &destination,
            ));
        }
        let safe = match safe_server(server, &self.roots) {
            Ok(safe) => safe,
            Err(error) if error.code == ReforgeErrorCode::ManualActionRequired => {
                return Ok(waiting_for_manual(&error.message, server, &destination));
            }
            Err(error) => return Err(error),
        };
        if safe.blocking_secret {
            return Ok(waiting_for_manual(
                "MCP registration contains a secret argument, endpoint, or working directory that requires reauthentication",
                server,
                &destination,
            ));
        }
        let existing = self.parse_target(&destination, &server.source_config.content_type)?;
        match &server.source_config.content_type {
            ContentType::Json | ContentType::Jsonc => self.write_json(
                &destination,
                existing.as_ref(),
                server,
                &source_container,
                &safe,
            ),
            ContentType::Toml => self.write_toml(
                &destination,
                existing.as_ref(),
                server,
                &source_container,
                &safe,
            ),
            _ => Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "MCP configuration must be JSON, JSONC, or TOML",
            )),
        }
    }
}

#[derive(Debug)]
enum ParsedTarget {
    Json {
        value: Value,
        metadata: std::fs::Metadata,
    },
    Toml {
        value: toml::Table,
        metadata: std::fs::Metadata,
    },
}

#[derive(Clone, Debug)]
struct SafeServer {
    value: Map<String, Value>,
    secret_references: Vec<String>,
    reauth_required: bool,
    blocking_secret: bool,
}

fn compatible_content_type(declared: &ContentType, indexed: &ContentType) -> bool {
    matches!(
        (declared, indexed),
        (ContentType::Json, ContentType::Json | ContentType::Jsonc)
            | (ContentType::Jsonc, ContentType::Json | ContentType::Jsonc)
            | (ContentType::Toml, ContentType::Toml)
    )
}

fn parse_source_document(bytes: &[u8], content_type: ContentType) -> RestoreResult<Value> {
    match content_type {
        ContentType::Json | ContentType::Jsonc => {
            parse_json_document(bytes, "source MCP JSON configuration")
        }
        ContentType::Toml => {
            let table = parse_toml_document(bytes, "source MCP TOML configuration")?;
            serde_json::to_value(table).map_err(|_| {
                operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "source MCP TOML configuration could not be normalized for inspection",
                )
            })
        }
        _ => Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "MCP configuration must be JSON, JSONC, or TOML",
        )),
    }
}

fn parse_json_document(bytes: &[u8], context: &str) -> RestoreResult<Value> {
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

fn parse_toml_document(bytes: &[u8], context: &str) -> RestoreResult<toml::Table> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is not UTF-8"),
        )
    })?;
    toml::from_str(text).map_err(|_| {
        operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{context} is malformed or unsupported"),
        )
    })
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
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(operation_error(
                    ReforgeErrorCode::SchemaInvalid,
                    "MCP JSONC block comment is unterminated",
                ));
            }
            index += 2;
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
            "MCP JSONC string is unterminated",
        ));
    }
    Ok(output)
}

fn source_container_for(document: &Value, server_name: &str) -> Option<String> {
    let object = document.as_object()?;
    let mut found = None;
    for key in ["mcpServers", "mcp_servers", "mcp"] {
        if let Some(servers) = object.get(key) {
            if found.is_some() {
                return None;
            }
            if servers
                .as_object()
                .is_some_and(|servers| servers.contains_key(server_name))
            {
                found = Some(key.to_owned());
            }
        }
    }
    found
}

fn choose_container<'a>(root: &Map<String, Value>, source: &'a str) -> &'a str {
    ["mcpServers", "mcp_servers", "mcp"]
        .into_iter()
        .find(|key| root.contains_key(*key))
        .unwrap_or(source)
}

fn choose_container_toml<'a>(root: &toml::Table, source: &'a str) -> &'a str {
    ["mcp_servers", "mcpServers", "mcp"]
        .into_iter()
        .find(|key| root.contains_key(*key))
        .unwrap_or(source)
}

fn safe_server(server: &McpServerSpec, roots: &KnownFolderMap) -> RestoreResult<SafeServer> {
    match server.transport {
        McpTransport::Stdio if server.command.is_none() || server.endpoint.is_some() => {
            return Err(operation_error(
                ReforgeErrorCode::ManualActionRequired,
                "MCP stdio transport requires one reviewed command and no network endpoint",
            ));
        }
        McpTransport::StreamableHttp | McpTransport::Sse
            if server.command.is_some() || server.endpoint.is_none() =>
        {
            return Err(operation_error(
                ReforgeErrorCode::ManualActionRequired,
                "MCP network transport requires one reviewed endpoint and no local command",
            ));
        }
        McpTransport::Unknown => {
            return Err(operation_error(
                ReforgeErrorCode::ManualActionRequired,
                "MCP transport is unsupported and requires manual review",
            ));
        }
        _ => {}
    }
    let mut value = Map::new();
    let mut secret_references = Vec::new();
    let mut reauth_required = false;
    let mut blocking_secret = false;
    value.insert(
        "type".to_owned(),
        Value::String(
            match server.transport {
                McpTransport::Stdio => "stdio",
                McpTransport::StreamableHttp => "http",
                McpTransport::Sse => "sse",
                McpTransport::Unknown => unreachable!("unknown transport rejected above"),
            }
            .to_owned(),
        ),
    );
    if let Some(command) = &server.command {
        validate_safe_text(&command.name, MAX_MCP_VALUE_BYTES, "MCP command")?;
        if reforge_domain::redact_text(&command.name).as_deref() != Some(command.name.as_str()) {
            return Err(operation_error(
                ReforgeErrorCode::ManualActionRequired,
                "MCP command identity contains unreviewed path or secret-like text",
            ));
        }
        value.insert("command".to_owned(), Value::String(command.name.clone()));
    }

    let mut args = Vec::with_capacity(server.args.len());
    for argument in &server.args {
        match safe_value(argument, &mut secret_references, &mut reauth_required) {
            Some(text) => args.push(Value::String(text)),
            None => {
                blocking_secret = true;
                break;
            }
        }
    }
    if !server.args.is_empty() && !blocking_secret {
        value.insert("args".to_owned(), Value::Array(args));
    }

    if let Some(cwd) = &server.cwd {
        match cwd {
            McpWorkingDirectory::Tokenized(path) => {
                let resolved = roots.resolve(path).map_err(|_| {
                    operation_error(
                        ReforgeErrorCode::PathNotFound,
                        "MCP working directory root is unavailable on this target",
                    )
                })?;
                let text = resolved.to_string_lossy().into_owned();
                validate_safe_text(&text, MAX_MCP_VALUE_BYTES, "MCP working directory")?;
                value.insert("cwd".to_owned(), Value::String(text));
            }
            McpWorkingDirectory::EnvironmentReference { name } => {
                validate_environment_name(name)?;
                value.insert("cwd".to_owned(), Value::String(format!("${{{name}}}")));
            }
            McpWorkingDirectory::SecretReference { id, .. } => {
                secret_references.push(id.as_str().to_owned());
                reauth_required = true;
                blocking_secret = true;
            }
            McpWorkingDirectory::RedactedUnknown => {
                reauth_required = true;
                blocking_secret = true;
            }
        }
    }

    if let Some(endpoint) = &server.endpoint {
        match endpoint {
            McpEndpoint::Public(url) => {
                if !matches!(url.scheme(), "http" | "https")
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    return Err(operation_error(
                        ReforgeErrorCode::ManualActionRequired,
                        "MCP endpoint contains credentials or an unsupported URL shape",
                    ));
                }
                value.insert("url".to_owned(), Value::String(url.as_str().to_owned()));
            }
            McpEndpoint::EnvironmentReference { name } => {
                validate_environment_name(name)?;
                value.insert("url".to_owned(), Value::String(format!("${{{name}}}")));
            }
            McpEndpoint::SecretReference { id, .. } => {
                secret_references.push(id.as_str().to_owned());
                reauth_required = true;
                blocking_secret = true;
            }
            McpEndpoint::RedactedUnknown => {
                reauth_required = true;
                blocking_secret = true;
            }
        }
    } else if matches!(
        server.transport,
        McpTransport::StreamableHttp | McpTransport::Sse
    ) {
        return Err(operation_error(
            ReforgeErrorCode::ManualActionRequired,
            "MCP endpoint was not safely observed and requires manual review",
        ));
    }

    let mut environment = Map::new();
    for EnvBinding {
        name,
        value: binding,
    } in &server.environment
    {
        validate_environment_name(name)?;
        if let Some(text) = safe_value(binding, &mut secret_references, &mut reauth_required) {
            environment.insert(name.clone(), Value::String(text));
        }
    }
    if !environment.is_empty() {
        value.insert("env".to_owned(), Value::Object(environment));
    }

    secret_references.sort();
    secret_references.dedup();
    Ok(SafeServer {
        value,
        secret_references,
        reauth_required,
        blocking_secret,
    })
}

fn safe_value(
    value: &SafeValueRef,
    secret_references: &mut Vec<String>,
    reauth_required: &mut bool,
) -> Option<String> {
    match value {
        SafeValueRef::LiteralNonSecret(value) => {
            if validate_safe_text(value, MAX_MCP_VALUE_BYTES, "MCP value").is_ok()
                && reforge_domain::redact_text(value).as_deref() == Some(value.as_str())
            {
                Some(value.clone())
            } else {
                *reauth_required = true;
                None
            }
        }
        SafeValueRef::EnvironmentReference { name } => {
            if validate_environment_name(name).is_ok() {
                Some(format!("${{{name}}}"))
            } else {
                *reauth_required = true;
                None
            }
        }
        SafeValueRef::SecretReference { id, .. } => {
            secret_references.push(id.as_str().to_owned());
            *reauth_required = true;
            None
        }
        SafeValueRef::RedactedUnknown => {
            *reauth_required = true;
            None
        }
    }
}

fn server_has_secret_or_unknown(server: &McpServerSpec) -> bool {
    server.args.iter().any(value_is_secret_or_unknown)
        || server
            .environment
            .iter()
            .any(|binding| value_is_secret_or_unknown(&binding.value))
        || matches!(
            server.cwd,
            Some(
                McpWorkingDirectory::SecretReference { .. } | McpWorkingDirectory::RedactedUnknown
            )
        )
        || matches!(
            server.endpoint,
            Some(McpEndpoint::SecretReference { .. } | McpEndpoint::RedactedUnknown)
        )
}

fn value_is_secret_or_unknown(value: &SafeValueRef) -> bool {
    matches!(
        value,
        SafeValueRef::SecretReference { .. } | SafeValueRef::RedactedUnknown
    )
}

fn validate_safe_text(value: &str, max_bytes: usize, field: &str) -> RestoreResult<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            format!("{field} is outside the reviewed safe value shape"),
        ));
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> RestoreResult<()> {
    let mut bytes = name.bytes();
    if name.len() > MAX_MCP_ENVIRONMENT_NAME_BYTES
        || !matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "MCP environment variable name is invalid",
        ));
    }
    Ok(())
}

fn merge_safe_server_json(
    servers: &mut Map<String, Value>,
    server: &McpServerSpec,
    safe: &SafeServer,
) -> RestoreResult<()> {
    let target = servers
        .entry(server.name.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    let target = target.as_object_mut().ok_or_else(|| {
        operation_error(
            ReforgeErrorCode::TargetConflict,
            "target MCP server entry is not an object",
        )
    })?;
    for (key, value) in &safe.value {
        if key == "env" {
            let target_env = target
                .entry(key.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let target_env = target_env.as_object_mut().ok_or_else(|| {
                operation_error(
                    ReforgeErrorCode::TargetConflict,
                    "target MCP environment is not an object",
                )
            })?;
            for (name, value) in value.as_object().expect("safe env is an object") {
                target_env.insert(name.clone(), value.clone());
            }
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

fn merge_safe_server_toml(
    servers: &mut toml::Table,
    server: &McpServerSpec,
    safe: &SafeServer,
) -> RestoreResult<()> {
    let target = servers
        .entry(server.name.clone())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let target = target.as_table_mut().ok_or_else(|| {
        operation_error(
            ReforgeErrorCode::TargetConflict,
            "target MCP server entry is not a TOML table",
        )
    })?;
    for (key, value) in &safe.value {
        let converted = json_to_toml(value).ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::OperationFailed,
                "normalized MCP value could not be represented in TOML",
            )
        })?;
        if key == "env" {
            let target_env = target
                .entry(key.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            let target_env = target_env.as_table_mut().ok_or_else(|| {
                operation_error(
                    ReforgeErrorCode::TargetConflict,
                    "target MCP environment is not a TOML table",
                )
            })?;
            let source_env = converted.as_table().expect("safe env is a TOML table");
            for (name, value) in source_env {
                target_env.insert(name.clone(), value.clone());
            }
        } else {
            target.insert(key.clone(), converted);
        }
    }
    Ok(())
}

fn json_to_toml(value: &Value) -> Option<toml::Value> {
    match value {
        Value::Null => None,
        Value::Bool(value) => Some(toml::Value::Boolean(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(toml::Value::Integer)
            .or_else(|| value.as_f64().map(toml::Value::Float)),
        Value::String(value) => Some(toml::Value::String(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(json_to_toml)
            .collect::<Option<Vec<_>>>()
            .map(toml::Value::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Some((key.clone(), json_to_toml(value)?)))
            .collect::<Option<toml::Table>>()
            .map(toml::Value::Table),
    }
}

fn json_server_matches(
    document: &Value,
    server: &McpServerSpec,
    safe: &Map<String, Value>,
) -> bool {
    let Some(object) = document.as_object() else {
        return false;
    };
    let Some(container) = ["mcpServers", "mcp_servers", "mcp"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(Value::as_object))
    else {
        return false;
    };
    let Some(target) = container.get(&server.name).and_then(Value::as_object) else {
        return false;
    };
    safe.iter()
        .all(|(key, value)| target.get(key) == Some(value))
}

fn toml_server_matches(
    document: &toml::Table,
    server: &McpServerSpec,
    safe: &Map<String, Value>,
) -> bool {
    let Some(container) = ["mcp_servers", "mcpServers", "mcp"]
        .into_iter()
        .find_map(|key| document.get(key).and_then(toml::Value::as_table))
    else {
        return false;
    };
    let Some(target) = container.get(&server.name).and_then(toml::Value::as_table) else {
        return false;
    };
    safe.iter().all(|(key, value)| {
        target
            .get(key)
            .and_then(toml_value_to_json)
            .is_some_and(|candidate| &candidate == value)
    })
}

fn toml_value_to_json(value: &toml::Value) -> Option<Value> {
    serde_json::to_value(value).ok()
}

fn target_has_package(
    context: &ExecutionContext<'_>,
    package: &reforge_domain::PackageSpec,
) -> bool {
    context.target.installed.iter().any(|installed| {
        installed
            .identity
            .provider_package
            .as_ref()
            .is_some_and(|(provider, id)| {
                provider == &package.provider
                    && id == &package.id
                    && package.version.as_ref().is_none_or(|required| {
                        installed.version.as_ref().is_some_and(|actual| {
                            actual.raw == *required
                                || actual.normalized.as_deref() == Some(required)
                        })
                    })
            })
    })
}

fn waiting_for_manual(
    reason: &str,
    server: &McpServerSpec,
    destination: &super::ResolvedDestination,
) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "changed": false,
        "server": server.name,
        "destination": destination.relative.as_str(),
        "manual_action_required": true,
        "reason": reason,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonc_parser_removes_comments_and_trailing_commas_without_touching_strings() {
        let bytes = strip_jsonc(
            r#"{"url":"https://example.test//literal", // comment
            "args":["x",],}"#,
        )
        .expect("JSONC sanitizes");
        let value: Value = serde_json::from_slice(&bytes).expect("sanitized JSON parses");
        assert_eq!(value["url"], "https://example.test//literal");
        assert_eq!(value["args"][0], "x");
    }

    #[test]
    fn secret_values_are_never_materialized_as_strings() {
        let id = reforge_domain::ComponentId::new(format!("cmp_{}", "s".repeat(52)))
            .expect("component ID");
        let mut references = Vec::new();
        let mut reauth = false;
        let result = safe_value(
            &SafeValueRef::SecretReference {
                id,
                label: "secret".to_owned(),
            },
            &mut references,
            &mut reauth,
        );
        assert!(result.is_none());
        assert!(reauth);
        assert_eq!(references.len(), 1);
    }
}
