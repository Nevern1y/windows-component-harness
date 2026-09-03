//! Shared MCP configuration parsing and secret-safe normalization.
//!
//! Harness adapters hand their documented MCP sections to this module.  The
//! parser accepts TOML, JSON, or JSON5, but emits only the closed domain MCP
//! model.  Raw configuration values are never returned after classification;
//! secret values become stable references derived from their field identity.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use reforge_domain::{
    ArtifactRef, ComponentId, ConfigScope, EnvBinding, ErrorEnvelope, ExecutableRef, Identity,
    IdentityQuality, McpArgument, McpEndpoint, McpServerSpec, McpTransport, McpWorkingDirectory,
    PackageSpec, PathToken, ReforgeErrorCode, SafeValueRef,
};
use reforge_platform_windows::KnownFolderMap;
use serde_json::{Map, Value};
use url::Url;

const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
const MAX_SERVERS: usize = 4_096;
const MAX_ARGUMENTS: usize = 4_096;
const MAX_ENVIRONMENT_ENTRIES: usize = 4_096;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_NESTING: usize = 64;

/// Input syntax accepted by the shared MCP normalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpInputFormat {
    Toml,
    Json,
    Json5,
}

/// A secret discovered while normalizing one MCP registration.
///
/// This is metadata only.  The secret value is intentionally not retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpSecretReference {
    pub id: ComponentId,
    pub label: String,
    pub server: String,
    pub source_field: String,
}

/// A value that needs user review before the MCP registration can be restored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpManualReview {
    pub server: String,
    pub field: String,
    pub reason: String,
}

/// Safe parser output consumed by harness adapters and later graph builders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpNormalization {
    pub servers: Vec<McpServerSpec>,
    pub safe_config: Value,
    pub secret_references: Vec<McpSecretReference>,
    pub manual_reviews: Vec<McpManualReview>,
}

/// References known to the current discovery run.
///
/// Executable entries must have been observed by an adapter or be one of the
/// reviewed built-in executables.  Runtime and package entries are likewise
/// supplied by discovery; an unresolved name is retained only as manual
/// metadata and is never promoted into an executable operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpReferenceCatalog {
    pub executables: BTreeMap<String, ExecutableRef>,
    pub runtimes: BTreeMap<String, ComponentId>,
    pub packages: BTreeMap<String, PackageSpec>,
}

impl McpReferenceCatalog {
    pub fn register_executable(&mut self, executable: ExecutableRef) {
        let key = executable_key(&executable.name);
        if !key.is_empty() {
            self.executables.insert(key, executable);
        }
    }

    pub fn register_runtime(&mut self, name: impl Into<String>, id: ComponentId) {
        let name = name.into();
        if !name.trim().is_empty() {
            self.runtimes.insert(name, id);
        }
    }

    pub fn register_package(&mut self, package: PackageSpec) {
        if !package.id.trim().is_empty() {
            self.packages.insert(package.id.clone(), package);
        }
    }
}

/// Inputs required to normalize an MCP section for one source artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpParserOptions {
    pub scope: ConfigScope,
    pub source_config: ArtifactRef,
    pub known_folders: KnownFolderMap,
    pub references: McpReferenceCatalog,
}

impl McpParserOptions {
    pub fn new(scope: ConfigScope, source_config: ArtifactRef) -> Self {
        Self {
            scope,
            source_config,
            known_folders: KnownFolderMap::default(),
            references: McpReferenceCatalog::default(),
        }
    }

    pub fn with_known_folders(mut self, known_folders: KnownFolderMap) -> Self {
        self.known_folders = known_folders;
        self
    }

    pub fn with_references(mut self, references: McpReferenceCatalog) -> Self {
        self.references = references;
        self
    }
}

/// Stateless parser for all harness MCP configuration syntaxes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpParser {
    options: McpParserOptions,
}

impl McpParser {
    pub fn new(options: McpParserOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &McpParserOptions {
        &self.options
    }

    pub fn parse_str(
        &self,
        input: &str,
        format: McpInputFormat,
    ) -> Result<McpNormalization, Box<ErrorEnvelope>> {
        normalize_mcp_config(input.as_bytes(), format, &self.options)
    }

    pub fn parse_bytes(
        &self,
        input: &[u8],
        format: McpInputFormat,
    ) -> Result<McpNormalization, Box<ErrorEnvelope>> {
        normalize_mcp_config(input, format, &self.options)
    }
}

/// Parse and normalize an MCP configuration without exposing source secrets.
pub fn normalize_mcp_config(
    input: &[u8],
    format: McpInputFormat,
    options: &McpParserOptions,
) -> Result<McpNormalization, Box<ErrorEnvelope>> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(security_error(
            "MCP configuration exceeds the reviewed size bound",
        ));
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| parse_error("MCP configuration is not valid UTF-8"))?;
    let document = parse_document(text, format)?;
    normalize_document(document, options)
}

/// Short alias used by harness adapters.
pub fn parse_mcp_config(
    input: &[u8],
    format: McpInputFormat,
    options: &McpParserOptions,
) -> Result<McpNormalization, Box<ErrorEnvelope>> {
    normalize_mcp_config(input, format, options)
}

fn parse_document(input: &str, format: McpInputFormat) -> Result<Value, Box<ErrorEnvelope>> {
    match format {
        McpInputFormat::Toml => {
            let document: toml::Value = toml::from_str(input)
                .map_err(|_| parse_error("MCP TOML configuration could not be parsed"))?;
            serde_json::to_value(document)
                .map_err(|_| parse_error("MCP TOML configuration could not be normalized"))
        }
        McpInputFormat::Json => serde_json::from_str(input)
            .map_err(|_| parse_error("MCP JSON configuration could not be parsed")),
        McpInputFormat::Json5 => json5::from_str(input)
            .map_err(|_| parse_error("MCP JSON5 configuration could not be parsed")),
    }
}

fn normalize_document(
    document: Value,
    options: &McpParserOptions,
) -> Result<McpNormalization, Box<ErrorEnvelope>> {
    let (container, names) = locate_servers(&document)?;
    if names.len() > MAX_SERVERS {
        return Err(security_error(
            "MCP configuration contains too many servers",
        ));
    }
    let direct_single =
        container.is_none() && document.as_object().is_some_and(looks_like_server_object);

    let mut state = NormalizeState::default();
    let mut normalized = Vec::with_capacity(names.len());
    let mut safe_servers = BTreeMap::new();
    for name in &names {
        let raw = if direct_single {
            Some(&document)
        } else {
            match container {
                Some(key) => document
                    .as_object()
                    .and_then(|object| object.get(key))
                    .and_then(Value::as_object)
                    .and_then(|servers| servers.get(name)),
                None => document.as_object().and_then(|servers| servers.get(name)),
            }
        }
        .ok_or_else(|| schema_error("MCP server entry is not an object"))?;
        let (server, safe_config) = normalize_server(name, raw, options, &mut state)?;
        normalized.push(server);
        safe_servers.insert(name.clone(), safe_config);
    }

    let mut safe_document =
        sanitize_outer_document(&document, container, direct_single, &mut state)?;
    if direct_single {
        safe_document = safe_servers
            .into_values()
            .next()
            .ok_or_else(|| schema_error("MCP server entry is missing"))?;
    } else {
        let safe_server_object = match container {
            Some(key) => safe_document
                .as_object_mut()
                .and_then(|object| object.get_mut(key))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| schema_error("MCP server container is not an object"))?,
            None => safe_document
                .as_object_mut()
                .ok_or_else(|| schema_error("MCP configuration root is not an object"))?,
        };
        for (name, safe_config) in safe_servers {
            safe_server_object.insert(name, safe_config);
        }
    }

    normalized.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(McpNormalization {
        servers: normalized,
        safe_config: safe_document,
        secret_references: state.secrets.into_values().collect(),
        manual_reviews: state.manual_reviews,
    })
}

fn sanitize_outer_document(
    document: &Value,
    container: Option<&str>,
    direct_single: bool,
    state: &mut NormalizeState,
) -> Result<Value, Box<ErrorEnvelope>> {
    if direct_single {
        return Ok(Value::Object(Map::new()));
    }
    let Some(object) = document.as_object() else {
        return Err(schema_error("MCP configuration root must be an object"));
    };
    let mut output = Map::new();
    for (key, value) in object {
        if container == Some(key.as_str()) {
            let Some(servers) = value.as_object() else {
                return Err(schema_error("MCP server table must be an object"));
            };
            let placeholders = servers
                .keys()
                .map(|name| (name.clone(), Value::Object(Map::new())))
                .collect();
            output.insert(key.clone(), Value::Object(placeholders));
        } else if container.is_none() {
            output.insert(key.clone(), Value::Object(Map::new()));
        } else {
            output.insert(
                key.clone(),
                sanitize_generic(value, "document", key, state)?,
            );
        }
    }
    Ok(Value::Object(output))
}

/// Locate a documented MCP server table while preserving the provider's outer shape.
fn locate_servers(
    document: &Value,
) -> Result<(Option<&'static str>, Vec<String>), Box<ErrorEnvelope>> {
    let Some(object) = document.as_object() else {
        return Err(schema_error("MCP configuration root must be an object"));
    };
    let mut found = None;
    for key in ["mcpServers", "mcp_servers", "mcp"] {
        if object.contains_key(key) {
            if found.is_some() {
                return Err(schema_error(
                    "MCP configuration contains multiple server tables",
                ));
            }
            found = Some(key);
        }
    }
    if let Some(key) = found {
        let Some(servers) = object.get(key).and_then(Value::as_object) else {
            return Err(schema_error("MCP server table must be an object"));
        };
        let names = checked_server_names(servers)?;
        return Ok((Some(key), names));
    }

    if looks_like_server_object(object) {
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("default")
            .to_owned();
        validate_server_name(&name)?;
        return Ok((None, vec![name]));
    }

    let names = checked_server_names(object)?;
    Ok((None, names))
}

fn checked_server_names(servers: &Map<String, Value>) -> Result<Vec<String>, Box<ErrorEnvelope>> {
    let mut names = Vec::with_capacity(servers.len());
    for (name, value) in servers {
        validate_server_name(name)?;
        if !value.is_object() {
            return Err(schema_error("MCP server entry is not an object"));
        }
        names.push(name.clone());
    }
    Ok(names)
}

fn looks_like_server_object(object: &Map<String, Value>) -> bool {
    [
        "name",
        "type",
        "transport",
        "command",
        "args",
        "cwd",
        "env",
        "environment",
        "url",
        "endpoint",
        "headers",
        "runtime",
        "required_runtime",
        "package",
        "required_package",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
}

fn normalize_server(
    name: &str,
    raw: &Value,
    options: &McpParserOptions,
    state: &mut NormalizeState,
) -> Result<(McpServerSpec, Value), Box<ErrorEnvelope>> {
    validate_server_name(name)?;
    let Some(object) = raw.as_object() else {
        return Err(schema_error("MCP server entry is not an object"));
    };
    for key in object.keys() {
        if !allowed_server_field(key) {
            return Err(schema_error("MCP server contains an unknown field"));
        }
    }

    let mut safe_config = sanitize_generic(raw, name, "", state)?;
    let safe_object = safe_config
        .as_object_mut()
        .ok_or_else(|| schema_error("MCP server entry is not an object"))?;

    let transport = parse_transport(object)?;
    let command_raw = optional_string(object, "command")?;
    let command = if let Some(value) = command_raw.as_deref() {
        match resolve_executable(value, &options.references) {
            Some(executable) => Some(executable),
            None => {
                state.manual(
                    name,
                    "command",
                    "The MCP command was not observed or built in",
                );
                None
            }
        }
    } else {
        None
    };

    let args = parse_args(object.get("args"), name, state)?;
    if object.contains_key("args") {
        safe_object.insert(
            "args".to_owned(),
            Value::Array(args.iter().map(safe_value_json).collect()),
        );
    }

    let cwd = object
        .get("cwd")
        .map(|value| parse_cwd(value, name, options, state))
        .transpose()?
        .flatten();
    if let Some(value) = &cwd {
        safe_object.insert("cwd".to_owned(), safe_value_json(value));
    }

    let endpoint_key = alias_key(object, "url", "endpoint")?;
    let endpoint = endpoint_key
        .map(|key| parse_endpoint(object.get(key).expect("endpoint alias exists"), name, state))
        .transpose()?
        .flatten();
    if let Some(key) = endpoint_key
        && let Some(value) = &endpoint
    {
        safe_object.insert(key.to_owned(), safe_value_json(value));
    }

    let env_key = alias_key(object, "env", "environment")?;
    let environment = env_key
        .map(|key| {
            parse_environment(
                object.get(key).expect("environment alias exists"),
                name,
                state,
            )
        })
        .transpose()?
        .unwrap_or_default();
    if let Some(key) = env_key {
        let values = environment
            .iter()
            .map(|binding| (binding.name.clone(), safe_value_json(&binding.value)))
            .collect();
        safe_object.insert(key.to_owned(), Value::Object(values));
    }

    if let Some(headers) = object.get("headers") {
        let safe_headers = parse_headers(headers, name, state)?;
        safe_object.insert("headers".to_owned(), safe_headers);
    }

    let required_runtime = parse_runtime_reference(object, options, name, state)?;
    let required_package = parse_package_reference(object, options, name, state)?;

    match transport {
        McpTransport::Stdio => {
            if command_raw.is_none() {
                return Err(schema_error("stdio MCP server is missing a command"));
            }
            if endpoint.is_some() {
                return Err(schema_error("stdio MCP server must not define an endpoint"));
            }
        }
        McpTransport::StreamableHttp | McpTransport::Sse => {
            if endpoint.is_none() {
                return Err(schema_error("HTTP MCP server is missing an endpoint"));
            }
            if command_raw.is_some() {
                return Err(schema_error("HTTP MCP server must not define a command"));
            }
        }
        McpTransport::Unknown => return Err(manual_error("MCP transport is not supported")),
    }

    let server = McpServerSpec {
        name: name.to_owned(),
        scope: options.scope.clone(),
        transport,
        command,
        args,
        cwd,
        endpoint,
        environment,
        required_runtime,
        required_package,
        source_config: options.source_config.clone(),
    };
    Ok((server, safe_config))
}

fn parse_transport(object: &Map<String, Value>) -> Result<McpTransport, Box<ErrorEnvelope>> {
    let key = alias_key(object, "type", "transport")?;
    let Some(key) = key else {
        if object.contains_key("command") {
            return Ok(McpTransport::Stdio);
        }
        if object.contains_key("url") || object.contains_key("endpoint") {
            return Ok(McpTransport::StreamableHttp);
        }
        return Err(schema_error("MCP server is missing a transport"));
    };
    let Some(raw) = object.get(key).and_then(Value::as_str) else {
        return Err(schema_error("MCP transport must be a string"));
    };
    let normalized = raw.trim().to_ascii_lowercase().replace(['-', '_', ' '], "");
    match normalized.as_str() {
        "stdio" | "local" => Ok(McpTransport::Stdio),
        "http" | "streamablehttp" | "streamable" | "remote" => Ok(McpTransport::StreamableHttp),
        "sse" | "serversentevents" => Ok(McpTransport::Sse),
        _ => Err(manual_error("MCP transport is not supported")),
    }
}

fn parse_args(
    value: Option<&Value>,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Vec<McpArgument>, Box<ErrorEnvelope>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(schema_error("MCP args must be an array"));
    };
    if values.len() > MAX_ARGUMENTS {
        return Err(security_error("MCP server contains too many arguments"));
    }
    let mut output = Vec::with_capacity(values.len());
    let mut secret_flag = false;
    for (index, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            return Err(schema_error("MCP arguments must be strings"));
        };
        let field = format!("args[{index}]");
        let classified = classify_value(value, server, &field, secret_flag, state);
        secret_flag = is_secret_flag(value) && !value.contains('=');
        output.push(classified);
    }
    if secret_flag {
        return Err(schema_error("MCP secret argument flag has no value"));
    }
    Ok(output)
}

fn parse_cwd(
    value: &Value,
    server: &str,
    options: &McpParserOptions,
    state: &mut NormalizeState,
) -> Result<Option<McpWorkingDirectory>, Box<ErrorEnvelope>> {
    if let Some(object) = value.as_object() {
        let token: PathToken = serde_json::from_value(Value::Object(object.clone()))
            .map_err(|_| schema_error("MCP cwd token is invalid"))?;
        token
            .validate()
            .map_err(|_| schema_error("MCP cwd token is invalid"))?;
        return Ok(Some(McpWorkingDirectory::Tokenized(token)));
    }
    let Some(raw) = value.as_str() else {
        return Err(schema_error(
            "MCP cwd must be a path or environment reference",
        ));
    };
    if let Some(name) = environment_reference(raw) {
        return Ok(Some(McpWorkingDirectory::EnvironmentReference { name }));
    }
    if contains_environment_reference(raw) {
        state.manual(
            server,
            "cwd",
            "MCP cwd contains a composite environment expression",
        );
        return Ok(Some(McpWorkingDirectory::RedactedUnknown));
    }
    if let Some(token) = token_for_absolute_path(raw, &options.known_folders) {
        return Ok(Some(McpWorkingDirectory::Tokenized(token)));
    }
    state.manual(
        server,
        "cwd",
        "MCP cwd is not below an allowlisted known folder",
    );
    Ok(Some(McpWorkingDirectory::RedactedUnknown))
}

fn parse_endpoint(
    value: &Value,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Option<McpEndpoint>, Box<ErrorEnvelope>> {
    let Some(raw) = value.as_str() else {
        return Err(schema_error(
            "MCP endpoint must be a URL or environment reference",
        ));
    };
    if let Some(name) = environment_reference(raw) {
        return Ok(Some(McpEndpoint::EnvironmentReference { name }));
    }
    if contains_environment_reference(raw) {
        state.manual(
            server,
            "endpoint",
            "MCP endpoint contains a composite environment expression",
        );
        return Ok(Some(McpEndpoint::RedactedUnknown));
    }

    let url =
        Url::parse(raw.trim()).map_err(|_| schema_error("MCP endpoint is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        state.manual(
            server,
            "endpoint",
            "MCP endpoint uses an unsupported URL scheme",
        );
        return Ok(Some(McpEndpoint::RedactedUnknown));
    }
    if url.username() != "" || url.password().is_some() || endpoint_has_secret_query(&url) {
        let reference = state.secret(server, "endpoint", raw);
        return Ok(Some(McpEndpoint::SecretReference {
            id: reference.id,
            label: reference.label,
        }));
    }
    if url.query().is_some() || url.fragment().is_some() {
        state.manual(
            server,
            "endpoint",
            "MCP endpoint query or fragment requires redaction review",
        );
        return Ok(Some(McpEndpoint::RedactedUnknown));
    }
    Ok(Some(McpEndpoint::Public(url)))
}

fn parse_environment(
    value: &Value,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Vec<EnvBinding>, Box<ErrorEnvelope>> {
    let Some(object) = value.as_object() else {
        return Err(schema_error("MCP environment must be an object"));
    };
    if object.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(security_error("MCP environment contains too many entries"));
    }
    let mut output = Vec::with_capacity(object.len());
    for (name, value) in object {
        validate_environment_name(name)?;
        let Some(value) = value.as_str() else {
            return Err(schema_error("MCP environment values must be strings"));
        };
        output.push(EnvBinding {
            name: name.clone(),
            value: classify_value(value, server, &format!("env.{name}"), false, state),
        });
    }
    output.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(output)
}

fn parse_headers(
    value: &Value,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Value, Box<ErrorEnvelope>> {
    let Some(object) = value.as_object() else {
        return Err(schema_error("MCP headers must be an object"));
    };
    if object.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(security_error("MCP headers contain too many entries"));
    }
    let mut output = Map::new();
    for (name, value) in object {
        let Some(value) = value.as_str() else {
            return Err(schema_error("MCP header values must be strings"));
        };
        let field = format!("headers.{name}");
        let value = classify_value(value, server, &field, false, state);
        output.insert(name.clone(), safe_value_json(&value));
    }
    Ok(Value::Object(output))
}

fn parse_runtime_reference(
    object: &Map<String, Value>,
    options: &McpParserOptions,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Option<ComponentId>, Box<ErrorEnvelope>> {
    let key = alias_key(object, "runtime", "required_runtime")?;
    let Some(key) = key else {
        return Ok(None);
    };
    let Some(raw) = object.get(key).and_then(Value::as_str) else {
        return Err(schema_error("MCP runtime reference must be a string"));
    };
    if let Some(id) = options.references.runtimes.get(raw) {
        return Ok(Some(id.clone()));
    }
    if let Ok(id) = ComponentId::new(raw.to_owned()) {
        return Ok(Some(id));
    }
    state.manual(server, key, "MCP runtime reference was not observed");
    Ok(None)
}

fn parse_package_reference(
    object: &Map<String, Value>,
    options: &McpParserOptions,
    server: &str,
    state: &mut NormalizeState,
) -> Result<Option<PackageSpec>, Box<ErrorEnvelope>> {
    let key = alias_key(object, "package", "required_package")?;
    let Some(key) = key else {
        return Ok(None);
    };
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if let Some(raw) = value.as_str() {
        if let Some(package) = lookup_package(&options.references.packages, raw) {
            return Ok(Some(package.clone()));
        }
        state.manual(server, key, "MCP package reference was not observed");
        return Ok(None);
    }
    let package: PackageSpec = serde_json::from_value(value.clone())
        .map_err(|_| schema_error("MCP package reference is invalid"))?;
    if package.id.trim().is_empty() {
        return Err(schema_error("MCP package reference has no identifier"));
    }
    Ok(Some(package))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, Box<ErrorEnvelope>> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(schema_error("MCP string field has an invalid type"));
    };
    if value.trim().is_empty() {
        return Err(schema_error("MCP string field must not be empty"));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(security_error(
            "MCP string field exceeds the reviewed size bound",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn alias_key(
    object: &Map<String, Value>,
    first: &'static str,
    second: &'static str,
) -> Result<Option<&'static str>, Box<ErrorEnvelope>> {
    match (object.contains_key(first), object.contains_key(second)) {
        (true, true) => Err(schema_error(
            "MCP configuration uses conflicting field aliases",
        )),
        (true, false) => Ok(Some(first)),
        (false, true) => Ok(Some(second)),
        (false, false) => Ok(None),
    }
}

fn allowed_server_field(key: &str) -> bool {
    matches!(
        key,
        "name"
            | "type"
            | "transport"
            | "command"
            | "args"
            | "cwd"
            | "env"
            | "environment"
            | "url"
            | "endpoint"
            | "headers"
            | "runtime"
            | "required_runtime"
            | "package"
            | "required_package"
            | "enabled"
            | "disabled"
            | "startup_timeout_sec"
            | "tool_timeout_sec"
            | "oauth"
            | "description"
    ) || is_secret_field(key)
}

fn classify_value(
    value: &str,
    server: &str,
    field: &str,
    force_secret: bool,
    state: &mut NormalizeState,
) -> SafeValueRef {
    if let Some(name) = environment_reference(value) {
        return SafeValueRef::EnvironmentReference { name };
    }
    if contains_environment_reference(value) {
        state.manual(
            server,
            field,
            "MCP value contains a composite environment expression",
        );
        return SafeValueRef::RedactedUnknown;
    }
    if force_secret || is_secret_field(field) || looks_like_secret_literal(value) {
        let reference = state.secret(server, field, value);
        return SafeValueRef::SecretReference {
            id: reference.id,
            label: reference.label,
        };
    }
    if value.len() > MAX_VALUE_BYTES || value.chars().any(char::is_control) {
        state.manual(
            server,
            field,
            "MCP value is outside the reviewed safe literal shape",
        );
        SafeValueRef::RedactedUnknown
    } else {
        SafeValueRef::LiteralNonSecret(value.to_owned())
    }
}

fn sanitize_generic(
    value: &Value,
    server: &str,
    field: &str,
    state: &mut NormalizeState,
) -> Result<Value, Box<ErrorEnvelope>> {
    sanitize_generic_at_depth(value, server, field, state, 0)
}

fn sanitize_generic_at_depth(
    value: &Value,
    server: &str,
    field: &str,
    state: &mut NormalizeState,
    depth: usize,
) -> Result<Value, Box<ErrorEnvelope>> {
    if depth > MAX_NESTING {
        return Err(security_error(
            "MCP configuration nesting exceeds the reviewed bound",
        ));
    }
    match value {
        Value::Object(object) => {
            let mut output = Map::new();
            for (key, value) in object {
                let child_field = if field.is_empty() {
                    key.clone()
                } else {
                    format!("{field}.{key}")
                };
                if is_secret_field(key) {
                    if let Some(raw) = value.as_str() {
                        let reference = state.secret(server, &child_field, raw);
                        output.insert(
                            child_key(key),
                            safe_value_json(&SafeValueRef::SecretReference {
                                id: reference.id,
                                label: reference.label,
                            }),
                        );
                    } else {
                        state.manual(server, &child_field, "MCP secret field is not a string");
                        output.insert(
                            child_key(key),
                            safe_value_json(&SafeValueRef::RedactedUnknown),
                        );
                    }
                } else {
                    output.insert(
                        child_key(key),
                        sanitize_generic_at_depth(value, server, &child_field, state, depth + 1)?,
                    );
                }
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                sanitize_generic_at_depth(
                    value,
                    server,
                    &format!("{field}[{index}]"),
                    state,
                    depth + 1,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn child_key(key: &str) -> String {
    key.to_owned()
}

fn safe_value_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("safe MCP domain values serialize")
}

fn resolve_executable(command: &str, references: &McpReferenceCatalog) -> Option<ExecutableRef> {
    let key = executable_key(command);
    if let Some(executable) = references.executables.get(&key) {
        return valid_executable(executable).then(|| executable.clone());
    }
    let basename = command
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    if let Some(executable) = references.executables.get(&basename) {
        return valid_executable(executable).then(|| executable.clone());
    }
    if is_builtin_executable(&basename) {
        return Some(ExecutableRef {
            name: basename,
            component: None,
            observed_path: None,
        });
    }
    None
}

fn valid_executable(executable: &ExecutableRef) -> bool {
    if executable.name.trim().is_empty() {
        return false;
    }
    if executable
        .observed_path
        .as_ref()
        .is_some_and(|path| path.validate().is_err())
    {
        return false;
    }
    executable.component.is_some()
        || executable.observed_path.is_some()
        || is_builtin_executable(&executable_key(&executable.name))
}

fn executable_key(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_builtin_executable(value: &str) -> bool {
    let value = value.strip_suffix(".exe").unwrap_or(value);
    matches!(
        value,
        "winget"
            | "choco"
            | "scoop"
            | "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "python"
            | "pipx"
            | "uv"
            | "cargo"
            | "rustup"
            | "go"
            | "dotnet"
            | "powershell"
            | "wsl"
            | "docker"
            | "code"
    )
}

fn lookup_package<'a>(
    packages: &'a BTreeMap<String, PackageSpec>,
    name: &str,
) -> Option<&'a PackageSpec> {
    packages.get(name).or_else(|| {
        packages
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    })
}

fn token_for_absolute_path(raw: &str, known_folders: &KnownFolderMap) -> Option<PathToken> {
    let candidate = PathBuf::from(raw);
    if !candidate.is_absolute() {
        return None;
    }
    let candidate_text = path_text(&candidate);
    let candidate_key = candidate_text.to_ascii_lowercase();
    for (token, root) in &known_folders.entries {
        let root_text = path_text(root);
        let root_key = root_text.to_ascii_lowercase();
        if candidate_key == root_key {
            return PathToken::new(token.clone(), "").ok();
        }
        let prefix = format!("{root_key}/");
        if candidate_key.starts_with(&prefix) {
            let relative = candidate_text[root_text.len() + 1..].to_owned();
            if let Ok(token) = PathToken::new(token.clone(), relative) {
                return Some(token);
            }
        }
    }
    None
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_owned()
}

fn environment_reference(value: &str) -> Option<String> {
    let value = value.trim();
    let candidate = if value.starts_with("${") && value.ends_with('}') {
        &value[2..value.len() - 1]
    } else if let Some(name) = value.strip_prefix('$') {
        name
    } else if value.starts_with('%') && value.ends_with('%') {
        &value[1..value.len() - 1]
    } else if value.starts_with("{env:") && value.ends_with('}') {
        &value[5..value.len() - 1]
    } else {
        value.strip_prefix("env:")?
    };
    valid_environment_name(candidate).then(|| candidate.to_owned())
}

fn contains_environment_reference(value: &str) -> bool {
    if value.contains("${") || value.contains("{env:") {
        return true;
    }
    let characters: Vec<_> = value.chars().collect();
    for (index, character) in characters.iter().enumerate() {
        if *character == '$' {
            if characters.get(index + 1) == Some(&'{') {
                return true;
            }
            let mut end = index + 1;
            while characters
                .get(end)
                .is_some_and(|candidate| *candidate == '_' || candidate.is_ascii_alphanumeric())
            {
                end += 1;
            }
            if end > index + 1 {
                let candidate: String = characters[index + 1..end].iter().collect();
                if valid_environment_name(&candidate) {
                    return true;
                }
            }
        } else if *character == '%' {
            let Some(end) = characters[index + 1..]
                .iter()
                .position(|candidate| *candidate == '%')
            else {
                continue;
            };
            let end = index + 1 + end;
            if end > index + 1 {
                let candidate: String = characters[index + 1..end].iter().collect();
                if valid_environment_name(&candidate) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_secret_field(field: &str) -> bool {
    let normalized = field
        .split(['.', '[', ']', '-', '_', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let has_key_pair = normalized.windows(2).any(|parts| {
        matches!(parts[1].as_str(), "key")
            && matches!(
                parts[0].as_str(),
                "api" | "access" | "private" | "client" | "secret" | "auth" | "ssh"
            )
    });
    normalized.iter().any(|part| {
        matches!(
            part.as_str(),
            "apikey"
                | "token"
                | "password"
                | "passwd"
                | "secret"
                | "authorization"
                | "bearer"
                | "credential"
                | "credentials"
                | "privatekey"
                | "accesskey"
                | "refreshtoken"
                | "cookie"
                | "session"
        )
    }) || has_key_pair
}

fn looks_like_secret_literal(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin ")
        || lower.contains("bearer ")
        || [
            "api_key=",
            "api-key=",
            "apikey=",
            "access_token=",
            "access-token=",
            "token=",
            "password=",
            "client_secret=",
            "client-secret=",
            "authorization=",
            "authorization:",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn endpoint_has_secret_query(url: &Url) -> bool {
    url.query_pairs().any(|(name, _)| is_secret_field(&name))
        || url.fragment().is_some_and(looks_like_secret_literal)
}

fn is_secret_flag(value: &str) -> bool {
    if !value.starts_with('-') || value.contains('=') {
        return false;
    }
    let value = value.trim_start_matches('-');
    !value.is_empty() && is_secret_field(value)
}

fn validate_server_name(name: &str) -> Result<(), Box<ErrorEnvelope>> {
    if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(schema_error("MCP server name is invalid"));
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
        && name.len() <= 256
}

fn validate_environment_name(name: &str) -> Result<(), Box<ErrorEnvelope>> {
    if valid_environment_name(name) {
        Ok(())
    } else {
        Err(schema_error("MCP environment variable name is invalid"))
    }
}

#[derive(Default)]
struct NormalizeState {
    secrets: BTreeMap<String, McpSecretReference>,
    manual_reviews: Vec<McpManualReview>,
}

impl NormalizeState {
    fn secret(&mut self, server: &str, field: &str, _raw: &str) -> McpSecretReference {
        let key = format!("{server}\u{1f}{field}");
        if let Some(reference) = self.secrets.get(&key) {
            return reference.clone();
        }
        let hash = blake3::hash(key.as_bytes()).to_hex().to_string();
        let identity = Identity {
            provider_package: None,
            provider_source: None,
            package_family: None,
            product_name: None,
            executable_name: Some("mcp-secret".to_owned()),
            publisher: None,
            executable_hash: Some(hash),
            install_role: None,
            identity_quality: IdentityQuality::Local,
        };
        let id = ComponentId::from_identity(&identity, None)
            .expect("MCP secret identity uses a valid local identity tuple")
            .id;
        let reference = McpSecretReference {
            id,
            label: format!("MCP {server} secret {field}"),
            server: server.to_owned(),
            source_field: field.to_owned(),
        };
        self.secrets.insert(key, reference.clone());
        reference
    }

    fn manual(&mut self, server: &str, field: &str, reason: &str) {
        if !self
            .manual_reviews
            .iter()
            .any(|review| review.server == server && review.field == field)
        {
            self.manual_reviews.push(McpManualReview {
                server: server.to_owned(),
                field: field.to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
}

fn parse_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::ProviderParseFailed,
        message,
    ))
}

fn schema_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(ReforgeErrorCode::SchemaInvalid, message))
}

fn manual_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::ManualActionRequired,
        message,
    ))
}

fn security_error(message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::SecurityPolicy,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{ArtifactId, ArtifactPolicy, KnownFolderToken};

    fn source_config() -> ArtifactRef {
        ArtifactRef {
            id: ArtifactId::new("mcp-config").unwrap(),
            source_path: PathToken::new(KnownFolderToken::UserProfile, ".codex/config.toml")
                .unwrap(),
            scope: ConfigScope::User,
            size_bytes: 100,
            content_type: reforge_domain::ContentType::Toml,
            policy: ArtifactPolicy::Config,
            object: None,
        }
    }

    fn options() -> McpParserOptions {
        McpParserOptions::new(ConfigScope::User, source_config())
    }

    #[test]
    fn json5_and_toml_parse_through_one_normalizer() {
        let json5 = r#"{
            // JSON5 comments and trailing commas are accepted.
            mcpServers: { demo: { type: 'stdio', command: 'npm', args: ['run', 'server',], }, },
        }"#;
        let result = McpParser::new(options())
            .parse_str(json5, McpInputFormat::Json5)
            .unwrap();
        assert_eq!(result.servers[0].transport, McpTransport::Stdio);
        assert_eq!(result.servers[0].args.len(), 2);

        let toml = r#"[mcp_servers.demo]
command = "npm"
args = ["run", "server"]
"#;
        let result = McpParser::new(options())
            .parse_str(toml, McpInputFormat::Toml)
            .unwrap();
        assert_eq!(result.servers[0].name, "demo");
    }

    #[test]
    fn secret_values_are_replaced_in_args_env_and_endpoint() {
        let input = br#"{"mcpServers":{"demo":{"type":"stdio","command":"npm","args":["--api-key","raw-argument-secret"],"env":{"CONTEXT7_API_KEY":"raw-env-secret"}}}}"#;
        let result = normalize_mcp_config(input, McpInputFormat::Json, &options()).unwrap();
        assert_eq!(result.secret_references.len(), 2);
        let json = serde_json::to_string(&result.safe_config).unwrap();
        assert!(!json.contains("raw-argument-secret"));
        assert!(!json.contains("raw-env-secret"));
        assert!(matches!(
            result.servers[0].args[1],
            SafeValueRef::SecretReference { .. }
        ));
        assert!(matches!(
            result.servers[0].environment[0].value,
            SafeValueRef::SecretReference { .. }
        ));

        let input = br#"{"mcpServers":{"remote":{"type":"http","url":"https://example.invalid/mcp?api_key=raw-endpoint-secret"}}}"#;
        let result = normalize_mcp_config(input, McpInputFormat::Json, &options()).unwrap();
        let json = serde_json::to_string(&result.safe_config).unwrap();
        assert!(!json.contains("raw-endpoint-secret"));
        assert!(matches!(
            result.servers[0].endpoint,
            Some(McpEndpoint::SecretReference { .. })
        ));
    }

    #[test]
    fn command_with_spaces_is_not_shell_split_and_cwd_is_tokenized() {
        let root = std::env::temp_dir().join("reforge-mcp-user");
        let mut entries = BTreeMap::new();
        entries.insert(KnownFolderToken::UserProfile, root.clone());
        let mut references = McpReferenceCatalog::default();
        references.register_executable(ExecutableRef {
            name: "node.exe".to_owned(),
            component: Some(ComponentId::new(format!("cmp_{}", "a".repeat(52))).unwrap()),
            observed_path: None,
        });
        let options = options()
            .with_known_folders(KnownFolderMap::from_entries(entries))
            .with_references(references);
        let command = r#"C:\Program Files\nodejs\node.exe"#.to_owned();
        let input = serde_json::json!({
            "mcpServers": {
                "demo": {
                    "type": "stdio",
                    "command": command,
                    "cwd": root.join("project").to_string_lossy(),
                }
            }
        })
        .to_string();
        let result = McpParser::new(options)
            .parse_str(&input, McpInputFormat::Json)
            .unwrap();
        assert_eq!(result.servers[0].command.as_ref().unwrap().name, "node.exe");
        assert_eq!(
            result.servers[0].cwd,
            Some(McpWorkingDirectory::Tokenized(
                PathToken::new(KnownFolderToken::UserProfile, "project").unwrap()
            ))
        );
    }

    #[test]
    fn unknown_transport_is_manual_and_unknown_field_is_schema_invalid() {
        let unknown = br#"{"mcpServers":{"demo":{"type":"grpc","command":"npm"}}}"#;
        let error = normalize_mcp_config(unknown, McpInputFormat::Json, &options()).unwrap_err();
        assert_eq!(error.code, ReforgeErrorCode::ManualActionRequired);

        let unknown_field =
            br#"{"mcpServers":{"demo":{"type":"stdio","command":"npm","not_allowed":true}}}"#;
        let error =
            normalize_mcp_config(unknown_field, McpInputFormat::Json, &options()).unwrap_err();
        assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
    }

    #[test]
    fn unresolved_references_are_manual_and_never_executable() {
        let input = br#"{"mcpServers":{"demo":{"type":"stdio","command":"unobserved-tool","required_runtime":"node-runtime","package":"demo-package"}}}"#;
        let result = normalize_mcp_config(input, McpInputFormat::Json, &options()).unwrap();
        assert!(result.servers[0].command.is_none());
        assert!(result.servers[0].required_runtime.is_none());
        assert!(result.servers[0].required_package.is_none());
        assert_eq!(result.manual_reviews.len(), 3);
    }
}
