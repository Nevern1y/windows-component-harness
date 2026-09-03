#![allow(dead_code)]

use std::collections::BTreeMap;

use reforge_discovery::harnesses::mcp::{
    McpInputFormat, McpParser, McpParserOptions, McpReferenceCatalog, normalize_mcp_config,
};
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, ComponentId, ConfigScope, ContentType, ExecutableRef,
    KnownFolderToken, McpEndpoint, McpTransport, McpWorkingDirectory, PackageSpec, PathToken,
    ProviderId, ReforgeErrorCode, SafeValueRef,
};
use reforge_platform_windows::KnownFolderMap;

const STDIO: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/mcp/stdio.json");
const HTTP: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/mcp/http.json");
const INVALID: &[u8] = include_bytes!("../../../../tests/fixtures/harnesses/mcp/invalid.json");

fn source_config() -> ArtifactRef {
    ArtifactRef {
        id: ArtifactId::new("mcp-config").expect("fixture artifact ID"),
        source_path: PathToken::new(KnownFolderToken::UserProfile, ".codex/config.toml")
            .expect("fixture source path"),
        scope: ConfigScope::User,
        size_bytes: 256,
        content_type: ContentType::Json,
        policy: ArtifactPolicy::Config,
        object: None,
    }
}

fn component_id(seed: char) -> ComponentId {
    ComponentId::new(format!("cmp_{}", seed.to_string().repeat(52))).expect("fixture component ID")
}

fn options() -> McpParserOptions {
    let root = std::env::temp_dir().join("reforge-mcp-fixture-user");
    let mut folders = BTreeMap::new();
    folders.insert(KnownFolderToken::UserProfile, root);

    let mut references = McpReferenceCatalog::default();
    references.register_executable(ExecutableRef {
        name: "npx.cmd".to_owned(),
        component: Some(component_id('a')),
        observed_path: None,
    });
    references.register_runtime("node", component_id('b'));
    references.register_package(PackageSpec {
        provider: ProviderId::new("npm").expect("fixture provider ID"),
        id: "@upstash/context7-mcp".to_owned(),
        version: Some("1.0.0".to_owned()),
        source_name: Some("npmjs".to_owned()),
        source_identifier: Some("@upstash/context7-mcp".to_owned()),
        source: None,
        architecture: None,
        installer_hash: None,
    });
    McpParserOptions::new(ConfigScope::User, source_config())
        .with_known_folders(KnownFolderMap::from_entries(folders))
        .with_references(references)
}

#[test]
fn stdio_fixture_normalizes_command_spaces_and_secret_references() {
    let result = McpParser::new(options())
        .parse_bytes(STDIO, McpInputFormat::Json)
        .expect("stdio fixture parses");
    assert_eq!(result.servers.len(), 1);
    let server = &result.servers[0];
    assert_eq!(server.name, "context7");
    assert_eq!(server.transport, McpTransport::Stdio);
    assert_eq!(
        server.command.as_ref().expect("resolved npx").name,
        "npx.cmd"
    );
    assert_eq!(server.args.len(), 4);
    assert!(matches!(
        server.args[3],
        SafeValueRef::SecretReference { .. }
    ));
    assert_eq!(server.environment[0].name, "CONTEXT7_API_KEY");
    assert!(matches!(
        server.environment[0].value,
        SafeValueRef::SecretReference { .. }
    ));
    assert_eq!(
        server.cwd,
        Some(McpWorkingDirectory::EnvironmentReference {
            name: "MCP_WORKSPACE".to_owned()
        })
    );
    let safe = serde_json::to_string(&result.safe_config).expect("safe config JSON");
    assert!(!safe.contains("fixture-context7-secret"));
    assert!(!safe.contains("fixture-argument-secret"));
}

#[test]
fn http_fixture_keeps_public_endpoint_and_redacts_auth_header() {
    let result =
        normalize_mcp_config(HTTP, McpInputFormat::Json, &options()).expect("HTTP fixture");
    let server = &result.servers[0];
    assert_eq!(server.transport, McpTransport::StreamableHttp);
    assert!(matches!(server.endpoint, Some(McpEndpoint::Public(_))));
    let safe = serde_json::to_string(&result.safe_config).expect("safe config JSON");
    assert!(!safe.contains("fixture-header-secret"));
    assert!(safe.contains("X-Client"));
}

#[test]
fn invalid_transport_is_a_manual_parse_error() {
    let error = normalize_mcp_config(INVALID, McpInputFormat::Json, &options())
        .expect_err("unknown transport must not normalize");
    assert_eq!(error.code, ReforgeErrorCode::ManualActionRequired);
}

#[test]
fn toml_and_json5_inputs_share_runtime_and_package_reference_validation() {
    let runtime = component_id('b');
    let toml = format!(
        "[mcp_servers.demo]\ncommand = \"npm\"\nargs = [\"run\", \"server\"]\nrequired_runtime = \"{runtime}\"\npackage = \"@upstash/context7-mcp\"\n"
    );
    let result = McpParser::new(options())
        .parse_str(&toml, McpInputFormat::Toml)
        .expect("TOML fixture parses");
    assert_eq!(result.servers[0].required_runtime, Some(runtime));
    assert_eq!(
        result.servers[0]
            .required_package
            .as_ref()
            .expect("package reference")
            .id,
        "@upstash/context7-mcp"
    );

    let json5 = "{ mcp: { demo: { type: 'sse', url: 'https://mcp.example.invalid/sse', }, }, }";
    let result = McpParser::new(options())
        .parse_str(json5, McpInputFormat::Json5)
        .expect("JSON5 fixture parses");
    assert_eq!(result.servers[0].transport, McpTransport::Sse);
}

#[test]
fn malformed_input_and_unknown_fields_fail_closed() {
    let malformed = McpParser::new(options())
        .parse_str("[mcp_servers.demo", McpInputFormat::Toml)
        .expect_err("malformed TOML");
    assert_eq!(malformed.code, ReforgeErrorCode::ProviderParseFailed);

    let unknown =
        br#"{"mcpServers":{"demo":{"type":"stdio","command":"npm","unknown_field":true}}}"#;
    let error = normalize_mcp_config(unknown, McpInputFormat::Json, &options())
        .expect_err("unknown server field");
    assert_eq!(error.code, ReforgeErrorCode::SchemaInvalid);
}
