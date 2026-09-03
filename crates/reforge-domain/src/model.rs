//! Canonical Reforge wire and domain DTOs.
//!
//! This module is the sole owner of data crossing the Rust, CLI, Tauri, package,
//! and UI boundaries.  The shapes intentionally remain closed and typed; the
//! only extensibility point is [`Component::extensions`].

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use typeshare::typeshare;
use url::Url;

use crate::ids::{
    ArtifactId, ComponentId, EvidenceId, ObjectId, OperationId, ProviderId, RunId, SnapshotId,
};

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentKind {
    Application,
    Package,
    Runtime,
    Tool,
    Harness,
    McpServer,
    Skill,
    Agent,
    Hook,
    Plugin,
    Browser,
    BrowserProfile,
    Editor,
    Extension,
    Configuration,
    DataArtifact,
    SecretReference,
    EnvironmentVariable,
    SystemFeature,
    Service,
    ScheduledTask,
    Shell,
    PortableBinary,
    WslDistribution,
    DockerContext,
    DockerImage,
    DockerVolume,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Confirmed,
    High,
    Medium,
    Low,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Portability {
    Portable,
    SupportedExport,
    SyncRestorable,
    PartiallyPortable,
    ApplicationBound,
    UserBound,
    MachineBound,
    ReauthRequired,
    Unsupported,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreStrategy {
    Reinstall,
    ConfigPortable,
    DataPortable,
    ExportImport,
    PortableBinary,
    SecretExportable,
    ReauthRequired,
    MachineBound,
    Partial,
    Manual,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Component {
    pub id: ComponentId,
    pub kind: ComponentKind,
    pub identity: Identity,
    pub display_name: String,
    pub version: Option<VersionValue>,
    pub architecture: Option<Architecture>,
    pub publisher: Option<Publisher>,
    pub provenance: Option<Provenance>,
    pub evidence: Vec<EvidenceRef>,
    pub confidence: Confidence,
    pub dependencies: Vec<DependencyEdge>,
    pub artifacts: Vec<ArtifactRef>,
    pub restore: RestoreDescriptor,
    pub compatibility: Compatibility,
    pub verification: Vec<VerificationRule>,
    pub selection: SelectionMetadata,
    #[serde(flatten)]
    #[typeshare(skip)]
    pub extensions: BTreeMap<String, Value>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageSpec {
    pub provider: ProviderId,
    pub id: String,
    pub version: Option<String>,
    pub source_name: Option<String>,
    pub source_identifier: Option<String>,
    #[typeshare(typescript(type = "string | undefined"))]
    pub source: Option<Url>,
    pub architecture: Option<Architecture>,
    pub installer_hash: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageInstallPolicy {
    pub accept_source_agreements: bool,
    pub accept_package_agreements: bool,
    pub silent: bool,
    pub allow_reboot: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Architecture {
    X86,
    X64,
    Arm64,
    Neutral,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountScope {
    User,
    Machine,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfigScope {
    Process,
    User,
    System,
    Project,
    Managed,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KnownFolderToken {
    UserProfile,
    RoamingAppData,
    LocalAppData,
    ProgramData,
    ProgramFiles,
    ProgramFilesX86,
    StartMenu,
    Startup,
    Desktop,
    Documents,
    UserSelected { id: String },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct PathTokenInput {
    root: KnownFolderToken,
    relative: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    rename_all = "snake_case",
    try_from = "PathTokenInput",
    into = "PathTokenInput"
)]
#[schemars(with = "PathTokenInput")]
pub struct PathToken {
    pub root: KnownFolderToken,
    pub relative: String,
}

impl PathToken {
    /// Construct a token after applying the documented relative-path grammar.
    pub fn new(root: KnownFolderToken, relative: impl AsRef<str>) -> Result<Self, String> {
        let relative = normalize_relative_path(relative.as_ref())?;
        Ok(Self { root, relative })
    }

    /// Validate a token constructed by trusted Rust code.
    pub fn validate(&self) -> Result<(), String> {
        let normalized = normalize_relative_path(&self.relative)?;
        if normalized != self.relative {
            return Err("path token relative path is not normalized".to_owned());
        }
        Ok(())
    }
}

impl TryFrom<PathTokenInput> for PathToken {
    type Error = String;

    fn try_from(value: PathTokenInput) -> Result<Self, Self::Error> {
        Self::new(value.root, value.relative)
    }
}

impl From<PathToken> for PathTokenInput {
    fn from(value: PathToken) -> Self {
        Self {
            root: value.root,
            relative: value.relative,
        }
    }
}

fn normalize_relative_path(relative: &str) -> Result<String, String> {
    if relative.contains('\0') {
        return Err("path token contains NUL".to_owned());
    }
    if relative.starts_with('/') || relative.starts_with('\\') {
        return Err("path token must not be absolute".to_owned());
    }
    if relative.len() >= 2 && relative.as_bytes()[1] == b':' {
        return Err("path token must not contain a drive prefix".to_owned());
    }
    if relative.starts_with("//") || relative.starts_with("\\\\") {
        return Err("path token must not contain a UNC prefix".to_owned());
    }
    if relative.chars().any(|character| character.is_control()) {
        return Err("path token contains a control character".to_owned());
    }

    let mut segments = Vec::new();
    for segment in relative.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => return Err("path token must not contain a parent segment".to_owned()),
            segment if segment.contains(':') => {
                return Err("path token contains an invalid colon".to_owned());
            }
            segment => segments.push(segment),
        }
    }
    Ok(segments.join("/"))
}

#[typeshare]
pub type TokenizedPath = PathToken;

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentType {
    Utf8Text,
    Json,
    Jsonc,
    Toml,
    Binary,
    Archive,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactPolicy {
    Config,
    Data,
    Export,
    PortableBinary,
    LargeOptIn,
    SecretReference,
    Manual,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ArtifactRef {
    pub id: ArtifactId,
    pub source_path: PathToken,
    pub scope: ConfigScope,
    #[typeshare(serialized_as = "u32")]
    pub size_bytes: u64,
    pub content_type: ContentType,
    pub policy: ArtifactPolicy,
    pub object: Option<ObjectId>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Identity {
    #[typeshare(serialized_as = "Option<String>")]
    #[typeshare(typescript(type = "[ProviderId, string]"))]
    pub provider_package: Option<(ProviderId, String)>,
    pub provider_source: Option<String>,
    pub package_family: Option<String>,
    pub product_name: Option<String>,
    pub executable_name: Option<String>,
    pub publisher: Option<String>,
    pub executable_hash: Option<String>,
    pub install_role: Option<String>,
    pub identity_quality: IdentityQuality,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityQuality {
    Provider,
    PackageFamily,
    SignedProduct,
    Product,
    Local,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Publisher {
    pub name: String,
    pub certificate_thumbprint: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Provenance {
    pub provider: Option<ProviderId>,
    pub package_id: Option<String>,
    #[typeshare(typescript(type = "string | undefined"))]
    pub source_url: Option<Url>,
    pub observed_version: Option<String>,
    pub adapter_id: String,
    pub adapter_version: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EvidenceRef {
    pub id: EvidenceId,
    pub strength: u8,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct VersionValue {
    pub raw: String,
    pub normalized: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    Registry,
    AppPaths,
    Shortcut,
    FileMetadata,
    Authenticode,
    WinGet,
    Chocolatey,
    Scoop,
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Python,
    Rust,
    Go,
    Dotnet,
    PowerShell,
    Wsl,
    Docker,
    Browser,
    Editor,
    Harness,
    UserSelected,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Evidence {
    pub id: EvidenceId,
    pub source: EvidenceSource,
    pub locator: String,
    #[typeshare(typescript(type = "string"))]
    pub observed_at: DateTime<Utc>,
    pub summary: String,
    pub strength: u8,
    pub independent_group: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyKind {
    RequiredRuntime,
    RequiredPackage,
    InstalledThrough,
    Configures,
    UsesSecret,
    OptionalFeature,
    ProvidesExecutable,
    Contains,
    RestoresBefore,
    VerifiesWith,
    RelatedOnly,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DependencyEdge {
    pub from: ComponentId,
    pub to: ComponentId,
    pub kind: DependencyKind,
    pub required: bool,
    pub evidence: Vec<EvidenceId>,
    pub confidence: Confidence,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestoreDescriptor {
    pub primary: RestoreStrategy,
    pub alternatives: Vec<RestoreStrategy>,
    pub portability: Portability,
    pub requires_elevation: bool,
    pub requires_user_action: bool,
    pub rationale: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Compatibility {
    pub required_os: Option<String>,
    pub required_architecture: Option<Architecture>,
    pub requires_provider: Option<ProviderId>,
    pub requires_runtime: Option<ComponentId>,
    pub requires_elevation: bool,
    pub requires_wsl: bool,
    pub requires_docker: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SelectionMetadata {
    pub recommended: bool,
    pub score: i16,
    pub selected_by_default: bool,
    pub sensitive: bool,
    #[typeshare(serialized_as = "u32")]
    pub size_bytes: u64,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DriveFact {
    pub token: String,
    pub filesystem: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DriveFreeSpace {
    pub token: String,
    #[typeshare(serialized_as = "u32")]
    pub bytes: u64,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HostFacts {
    pub os_version: String,
    pub os_build: String,
    pub architecture: Architecture,
    pub elevated: bool,
    pub account_scope: AccountScope,
    pub sid_fingerprint: Option<String>,
    pub known_folders: Vec<PathToken>,
    pub drives: Vec<DriveFact>,
    pub free_bytes: Vec<DriveFreeSpace>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SourceHostSummary {
    pub os_version: String,
    pub os_build: String,
    pub architecture: Architecture,
    pub known_folder_tokens: Vec<KnownFolderToken>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InstalledFact {
    pub kind: ComponentKind,
    pub identity: Identity,
    pub version: Option<VersionValue>,
    pub publisher: Option<Publisher>,
    pub provenance: Option<Provenance>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProviderFact {
    pub id: ProviderId,
    pub version: Option<VersionValue>,
    pub available: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuntimeFact {
    pub id: ComponentId,
    pub version: Option<VersionValue>,
    pub architecture: Option<Architecture>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EnvironmentFact {
    pub scope: ConfigScope,
    pub name: String,
    pub value_hash: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TargetFacts {
    pub host: HostFacts,
    pub installed: Vec<InstalledFact>,
    pub providers: Vec<ProviderFact>,
    pub runtimes: Vec<RuntimeFact>,
    pub environment: Vec<EnvironmentFact>,
    pub fingerprint: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum McpTransport {
    Stdio,
    StreamableHttp,
    Sse,
    Unknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExecutableRef {
    pub name: String,
    pub component: Option<ComponentId>,
    pub observed_path: Option<PathToken>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafeValueRef {
    LiteralNonSecret(String),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EnvBinding {
    pub name: String,
    pub value: SafeValueRef,
}

#[typeshare]
pub type McpArgument = SafeValueRef;

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum McpWorkingDirectory {
    Tokenized(PathToken),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
enum McpEndpointWire {
    Public(Url),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "content",
    rename_all = "SCREAMING_SNAKE_CASE",
    try_from = "McpEndpointWire",
    into = "McpEndpointWire"
)]
#[schemars(with = "McpEndpointWire")]
pub enum McpEndpoint {
    Public(#[typeshare(serialized_as = "String")] Url),
    EnvironmentReference { name: String },
    SecretReference { id: ComponentId, label: String },
    RedactedUnknown,
}

impl TryFrom<McpEndpointWire> for McpEndpoint {
    type Error = String;

    fn try_from(value: McpEndpointWire) -> Result<Self, Self::Error> {
        match value {
            McpEndpointWire::Public(url) => {
                validate_public_endpoint(&url)?;
                Ok(Self::Public(url))
            }
            McpEndpointWire::EnvironmentReference { name } => {
                Ok(Self::EnvironmentReference { name })
            }
            McpEndpointWire::SecretReference { id, label } => {
                Ok(Self::SecretReference { id, label })
            }
            McpEndpointWire::RedactedUnknown => Ok(Self::RedactedUnknown),
        }
    }
}

impl From<McpEndpoint> for McpEndpointWire {
    fn from(value: McpEndpoint) -> Self {
        match value {
            McpEndpoint::Public(url) => Self::Public(url),
            McpEndpoint::EnvironmentReference { name } => Self::EnvironmentReference { name },
            McpEndpoint::SecretReference { id, label } => Self::SecretReference { id, label },
            McpEndpoint::RedactedUnknown => Self::RedactedUnknown,
        }
    }
}

fn validate_public_endpoint(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("MCP public endpoint must use HTTP or HTTPS".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("MCP public endpoint must not contain credentials".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("MCP endpoint query or fragment requires redaction review".to_owned());
    }
    Ok(())
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct McpServerSpec {
    pub name: String,
    pub scope: ConfigScope,
    pub transport: McpTransport,
    pub command: Option<ExecutableRef>,
    pub args: Vec<McpArgument>,
    pub cwd: Option<McpWorkingDirectory>,
    pub endpoint: Option<McpEndpoint>,
    pub environment: Vec<EnvBinding>,
    pub required_runtime: Option<ComponentId>,
    pub required_package: Option<PackageSpec>,
    pub source_config: ArtifactRef,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationRule {
    ProviderIdentity {
        provider: ProviderId,
        package: PackageSpec,
    },
    File {
        destination: TokenizedPath,
        object: Option<ObjectId>,
    },
    FileVersion {
        destination: TokenizedPath,
        version: Option<VersionValue>,
        publisher: Option<Publisher>,
    },
    ConfigParses {
        destination: TokenizedPath,
        content_type: ContentType,
    },
    Environment {
        scope: ConfigScope,
        name: String,
        expected: SafeValueRef,
    },
    McpRegistration {
        name: String,
        config: TokenizedPath,
    },
    WslState {
        distro: String,
        version: Option<String>,
    },
    DockerObject {
        kind: ComponentKind,
        identity: String,
    },
    BrowserArtifact {
        profile: TokenizedPath,
    },
    SecureTarget {
        secret: ComponentId,
    },
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuntimeSpec {
    pub id: String,
    pub version: Option<String>,
    pub architecture: Option<Architecture>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WslSpec {
    pub distribution: String,
    pub wsl_version: Option<u8>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DockerImageSpec {
    pub repository: String,
    pub tag: Option<String>,
    pub image_id: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DockerVolumeSpec {
    pub name: String,
    pub driver: Option<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileMode {
    PreserveTarget,
    Replace,
    CreateOnly,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MergePolicy {
    PreserveUnknown,
    ReplaceKnownKeys,
    AppendUnique,
    ManualOnConflict,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManualActionState {
    Pending,
    Acknowledged,
    Completed,
    Skipped,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ManualAction {
    pub id: String,
    pub component: Option<ComponentId>,
    pub title: String,
    pub reason: String,
    pub risk: RiskLevel,
    pub instructions: Vec<String>,
    #[typeshare(typescript(type = "string | undefined"))]
    pub docs_url: Option<Url>,
    pub state: ManualActionState,
    pub independent_operations_may_continue: bool,
    #[typeshare(typescript(type = "string | undefined"))]
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub verification: Option<VerificationRule>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageManifest {
    pub package_id: String,
    pub format_version: u16,
    #[typeshare(typescript(type = "string"))]
    pub created_at: DateTime<Utc>,
    pub source_host: SourceHostSummary,
    pub required_os: Option<String>,
    pub required_architecture: Option<Architecture>,
    pub component_ids: Vec<ComponentId>,
    pub warnings: Vec<String>,
    pub object_index_digest: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SnapshotManifest {
    pub snapshot_id: SnapshotId,
    pub base_snapshot_id: Option<SnapshotId>,
    pub package: PackageManifest,
    pub reused_objects: Vec<ObjectId>,
    pub new_objects: Vec<ObjectId>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageGraph {
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
}

#[typeshare]
pub type ComponentGraph = PackageGraph;

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObjectIndex {
    pub objects: Vec<ObjectEntry>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ObjectEntry {
    pub id: ObjectId,
    #[typeshare(serialized_as = "u32")]
    pub uncompressed_bytes: u64,
    #[typeshare(serialized_as = "u32")]
    pub compressed_bytes: u64,
    pub content_type: ContentType,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ChunkRef {
    pub id: ObjectId,
    #[typeshare(serialized_as = "u32")]
    pub uncompressed_bytes: u64,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FileManifest {
    #[typeshare(serialized_as = "u32")]
    pub size_bytes: u64,
    pub chunks: Vec<ChunkRef>,
    pub content_type: ContentType,
    pub attributes: u32,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TransportReceipt {
    pub package_id: String,
    #[typeshare(serialized_as = "u32")]
    pub object_count: u64,
    pub index_digest: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Inventory {
    pub format_version: u16,
    pub scan_id: RunId,
    #[typeshare(typescript(type = "string"))]
    pub captured_at: DateTime<Utc>,
    pub host: HostFacts,
    pub graph: ComponentGraph,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WireEnvelope<T> {
    pub schema_version: u16,
    pub request_id: String,
    pub payload: T,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanPhase {
    HostPreflight,
    PackageExports,
    WindowsRegistration,
    RuntimeProbes,
    KnownFolderConfig,
    AppAdapters,
    GenericExecutables,
    Correlation,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProgressStatus {
    Started,
    Progress,
    Completed,
    Warning,
    WaitingForUser,
    Failed,
    Cancelled,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProgressEvent {
    pub run_id: RunId,
    pub phase: ScanPhase,
    pub status: ProgressStatus,
    pub current_component: Option<ComponentId>,
    #[typeshare(serialized_as = "u32")]
    pub completed: u64,
    #[typeshare(serialized_as = "Option<u32>")]
    pub total: Option<u64>,
    #[typeshare(serialized_as = "Option<u32>")]
    pub bytes: Option<u64>,
    pub message: String,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    Planned,
    WaitingForApproval,
    Running,
    WaitingForUser,
    WaitingForReboot,
    Completed,
    Partial,
    Failed,
    Cancelled,
    Interrupted,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    WaitingForUser,
    WaitingForReboot,
    Interrupted,
    Cancelled,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustState {
    Unchecked,
    IntegrityVerified,
    Unsigned,
    SignatureInvalid,
    SignatureValidUntrusted,
    SignatureValidTrusted,
    UserApproved,
    Rejected,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecommendationScore {
    pub component: ComponentId,
    pub score: i16,
    pub recommended: bool,
    pub chips: Vec<ExplanationChip>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExplanationChip {
    pub code: String,
    pub label: String,
    pub delta: i16,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretSelectionPolicy {
    Exclude,
    VaultExplicit,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LargeDataSelectionPolicy {
    Exclude,
    RequireConfirmation,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownBinarySelectionPolicy {
    Exclude,
    PortableBinaryExplicit,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SelectionPolicy {
    pub secrets: SecretSelectionPolicy,
    pub large_data: LargeDataSelectionPolicy,
    pub unknown_binaries: UnknownBinarySelectionPolicy,
    #[typeshare(serialized_as = "Option<u32>")]
    pub max_bytes: Option<u64>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ArtifactSelection {
    pub artifact: ArtifactId,
    pub include: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SelectionInput {
    pub components: Vec<ComponentId>,
    pub artifacts: Vec<ArtifactSelection>,
    pub policy: SelectionPolicy,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SelectionClosure {
    pub selected_components: Vec<ComponentId>,
    pub selected_artifacts: Vec<ArtifactId>,
    pub auto_added_dependencies: Vec<ComponentId>,
    #[typeshare(serialized_as = "u32")]
    pub total_bytes: u64,
    pub warnings: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreMode {
    Rebuild,
    Migration,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityStatus {
    Ready,
    RequiresConfirmation,
    Blocked,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Blocker {
    pub code: ReforgeErrorCode,
    pub component: Option<ComponentId>,
    pub reason: String,
    pub required_action: Option<ManualAction>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Confirmation {
    pub id: String,
    pub component: Option<ComponentId>,
    pub reason: String,
    pub risk: RiskLevel,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CompatibilityResult {
    pub status: CompatibilityStatus,
    pub blockers: Vec<Blocker>,
    pub confirmations: Vec<Confirmation>,
    pub warnings: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Precondition {
    Always,
    TargetFingerprint {
        fingerprint: String,
    },
    ComponentAbsent {
        component: ComponentId,
    },
    ComponentVersion {
        component: ComponentId,
        minimum: Option<VersionValue>,
    },
    ArtifactPresent {
        object: ObjectId,
    },
    ManualApproval {
        action: String,
    },
}

#[typeshare]
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "content", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationKind {
    EnsureProvider {
        provider: ProviderId,
    },
    InstallPackage {
        provider: ProviderId,
        package: PackageSpec,
        policy: PackageInstallPolicy,
    },
    EnsureRuntime {
        runtime: RuntimeSpec,
    },
    WriteFile {
        destination: TokenizedPath,
        object: ObjectId,
        mode: FileMode,
    },
    MergeJson {
        destination: TokenizedPath,
        object: ObjectId,
        policy: MergePolicy,
    },
    MergeToml {
        destination: TokenizedPath,
        object: ObjectId,
        policy: MergePolicy,
    },
    SetUserEnvironment {
        name: String,
        value: SafeValueRef,
    },
    AppendUserPath {
        entries: Vec<TokenizedPath>,
    },
    ImportWsl {
        distro: WslSpec,
        object: ObjectId,
    },
    RestoreDockerImage {
        image: DockerImageSpec,
        object: ObjectId,
    },
    RestoreDockerVolume {
        volume: DockerVolumeSpec,
        object: ObjectId,
    },
    InstallVsCodeExtension {
        id: String,
        version: Option<String>,
        profile: Option<String>,
    },
    RegisterMcp {
        server: McpServerSpec,
    },
    OpenManualAction {
        action: ManualAction,
    },
    RequireReboot {
        reason: String,
    },
    Verify {
        rule: VerificationRule,
    },
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Operation {
    pub id: OperationId,
    pub component: ComponentId,
    pub kind: OperationKind,
    pub prerequisites: Vec<OperationId>,
    pub precondition: Precondition,
    pub idempotency_key: String,
    pub verification: Vec<VerificationRule>,
    pub requires_elevation: bool,
    pub non_idempotent: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictKind {
    AlreadySatisfied,
    VersionDifference,
    ConfigDifference,
    DataCollision,
    SecretCollision,
    PathCollision,
    PortCollision,
    DependencyConflict,
    ArchitectureConflict,
    UnsupportedTarget,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictResolution {
    Skip,
    Install,
    Replace,
    Merge,
    PreserveTarget,
    Manual,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Conflict {
    pub id: String,
    pub component: Option<ComponentId>,
    pub kind: ConflictKind,
    pub source_summary: String,
    pub target_summary: String,
    pub resolution: ConflictResolution,
    pub requires_confirmation: bool,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestorePlan {
    pub format_version: u16,
    pub run_id: RunId,
    pub package_id: String,
    pub mode: RestoreMode,
    pub target_fingerprint: String,
    pub selected_components: Vec<ComponentId>,
    pub operations: Vec<Operation>,
    pub conflicts: Vec<Conflict>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportStatus {
    Verified,
    PartiallyVerified,
    AlreadyPresent,
    Skipped,
    WaitingForUser,
    ReauthRequired,
    RebootRequired,
    Unsupported,
    Failed,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct VerificationEvidence {
    pub rule: VerificationRule,
    pub status: ReportStatus,
    pub summary: String,
    #[typeshare(typescript(type = "string"))]
    pub observed_at: DateTime<Utc>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ComponentReport {
    pub component: ComponentId,
    pub status: ReportStatus,
    pub evidence: Vec<VerificationEvidence>,
    pub manual_actions: Vec<String>,
    pub warnings: Vec<String>,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReportCounts {
    #[typeshare(serialized_as = "u32")]
    pub verified: u64,
    #[typeshare(serialized_as = "u32")]
    pub partial: u64,
    #[typeshare(serialized_as = "u32")]
    pub already_present: u64,
    #[typeshare(serialized_as = "u32")]
    pub waiting_for_user: u64,
    #[typeshare(serialized_as = "u32")]
    pub reauth_required: u64,
    #[typeshare(serialized_as = "u32")]
    pub reboot_required: u64,
    #[typeshare(serialized_as = "u32")]
    pub unsupported: u64,
    #[typeshare(serialized_as = "u32")]
    pub failed: u64,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestoreReport {
    pub format_version: u16,
    pub run_id: RunId,
    pub package_id: String,
    pub status: ReportStatus,
    pub counts: ReportCounts,
    pub components: Vec<ComponentReport>,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<String>,
    #[typeshare(serialized_as = "u32")]
    pub elapsed_ms: u64,
    #[typeshare(serialized_as = "u32")]
    pub bytes_written: u64,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReforgeErrorCode {
    AccessDenied,
    PathNotFound,
    FileLocked,
    InvalidPath,
    ReparsePoint,
    ProviderUnavailable,
    ProviderParseFailed,
    SourceUnavailable,
    VersionUnavailable,
    PackageNotFound,
    PackageCorrupt,
    PackageUntrusted,
    VaultRequired,
    VaultDecryptFailed,
    SecretNotPortable,
    ManualSecretRequired,
    SchemaInvalid,
    UnsupportedVersion,
    ArchitectureConflict,
    OsConflict,
    InsufficientDisk,
    DependencyCycle,
    SelectionIncomplete,
    TargetConflict,
    SecurityPolicy,
    ManualActionRequired,
    UserActionRequired,
    RebootRequired,
    OperationFailed,
    InstallFailed,
    VerificationFailed,
    Interrupted,
    Cancelled,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Retryability {
    Never,
    SafeRetry,
    RequiresUserAction,
    AfterReboot,
}

#[typeshare]
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub code: ReforgeErrorCode,
    pub message: String,
    pub technical_detail: Option<String>,
    pub component: Option<ComponentId>,
    pub operation: Option<OperationId>,
    pub retryability: Retryability,
    pub context_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelValidationError {
    pub code: ReforgeErrorCode,
    pub message: String,
}

impl ModelValidationError {
    fn new(code: ReforgeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Validate references and security-sensitive shape before approval/execution.
///
/// This performs the model-level checks that do not require target state:
/// operation IDs and keys are unique, prerequisites exist and are acyclic,
/// referenced objects are indexed, path tokens are normalized, protected
/// generic roots are gated, and overlapping file/merge writes are ordered.
pub fn validate_restore_plan(
    plan: &RestorePlan,
    object_index: &ObjectIndex,
) -> Result<(), ModelValidationError> {
    let mut operation_ids = BTreeSet::new();
    let mut operation_keys = BTreeSet::new();
    let mut operations_by_id = BTreeMap::new();

    for operation in &plan.operations {
        if !operation_ids.insert(operation.id.clone()) {
            return Err(ModelValidationError::new(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains duplicate operation IDs",
            ));
        }
        if !operation_keys.insert(operation.idempotency_key.clone()) {
            return Err(ModelValidationError::new(
                ReforgeErrorCode::SchemaInvalid,
                "restore plan contains duplicate idempotency keys",
            ));
        }
        operations_by_id.insert(operation.id.clone(), operation);
    }

    for operation in &plan.operations {
        for prerequisite in &operation.prerequisites {
            if !operations_by_id.contains_key(prerequisite) {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SchemaInvalid,
                    "restore plan contains a missing prerequisite",
                ));
            }
        }
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in operation_ids {
        visit_operation(&id, &operations_by_id, &mut visiting, &mut visited)?;
    }

    let indexed_objects: BTreeSet<_> = object_index.objects.iter().map(|entry| &entry.id).collect();
    if indexed_objects.len() != object_index.objects.len() {
        return Err(ModelValidationError::new(
            ReforgeErrorCode::SchemaInvalid,
            "object index contains duplicate object IDs",
        ));
    }

    let mut writes = Vec::new();
    for operation in &plan.operations {
        validate_operation_paths(operation)?;
        for object in operation_objects(&operation.kind) {
            if !indexed_objects.contains(object) {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SchemaInvalid,
                    "operation references an object absent from the package index",
                ));
            }
        }
        for rule in &operation.verification {
            validate_verification_rule(rule)?;
            if let Some(object) = verification_object(rule)
                && !indexed_objects.contains(object)
            {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SchemaInvalid,
                    "verification references an object absent from the package index",
                ));
            }
        }
        if let Precondition::ArtifactPresent { object } = &operation.precondition
            && !indexed_objects.contains(object)
        {
            return Err(ModelValidationError::new(
                ReforgeErrorCode::SchemaInvalid,
                "precondition references an object absent from the package index",
            ));
        }
        if matches!(
            &operation.kind,
            OperationKind::WriteFile { .. }
                | OperationKind::MergeJson { .. }
                | OperationKind::MergeToml { .. }
        ) && let Some(path) = operation_destination(&operation.kind)
        {
            if matches!(
                path.root,
                KnownFolderToken::ProgramFiles | KnownFolderToken::ProgramFilesX86
            ) {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "generic file operations cannot target Program Files",
                ));
            }
            if matches!(path.root, KnownFolderToken::ProgramData) && !operation.requires_elevation {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "ProgramData writes require an explicit elevation boundary",
                ));
            }
            writes.push((operation, path));
        }
        if let OperationKind::SetUserEnvironment { value, .. } = &operation.kind
            && matches!(value, SafeValueRef::SecretReference { .. })
        {
            return Err(ModelValidationError::new(
                ReforgeErrorCode::SecurityPolicy,
                "plain user environment writes cannot consume secret references",
            ));
        }
    }

    for (index, (left_operation, left_path)) in writes.iter().enumerate() {
        for (right_operation, right_path) in writes.iter().skip(index + 1) {
            let left_is_merge = matches!(
                left_operation.kind,
                OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. }
            );
            let right_is_merge = matches!(
                right_operation.kind,
                OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. }
            );
            if left_is_merge == right_is_merge || !paths_overlap(left_path, right_path) {
                continue;
            }
            let ordered =
                operation_precedes(&left_operation.id, &right_operation.id, &operations_by_id)
                    || operation_precedes(
                        &right_operation.id,
                        &left_operation.id,
                        &operations_by_id,
                    );
            if !ordered {
                return Err(ModelValidationError::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "overlapping file and merge operations lack deterministic ordering",
                ));
            }
        }
    }

    Ok(())
}

fn visit_operation(
    id: &OperationId,
    operations: &BTreeMap<OperationId, &Operation>,
    visiting: &mut BTreeSet<OperationId>,
    visited: &mut BTreeSet<OperationId>,
) -> Result<(), ModelValidationError> {
    if visited.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.clone()) {
        return Err(ModelValidationError::new(
            ReforgeErrorCode::DependencyCycle,
            "restore plan operation prerequisites contain a cycle",
        ));
    }
    let operation = operations.get(id).expect("prerequisite existence checked");
    for prerequisite in &operation.prerequisites {
        visit_operation(prerequisite, operations, visiting, visited)?;
    }
    visiting.remove(id);
    visited.insert(id.clone());
    Ok(())
}

fn operation_precedes(
    before: &OperationId,
    after: &OperationId,
    operations: &BTreeMap<OperationId, &Operation>,
) -> bool {
    let mut pending = vec![after.clone()];
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(operation) = operations.get(&current) else {
            continue;
        };
        if operation.prerequisites.iter().any(|id| id == before) {
            return true;
        }
        pending.extend(operation.prerequisites.iter().cloned());
    }
    false
}

fn operation_objects(kind: &OperationKind) -> Vec<&ObjectId> {
    match kind {
        OperationKind::WriteFile { object, .. }
        | OperationKind::MergeJson { object, .. }
        | OperationKind::MergeToml { object, .. }
        | OperationKind::ImportWsl { object, .. }
        | OperationKind::RestoreDockerImage { object, .. }
        | OperationKind::RestoreDockerVolume { object, .. } => vec![object],
        _ => Vec::new(),
    }
}

fn operation_destination(kind: &OperationKind) -> Option<&PathToken> {
    match kind {
        OperationKind::WriteFile { destination, .. }
        | OperationKind::MergeJson { destination, .. }
        | OperationKind::MergeToml { destination, .. } => Some(destination),
        _ => None,
    }
}

fn validate_operation_paths(operation: &Operation) -> Result<(), ModelValidationError> {
    if let Some(path) = operation_destination(&operation.kind) {
        validate_path(path)?;
    }
    if let OperationKind::AppendUserPath { entries } = &operation.kind {
        for path in entries {
            validate_path(path)?;
        }
    }
    Ok(())
}

fn validate_verification_rule(rule: &VerificationRule) -> Result<(), ModelValidationError> {
    let path = match rule {
        VerificationRule::File { destination, .. }
        | VerificationRule::FileVersion { destination, .. }
        | VerificationRule::ConfigParses { destination, .. }
        | VerificationRule::McpRegistration {
            config: destination,
            ..
        }
        | VerificationRule::BrowserArtifact {
            profile: destination,
        } => Some(destination),
        _ => None,
    };
    if let Some(path) = path {
        validate_path(path)?;
    }
    Ok(())
}

fn validate_path(path: &PathToken) -> Result<(), ModelValidationError> {
    path.validate()
        .map_err(|message| ModelValidationError::new(ReforgeErrorCode::InvalidPath, message))
}

fn verification_object(rule: &VerificationRule) -> Option<&ObjectId> {
    match rule {
        VerificationRule::File { object, .. } => object.as_ref(),
        _ => None,
    }
}

fn paths_overlap(left: &PathToken, right: &PathToken) -> bool {
    if left.root != right.root {
        return false;
    }
    let left = left.relative.to_ascii_lowercase();
    let right = right.relative.to_ascii_lowercase();
    left == right
        || (!left.is_empty() && right.starts_with(&(left.clone() + "/")))
        || (!right.is_empty() && left.starts_with(&(right.clone() + "/")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn component_id() -> ComponentId {
        ComponentId::new(format!("cmp_{}", "a".repeat(52))).expect("valid component ID")
    }

    fn object_id(hex: char) -> ObjectId {
        ObjectId::new(format!("obj_{}", hex.to_string().repeat(64))).expect("valid object ID")
    }

    fn operation_id(ordinal: u16) -> OperationId {
        OperationId::new(format!("op_018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31_{ordinal}"))
            .expect("valid operation ID")
    }

    fn empty_plan(operation: Operation) -> RestorePlan {
        RestorePlan {
            format_version: 1,
            run_id: RunId::new("018f2f8c-3f2d-7cc0-8d37-7b8c4fbe5e31".parse().unwrap()).unwrap(),
            package_id: "pkg_test".to_owned(),
            mode: RestoreMode::Rebuild,
            target_fingerprint: "target".to_owned(),
            selected_components: vec![component_id()],
            operations: vec![operation],
            conflicts: Vec::new(),
            manual_actions: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn object_index(object: ObjectId) -> ObjectIndex {
        ObjectIndex {
            objects: vec![ObjectEntry {
                id: object,
                uncompressed_bytes: 1,
                compressed_bytes: 1,
                content_type: ContentType::Binary,
            }],
        }
    }

    #[test]
    fn path_token_rejects_absolute_and_parent_paths() {
        assert!(PathToken::new(KnownFolderToken::Documents, "C:/unsafe").is_err());
        assert!(PathToken::new(KnownFolderToken::Documents, "nested/../unsafe").is_err());
        assert_eq!(
            PathToken::new(KnownFolderToken::Documents, "nested\\./file.txt")
                .unwrap()
                .relative,
            "nested/file.txt"
        );
        let result: Result<PathToken, _> = serde_json::from_value(json!({
            "root": "DOCUMENTS",
            "relative": "/absolute"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn json_round_trip_rejects_missing_fields_and_unknown_enums() {
        let original = VersionValue {
            raw: "1.0".to_owned(),
            normalized: Some("1.0.0".to_owned()),
        };
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: VersionValue = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);

        let missing: Result<VersionValue, _> = serde_json::from_value(json!({
            "normalized": "1.0.0"
        }));
        assert!(missing.is_err());

        let unknown: Result<ConfigScope, _> = serde_json::from_value(json!("NOT_A_SCOPE"));
        assert!(unknown.is_err());
    }

    #[test]
    fn component_preserves_unknown_fields_only_in_extensions() {
        let value: Component = serde_json::from_value(json!({
            "id": component_id().to_string(),
            "kind": "APPLICATION",
            "identity": {"identity_quality": "PRODUCT"},
            "display_name": "Example",
            "version": null,
            "architecture": null,
            "publisher": null,
            "provenance": null,
            "evidence": [],
            "confidence": "UNKNOWN",
            "dependencies": [],
            "artifacts": [],
            "restore": {
                "primary": "UNKNOWN",
                "alternatives": [],
                "portability": "UNKNOWN",
                "requires_elevation": false,
                "requires_user_action": false,
                "rationale": []
            },
            "compatibility": {
                "required_os": null,
                "required_architecture": null,
                "requires_provider": null,
                "requires_runtime": null,
                "requires_elevation": false,
                "requires_wsl": false,
                "requires_docker": false
            },
            "verification": [],
            "selection": {
                "recommended": false,
                "score": 0,
                "selected_by_default": false,
                "sensitive": false,
                "size_bytes": 0
            },
            "future_field": {"opaque": true}
        }))
        .unwrap();
        assert_eq!(value.extensions["future_field"], json!({"opaque": true}));
    }

    #[test]
    fn mcp_secret_reference_never_serializes_a_secret_value() {
        let reference = SafeValueRef::SecretReference {
            id: component_id(),
            label: "CONTEXT7_API_KEY".to_owned(),
        };
        let value = serde_json::to_value(reference).unwrap();
        assert_eq!(
            value,
            json!({
                "type": "SECRET_REFERENCE",
                "content": {
                    "id": component_id().to_string(),
                    "label": "CONTEXT7_API_KEY"
                }
            })
        );
        assert!(!value.to_string().contains("secret-value"));
    }

    #[test]
    fn public_mcp_endpoint_rejects_credentials_and_query_values() {
        let credentials: Result<McpEndpoint, _> = serde_json::from_value(json!({
            "PUBLIC": "https://user:password@example.test/mcp"
        }));
        assert!(credentials.is_err());
        let query: Result<McpEndpoint, _> = serde_json::from_value(json!({
            "PUBLIC": "https://example.test/mcp?token=secret"
        }));
        assert!(query.is_err());
    }

    #[test]
    fn restore_plan_rejects_missing_object_and_cycles() {
        let object = object_id('a');
        let operation = Operation {
            id: operation_id(1),
            component: component_id(),
            kind: OperationKind::WriteFile {
                destination: PathToken::new(KnownFolderToken::Documents, "settings.json").unwrap(),
                object: object.clone(),
                mode: FileMode::Replace,
            },
            prerequisites: vec![operation_id(2)],
            precondition: Precondition::Always,
            idempotency_key: "key-1".to_owned(),
            verification: Vec::new(),
            requires_elevation: false,
            non_idempotent: false,
        };
        let missing = validate_restore_plan(
            &empty_plan(operation.clone()),
            &ObjectIndex { objects: vec![] },
        );
        assert_eq!(missing.unwrap_err().code, ReforgeErrorCode::SchemaInvalid);

        let mut plan = empty_plan(operation);
        plan.operations.push(Operation {
            id: operation_id(2),
            component: component_id(),
            kind: OperationKind::RequireReboot {
                reason: "test".to_owned(),
            },
            prerequisites: vec![operation_id(1)],
            precondition: Precondition::Always,
            idempotency_key: "key-2".to_owned(),
            verification: Vec::new(),
            requires_elevation: false,
            non_idempotent: false,
        });
        let cycle = validate_restore_plan(&plan, &object_index(object));
        assert_eq!(cycle.unwrap_err().code, ReforgeErrorCode::DependencyCycle);
    }

    #[test]
    fn deterministic_serialization_preserves_struct_field_order() {
        let value = VersionValue {
            raw: "1.0".to_owned(),
            normalized: Some("1.0.0".to_owned()),
        };
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"raw":"1.0","normalized":"1.0.0"}"#
        );
    }

    #[test]
    fn timestamp_serializes_as_rfc3339_utc() {
        let timestamp = Utc.with_ymd_and_hms(2026, 8, 29, 12, 34, 56).unwrap();
        let evidence = Evidence {
            id: EvidenceId::new("evidence-test").unwrap(),
            source: EvidenceSource::Unknown,
            locator: "redacted".to_owned(),
            observed_at: timestamp,
            summary: "test".to_owned(),
            strength: 10,
            independent_group: "test".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(evidence).unwrap()["observed_at"],
            "2026-08-29T12:34:56Z"
        );
    }
}
