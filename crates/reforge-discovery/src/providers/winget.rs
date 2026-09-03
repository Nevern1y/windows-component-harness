//! WinGet package discovery, normalization, planning, and verification descriptors.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken,
    ManualAction, ManualActionState, Operation, OperationId, OperationKind, PackageInstallPolicy,
    PackageSpec, PathToken, Portability, Precondition, Provenance, ProviderId, RedactionPolicy,
    ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel, RunId, SelectionMetadata,
    TargetFacts, VerificationRule, VersionValue,
};
use reforge_platform_windows::{
    BoundedFileReader, BuiltinExecutable, CommandSpec, ProcessResult, SafePath, TrustedExecutable,
};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "winget";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXPORT_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCES: usize = 1_024;
const MAX_PACKAGES: usize = 100_000;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const MAX_PROVIDER_TEXT_BYTES: usize = 256;
const MAX_SOURCE_IDENTIFIER_BYTES: usize = 512;
const MAX_SOURCE_ARGUMENT_BYTES: usize = 2_048;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// WinGet adapter for documented JSON exports and exact identity queries.
#[derive(Clone, Debug)]
pub struct WinGetAdapter {
    id: ProviderId,
}

impl WinGetAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant WinGet provider ID"),
        }
    }

    /// Parse a completed, bounded WinGet export capture.
    ///
    /// This pure boundary is also used by deterministic fixtures. `process`
    /// contains only already-bounded process output; `json` is independently
    /// bounded because WinGet writes it to a file rather than stdout.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        json: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        validate_process_result(process, "export")?;
        if json.len() as u64 > MAX_EXPORT_BYTES {
            return Err(security_error(
                "WinGet export exceeds the reviewed byte limit",
            ));
        }

        let mut enumeration = parse_export_document(&self.id, json, observed_at)?;
        enumeration
            .warnings
            .extend(provider_output_warnings(process));
        enumeration.warnings.sort();
        enumeration.warnings.dedup();
        if enumeration.warnings.len() > MAX_WARNINGS {
            return Err(security_error(
                "WinGet export produced too many bounded warnings",
            ));
        }
        Ok(enumeration)
    }

    /// Build the exact, non-JSON WinGet query used by the verification engine.
    /// The output is deliberately not parsed as a localized table.
    pub fn verification_command(&self, package: &PackageSpec) -> ProviderResult<CommandSpec> {
        validate_package_spec(package, &self.id)?;
        let source_name = package
            .source_name
            .as_deref()
            .ok_or_else(|| source_error("WinGet verification requires the recorded source name"))?;
        CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
            [
                OsString::from("list"),
                OsString::from("--id"),
                OsString::from(&package.id),
                OsString::from("--exact"),
                OsString::from("--source"),
                OsString::from(source_name),
                OsString::from("--disable-interactivity"),
            ],
            VERIFICATION_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )
    }

    async fn live_export(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let temporary = ExportDirectory::create(context)?;
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::WinGet),
            [
                OsString::from("export"),
                OsString::from("--output"),
                temporary.output.as_os_str().to_owned(),
                OsString::from("--include-versions"),
                OsString::from("--disable-interactivity"),
            ],
            EXPORT_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let process = context
            .runner
            .run(&command, context.cancellation)
            .await
            .map_err(map_runner_error)?;
        validate_process_result(&process, "export")?;

        let root = temporary.root.clone();
        let json = tokio::task::spawn_blocking(move || read_export_file(&root))
            .await
            .map_err(|_| operation_error("WinGet export reader task failed"))??;
        self.parse_capture(&process, &json, Utc::now())
    }
}

impl Default for WinGetAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for WinGetAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::WinGet) {
            return DetectionResult::unavailable();
        }

        DetectionResult {
            available: true,
            version: None,
            evidence: vec![Evidence {
                id: EvidenceId::new("winget-provider-path")
                    .expect("constant WinGet provider evidence ID"),
                source: EvidenceSource::WinGet,
                locator: "PATH:winget.exe".to_owned(),
                observed_at: Utc::now(),
                summary: "The reviewed WinGet executable name resolves from PATH".to_owned(),
                strength: 50,
                independent_group: "winget-provider".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        self.live_export(context).await
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Package {
            spec,
            version,
            evidence,
        } = observation
        else {
            return Err(schema_error(
                "WinGet received a non-package discovery observation",
            ));
        };
        validate_package_spec(&spec, &self.id)?;
        if evidence.is_empty() {
            return Err(schema_error(
                "WinGet package observation has no supporting evidence",
            ));
        }
        if spec.version.as_deref() != version.as_ref().map(|value| value.raw.as_str()) {
            return Err(schema_error(
                "WinGet package and observation versions disagree",
            ));
        }
        let source_identifier = spec.source_identifier.clone().ok_or_else(|| {
            source_error("WinGet package identity requires a stable source identifier")
        })?;
        let identity = Identity {
            provider_package: Some((self.id.clone(), spec.id.clone())),
            provider_source: Some(source_identifier),
            package_family: None,
            product_name: None,
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        };
        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("WinGet package identity is not canonical"))?;
        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: spec.clone(),
        };
        let exact_restore = spec.version.is_some();
        let mut evidence_refs: Vec<_> = evidence
            .iter()
            .map(|record| EvidenceRef {
                id: record.id.clone(),
                strength: record.strength,
            })
            .collect();
        evidence_refs.sort_by(|left, right| left.id.cmp(&right.id));
        evidence_refs.dedup_by(|left, right| left.id == right.id);

        Ok(vec![Component {
            id: canonical.id,
            kind: ComponentKind::Package,
            identity,
            display_name: spec.id.clone(),
            version,
            architecture: spec.architecture.clone(),
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some(spec.id.clone()),
                source_url: spec.source.clone(),
                observed_version: spec.version.clone(),
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs,
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: if exact_restore {
                RestoreDescriptor {
                    primary: RestoreStrategy::Reinstall,
                    alternatives: Vec::new(),
                    portability: Portability::SupportedExport,
                    requires_elevation: false,
                    requires_user_action: false,
                    rationale: vec![
                        "WinGet recorded an exact package, source, and version identity".to_owned(),
                    ],
                }
            } else {
                RestoreDescriptor {
                    primary: RestoreStrategy::Manual,
                    alternatives: Vec::new(),
                    portability: Portability::PartiallyPortable,
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale: vec![
                        "WinGet did not export a version; latest-version substitution is disabled"
                            .to_owned(),
                    ],
                }
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: spec.architecture.clone(),
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: vec![verification],
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: 0,
            },
            extensions: BTreeMap::new(),
        }])
    }

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        let package = package_from_component(component, &self.id)?.clone();
        let provider_available = target
            .providers
            .iter()
            .any(|provider| provider.id == self.id && provider.available);
        let unavailable_reason = (!provider_available).then_some(
            "WinGet is unavailable on the target and no reviewed automatic bootstrap exists",
        );
        let incomplete_reason = if package.version.is_none() {
            Some("The WinGet export did not include a package version")
        } else if package.source_name.is_none() || package.source_identifier.is_none() {
            Some("The WinGet export did not include an exact source identity")
        } else {
            None
        };
        if let Some(reason) = unavailable_reason.or(incomplete_reason) {
            return Ok(vec![manual_operation(
                component,
                &self.id,
                package,
                reason,
                run_id,
                first_ordinal,
            )?]);
        }

        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: package.clone(),
        };
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| schema_error("WinGet operation ID could not be constructed"))?;
        Ok(vec![Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::InstallPackage {
                provider: self.id.clone(),
                package: package.clone(),
                policy: PackageInstallPolicy {
                    accept_source_agreements: false,
                    accept_package_agreements: false,
                    silent: false,
                    allow_reboot: false,
                },
            },
            prerequisites: Vec::new(),
            precondition: Precondition::ComponentAbsent {
                component: component.id.clone(),
            },
            idempotency_key: operation_key("install", &package),
            verification: vec![verification],
            requires_elevation: false,
            non_idempotent: false,
        }])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        let package = package_from_component(component, &self.id)?.clone();
        self.verification_command(&package)?;
        Ok(vec![VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package,
        }])
    }
}

#[derive(Debug, Deserialize)]
struct ExportDocument {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    #[serde(rename = "WinGetVersion")]
    winget_version: Option<String>,
    #[serde(rename = "Sources")]
    sources: Vec<ExportSource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportSchema {
    V1,
    V2,
}

#[derive(Debug, Deserialize)]
struct ExportSource {
    #[serde(rename = "SourceDetails")]
    details: SourceDetails,
    #[serde(rename = "Packages")]
    packages: Vec<ExportPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct SourceDetails {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Identifier")]
    identifier: String,
    #[serde(rename = "Argument")]
    argument: String,
    #[serde(rename = "Type")]
    source_type: String,
}

#[derive(Debug, Deserialize)]
struct ExportPackage {
    #[serde(rename = "PackageIdentifier")]
    package_identifier: Option<String>,
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
}

#[derive(Clone)]
struct PackageRecord {
    spec: PackageSpec,
    version: Option<VersionValue>,
    evidence: Evidence,
}

fn parse_export_document(
    provider: &ProviderId,
    bytes: &[u8],
    observed_at: DateTime<Utc>,
) -> ProviderResult<ProviderEnumeration> {
    let document: ExportDocument = serde_json::from_slice(bytes).map_err(|error| {
        Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::ProviderParseFailed,
                "The WinGet export is not valid JSON for the reviewed schema",
            )
            .with_technical_detail(error.to_string()),
        )
    })?;
    let schema = validate_schema(
        document.schema.as_deref(),
        document.winget_version.as_deref(),
    )?;
    if let Some(version) = document.winget_version.as_deref() {
        validate_text("WinGet version", version, MAX_PROVIDER_TEXT_BYTES)?;
    }
    if document.sources.len() > MAX_SOURCES {
        return Err(security_error(
            "WinGet export exceeds the reviewed source count",
        ));
    }

    let mut sources_by_identifier = BTreeMap::<String, SourceDetails>::new();
    let mut identifiers_by_name = BTreeMap::<String, String>::new();
    let mut packages = BTreeMap::<(String, String), PackageRecord>::new();
    let mut warnings = BTreeSet::<String>::new();
    let mut package_count = 0usize;

    for source in document.sources {
        validate_source_details(&source.details)?;
        if source.packages.is_empty() {
            return Err(parse_error("WinGet source contains no packages"));
        }
        package_count = package_count
            .checked_add(source.packages.len())
            .ok_or_else(|| security_error("WinGet package count overflow"))?;
        if package_count > MAX_PACKAGES {
            return Err(security_error(
                "WinGet export exceeds the reviewed package count",
            ));
        }

        let identifier_key = source.details.identifier.to_lowercase();
        let name_key = source.details.name.to_lowercase();
        if let Some(existing) = sources_by_identifier.get(&identifier_key) {
            if existing != &source.details {
                return Err(parse_error(
                    "WinGet source identifier has conflicting source details",
                ));
            }
            push_warning(
                &mut warnings,
                format!(
                    "WinGet export repeated source {}; identical records were merged",
                    source.details.name
                ),
            )?;
        } else {
            sources_by_identifier.insert(identifier_key.clone(), source.details.clone());
        }
        if let Some(existing_identifier) = identifiers_by_name.get(&name_key) {
            if existing_identifier != &identifier_key {
                return Err(parse_error(
                    "WinGet source name maps to conflicting source identifiers",
                ));
            }
        } else {
            identifiers_by_name.insert(name_key, identifier_key.clone());
        }

        let source_url = public_source_url(&source.details.argument);
        if source_url.is_none() {
            push_warning(
                &mut warnings,
                format!(
                    "WinGet source {} has no preservable public HTTP(S) URL",
                    source.details.name
                ),
            )?;
        }

        for raw_package in source.packages {
            let package_id =
                package_identifier(schema, raw_package.package_identifier, raw_package.id)?;
            validate_package_id(&package_id)?;
            if let Some(version) = raw_package.version.as_deref() {
                validate_package_version(version)?;
            }
            let spec = PackageSpec {
                provider: provider.clone(),
                id: package_id.clone(),
                version: raw_package.version.clone(),
                source_name: Some(source.details.name.clone()),
                source_identifier: Some(source.details.identifier.clone()),
                source: source_url.clone(),
                architecture: None,
                installer_hash: None,
            };
            let version = raw_package.version.as_ref().map(|raw| VersionValue {
                raw: raw.clone(),
                normalized: None,
            });
            let evidence = package_evidence(
                &source.details,
                &package_id,
                raw_package.version.as_deref(),
                observed_at,
            )?;
            let key = (identifier_key.clone(), package_id.to_lowercase());
            if let Some(existing) = packages.get(&key) {
                if existing.spec.version != spec.version {
                    return Err(parse_error(
                        "WinGet export repeats a package with conflicting versions",
                    ));
                }
                push_warning(
                    &mut warnings,
                    format!(
                        "WinGet export repeated package {} from source {}; identical records were merged",
                        package_id, source.details.name
                    ),
                )?;
                continue;
            }
            if spec.version.is_none() {
                push_warning(
                    &mut warnings,
                    format!(
                        "WinGet package {} from source {} has no version; automatic latest fallback is disabled",
                        package_id, source.details.name
                    ),
                )?;
            }
            packages.insert(
                key,
                PackageRecord {
                    spec,
                    version,
                    evidence,
                },
            );
        }
    }

    let observations = packages
        .into_values()
        .map(|record| Observation::Package {
            spec: record.spec,
            version: record.version,
            evidence: vec![record.evidence],
        })
        .collect();
    Ok(ProviderEnumeration {
        observations,
        warnings: warnings.into_iter().collect(),
    })
}

fn validate_schema(
    schema: Option<&str>,
    winget_version: Option<&str>,
) -> ProviderResult<ExportSchema> {
    let schema = match schema {
        Some("https://aka.ms/winget-packages.schema.1.0.json") => ExportSchema::V1,
        Some("https://aka.ms/winget-packages.schema.2.0.json") => ExportSchema::V2,
        Some(_) => {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::UnsupportedVersion,
                "The WinGet export schema version is not supported",
            )));
        }
        None => return Err(parse_error("WinGet export is missing its schema URI")),
    };
    if matches!(schema, ExportSchema::V1) && winget_version.is_none() {
        return Err(parse_error(
            "WinGet schema 1.0 requires the generating WinGet version",
        ));
    }
    if let Some(version) = winget_version {
        validate_winget_version(version, schema)?;
    }
    Ok(schema)
}

fn validate_winget_version(value: &str, schema: ExportSchema) -> ProviderResult<()> {
    let numeric = match schema {
        ExportSchema::V1 => value,
        ExportSchema::V2 => value.strip_suffix("-preview").unwrap_or(value),
    };
    let parts: Vec<_> = numeric.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(parse_error(
            "WinGetVersion is outside the documented schema grammar",
        ));
    }
    if matches!(schema, ExportSchema::V1) && value.contains("-preview") {
        return Err(parse_error(
            "WinGet schema 1.0 does not accept preview version suffixes",
        ));
    }
    Ok(())
}

fn validate_source_details(details: &SourceDetails) -> ProviderResult<()> {
    validate_text("WinGet source name", &details.name, MAX_PROVIDER_TEXT_BYTES)?;
    validate_text(
        "WinGet source identifier",
        &details.identifier,
        MAX_SOURCE_IDENTIFIER_BYTES,
    )?;
    validate_text(
        "WinGet source argument",
        &details.argument,
        MAX_SOURCE_ARGUMENT_BYTES,
    )?;
    validate_text(
        "WinGet source type",
        &details.source_type,
        MAX_PROVIDER_TEXT_BYTES,
    )
}

fn validate_package_spec(package: &PackageSpec, provider: &ProviderId) -> ProviderResult<()> {
    if &package.provider != provider {
        return Err(schema_error("WinGet package uses a different provider ID"));
    }
    validate_package_id(&package.id)?;
    if let Some(version) = package.version.as_deref() {
        validate_package_version(version)?;
    }
    if let Some(name) = package.source_name.as_deref() {
        validate_text("WinGet source name", name, MAX_PROVIDER_TEXT_BYTES)?;
    }
    if let Some(identifier) = package.source_identifier.as_deref() {
        validate_text(
            "WinGet source identifier",
            identifier,
            MAX_SOURCE_IDENTIFIER_BYTES,
        )?;
    }
    if let Some(source) = package.source.as_ref()
        && (!matches!(source.scheme(), "http" | "https")
            || !source.username().is_empty()
            || source.password().is_some()
            || source.query().is_some()
            || source.fragment().is_some())
    {
        return Err(source_error(
            "WinGet source URL is not a public credential-free HTTP(S) URL",
        ));
    }
    Ok(())
}

fn validate_text(kind: &str, value: &str, max_bytes: usize) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(parse_error(&format!(
            "{kind} is outside the reviewed grammar"
        )));
    }
    Ok(())
}

fn validate_package_id(value: &str) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(
                    character,
                    '\\' | '/'
                        | ':'
                        | '*'
                        | '?'
                        | '"'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                        | ';'
                        | '`'
                        | '$'
                        | '%'
                )
        })
    {
        return Err(parse_error(
            "WinGet package ID is outside the reviewed argument grammar",
        ));
    }
    Ok(())
}

fn validate_package_version(value: &str) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(
                    character,
                    '\\' | '/'
                        | ':'
                        | '*'
                        | '?'
                        | '"'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                        | ';'
                        | '`'
                        | '$'
                        | '%'
                )
        })
    {
        return Err(parse_error(
            "WinGet package version is outside the reviewed argument grammar",
        ));
    }
    Ok(())
}

fn package_identifier(
    schema: ExportSchema,
    package_identifier: Option<String>,
    legacy_id: Option<String>,
) -> ProviderResult<String> {
    match schema {
        ExportSchema::V1 => match (legacy_id, package_identifier) {
            (Some(id), None) => Ok(id),
            (Some(id), Some(package_identifier)) if id == package_identifier => Err(parse_error(
                "WinGet schema 1.0 package contains both identifier spellings",
            )),
            (Some(_), Some(_)) => Err(parse_error(
                "WinGet package contains conflicting current and legacy identifiers",
            )),
            (None, _) => Err(parse_error("WinGet schema 1.0 package has no Id field")),
        },
        ExportSchema::V2 => match (package_identifier, legacy_id) {
            (Some(package_identifier), None) => Ok(package_identifier),
            (Some(package_identifier), Some(id)) if id == package_identifier => Err(parse_error(
                "WinGet schema 2.0 package contains both identifier spellings",
            )),
            (Some(_), Some(_)) => Err(parse_error(
                "WinGet package contains conflicting current and legacy identifiers",
            )),
            (None, _) => Err(parse_error(
                "WinGet schema 2.0 package has no PackageIdentifier field",
            )),
        },
    }
}

fn public_source_url(argument: &str) -> Option<Url> {
    let url = Url::parse(argument).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url)
}

fn package_evidence(
    source: &SourceDetails,
    package_id: &str,
    version: Option<&str>,
    observed_at: DateTime<Utc>,
) -> ProviderResult<Evidence> {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &source.identifier);
    hash_field(&mut hasher, package_id);
    hash_field(&mut hasher, version.unwrap_or(""));
    let id = EvidenceId::new(format!("winget-export-{}", hasher.finalize().to_hex()))
        .map_err(|_| schema_error("WinGet evidence ID could not be constructed"))?;
    Ok(Evidence {
        id,
        source: EvidenceSource::WinGet,
        locator: format!("winget:{}:{package_id}", source.identifier),
        observed_at,
        summary: format!(
            "WinGet exported package {package_id} from source {}{}",
            source.name,
            version.map_or("".to_owned(), |value| format!(" at version {value}"))
        ),
        strength: 80,
        independent_group: "winget-export".to_owned(),
    })
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn provider_output_warnings(result: &ProcessResult) -> Vec<String> {
    let redacted = RedactionPolicy::with_max_bytes(PROCESS_OUTPUT_BYTES)
        .redact_provider_output(result.stdout.as_bytes(), result.stderr.as_bytes());
    let mut warnings = Vec::new();
    for (stream, output) in [("stdout", redacted.stdout), ("stderr", redacted.stderr)] {
        let Some(output) = output else {
            continue;
        };
        for line in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if warnings.len() == 128 {
                warnings.push(
                    "Additional WinGet process output was omitted at the reviewed warning bound"
                        .to_owned(),
                );
                return warnings;
            }
            warnings.push(format!(
                "WinGet {stream}: {}",
                truncate_utf8(line, MAX_WARNING_BYTES)
            ));
        }
    }
    warnings
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn push_warning(warnings: &mut BTreeSet<String>, warning: String) -> ProviderResult<()> {
    if warnings.len() == MAX_WARNINGS {
        return Err(security_error(
            "WinGet export exceeds the reviewed warning count",
        ));
    }
    warnings.insert(warning);
    Ok(())
}

fn confidence_from_evidence(evidence: &[Evidence]) -> Confidence {
    let mut score = evidence
        .iter()
        .fold(0u16, |score, record| {
            score.saturating_add(u16::from(record.strength))
        })
        .min(100);
    let independent_groups: BTreeSet<_> = evidence
        .iter()
        .map(|record| record.independent_group.as_str())
        .collect();
    if independent_groups.len() >= 2 {
        score = score.saturating_add(10).min(100);
    }
    if score >= 90 && independent_groups.len() >= 2 {
        Confidence::Confirmed
    } else if score >= 75 {
        Confidence::High
    } else if score >= 45 {
        Confidence::Medium
    } else if score >= 20 {
        Confidence::Low
    } else {
        Confidence::Unknown
    }
}

fn package_from_component<'a>(
    component: &'a Component,
    provider: &ProviderId,
) -> ProviderResult<&'a PackageSpec> {
    let mut packages = component.verification.iter().filter_map(|rule| match rule {
        VerificationRule::ProviderIdentity {
            provider: rule_provider,
            package,
        } if rule_provider == provider => Some(package),
        _ => None,
    });
    let package = packages.next().ok_or_else(|| {
        schema_error("WinGet component has no typed provider identity verification")
    })?;
    if packages.next().is_some() {
        return Err(schema_error(
            "WinGet component has multiple provider identity descriptors",
        ));
    }
    validate_package_spec(package, provider)?;
    Ok(package)
}

fn manual_operation(
    component: &Component,
    provider: &ProviderId,
    package: PackageSpec,
    reason: &str,
    run_id: &RunId,
    ordinal: u64,
) -> ProviderResult<Operation> {
    let verification = VerificationRule::ProviderIdentity {
        provider: provider.clone(),
        package: package.clone(),
    };
    let operation_id = OperationId::for_run(run_id, ordinal)
        .map_err(|_| schema_error("WinGet manual operation ID could not be constructed"))?;
    let digest = operation_key("manual", &package);
    Ok(Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::OpenManualAction {
            action: ManualAction {
                id: digest.clone(),
                component: Some(component.id.clone()),
                title: "Review WinGet package restore".to_owned(),
                reason: reason.to_owned(),
                risk: RiskLevel::Medium,
                instructions: vec![
                    "Confirm an exact WinGet source and package version before installing"
                        .to_owned(),
                    "Do not substitute the latest available package version".to_owned(),
                ],
                docs_url: Some(
                    Url::parse(
                        "https://learn.microsoft.com/windows/package-manager/winget/install",
                    )
                    .expect("constant WinGet documentation URL"),
                ),
                state: ManualActionState::Pending,
                independent_operations_may_continue: true,
                acknowledged_at: None,
                verification: Some(verification.clone()),
            },
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key: digest,
        verification: vec![verification],
        requires_elevation: false,
        non_idempotent: false,
    })
}

fn operation_key(role: &str, package: &PackageSpec) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, role);
    hash_field(&mut hasher, package.provider.as_str());
    hash_field(
        &mut hasher,
        package.source_identifier.as_deref().unwrap_or(""),
    );
    hash_field(&mut hasher, &package.id);
    hash_field(&mut hasher, package.version.as_deref().unwrap_or(""));
    format!("winget-{role}-{}", hasher.finalize().to_hex())
}

fn validate_process_result(result: &ProcessResult, operation: &str) -> ProviderResult<()> {
    if result.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            "WinGet discovery was cancelled",
        )));
    }
    if result.timed_out {
        return Err(operation_error(&format!("WinGet {operation} timed out")));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(operation_error(&format!(
            "WinGet {operation} exited with code {code}"
        ))),
        None => Err(operation_error(&format!(
            "WinGet {operation} ended without an exit code"
        ))),
    }
}

fn read_export_file(root: &Path) -> ProviderResult<Vec<u8>> {
    let path = SafePath::new("export.json")?;
    let mut reader = BoundedFileReader::open(root, &path, MAX_EXPORT_BYTES)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

struct ExportDirectory {
    root: PathBuf,
    output: PathBuf,
}

impl ExportDirectory {
    fn create(context: &ProviderContext<'_>) -> ProviderResult<Self> {
        let local_app_data = context.known_folders.resolve(
            &PathToken::new(KnownFolderToken::LocalAppData, "")
                .map_err(|_| schema_error("LocalAppData token could not be constructed"))?,
        )?;
        for _ in 0..32 {
            let root = local_app_data.join(format!(".reforge-winget-{}", Uuid::now_v7()));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&root).map_err(|error| {
                        io_boundary_error("inspect WinGet export directory", &error)
                    })?;
                    if !metadata.is_dir()
                        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    {
                        let _ = fs::remove_dir(&root);
                        return Err(security_error(
                            "WinGet export directory is not a regular local directory",
                        ));
                    }
                    return Ok(Self {
                        output: root.join("export.json"),
                        root,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(io_boundary_error(
                        "create private WinGet export directory",
                        &error,
                    ));
                }
            }
        }
        Err(security_error(
            "Could not allocate a unique WinGet export directory",
        ))
    }
}

impl Drop for ExportDirectory {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.output)
            && (metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        {
            let _ = fs::remove_file(&self.output);
        }
        let _ = fs::remove_dir(&self.root);
    }
}

fn map_runner_error(error: Box<ErrorEnvelope>) -> Box<ErrorEnvelope> {
    if error.code == ReforgeErrorCode::PathNotFound {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ProviderUnavailable,
            "WinGet is unavailable on this Windows target",
        ))
    } else {
        error
    }
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "The WinGet export did not match the reviewed schema",
        )
        .with_technical_detail(detail),
    )
}

fn source_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SourceUnavailable,
            "The WinGet source identity is incomplete or unsafe",
        )
        .with_technical_detail(detail),
    )
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "The WinGet component contract is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "WinGet discovery exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "The WinGet discovery command could not be completed",
        )
        .with_technical_detail(detail),
    )
}

fn io_boundary_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(
        error,
        format!("{operation} failed"),
    ))
}
