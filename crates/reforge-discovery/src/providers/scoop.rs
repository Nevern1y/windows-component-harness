//! Scoop export discovery and typed restore descriptors.
//!
//! The adapter consumes the documented JSON export shape, resolves each app's
//! bucket metadata, and refuses automatic restore when a bucket is missing or
//! custom. No Scoop import command is executed during discovery.

use std::{collections::BTreeMap, ffi::OsString, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, ManualAction,
    ManualActionState, Operation, OperationId, OperationKind, PackageInstallPolicy, PackageSpec,
    Portability, Precondition, Provenance, ProviderId, RedactionPolicy, ReforgeErrorCode,
    RestoreDescriptor, RestoreStrategy, RiskLevel, RunId, SelectionMetadata, TargetFacts,
    VerificationRule, VersionValue,
};
use reforge_platform_windows::{BuiltinExecutable, CommandSpec, ProcessResult, TrustedExecutable};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "scoop";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXPORT_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_APPS: usize = 100_000;
const MAX_BUCKETS: usize = 4_096;
const MAX_PACKAGE_ID_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 128;
const MAX_SOURCE_BYTES: usize = 2_048;
const MAX_WARNING_BYTES: usize = 512;
const MAX_WARNINGS: usize = 4_096;
const DEFAULT_BUCKET_HOST: &str = "github.com";
const SCRIPT_RISK_WARNING: &str =
    "Scoop manifests may execute installer scripts; review bucket and manifest risk before restore";

/// Scoop provider adapter for documented JSON exports.
#[derive(Clone, Debug)]
pub struct ScoopAdapter {
    id: ProviderId,
}

impl ScoopAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Scoop provider ID"),
        }
    }

    /// Parse a bounded completed `scoop export` capture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        json: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        validate_process_result(process, "export")?;
        if json.len() > MAX_EXPORT_BYTES {
            return Err(security_error(
                "Scoop export exceeds the reviewed byte limit",
            ));
        }
        let document: ExportDocument = serde_json::from_slice(json).map_err(|error| {
            Box::new(
                ErrorEnvelope::new(
                    ReforgeErrorCode::ProviderParseFailed,
                    "The Scoop export is not valid JSON for the reviewed schema",
                )
                .with_technical_detail(error.to_string()),
            )
        })?;
        if document.apps.len() > MAX_APPS {
            return Err(security_error(
                "Scoop export exceeds the reviewed app count",
            ));
        }
        if document.buckets.len() > MAX_BUCKETS {
            return Err(security_error(
                "Scoop export exceeds the reviewed bucket count",
            ));
        }
        let mut warnings = vec![SCRIPT_RISK_WARNING.to_owned()];
        if document.config.is_some() {
            warnings.push(
                "Scoop export configuration values were not imported into package metadata"
                    .to_owned(),
            );
        }
        if !document.extra.is_empty() {
            warnings.push(
                "Scoop export contains unsupported top-level fields; they were not imported"
                    .to_owned(),
            );
        }

        let mut buckets = BTreeMap::<String, BucketRecord>::new();
        for bucket in document.buckets {
            let name = validate_bucket_name(&bucket.name)?;
            let key = name.to_ascii_lowercase();
            let record = bucket_record(&name, bucket.source.as_deref())?;
            if let Some(existing) = buckets.get(&key)
                && existing != &record
            {
                return Err(parse_error(
                    "Scoop export repeats a bucket with conflicting metadata",
                ));
            }
            if !record.trusted {
                warnings.push(format!(
                    "Scoop bucket {name} is custom or unverifiable; dependent package restores remain manual"
                ));
            }
            buckets.insert(key, record);
        }

        let mut apps = BTreeMap::<String, AppRecord>::new();
        for app in document.apps {
            let name = validate_package_id(&app.name)?;
            let version = app.version.map(|value| {
                validate_version(&value).map(|()| VersionValue {
                    raw: value,
                    normalized: None,
                })
            });
            let version = version.transpose()?;
            let source = resolve_app_source(app.source.as_deref(), &buckets)?;
            let key = name.to_ascii_lowercase();
            let record = AppRecord {
                name: name.clone(),
                version,
                source,
            };
            if let Some(existing) = apps.get(&key)
                && existing != &record
            {
                return Err(parse_error(
                    "Scoop export repeats an app with conflicting metadata",
                ));
            }
            apps.insert(key, record);
        }

        let observations = apps
            .into_values()
            .map(|app| {
                let spec = PackageSpec {
                    provider: self.id.clone(),
                    id: app.name.clone(),
                    version: app.version.as_ref().map(|value| value.raw.clone()),
                    source_name: Some(app.source.name.clone()),
                    source_identifier: Some(app.source.identifier.clone()),
                    source: app.source.url.clone(),
                    architecture: None,
                    installer_hash: None,
                };
                let version_label = app
                    .version
                    .as_ref()
                    .map_or_else(|| "unversioned".to_owned(), |value| value.raw.clone());
                let summary = if app.source.trusted {
                    format!(
                        "Scoop export recorded app {} version {version_label} from bucket {}",
                        app.name,
                        app.source.name
                    )
                } else {
                    format!(
                        "Scoop export recorded app {} version {version_label}; bucket source requires manual review",
                        app.name
                    )
                };
                let mut evidence = vec![make_evidence(
                    EvidenceSource::Scoop,
                    format!("scoop-export:{}", app.name),
                    &summary,
                    if app.source.trusted { 80 } else { 50 },
                    if app.source.trusted {
                        "scoop-reviewed-bucket"
                    } else {
                        "scoop-custom-bucket"
                    },
                    observed_at,
                )];
                evidence.push(make_evidence(
                    EvidenceSource::Scoop,
                    format!("scoop-source:{}", app.source.identifier),
                    &format!(
                        "Scoop source metadata recorded for app {} without importing configuration values",
                        app.name
                    ),
                    if app.source.trusted { 70 } else { 40 },
                    if app.source.trusted {
                        "scoop-reviewed-source"
                    } else {
                        "scoop-custom-source"
                    },
                    observed_at,
                ));
                Observation::Package {
                    spec,
                    version: app.version,
                    evidence,
                }
            })
            .collect();
        if !process.stderr.trim().is_empty() {
            warnings.push(format!(
                "Scoop export reported stderr: {}",
                process.stderr.trim()
            ));
        }
        warnings = warnings
            .into_iter()
            .filter_map(|warning| safe_text(&warning, MAX_WARNING_BYTES))
            .collect();
        warnings.sort();
        warnings.dedup();
        warnings.truncate(MAX_WARNINGS);
        Ok(ProviderEnumeration {
            observations,
            warnings,
        })
    }

    fn export_command(&self) -> ProviderResult<CommandSpec> {
        CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Scoop),
            [OsString::from("export")],
            EXPORT_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )
    }

    async fn live_export(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let command = self.export_command()?;
        let process = context
            .runner
            .run(&command, context.cancellation)
            .await
            .map_err(map_runner_error)?;
        self.parse_capture(&process, process.stdout.as_bytes(), Utc::now())
    }
}

impl Default for ScoopAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for ScoopAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::Scoop) {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![make_evidence(
                EvidenceSource::Scoop,
                "PATH:scoop.exe".to_owned(),
                "The reviewed Scoop executable name resolves from PATH",
                60,
                "scoop-provider",
                Utc::now(),
            )],
            warnings: vec![SCRIPT_RISK_WARNING.to_owned()],
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
                "Scoop received a non-package discovery observation",
            ));
        };
        validate_package_spec(&spec, &self.id)?;
        if evidence.is_empty() {
            return Err(schema_error(
                "Scoop package observation has no supporting evidence",
            ));
        }
        if spec.version.as_deref() != version.as_ref().map(|value| value.raw.as_str()) {
            return Err(schema_error(
                "Scoop package and observation versions disagree",
            ));
        }
        let source_identifier = spec
            .source_identifier
            .clone()
            .ok_or_else(|| source_error("Scoop package identity requires bucket metadata"))?;
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
            .map_err(|_| schema_error("Scoop package identity is not canonical"))?;
        let exact_restore = is_reviewed_source(&spec) && version.is_some();
        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: spec.clone(),
        };
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
            evidence: evidence_refs(&evidence),
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: if exact_restore {
                RestoreDescriptor {
                    primary: RestoreStrategy::Reinstall,
                    alternatives: vec![RestoreStrategy::Manual],
                    portability: Portability::SupportedExport,
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale: vec![
                        "Scoop export recorded an exact app version and reviewed bucket source"
                            .to_owned(),
                        SCRIPT_RISK_WARNING.to_owned(),
                    ],
                }
            } else {
                RestoreDescriptor {
                    primary: RestoreStrategy::Manual,
                    alternatives: vec![RestoreStrategy::Reinstall],
                    portability: Portability::PartiallyPortable,
                    requires_elevation: false,
                    requires_user_action: true,
                    rationale: vec![
                        "Scoop bucket or version evidence is incomplete or custom".to_owned(),
                        "Latest-version substitution is disabled".to_owned(),
                        SCRIPT_RISK_WARNING.to_owned(),
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
        if !provider_available {
            return Ok(vec![manual_operation(
                component,
                &package,
                "Scoop is unavailable on the target; provider bootstrap is not automatic",
                run_id,
                first_ordinal,
            )?]);
        }
        if !is_reviewed_source(&package) || package.version.is_none() {
            return Ok(vec![manual_operation(
                component,
                &package,
                "Scoop export lacks a reviewed bucket source and exact version for automatic restore",
                run_id,
                first_ordinal,
            )?]);
        }
        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: package.clone(),
        };
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| schema_error("Scoop operation ID could not be constructed"))?;
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
        Ok(vec![VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package,
        }])
    }
}

#[derive(Debug, Deserialize)]
struct ExportDocument {
    #[serde(default)]
    apps: Vec<ExportApp>,
    #[serde(default)]
    buckets: Vec<ExportBucket>,
    #[serde(default)]
    config: Option<Value>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ExportApp {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version", default)]
    version: Option<String>,
    #[serde(rename = "Source", default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportBucket {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Source", default)]
    source: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BucketRecord {
    name: String,
    identifier: String,
    url: Option<Url>,
    trusted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppRecord {
    name: String,
    version: Option<VersionValue>,
    source: BucketRecord,
}

fn resolve_app_source(
    source: Option<&str>,
    buckets: &BTreeMap<String, BucketRecord>,
) -> ProviderResult<BucketRecord> {
    let Some(source) = source else {
        return Ok(BucketRecord {
            name: "unknown".to_owned(),
            identifier: "bucket-unknown".to_owned(),
            url: None,
            trusted: false,
        });
    };
    validate_text("Scoop app source", source, MAX_SOURCE_BYTES)?;
    if let Some(bucket) = buckets.get(&source.to_ascii_lowercase()) {
        return Ok(bucket.clone());
    }
    if let Some(url) = public_url(source) {
        return Ok(BucketRecord {
            name: "custom".to_owned(),
            identifier: format!("bucket-custom:{}", url.host_str().unwrap_or("unknown")),
            url: Some(url),
            trusted: false,
        });
    }
    let name = validate_bucket_name(source)?;
    Ok(BucketRecord {
        name: name.clone(),
        identifier: format!("bucket-unknown:{name}"),
        url: None,
        trusted: false,
    })
}

fn bucket_record(name: &str, source: Option<&str>) -> ProviderResult<BucketRecord> {
    let Some(source) = source else {
        return Ok(BucketRecord {
            name: name.to_owned(),
            identifier: format!("bucket-unknown:{name}"),
            url: None,
            trusted: false,
        });
    };
    validate_text("Scoop bucket source", source, MAX_SOURCE_BYTES)?;
    let Some(url) = public_url(source) else {
        return Ok(BucketRecord {
            name: name.to_owned(),
            identifier: format!("bucket-custom:{name}"),
            url: None,
            trusted: false,
        });
    };
    let trusted = is_reviewed_bucket(name, &url);
    Ok(BucketRecord {
        name: name.to_owned(),
        identifier: if trusted {
            format!("bucket:{name}")
        } else {
            format!("bucket-custom:{name}")
        },
        url: Some(url),
        trusted,
    })
}

fn is_reviewed_bucket(name: &str, source: &Url) -> bool {
    let name = name.to_ascii_lowercase();
    let path = source.path().trim_matches('/').to_ascii_lowercase();
    source
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(DEFAULT_BUCKET_HOST))
        && path == format!("scoopinstaller/{name}")
        && matches!(name.as_str(), "main" | "extras" | "versions")
}

fn is_reviewed_source(package: &PackageSpec) -> bool {
    let Some(identifier) = package.source_identifier.as_deref() else {
        return false;
    };
    identifier.starts_with("bucket:")
        && package.source.as_ref().is_some_and(|source| {
            package
                .source_name
                .as_deref()
                .is_some_and(|name| is_reviewed_bucket(name, source))
        })
}

fn validate_package_spec(package: &PackageSpec, provider: &ProviderId) -> ProviderResult<()> {
    if &package.provider != provider {
        return Err(schema_error("Scoop package uses a different provider ID"));
    }
    validate_package_id(&package.id)?;
    if let Some(version) = package.version.as_deref() {
        validate_version(version)?;
    }
    if let Some(name) = package.source_name.as_deref() {
        validate_bucket_name(name)?;
    }
    if let Some(identifier) = package.source_identifier.as_deref() {
        validate_text("Scoop source identifier", identifier, MAX_SOURCE_BYTES)?;
    }
    if let Some(source) = package.source.as_ref()
        && !is_public_url(source)
    {
        return Err(source_error(
            "Scoop bucket URL is not a public credential-free HTTP(S) URL",
        ));
    }
    Ok(())
}

fn validate_package_id(value: &str) -> ProviderResult<String> {
    validate_identifier("Scoop app name", value, MAX_PACKAGE_ID_BYTES)
}

fn validate_bucket_name(value: &str) -> ProviderResult<String> {
    validate_identifier("Scoop bucket name", value, MAX_SOURCE_BYTES)
}

fn validate_identifier(kind: &str, value: &str, max_bytes: usize) -> ProviderResult<String> {
    if value.is_empty()
        || value.len() > max_bytes
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
        return Err(parse_error(&format!(
            "{kind} is outside the reviewed grammar"
        )));
    }
    Ok(value.to_owned())
}

fn validate_version(value: &str) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > MAX_VERSION_BYTES
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(parse_error(
            "Scoop app version is outside the reviewed grammar",
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

fn public_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

fn is_public_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn package_from_component<'a>(
    component: &'a Component,
    provider: &ProviderId,
) -> ProviderResult<&'a PackageSpec> {
    if component.kind != ComponentKind::Package
        || component
            .provenance
            .as_ref()
            .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
    {
        return Err(schema_error("Scoop component belongs to another adapter"));
    }
    let mut packages = component.verification.iter().filter_map(|rule| match rule {
        VerificationRule::ProviderIdentity {
            provider: rule_provider,
            package,
        } if rule_provider == provider => Some(package),
        _ => None,
    });
    let package = packages
        .next()
        .ok_or_else(|| schema_error("Scoop component has no provider identity"))?;
    if packages.next().is_some() {
        return Err(schema_error(
            "Scoop component has multiple provider identities",
        ));
    }
    validate_package_spec(package, provider)?;
    Ok(package)
}

fn manual_operation(
    component: &Component,
    package: &PackageSpec,
    reason: &str,
    run_id: &RunId,
    ordinal: u64,
) -> ProviderResult<Operation> {
    let verification = VerificationRule::ProviderIdentity {
        provider: package.provider.clone(),
        package: package.clone(),
    };
    let operation_id = OperationId::for_run(run_id, ordinal)
        .map_err(|_| schema_error("Scoop manual operation ID could not be constructed"))?;
    let idempotency_key = operation_key("manual", package);
    Ok(Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::OpenManualAction {
            action: ManualAction {
                id: idempotency_key.clone(),
                component: Some(component.id.clone()),
                title: "Review Scoop package restore".to_owned(),
                reason: reason.to_owned(),
                risk: RiskLevel::High,
                instructions: vec![
                    "Confirm the Scoop bucket, manifest, package version, license, and installer-script risk"
                        .to_owned(),
                    "Do not substitute the latest package version".to_owned(),
                ],
                docs_url: Some(
                    Url::parse("https://github.com/ScoopInstaller/Scoop/wiki/Commands")
                        .expect("constant Scoop documentation URL"),
                ),
                state: ManualActionState::Pending,
                independent_operations_may_continue: true,
                acknowledged_at: None,
                verification: Some(verification.clone()),
            },
        },
        prerequisites: Vec::new(),
        precondition: Precondition::Always,
        idempotency_key,
        verification: vec![verification],
        requires_elevation: false,
        non_idempotent: false,
    })
}

fn operation_key(role: &str, package: &PackageSpec) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, role);
    hash_field(&mut hasher, package.provider.as_str());
    hash_field(&mut hasher, &package.id);
    hash_field(&mut hasher, package.version.as_deref().unwrap_or(""));
    hash_field(
        &mut hasher,
        package.source_identifier.as_deref().unwrap_or(""),
    );
    format!("scoop-{role}-{}", hasher.finalize().to_hex())
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn make_evidence(
    source: EvidenceSource,
    locator: String,
    summary: &str,
    strength: u8,
    independent_group: &str,
    observed_at: DateTime<Utc>,
) -> Evidence {
    let summary = safe_text(summary, MAX_WARNING_BYTES)
        .unwrap_or_else(|| "Scoop evidence was redacted".to_owned());
    let id = evidence_id(&source, &locator, &summary);
    Evidence {
        id,
        source,
        locator,
        observed_at,
        summary,
        strength,
        independent_group: independent_group.to_owned(),
    }
}

fn evidence_id(source: &EvidenceSource, locator: &str, summary: &str) -> EvidenceId {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &format!("{source:?}"));
    hash_field(&mut hasher, locator);
    hash_field(&mut hasher, summary);
    EvidenceId::new(format!("scoop-evidence-{}", hasher.finalize().to_hex()))
        .expect("hashed Scoop evidence ID")
}

fn evidence_refs(evidence: &[Evidence]) -> Vec<EvidenceRef> {
    let mut refs: Vec<_> = evidence
        .iter()
        .map(|record| EvidenceRef {
            id: record.id.clone(),
            strength: record.strength,
        })
        .collect();
    refs.sort_by(|left, right| left.id.cmp(&right.id));
    refs.dedup_by(|left, right| left.id == right.id);
    refs
}

fn confidence_from_evidence(evidence: &[Evidence]) -> Confidence {
    let score = evidence
        .iter()
        .fold(0u16, |score, record| {
            score.saturating_add(u16::from(record.strength))
        })
        .min(100);
    match score {
        90..=100 => Confidence::Confirmed,
        75..=89 => Confidence::High,
        45..=74 => Confidence::Medium,
        20..=44 => Confidence::Low,
        _ => Confidence::Unknown,
    }
}

fn safe_text(value: &str, max_bytes: usize) -> Option<String> {
    RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
}

fn validate_process_result(result: &ProcessResult, operation: &str) -> ProviderResult<()> {
    if result.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            format!("Scoop {operation} was cancelled"),
        )));
    }
    if result.timed_out {
        return Err(operation_error(&format!("Scoop {operation} timed out")));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(operation_error(&format!(
            "Scoop {operation} exited with code {code}"
        ))),
        None => Err(operation_error(&format!(
            "Scoop {operation} ended without an exit code"
        ))),
    }
}

fn map_runner_error(error: Box<ErrorEnvelope>) -> Box<ErrorEnvelope> {
    if error.code == ReforgeErrorCode::PathNotFound {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ProviderUnavailable,
            "Scoop is unavailable on this Windows target",
        ))
    } else {
        error
    }
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Scoop provider data is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Scoop export did not match the reviewed JSON shape",
        )
        .with_technical_detail(detail),
    )
}

fn source_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SourceUnavailable,
            "Scoop bucket source is incomplete or unsafe",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Scoop export exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Scoop export could not be completed",
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success() -> ProcessResult {
        ProcessResult {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            cancelled: false,
        }
    }

    #[test]
    fn parses_reviewed_bucket_and_exact_version() {
        let adapter = ScoopAdapter::new();
        let result = adapter
            .parse_capture(
                &success(),
                br#"{"apps":[{"Name":"git","Version":"2.47.1","Source":"main"}],"buckets":[{"Name":"main","Source":"https://github.com/ScoopInstaller/Main"}]}"#,
                Utc::now(),
            )
            .expect("Scoop JSON parses");
        let Observation::Package { spec, version, .. } = &result.observations[0] else {
            panic!("package observation");
        };
        assert_eq!(spec.id, "git");
        assert_eq!(
            version.as_ref().map(|value| value.raw.as_str()),
            Some("2.47.1")
        );
        assert_eq!(spec.source_name.as_deref(), Some("main"));
        let component = adapter
            .normalize(result.observations.into_iter().next().expect("observation"))
            .expect("component")
            .remove(0);
        assert_eq!(component.restore.primary, RestoreStrategy::Reinstall);
    }

    #[test]
    fn custom_bucket_is_manual_and_malformed_json_fails() {
        let adapter = ScoopAdapter::new();
        assert!(adapter.parse_capture(&success(), b"{", Utc::now()).is_err());
        let result = adapter
            .parse_capture(
                &success(),
                br#"{"apps":[{"Name":"private-tool","Version":"1.0","Source":"private"}],"buckets":[{"Name":"private","Source":"https://example.invalid/bucket"}]}"#,
                Utc::now(),
            )
            .expect("custom Scoop JSON parses");
        let component = adapter
            .normalize(result.observations.into_iter().next().expect("observation"))
            .expect("component")
            .remove(0);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert!(
            component
                .restore
                .rationale
                .iter()
                .any(|reason| reason.contains("installer scripts"))
        );
    }
}
