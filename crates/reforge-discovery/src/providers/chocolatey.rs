//! Chocolatey export discovery and typed restore descriptors.
//!
//! Chocolatey exports are XML package manifests. The adapter parses only the
//! reviewed `<packages><package id="..." version="..." /></packages>` shape,
//! keeps source trust explicit, and never executes package scripts during
//! discovery.
use std::ffi::OsString;
use std::{
    collections::BTreeMap,
    fs, io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
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
use tokio::task;
use url::Url;
use uuid::Uuid;

const PROVIDER_ID: &str = "chocolatey";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXPORT_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_PACKAGE_ID_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 128;
const MAX_SOURCE_BYTES: usize = 2_048;
const MAX_XML_TAG_BYTES: usize = 16 * 1024;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const DEFAULT_SOURCE_NAME: &str = "community";
const DEFAULT_SOURCE_IDENTIFIER: &str = "community";
const PROVIDER_DEFAULT_SOURCE_ID: &str = "provider-default";
const SCRIPT_RISK_WARNING: &str =
    "Chocolatey packages may execute install scripts; source and license risk require review";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Chocolatey provider adapter for versioned XML exports.
#[derive(Clone, Debug)]
pub struct ChocolateyAdapter {
    id: ProviderId,
}

impl ChocolateyAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Chocolatey provider ID"),
        }
    }

    /// Parse a bounded completed `choco export` manifest.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        xml: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        validate_process_result(process, "export")?;
        if xml.len() > MAX_EXPORT_BYTES {
            return Err(security_error(
                "Chocolatey export exceeds the reviewed byte limit",
            ));
        }
        let text = std::str::from_utf8(xml)
            .map_err(|_| parse_error("Chocolatey export is not valid UTF-8 XML"))?;
        let packages = parse_export(text)?;
        let mut records = BTreeMap::<String, PackageRecord>::new();
        let mut warnings = vec![SCRIPT_RISK_WARNING.to_owned()];
        for package in packages {
            let key = package.id.to_ascii_lowercase();
            if let Some(existing) = records.get(&key) {
                if existing.version != package.version || existing.source != package.source {
                    return Err(parse_error(
                        "Chocolatey export repeats a package with conflicting metadata",
                    ));
                }
                push_warning(
                    &mut warnings,
                    format!(
                        "Chocolatey export repeated package {}; identical records were merged",
                        package.id
                    ),
                );
                continue;
            }
            if !package.source.trusted {
                push_warning(
                    &mut warnings,
                    "Chocolatey export contains a custom or unverifiable source; restore remains manual"
                        .to_owned(),
                );
            }
            records.insert(key, package);
        }

        let observations = records
            .into_values()
            .map(|package| {
                let version = package.version.as_ref().map(|raw| VersionValue {
                    raw: raw.clone(),
                    normalized: None,
                });
                let spec = PackageSpec {
                    provider: self.id.clone(),
                    id: package.id.clone(),
                    version: package.version.clone(),
                    source_name: package.source.name.clone(),
                    source_identifier: package.source.identifier.clone(),
                    source: package.source.url.clone(),
                    architecture: None,
                    installer_hash: None,
                };
                let version_label = package.version.as_deref().unwrap_or("unversioned");
                let (summary, strength, independent_group) =
                    if package.source.trusted && package.source.name.is_none() {
                        (
                            format!(
                                "Chocolatey export recorded provider-owned package {} version {version_label}; source was not recorded",
                                package.id
                            ),
                            70,
                            "chocolatey-provider-identity",
                        )
                    } else if package.source.trusted {
                        (
                            format!(
                                "Chocolatey export recorded package {} version {version_label} from the reviewed community source",
                                package.id
                            ),
                            80,
                            "chocolatey-reviewed-source",
                        )
                    } else {
                        (
                            format!(
                                "Chocolatey export recorded package {} version {version_label}; source requires manual review",
                                package.id
                            ),
                            50,
                            "chocolatey-custom-source",
                        )
                    };
                Observation::Package {
                    spec,
                    version,
                    evidence: vec![make_evidence(
                        EvidenceSource::Chocolatey,
                        format!("choco-export:{}", package.id),
                        &summary,
                        strength,
                        independent_group,
                        observed_at,
                    )],
                }
            })
            .collect();
        if !process.stderr.trim().is_empty() {
            push_warning(
                &mut warnings,
                format!(
                    "Chocolatey export reported stderr: {}",
                    process.stderr.trim()
                ),
            );
        }
        warnings.sort();
        warnings.dedup();
        warnings.truncate(MAX_WARNINGS);
        Ok(ProviderEnumeration {
            observations,
            warnings,
        })
    }

    fn export_command(&self, output: &Path) -> ProviderResult<CommandSpec> {
        CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Chocolatey),
            [
                OsString::from("export"),
                OsString::from("--output-file-path"),
                output.as_os_str().to_owned(),
                OsString::from("--include-version-numbers"),
            ],
            EXPORT_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )
    }

    async fn live_export(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let temporary = ExportDirectory::create(context)?;
        let command = self.export_command(&temporary.output)?;
        let process = context
            .runner
            .run(&command, context.cancellation)
            .await
            .map_err(map_runner_error)?;
        let root = temporary.root.clone();
        let xml = task::spawn_blocking(move || read_export_file(&root))
            .await
            .map_err(|_| operation_error("Chocolatey export reader worker failed"))??;
        self.parse_capture(&process, &xml, Utc::now())
    }
}

impl Default for ChocolateyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for ChocolateyAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context
            .runner
            .builtin_available(BuiltinExecutable::Chocolatey)
        {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![make_evidence(
                EvidenceSource::Chocolatey,
                "PATH:choco.exe".to_owned(),
                "The reviewed Chocolatey executable name resolves from PATH",
                60,
                "chocolatey-provider",
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
                "Chocolatey received a non-package discovery observation",
            ));
        };
        validate_package_spec(&spec, &self.id)?;
        if evidence.is_empty() {
            return Err(schema_error(
                "Chocolatey package observation has no supporting evidence",
            ));
        }
        let identity = Identity {
            provider_package: Some((self.id.clone(), spec.id.clone())),
            provider_source: Some(
                spec.source_identifier
                    .clone()
                    .unwrap_or_else(|| PROVIDER_DEFAULT_SOURCE_ID.to_owned()),
            ),
            package_family: None,
            product_name: None,
            executable_name: None,
            publisher: None,
            executable_hash: None,
            install_role: None,
            identity_quality: IdentityQuality::Provider,
        };
        let canonical = ComponentId::from_identity(&identity, None)
            .map_err(|_| schema_error("Chocolatey package identity is not canonical"))?;
        let exact_restore = is_reviewed_source(&spec) && version.is_some();
        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: spec.clone(),
        };
        let portability = if spec.source.is_some() {
            Portability::SupportedExport
        } else {
            Portability::PartiallyPortable
        };
        let mut rationale = if exact_restore {
            vec!["Chocolatey export recorded an exact package version".to_owned()]
        } else {
            vec![
                "Chocolatey source or version evidence is incomplete".to_owned(),
                "Latest-version substitution is disabled".to_owned(),
            ]
        };
        if spec.source.is_none() {
            rationale.push(
                "Chocolatey export does not record the configured source; verify it before restore"
                    .to_owned(),
            );
        }
        rationale.push(SCRIPT_RISK_WARNING.to_owned());
        Ok(vec![Component {
            id: canonical.id,
            kind: ComponentKind::Package,
            identity,
            display_name: spec.id.clone(),
            version: version.clone(),
            architecture: spec.architecture.clone(),
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some(spec.id.clone()),
                source_url: spec.source.clone(),
                observed_version: version.as_ref().map(|value| value.raw.clone()),
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs(&evidence),
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary: if exact_restore {
                    RestoreStrategy::Reinstall
                } else {
                    RestoreStrategy::Manual
                },
                alternatives: if exact_restore {
                    vec![RestoreStrategy::Manual]
                } else {
                    vec![RestoreStrategy::Reinstall]
                },
                portability,
                requires_elevation: false,
                requires_user_action: true,
                rationale,
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
                "Chocolatey is unavailable on the target; provider bootstrap is not automatic",
                run_id,
                first_ordinal,
            )?]);
        }
        if !is_reviewed_source(&package) || package.version.is_none() {
            return Ok(vec![manual_operation(
                component,
                &package,
                "Chocolatey export lacks a reviewed source and exact version for automatic restore",
                run_id,
                first_ordinal,
            )?]);
        }
        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: package.clone(),
        };
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| schema_error("Chocolatey operation ID could not be constructed"))?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceDescriptor {
    name: Option<String>,
    identifier: Option<String>,
    url: Option<Url>,
    trusted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageRecord {
    id: String,
    version: Option<String>,
    source: SourceDescriptor,
}

fn parse_export(input: &str) -> ProviderResult<Vec<PackageRecord>> {
    let mut reader = XmlReader::new(input);
    let root = loop {
        let Some(token) = reader.next()? else {
            return Err(parse_error("Chocolatey export has no root element"));
        };
        match token {
            XmlToken::Text(text) if text.trim().is_empty() => continue,
            XmlToken::Tag(root) => break root,
            XmlToken::Text(_) => {
                return Err(parse_error("Chocolatey export has non-whitespace preamble"));
            }
        }
    };
    if root.name != "packages" || root.closing {
        return Err(parse_error("Chocolatey export root must be <packages>"));
    }
    if root.self_closing {
        consume_trailing_whitespace(&mut reader)?;
        return Ok(Vec::new());
    }

    let mut packages = Vec::new();
    loop {
        let Some(token) = reader.next()? else {
            return Err(parse_error("Chocolatey export root is not closed"));
        };
        match token {
            XmlToken::Text(text) if text.trim().is_empty() => {}
            XmlToken::Tag(tag) if tag.closing && tag.name == "packages" => break,
            XmlToken::Tag(tag) if !tag.closing && tag.name == "package" => {
                let self_closing = tag.self_closing;
                let package = package_from_tag(tag)?;
                if !self_closing {
                    consume_package_body(&mut reader)?;
                }
                packages.push(package);
                if packages.len() > MAX_PACKAGES {
                    return Err(security_error(
                        "Chocolatey export exceeds the reviewed package count",
                    ));
                }
            }
            XmlToken::Tag(_) => {
                return Err(parse_error(
                    "Chocolatey export contains an unsupported nested element",
                ));
            }
            XmlToken::Text(_) => {
                return Err(parse_error(
                    "Chocolatey export contains non-whitespace text",
                ));
            }
        }
    }
    consume_trailing_whitespace(&mut reader)?;
    Ok(packages)
}

fn consume_trailing_whitespace(reader: &mut XmlReader<'_>) -> ProviderResult<()> {
    while let Some(token) = reader.next()? {
        if !matches!(token, XmlToken::Text(text) if text.trim().is_empty()) {
            return Err(parse_error("Chocolatey export has trailing XML content"));
        }
    }
    Ok(())
}

fn consume_package_body(reader: &mut XmlReader<'_>) -> ProviderResult<()> {
    loop {
        let Some(token) = reader.next()? else {
            return Err(parse_error("Chocolatey package element is not closed"));
        };
        match token {
            XmlToken::Text(text) if text.trim().is_empty() => {}
            XmlToken::Tag(tag) if tag.closing && tag.name == "package" => return Ok(()),
            _ => {
                return Err(parse_error(
                    "Chocolatey package element contains unsupported content",
                ));
            }
        }
    }
}

fn package_from_tag(tag: XmlTag) -> ProviderResult<PackageRecord> {
    let mut attributes = tag.attributes;
    let id = attributes
        .remove("id")
        .ok_or_else(|| parse_error("Chocolatey package is missing its id attribute"))?;
    validate_package_id(&id)?;
    let version = attributes.remove("version");
    if let Some(version) = version.as_deref() {
        validate_version(version)?;
    }
    let source = attributes.remove("source");
    if !attributes.is_empty() {
        return Err(parse_error(
            "Chocolatey package contains an unsupported attribute",
        ));
    }
    let source_descriptor = source_descriptor(source.as_deref())?;
    Ok(PackageRecord {
        id,
        version,
        source: source_descriptor,
    })
}

struct XmlReader<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> XmlReader<'a> {
    fn new(input: &'a str) -> Self {
        let offset = input
            .strip_prefix('\u{feff}')
            .map_or(0, |value| input.len() - value.len());
        Self { input, offset }
    }

    fn next(&mut self) -> ProviderResult<Option<XmlToken>> {
        if self.offset >= self.input.len() {
            return Ok(None);
        }
        if self.input[self.offset..].starts_with("<!--") {
            let Some(end) = self.input[self.offset + 4..].find("-->") else {
                return Err(parse_error("Chocolatey XML comment is not closed"));
            };
            self.offset += 4 + end + 3;
            return self.next();
        }
        if self.input[self.offset..].starts_with("<?") {
            let Some(end) = self.input[self.offset + 2..].find("?>") else {
                return Err(parse_error(
                    "Chocolatey XML processing instruction is not closed",
                ));
            };
            self.offset += 2 + end + 2;
            return self.next();
        }
        if self.input[self.offset..].starts_with("<!") {
            return Err(parse_error(
                "Chocolatey XML declarations and external entities are not accepted",
            ));
        }
        if self.input.as_bytes()[self.offset] == b'<' {
            let start = self.offset + 1;
            let mut cursor = start;
            let mut quote = None;
            while cursor < self.input.len() {
                let byte = self.input.as_bytes()[cursor];
                if let Some(delimiter) = quote {
                    if byte == delimiter {
                        quote = None;
                    }
                } else if byte == b'\'' || byte == b'"' {
                    quote = Some(byte);
                } else if byte == b'>' {
                    break;
                }
                cursor += 1;
            }
            if cursor >= self.input.len() || quote.is_some() {
                return Err(parse_error(
                    "Chocolatey XML tag is malformed or unterminated",
                ));
            }
            if cursor - start > MAX_XML_TAG_BYTES {
                return Err(security_error(
                    "Chocolatey XML tag exceeds the reviewed bound",
                ));
            }
            let tag = parse_tag(&self.input[start..cursor])?;
            self.offset = cursor + 1;
            return Ok(Some(XmlToken::Tag(tag)));
        }
        let start = self.offset;
        let end = self.input[start..]
            .find('<')
            .map_or(self.input.len(), |offset| start + offset);
        self.offset = end;
        Ok(Some(XmlToken::Text(self.input[start..end].to_owned())))
    }
}

#[derive(Debug)]
enum XmlToken {
    Tag(XmlTag),
    Text(String),
}

#[derive(Debug)]
struct XmlTag {
    name: String,
    attributes: BTreeMap<String, String>,
    closing: bool,
    self_closing: bool,
}

fn parse_tag(raw: &str) -> ProviderResult<XmlTag> {
    let mut value = raw.trim();
    let closing = value.strip_prefix('/').is_some();
    if closing {
        value = value[1..].trim_start();
    }
    let self_closing = !closing && value.ends_with('/');
    if self_closing {
        value = value[..value.len() - 1].trim_end();
    }
    let (name, mut rest) = xml_name(value)?;
    let mut attributes = BTreeMap::new();
    while !rest.trim().is_empty() {
        rest = rest.trim_start();
        let (attribute, remainder) = xml_name(rest)?;
        rest = remainder.trim_start();
        if !rest.starts_with('=') {
            return Err(parse_error("Chocolatey XML attribute is missing '='"));
        }
        rest = rest[1..].trim_start();
        let Some(delimiter) = rest.as_bytes().first().copied() else {
            return Err(parse_error("Chocolatey XML attribute is missing its value"));
        };
        if delimiter != b'\'' && delimiter != b'"' {
            return Err(parse_error("Chocolatey XML attribute value is not quoted"));
        }
        let Some(end) = rest[1..].find(char::from(delimiter)) else {
            return Err(parse_error(
                "Chocolatey XML attribute value is unterminated",
            ));
        };
        let raw_value = &rest[1..end + 1];
        let decoded = decode_entities(raw_value)?;
        if decoded.len() > MAX_SOURCE_BYTES {
            return Err(security_error(
                "Chocolatey XML attribute exceeds the reviewed bound",
            ));
        }
        if attributes
            .insert(attribute.to_ascii_lowercase(), decoded)
            .is_some()
        {
            return Err(parse_error("Chocolatey XML tag repeats an attribute"));
        }
        rest = &rest[end + 2..];
    }
    if closing && (!attributes.is_empty() || self_closing) {
        return Err(parse_error(
            "Chocolatey XML closing tag contains attributes or a slash",
        ));
    }
    Ok(XmlTag {
        name: name.to_ascii_lowercase(),
        attributes,
        closing,
        self_closing,
    })
}

fn xml_name(input: &str) -> ProviderResult<(String, &str)> {
    let end = input
        .char_indices()
        .find_map(|(index, character)| {
            (!character.is_ascii_alphanumeric()
                && character != '_'
                && character != '-'
                && character != '.')
                .then_some(index)
        })
        .unwrap_or(input.len());
    if end == 0 {
        return Err(parse_error("Chocolatey XML name is missing or invalid"));
    }
    let name = &input[..end];
    Ok((name.to_owned(), &input[end..]))
}

fn decode_entities(input: &str) -> ProviderResult<String> {
    let mut output = String::with_capacity(input.len());
    let mut remainder = input;
    while let Some(index) = remainder.find('&') {
        output.push_str(&remainder[..index]);
        let after = &remainder[index + 1..];
        let Some(end) = after.find(';') else {
            return Err(parse_error("Chocolatey XML entity is unterminated"));
        };
        let entity = &after[..end];
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => return Err(parse_error("Chocolatey XML entity is unsupported")),
        };
        output.push(decoded);
        remainder = &after[end + 1..];
    }
    output.push_str(remainder);
    Ok(output)
}

fn source_descriptor(source: Option<&str>) -> ProviderResult<SourceDescriptor> {
    let Some(source) = source else {
        return Ok(SourceDescriptor {
            name: None,
            identifier: None,
            url: None,
            trusted: true,
        });
    };
    validate_text("Chocolatey source", source, MAX_SOURCE_BYTES)?;
    if let Some(url) = public_url(source) {
        let trusted = is_default_source_url(&url);
        return Ok(SourceDescriptor {
            name: Some(
                if trusted {
                    DEFAULT_SOURCE_NAME
                } else {
                    "custom"
                }
                .to_owned(),
            ),
            identifier: Some(if trusted {
                DEFAULT_SOURCE_IDENTIFIER.to_owned()
            } else {
                format!("custom-source:{}", url.host_str().unwrap_or("unknown"))
            }),
            url: Some(url),
            trusted,
        });
    }
    Ok(SourceDescriptor {
        name: Some("custom".to_owned()),
        identifier: Some("custom-source".to_owned()),
        url: None,
        trusted: false,
    })
}

fn is_default_source_url(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("community.chocolatey.org"))
        && url.path().trim_end_matches('/') == "/api/v2"
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

fn validate_package_spec(package: &PackageSpec, provider: &ProviderId) -> ProviderResult<()> {
    if &package.provider != provider {
        return Err(schema_error(
            "Chocolatey package uses a different provider ID",
        ));
    }
    validate_package_id(&package.id)?;
    if let Some(version) = package.version.as_deref() {
        validate_version(version)?;
    }
    if let Some(name) = package.source_name.as_deref() {
        validate_text("Chocolatey source name", name, MAX_SOURCE_BYTES)?;
    }
    if let Some(identifier) = package.source_identifier.as_deref() {
        validate_text("Chocolatey source identifier", identifier, MAX_SOURCE_BYTES)?;
    }
    if let Some(source) = package.source.as_ref()
        && !is_public_url(source)
    {
        return Err(source_error(
            "Chocolatey source URL is not a public credential-free HTTP(S) URL",
        ));
    }
    Ok(())
}

fn is_public_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn validate_package_id(value: &str) -> ProviderResult<()> {
    if value.is_empty()
        || value.len() > MAX_PACKAGE_ID_BYTES
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
            "Chocolatey package ID is outside the reviewed grammar",
        ));
    }
    Ok(())
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
            "Chocolatey package version is outside the reviewed grammar",
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

fn is_reviewed_source(package: &PackageSpec) -> bool {
    if package.source_name.is_none()
        && package.source_identifier.is_none()
        && package.source.is_none()
    {
        return true;
    }
    package.source_identifier.as_deref() == Some(DEFAULT_SOURCE_IDENTIFIER)
        && package.source.as_ref().is_some_and(is_default_source_url)
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
        return Err(schema_error(
            "Chocolatey component belongs to another adapter",
        ));
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
        .ok_or_else(|| schema_error("Chocolatey component has no provider identity"))?;
    if packages.next().is_some() {
        return Err(schema_error(
            "Chocolatey component has multiple provider identities",
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
        .map_err(|_| schema_error("Chocolatey manual operation ID could not be constructed"))?;
    let idempotency_key = operation_key("manual", package);
    Ok(Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::OpenManualAction {
            action: ManualAction {
                id: idempotency_key.clone(),
                component: Some(component.id.clone()),
                title: "Review Chocolatey package restore".to_owned(),
                reason: reason.to_owned(),
                risk: RiskLevel::High,
                instructions: vec![
                    "Confirm the Chocolatey source, package version, license, and install-script risk"
                        .to_owned(),
                    "Do not substitute the latest package version".to_owned(),
                ],
                docs_url: Some(
                    Url::parse("https://docs.chocolatey.org/en-us/choco/commands/install")
                        .expect("constant Chocolatey documentation URL"),
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
    format!("chocolatey-{role}-{}", hasher.finalize().to_hex())
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
        .unwrap_or_else(|| "Chocolatey evidence was redacted".to_owned());
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
    EvidenceId::new(format!(
        "chocolatey-evidence-{}",
        hasher.finalize().to_hex()
    ))
    .expect("hashed Chocolatey evidence ID")
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

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if let Some(warning) = safe_text(&warning, MAX_WARNING_BYTES) {
        warnings.push(warning);
    }
}

fn validate_process_result(result: &ProcessResult, operation: &str) -> ProviderResult<()> {
    if result.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            format!("Chocolatey {operation} was cancelled"),
        )));
    }
    if result.timed_out {
        return Err(operation_error(&format!(
            "Chocolatey {operation} timed out"
        )));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(operation_error(&format!(
            "Chocolatey {operation} exited with code {code}"
        ))),
        None => Err(operation_error(&format!(
            "Chocolatey {operation} ended without an exit code"
        ))),
    }
}

fn read_export_file(root: &Path) -> ProviderResult<Vec<u8>> {
    let path = SafePath::new("packages.config")?;
    let mut reader = BoundedFileReader::open(root, &path, MAX_EXPORT_BYTES as u64)?;
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
            let root = local_app_data.join(format!(".reforge-chocolatey-{}", Uuid::now_v7()));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&root)
                        .map_err(|error| io_error("inspect Chocolatey export directory", &error))?;
                    if !metadata.is_dir()
                        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    {
                        let _ = fs::remove_dir(&root);
                        return Err(security_error(
                            "Chocolatey export directory is not a regular local directory",
                        ));
                    }
                    return Ok(Self {
                        output: root.join("packages.config"),
                        root,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(io_error(
                        "create private Chocolatey export directory",
                        &error,
                    ));
                }
            }
        }
        Err(security_error(
            "Could not allocate a unique Chocolatey export directory",
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
            "Chocolatey is unavailable on this Windows target",
        ))
    } else {
        error
    }
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Chocolatey provider data is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn parse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Chocolatey export did not match the reviewed XML shape",
        )
        .with_technical_detail(detail),
    )
}

fn source_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SourceUnavailable,
            "Chocolatey package source is incomplete or unsafe",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Chocolatey export exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Chocolatey export could not be completed",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, operation.to_owned()))
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
    fn parses_versioned_export_and_marks_script_risk() {
        let adapter = ChocolateyAdapter::new();
        let result = adapter
            .parse_capture(
                &success(),
                br#"<?xml version="1.0"?><packages><package id="git" version="2.47.1" /></packages>"#,
                Utc::now(),
            )
            .expect("Chocolatey XML parses");
        assert_eq!(result.observations.len(), 1);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("install scripts"))
        );
        let Observation::Package { spec, version, .. } = &result.observations[0] else {
            panic!("package observation");
        };
        assert_eq!(spec.id, "git");
        assert_eq!(
            version.as_ref().map(|value| value.raw.as_str()),
            Some("2.47.1")
        );
        assert!(spec.source_name.is_none());
        assert!(spec.source_identifier.is_none());
        assert!(spec.source.is_none());
    }

    #[test]
    fn malformed_or_custom_source_exports_fail_closed_to_manual() {
        let adapter = ChocolateyAdapter::new();
        assert!(
            adapter
                .parse_capture(&success(), b"<packages><package", Utc::now())
                .is_err()
        );
        let result = adapter
            .parse_capture(
                &success(),
                br#"<packages><package id="local-tool" version="1.0" source="C:\custom" /></packages>"#,
                Utc::now(),
            )
            .expect("custom source shape parses");
        let observation = result.observations.into_iter().next().expect("observation");
        let component = adapter.normalize(observation).expect("component").remove(0);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert!(result_warning_contains_script_risk(&component));
    }

    fn result_warning_contains_script_risk(component: &Component) -> bool {
        component
            .restore
            .rationale
            .iter()
            .any(|reason| reason.contains("install scripts"))
    }
}
