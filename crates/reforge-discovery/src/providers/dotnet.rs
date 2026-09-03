//! .NET SDK/runtime and global tool discovery.

use std::{ffi::OsString, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    Component, EvidenceSource, PackageSpec, ProviderId, RuntimeSpec, TargetFacts, VerificationRule,
    VersionValue,
};
use reforge_platform_windows::{BuiltinExecutable, CommandSpec, ProcessResult, TrustedExecutable};
use serde_json::Value;
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult, normalize_runtime_observation, plan_runtime_install, runtime_make_evidence,
    runtime_output_text, runtime_process_result, runtime_warning, verify_runtime_component,
};

const PROVIDER_ID: &str = "dotnet";
const RUNTIME_ID: &str = "dotnet";
const ADAPTER_ID: &str = "dotnet";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct DotnetAdapter {
    id: ProviderId,
}

impl DotnetAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant .NET provider ID"),
        }
    }

    /// Parse `dotnet --list-sdks`, `--list-runtimes`, or a structured fixture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        runtime_process_result(process, &self.id, ".NET provider listing")?;
        let text =
            runtime_output_text(output, MAX_OUTPUT_BYTES, &self.id, ".NET provider listing")?;
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            return self.parse_value(&value, observed_at);
        }
        self.parse_lines(text, observed_at)
    }

    fn parse_value(
        &self,
        value: &Value,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let object = value.as_object().ok_or_else(|| {
            super::runtime_parse_error(&self.id, ".NET listing root is not an object")
        })?;
        let runtime = object
            .get("runtime")
            .or_else(|| object.get("sdk"))
            .map(|value| parse_runtime(value, &self.id))
            .transpose()?;
        let values = object
            .get("tools")
            .or_else(|| object.get("packages"))
            .or_else(|| object.get("sdks"));
        let mut records = Vec::new();
        if let Some(values) = values {
            let values = values.as_array().ok_or_else(|| {
                super::runtime_parse_error(&self.id, ".NET package collection is not an array")
            })?;
            if values.len() > MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    ".NET package listing exceeds the package limit",
                ));
            }
            for value in values {
                let object = value.as_object().ok_or_else(|| {
                    super::runtime_parse_error(&self.id, ".NET package record is not an object")
                })?;
                records.push(parse_package(object, &self.id)?);
            }
        } else if object.get("packageId").is_some() || object.get("id").is_some() {
            records.push(parse_package(object, &self.id)?);
        }
        self.observations(runtime, records, observed_at)
    }

    fn parse_lines(
        &self,
        text: &str,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let mut runtime = None;
        let mut records = Vec::new();
        let mut warnings = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(first) = fields.next() else { continue };
            let Some(version) = fields.next() else {
                continue;
            };
            let first_is_version = first
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit());
            let microsoft_runtime = first.starts_with("Microsoft.")
                && version
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit());
            if first_is_version || microsoft_runtime {
                if runtime.is_none() {
                    runtime = Some(RuntimeSpec {
                        id: RUNTIME_ID.to_owned(),
                        version: Some(if first_is_version {
                            first.to_owned()
                        } else {
                            version.to_owned()
                        }),
                        architecture: None,
                    });
                }
                continue;
            }
            if first == "Package" || first == "Id" || first == "---" {
                continue;
            }
            records.push(PackageRecord {
                spec: PackageSpec {
                    provider: self.id.clone(),
                    id: first.to_owned(),
                    version: Some(version.to_owned()),
                    source_name: None,
                    source_identifier: None,
                    source: None,
                    architecture: None,
                    installer_hash: None,
                },
            });
            if records.len() > MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    ".NET line listing exceeds the package limit",
                ));
            }
        }
        if runtime.is_none() && records.is_empty() {
            runtime_warning(
                &mut warnings,
                ".NET listing contained no recognized records",
            );
        }
        let mut result = self.observations(runtime, records, observed_at)?;
        result.warnings.extend(warnings);
        Ok(result)
    }

    fn observations(
        &self,
        runtime: Option<RuntimeSpec>,
        records: Vec<PackageRecord>,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let mut observations = Vec::with_capacity(records.len() + usize::from(runtime.is_some()));
        if let Some(spec) = runtime {
            observations.push(Observation::Runtime {
                spec,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Dotnet,
                    "dotnet-runtime-list".to_owned(),
                    ".NET runtime facts were collected from a reviewed provider listing",
                    85,
                    "dotnet-runtime",
                    observed_at,
                )],
            });
        }
        for record in records {
            let version = record.spec.version.as_ref().map(|raw| VersionValue {
                raw: raw.clone(),
                normalized: None,
            });
            observations.push(Observation::Package {
                spec: record.spec,
                version,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Dotnet,
                    "dotnet-tool-list".to_owned(),
                    ".NET tool metadata was collected from a bounded provider listing",
                    75,
                    "dotnet-packages",
                    observed_at,
                )],
            });
        }
        Ok(ProviderEnumeration {
            observations,
            warnings: Vec::new(),
        })
    }

    async fn enumerate_live(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let version_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Dotnet),
            [OsString::from("--version")],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let version_process = context
            .runner
            .run(&version_command, context.cancellation)
            .await?;
        runtime_process_result(&version_process, &self.id, ".NET version probe")?;
        let version_text = runtime_output_text(
            version_process.stdout.as_bytes(),
            MAX_OUTPUT_BYTES,
            &self.id,
            ".NET version probe",
        )?;
        let version = version_text
            .split_whitespace()
            .find(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
            })
            .ok_or_else(|| super::runtime_parse_error(&self.id, ".NET version has no version"))?;
        let runtime_observation = Observation::Runtime {
            spec: RuntimeSpec {
                id: RUNTIME_ID.to_owned(),
                version: Some(version.to_owned()),
                architecture: None,
            },
            evidence: vec![runtime_make_evidence(
                EvidenceSource::Dotnet,
                "dotnet-version".to_owned(),
                ".NET runtime facts were collected from a bounded version probe",
                85,
                "dotnet-runtime",
                Utc::now(),
            )],
        };
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Dotnet),
            [
                OsString::from("tool"),
                OsString::from("list"),
                OsString::from("--global"),
                OsString::from("--format=json"),
            ],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let process = context.runner.run(&command, context.cancellation).await?;
        let mut result = self.parse_capture(&process, process.stdout.as_bytes(), Utc::now())?;
        result.observations.insert(0, runtime_observation);
        Ok(result)
    }
}

impl Default for DotnetAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for DotnetAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::Dotnet) {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![runtime_make_evidence(
                EvidenceSource::Dotnet,
                "PATH:dotnet.exe".to_owned(),
                ".NET resolves from PATH",
                60,
                "dotnet-provider",
                Utc::now(),
            )],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        self.enumerate_live(context).await
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        normalize_runtime_observation(observation, &self.id, ADAPTER_ID, RUNTIME_ID, false)
    }

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &reforge_domain::RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<reforge_domain::Operation>> {
        plan_runtime_install(
            component,
            target,
            run_id,
            first_ordinal,
            &self.id,
            ADAPTER_ID,
            RUNTIME_ID,
            false,
        )
    }

    fn verify(
        &self,
        component: &Component,
        target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        verify_runtime_component(component, target, &self.id, ADAPTER_ID)
    }
}

fn parse_runtime(value: &Value, provider: &ProviderId) -> ProviderResult<RuntimeSpec> {
    let object = value.as_object().ok_or_else(|| {
        super::runtime_parse_error(provider, ".NET runtime record is not an object")
    })?;
    Ok(RuntimeSpec {
        id: RUNTIME_ID.to_owned(),
        version: object
            .get("version")
            .or_else(|| object.get("sdkVersion"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        architecture: None,
    })
}

fn parse_package(
    object: &serde_json::Map<String, Value>,
    provider: &ProviderId,
) -> ProviderResult<PackageRecord> {
    let name = object
        .get("packageId")
        .or_else(|| object.get("name"))
        .or_else(|| object.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            super::runtime_parse_error(provider, ".NET tool record has no package ID")
        })?;
    if name.is_empty()
        || name.len() > 64 * 1024
        || name.trim() != name
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(super::runtime_parse_error(
            provider,
            ".NET package ID is outside the reviewed grammar",
        ));
    }
    let version = object
        .get("version")
        .or_else(|| object.get("packageVersion"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(version) = &version
        && (version.is_empty()
            || version.len() > 64 * 1024
            || version.trim() != version
            || version.chars().any(char::is_control))
    {
        return Err(super::runtime_parse_error(
            provider,
            ".NET package version is outside the reviewed grammar",
        ));
    }
    let source_name = object
        .get("source_kind")
        .or_else(|| object.get("sourceType"))
        .and_then(Value::as_str)
        .map(|kind| match kind.to_ascii_lowercase().as_str() {
            "nuget" | "nuget.org" | "registry" => "nuget".to_owned(),
            other => other.to_owned(),
        });
    let source = object
        .get("source")
        .or_else(|| object.get("url"))
        .and_then(Value::as_str)
        .and_then(|raw| Url::parse(raw).ok())
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        });
    let source_identifier = object
        .get("source_identifier")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64 * 1024
                && value.trim() == *value
                && super::runtime_safe_source_identifier(value)
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned);
    Ok(PackageRecord {
        spec: PackageSpec {
            provider: provider.clone(),
            id: name.to_owned(),
            version,
            source_name,
            source_identifier,
            source,
            architecture: None,
            installer_hash: None,
        },
    })
}

#[derive(Debug)]
struct PackageRecord {
    spec: PackageSpec,
}
