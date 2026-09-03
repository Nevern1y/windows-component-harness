//! Go toolchain discovery with conservative module provenance handling.

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
    runtime_output_text, runtime_process_result, verify_runtime_component,
};

const PROVIDER_ID: &str = "go";
const RUNTIME_ID: &str = "go";
const ADAPTER_ID: &str = "go";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct GoAdapter {
    id: ProviderId,
}

impl GoAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Go provider ID"),
        }
    }

    /// Parse a structured `go env -json`, module metadata, or fixture capture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        runtime_process_result(process, &self.id, "Go provider listing")?;
        let text = runtime_output_text(output, MAX_OUTPUT_BYTES, &self.id, "Go provider listing")?;
        let value: Value = serde_json::from_str(text).map_err(|_| {
            super::runtime_parse_error(&self.id, "Go provider listing is not valid JSON")
        })?;
        self.parse_value(&value, observed_at)
    }

    fn parse_value(
        &self,
        value: &Value,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let object = value.as_object().ok_or_else(|| {
            super::runtime_parse_error(&self.id, "Go provider listing root is not an object")
        })?;
        let runtime_version = object
            .get("version")
            .or_else(|| object.get("go_version"))
            .or_else(|| object.get("GOVERSION"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let runtime = object
            .get("runtime")
            .or_else(|| object.get("toolchain"))
            .map(|value| parse_runtime(value, runtime_version.clone()))
            .transpose()?;
        let runtime = runtime.or_else(|| {
            runtime_version.map(|version| RuntimeSpec {
                id: RUNTIME_ID.to_owned(),
                version: Some(version),
                architecture: object
                    .get("GOARCH")
                    .and_then(Value::as_str)
                    .map(parse_architecture),
            })
        });
        let mut records = Vec::new();
        if let Some(packages) = object
            .get("packages")
            .or_else(|| object.get("modules"))
            .or_else(|| object.get("binaries"))
        {
            let packages = packages.as_array().ok_or_else(|| {
                super::runtime_parse_error(&self.id, "Go package collection is not an array")
            })?;
            if packages.len() > MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    "Go package listing exceeds the package limit",
                ));
            }
            for package in packages {
                let object = package.as_object().ok_or_else(|| {
                    super::runtime_parse_error(&self.id, "Go package record is not an object")
                })?;
                records.push(parse_package(object, &self.id)?);
            }
        } else if object.get("path").is_some() || object.get("module").is_some() {
            records.push(parse_package(object, &self.id)?);
        }
        let mut observations = Vec::with_capacity(records.len() + usize::from(runtime.is_some()));
        if let Some(spec) = runtime {
            observations.push(Observation::Runtime {
                spec,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Go,
                    "go-env-json".to_owned(),
                    "Go toolchain facts were collected from a reviewed structured environment probe",
                    85,
                    "go-runtime",
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
                    EvidenceSource::Go,
                    "go-module-debug".to_owned(),
                    "Go module or tool metadata was collected from bounded provider output",
                    60,
                    "go-packages",
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
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Go),
            [OsString::from("env"), OsString::from("-json")],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let process = context.runner.run(&command, context.cancellation).await?;
        self.parse_capture(&process, process.stdout.as_bytes(), Utc::now())
    }
}

impl Default for GoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for GoAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context.runner.builtin_available(BuiltinExecutable::Go) {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![runtime_make_evidence(
                EvidenceSource::Go,
                "PATH:go.exe".to_owned(),
                "Go resolves from PATH",
                60,
                "go-provider",
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
        normalize_runtime_observation(observation, &self.id, ADAPTER_ID, RUNTIME_ID, true)
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
            true,
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

fn parse_runtime(value: &Value, fallback_version: Option<String>) -> ProviderResult<RuntimeSpec> {
    let object = value.as_object().ok_or_else(|| {
        super::runtime_parse_error(
            &ProviderId::new(PROVIDER_ID).expect("constant Go provider ID"),
            "Go runtime record is not an object",
        )
    })?;
    Ok(RuntimeSpec {
        id: RUNTIME_ID.to_owned(),
        version: object
            .get("version")
            .or_else(|| object.get("go_version"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(fallback_version),
        architecture: object
            .get("architecture")
            .or_else(|| object.get("GOARCH"))
            .and_then(Value::as_str)
            .map(parse_architecture),
    })
}

fn parse_package(
    object: &serde_json::Map<String, Value>,
    provider: &ProviderId,
) -> ProviderResult<PackageRecord> {
    let name = object
        .get("module")
        .or_else(|| object.get("path"))
        .or_else(|| object.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| super::runtime_parse_error(provider, "Go module record has no path"))?;
    if name.is_empty()
        || name.len() > 512
        || name.trim() != name
        || name.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == '\\'
        })
    {
        return Err(super::runtime_parse_error(
            provider,
            "Go module path is outside the reviewed grammar",
        ));
    }
    let version = object
        .get("version")
        .or_else(|| object.get("mod_version"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(version) = &version
        && (version.is_empty()
            || version.len() > 512
            || version.trim() != version
            || version.chars().any(char::is_control))
    {
        return Err(super::runtime_parse_error(
            provider,
            "Go module version is outside the reviewed grammar",
        ));
    }
    let source_kind = object
        .get("source_kind")
        .or_else(|| object.get("source_type"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| object.get("replace").map(|_| "replace".to_owned()));
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
                && value.len() <= 512
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
            source_name: source_kind,
            source_identifier,
            source,
            architecture: None,
            installer_hash: None,
        },
    })
}

fn parse_architecture(value: &str) -> reforge_domain::Architecture {
    match value.to_ascii_lowercase().as_str() {
        "386" | "x86" => reforge_domain::Architecture::X86,
        "amd64" | "x64" => reforge_domain::Architecture::X64,
        "arm64" => reforge_domain::Architecture::Arm64,
        _ => reforge_domain::Architecture::Unknown,
    }
}

#[derive(Debug)]
struct PackageRecord {
    spec: PackageSpec,
}
