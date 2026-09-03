//! PowerShell Gallery module discovery with manual restore by default.

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

const PROVIDER_ID: &str = "powershell";
const RUNTIME_ID: &str = "powershell";
const ADAPTER_ID: &str = "powershell";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct PowerShellAdapter {
    id: ProviderId,
}

impl PowerShellAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant PowerShell provider ID"),
        }
    }

    /// Parse JSON emitted by Get-InstalledModule or a versioned fixture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        runtime_process_result(process, &self.id, "PowerShell module listing")?;
        let text = runtime_output_text(
            output,
            MAX_OUTPUT_BYTES,
            &self.id,
            "PowerShell module listing",
        )?;
        if text.trim().is_empty() {
            return Ok(ProviderEnumeration::empty());
        }
        let value: Value = serde_json::from_str(text).map_err(|_| {
            super::runtime_parse_error(&self.id, "PowerShell module listing is not valid JSON")
        })?;
        self.parse_value(&value, observed_at)
    }

    fn parse_value(
        &self,
        value: &Value,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let (entries, runtime) = match value {
            Value::Array(entries) => (entries.as_slice(), None),
            Value::Object(object) => {
                let entries = object
                    .get("modules")
                    .or_else(|| object.get("installed"))
                    .or_else(|| object.get("packages"));
                let runtime = object
                    .get("runtime")
                    .map(|value| parse_runtime(value, &self.id))
                    .transpose()?;
                let entries = if let Some(value) = entries {
                    value
                        .as_array()
                        .map(|values| values.as_slice())
                        .ok_or_else(|| {
                            super::runtime_parse_error(
                                &self.id,
                                "PowerShell module collection is not an array",
                            )
                        })?
                } else if object.get("Name").is_some() || object.get("name").is_some() {
                    std::slice::from_ref(value)
                } else {
                    &[]
                };
                (entries, runtime)
            }
            _ => {
                return Err(super::runtime_parse_error(
                    &self.id,
                    "PowerShell module listing root is not an object or array",
                ));
            }
        };
        if entries.len() > MAX_RECORDS {
            return Err(super::runtime_security_error(
                &self.id,
                "PowerShell module listing exceeds the package limit",
            ));
        }
        let mut observations = Vec::with_capacity(entries.len() + usize::from(runtime.is_some()));
        if let Some(spec) = runtime {
            observations.push(Observation::Runtime {
                spec,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::PowerShell,
                    "powershell-runtime".to_owned(),
                    "PowerShell runtime facts were collected from a reviewed provider probe",
                    80,
                    "powershell-runtime",
                    observed_at,
                )],
            });
        }
        for entry in entries {
            let object = entry.as_object().ok_or_else(|| {
                super::runtime_parse_error(&self.id, "PowerShell module record is not an object")
            })?;
            let spec = parse_package(object, &self.id)?;
            let version = spec.version.as_ref().map(|raw| VersionValue {
                raw: raw.clone(),
                normalized: None,
            });
            observations.push(Observation::Package {
                spec,
                version,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::PowerShell,
                    "powershell-gallery-module".to_owned(),
                    "PowerShell module metadata was collected from a bounded provider listing",
                    75,
                    "powershell-modules",
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
        let runtime_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::PowerShell),
            [
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from("$PSVersionTable.PSVersion.ToString()"),
            ],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let runtime_process = context
            .runner
            .run(&runtime_command, context.cancellation)
            .await?;
        runtime_process_result(&runtime_process, &self.id, "PowerShell version probe")?;
        let runtime_text = runtime_output_text(
            runtime_process.stdout.as_bytes(),
            MAX_OUTPUT_BYTES,
            &self.id,
            "PowerShell version probe",
        )?;
        let version = runtime_text
            .split_whitespace()
            .find(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
            })
            .ok_or_else(|| {
                super::runtime_parse_error(&self.id, "PowerShell version has no version")
            })?;
        let runtime_observation = Observation::Runtime {
            spec: RuntimeSpec {
                id: RUNTIME_ID.to_owned(),
                version: Some(version.to_owned()),
                architecture: None,
            },
            evidence: vec![runtime_make_evidence(
                EvidenceSource::PowerShell,
                "powershell-version".to_owned(),
                "PowerShell runtime facts were collected from a bounded version probe",
                85,
                "powershell-runtime",
                Utc::now(),
            )],
        };
        let script = OsString::from(
            "Get-InstalledModule | Select-Object Name,Version,Repository | ConvertTo-Json -Compress",
        );
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::PowerShell),
            [
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                script,
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

impl Default for PowerShellAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for PowerShellAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        if !context
            .runner
            .builtin_available(BuiltinExecutable::PowerShell)
        {
            return DetectionResult::unavailable();
        }
        DetectionResult {
            available: true,
            version: None,
            evidence: vec![runtime_make_evidence(
                EvidenceSource::PowerShell,
                "PATH:powershell.exe".to_owned(),
                "PowerShell resolves from PATH",
                60,
                "powershell-provider",
                Utc::now(),
            )],
            warnings: vec![
                "PowerShell modules are executable supply-chain inputs; restore remains manual"
                    .to_owned(),
            ],
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

fn parse_runtime(value: &Value, provider: &ProviderId) -> ProviderResult<RuntimeSpec> {
    let object = value.as_object().ok_or_else(|| {
        super::runtime_parse_error(provider, "PowerShell runtime record is not an object")
    })?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(RUNTIME_ID);
    if id != RUNTIME_ID {
        return Err(super::runtime_parse_error(
            provider,
            "PowerShell runtime record uses an unexpected runtime ID",
        ));
    }
    Ok(RuntimeSpec {
        id: RUNTIME_ID.to_owned(),
        version: object
            .get("version")
            .or_else(|| object.get("PSVersion"))
            .or_else(|| object.get("powershell_version"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        architecture: None,
    })
}

fn parse_package(
    object: &serde_json::Map<String, Value>,
    provider: &ProviderId,
) -> ProviderResult<PackageSpec> {
    let name = object
        .get("Name")
        .or_else(|| object.get("name"))
        .or_else(|| object.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| super::runtime_parse_error(provider, "PowerShell module has no name"))?;
    if name.is_empty()
        || name.len() > 512
        || name.trim() != name
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(super::runtime_parse_error(
            provider,
            "PowerShell module name is outside the reviewed grammar",
        ));
    }
    let version = object
        .get("Version")
        .or_else(|| object.get("version"))
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
            "PowerShell module version is outside the reviewed grammar",
        ));
    }
    let source_name = object
        .get("Repository")
        .or_else(|| object.get("repository"))
        .and_then(Value::as_str)
        .map(str::to_owned);
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
    Ok(PackageSpec {
        provider: provider.clone(),
        id: name.to_owned(),
        version,
        source_name,
        source_identifier,
        source,
        architecture: None,
        installer_hash: None,
    })
}
