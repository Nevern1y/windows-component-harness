//! Rust toolchain and Cargo-installed tool discovery.

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

const PROVIDER_ID: &str = "rust";
const RUNTIME_ID: &str = "rust";
const ADAPTER_ID: &str = "rust";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct RustAdapter {
    id: ProviderId,
}

impl RustAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Rust provider ID"),
        }
    }

    /// Parse a Cargo/rustup JSON or line-oriented fixture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        runtime_process_result(process, &self.id, "Rust provider listing")?;
        let text =
            runtime_output_text(output, MAX_OUTPUT_BYTES, &self.id, "Rust provider listing")?;
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
            super::runtime_parse_error(&self.id, "Rust provider listing root is not an object")
        })?;
        let runtime_value = object.get("runtime").or_else(|| object.get("toolchain"));
        let runtime = runtime_value
            .map(|value| parse_runtime(value, &self.id))
            .transpose()?;
        let package_values = object
            .get("packages")
            .or_else(|| object.get("installed"))
            .or_else(|| object.get("tools"));
        let mut records = Vec::new();
        if let Some(values) = package_values {
            let values = values.as_array().ok_or_else(|| {
                super::runtime_parse_error(&self.id, "Rust package collection is not an array")
            })?;
            if values.len() > MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    "Rust package listing exceeds the package limit",
                ));
            }
            for value in values {
                let object = value.as_object().ok_or_else(|| {
                    super::runtime_parse_error(&self.id, "Rust package record is not an object")
                })?;
                records.push(parse_package(object, &self.id)?);
            }
        } else if object.get("name").is_some() || object.get("crate").is_some() {
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
            if line.is_empty() || line.starts_with("info:") {
                continue;
            }
            if line.starts_with("No tools") || line.starts_with("No installed") {
                continue;
            }
            let toolchain = line.split_whitespace().next().unwrap_or_default();
            if line.contains('(')
                && (toolchain.contains("stable")
                    || toolchain.contains("nightly")
                    || toolchain.contains("beta")
                    || toolchain
                        .chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_digit()))
            {
                if runtime.is_none() {
                    runtime = Some(RuntimeSpec {
                        id: RUNTIME_ID.to_owned(),
                        version: Some(toolchain.trim_end_matches(',').to_owned()),
                        architecture: None,
                    });
                }
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(name) = fields.next() else { continue };
            let Some(version) = fields.next() else {
                continue;
            };
            if name == "-" || name == "Installed" || name == "toolchain" {
                continue;
            }
            let version = version.trim_end_matches(':');
            let source_name = fields.next().map(str::to_owned);
            records.push(PackageRecord {
                spec: PackageSpec {
                    provider: self.id.clone(),
                    id: name.to_owned(),
                    version: Some(version.to_owned()),
                    source_name,
                    source_identifier: None,
                    source: None,
                    architecture: None,
                    installer_hash: None,
                },
            });
            if records.len() > MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    "Rust line listing exceeds the package limit",
                ));
            }
        }
        if runtime.is_none() && records.is_empty() {
            runtime_warning(
                &mut warnings,
                "Rust provider listing contained no recognized records",
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
                    EvidenceSource::Rust,
                    "rust-toolchain".to_owned(),
                    "Rust toolchain facts were collected from a reviewed provider probe",
                    85,
                    "rust-runtime",
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
                    EvidenceSource::Rust,
                    "cargo-install-list".to_owned(),
                    "Cargo package metadata was collected from a bounded provider listing",
                    75,
                    "rust-packages",
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
        let mut result = ProviderEnumeration::empty();
        if context.runner.builtin_available(BuiltinExecutable::Cargo) {
            let cargo_command = CommandSpec::new(
                TrustedExecutable::Builtin(BuiltinExecutable::Cargo),
                [OsString::from("install"), OsString::from("--list")],
                PROCESS_TIMEOUT,
                PROCESS_OUTPUT_BYTES,
            )?;
            let cargo = context
                .runner
                .run(&cargo_command, context.cancellation)
                .await?;
            if cargo.cancelled {
                runtime_process_result(&cargo, &self.id, "Cargo installed-tool listing")?;
            } else if cargo.exit_code == Some(0) && !cargo.timed_out {
                result = self.parse_capture(&cargo, cargo.stdout.as_bytes(), Utc::now())?;
            } else {
                runtime_warning(
                    &mut result.warnings,
                    "Cargo installed-tool listing was unavailable",
                );
            }
        }
        if context.runner.builtin_available(BuiltinExecutable::Rustup) {
            let rustup_command = CommandSpec::new(
                TrustedExecutable::Builtin(BuiltinExecutable::Rustup),
                [OsString::from("toolchain"), OsString::from("list")],
                PROCESS_TIMEOUT,
                PROCESS_OUTPUT_BYTES,
            )?;
            let rustup = context
                .runner
                .run(&rustup_command, context.cancellation)
                .await?;
            if rustup.cancelled {
                runtime_process_result(&rustup, &self.id, "rustup toolchain listing")?;
            } else if rustup.exit_code == Some(0) && !rustup.timed_out {
                let runtime = self.parse_capture(&rustup, rustup.stdout.as_bytes(), Utc::now())?;
                if let Some(observation) = runtime
                    .observations
                    .into_iter()
                    .find(|observation| matches!(observation, Observation::Runtime { .. }))
                {
                    result.observations.insert(0, observation);
                }
                result.warnings.extend(runtime.warnings);
            } else {
                runtime_warning(
                    &mut result.warnings,
                    "rustup toolchain listing was unavailable",
                );
            }
        }
        Ok(result)
    }
}

impl Default for RustAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for RustAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        let cargo = context.runner.builtin_available(BuiltinExecutable::Cargo);
        let rustup = context.runner.builtin_available(BuiltinExecutable::Rustup);
        if !cargo && !rustup {
            return DetectionResult::unavailable();
        }
        let mut evidence = Vec::new();
        if cargo {
            evidence.push(runtime_make_evidence(
                EvidenceSource::Rust,
                "PATH:cargo.exe".to_owned(),
                "Cargo resolves from PATH",
                60,
                "rust-provider",
                Utc::now(),
            ));
        }
        if rustup {
            evidence.push(runtime_make_evidence(
                EvidenceSource::Rust,
                "PATH:rustup.exe".to_owned(),
                "rustup resolves from PATH",
                60,
                "rust-provider",
                Utc::now(),
            ));
        }
        DetectionResult {
            available: true,
            version: None,
            evidence,
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

#[derive(Debug)]
struct PackageRecord {
    spec: PackageSpec,
}

fn parse_runtime(value: &Value, provider: &ProviderId) -> ProviderResult<RuntimeSpec> {
    let object = value.as_object().ok_or_else(|| {
        super::runtime_parse_error(provider, "Rust runtime record is not an object")
    })?;
    if let Some(id) = object.get("id").and_then(Value::as_str)
        && id != RUNTIME_ID
    {
        return Err(super::runtime_parse_error(
            provider,
            "Rust runtime record uses an unexpected runtime ID",
        ));
    }
    let version = object
        .get("version")
        .or_else(|| object.get("toolchain"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(RuntimeSpec {
        id: RUNTIME_ID.to_owned(),
        version,
        architecture: object
            .get("architecture")
            .or_else(|| object.get("arch"))
            .and_then(Value::as_str)
            .map(parse_architecture),
    })
}

fn parse_architecture(value: &str) -> reforge_domain::Architecture {
    match value.to_ascii_lowercase().as_str() {
        "x86" | "i386" | "i686" | "32" => reforge_domain::Architecture::X86,
        "x64" | "amd64" | "x86_64" | "64" => reforge_domain::Architecture::X64,
        "arm64" | "aarch64" => reforge_domain::Architecture::Arm64,
        "neutral" | "any" => reforge_domain::Architecture::Neutral,
        _ => reforge_domain::Architecture::Unknown,
    }
}

fn parse_package(
    object: &serde_json::Map<String, Value>,
    provider: &ProviderId,
) -> ProviderResult<PackageRecord> {
    let name = object
        .get("name")
        .or_else(|| object.get("crate"))
        .or_else(|| object.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| super::runtime_parse_error(provider, "Cargo package has no name"))?;
    let version = object
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if name.is_empty()
        || name.len() > 64 * 1024
        || name.trim() != name
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(super::runtime_parse_error(
            provider,
            "Cargo package name is outside the reviewed grammar",
        ));
    }
    if let Some(version) = &version
        && (version.is_empty()
            || version.len() > 64 * 1024
            || version.trim() != version
            || version.chars().any(char::is_control))
    {
        return Err(super::runtime_parse_error(
            provider,
            "Cargo package version is outside the reviewed grammar",
        ));
    }
    let source_name = object
        .get("source_kind")
        .or_else(|| object.get("source_type"))
        .and_then(Value::as_str)
        .map(|kind| match kind.to_ascii_lowercase().as_str() {
            "registry" | "crates" | "crates.io" => "crates.io".to_owned(),
            "git" | "vcs" => "git".to_owned(),
            "path" | "directory" => "path".to_owned(),
            other => other.to_owned(),
        })
        .or_else(|| {
            object
                .get("git")
                .and_then(Value::as_str)
                .map(|_| "git".to_owned())
        })
        .or_else(|| {
            object
                .get("path")
                .and_then(Value::as_str)
                .map(|_| "path".to_owned())
        });
    let source = object
        .get("source")
        .or_else(|| object.get("url"))
        .or_else(|| object.get("git"))
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
