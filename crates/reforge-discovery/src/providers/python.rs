//! Python, pip, pipx, and uv discovery with bounded structured parsing.

use std::{ffi::OsString, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    Architecture, Component, EvidenceSource, PackageSpec, ProviderId, RuntimeSpec, TargetFacts,
    VerificationRule, VersionValue,
};
use reforge_platform_windows::{BuiltinExecutable, CommandSpec, ProcessResult, TrustedExecutable};
use serde_json::Value;
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult, normalize_runtime_observation, plan_runtime_install, runtime_make_evidence,
    runtime_output_text, runtime_process_result, runtime_warning, verify_runtime_component,
};

const PROVIDER_ID: &str = "python";
const RUNTIME_ID: &str = "python";
const ADAPTER_ID: &str = "python";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_TEXT_BYTES: usize = 512;

#[derive(Clone, Debug)]
pub struct PythonAdapter {
    id: ProviderId,
}

#[derive(Debug)]
struct PackageRecord {
    spec: PackageSpec,
    required_abi: Option<String>,
}

impl PythonAdapter {
    pub fn new() -> Self {
        Self {
            id: ProviderId::new(PROVIDER_ID).expect("constant Python provider ID"),
        }
    }

    /// Parse a bounded pip, pipx JSON capture or recognized uv listing.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        runtime_process_result(process, &self.id, "Python package listing")?;
        let text =
            runtime_output_text(output, MAX_OUTPUT_BYTES, &self.id, "Python package listing")?;
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            return self.parse_value(&value, observed_at);
        }
        if text.lines().any(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("Package") | Some("Tool")
            )
        }) {
            return self.parse_uv_lines(text, observed_at);
        }
        Err(super::runtime_parse_error(
            &self.id,
            "Python package listing is not valid JSON or a recognized uv listing",
        ))
    }

    fn parse_value(
        &self,
        value: &Value,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let mut warnings = Vec::new();
        let mut runtime = None;
        let mut runtime_abi = None;
        let mut records = Vec::new();

        match value {
            Value::Array(entries) => {
                self.collect_packages(entries, &mut records, &mut warnings)?;
            }
            Value::Object(object) => {
                if let Some(runtime_value) =
                    object.get("runtime").or_else(|| object.get("environment"))
                {
                    let (spec, abi) = parse_runtime(runtime_value, &self.id)?;
                    runtime = Some(spec);
                    runtime_abi = abi;
                } else if object.get("python_version").is_some()
                    || object.get("pythonVersion").is_some()
                {
                    let (spec, abi) = parse_runtime(value, &self.id)?;
                    runtime = Some(spec);
                    runtime_abi = abi;
                }

                if let Some(entries) = object
                    .get("installed")
                    .or_else(|| object.get("packages"))
                    .or_else(|| object.get("tools"))
                    .or_else(|| object.get("venvs"))
                {
                    self.collect_package_value(entries, &mut records, &mut warnings)?;
                } else if object.get("name").is_some() || object.get("package").is_some() {
                    records.push(parse_package(object, &self.id, &mut warnings, None)?);
                } else if runtime.is_none() {
                    return Err(super::runtime_parse_error(
                        &self.id,
                        "Python listing has no runtime or package collection",
                    ));
                }
            }
            _ => {
                return Err(super::runtime_parse_error(
                    &self.id,
                    "Python listing root is not an object or array",
                ));
            }
        }

        for record in &mut records {
            if let (Some(required), Some(actual)) =
                (record.required_abi.as_deref(), runtime_abi.as_deref())
                && required != actual
            {
                record.spec.source_name = Some("abi-mismatch".to_owned());
                record.spec.source_identifier = None;
                runtime_warning(
                    &mut warnings,
                    format!(
                        "Python package {} requires ABI {required}, but the interpreter reports {actual}; restore remains manual",
                        record.spec.id
                    ),
                );
            }
        }

        let mut observations = Vec::with_capacity(records.len() + usize::from(runtime.is_some()));
        if let Some(spec) = runtime {
            let abi = runtime_abi
                .as_deref()
                .map(|value| format!("|abi={value}"))
                .unwrap_or_default();
            let architecture = spec
                .architecture
                .as_ref()
                .map(|value| format!("|arch={value:?}"))
                .unwrap_or_default();
            observations.push(Observation::Runtime {
                spec,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Python,
                    format!("python-runtime{abi}{architecture}"),
                    "Python interpreter facts were collected from a reviewed provider probe",
                    85,
                    "python-runtime",
                    observed_at,
                )],
            });
        }
        for record in records {
            let version = record.spec.version.as_ref().map(|raw| VersionValue {
                raw: raw.clone(),
                normalized: None,
            });
            let source_label = record
                .spec
                .source_name
                .as_deref()
                .unwrap_or("unknown")
                .to_owned();
            observations.push(Observation::Package {
                spec: record.spec,
                version,
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Python,
                    format!("python-package:{source_label}"),
                    "Python package metadata was collected from a bounded provider listing",
                    75,
                    "python-packages",
                    observed_at,
                )],
            });
        }
        Ok(ProviderEnumeration {
            observations,
            warnings,
        })
    }

    fn collect_packages(
        &self,
        entries: &[Value],
        records: &mut Vec<PackageRecord>,
        warnings: &mut Vec<String>,
    ) -> ProviderResult<()> {
        if records
            .len()
            .checked_add(entries.len())
            .is_none_or(|count| count > MAX_RECORDS)
        {
            return Err(super::runtime_security_error(
                &self.id,
                "Python package listing exceeds the package limit",
            ));
        }
        for entry in entries {
            let object = entry.as_object().ok_or_else(|| {
                super::runtime_parse_error(&self.id, "Python package record is not an object")
            })?;
            records.push(parse_package(object, &self.id, warnings, None)?);
        }
        Ok(())
    }

    fn collect_package_value(
        &self,
        value: &Value,
        records: &mut Vec<PackageRecord>,
        warnings: &mut Vec<String>,
    ) -> ProviderResult<()> {
        match value {
            Value::Array(entries) => self.collect_packages(entries, records, warnings),
            Value::Object(object) => {
                if let Some(main_package) = object
                    .get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("main_package"))
                    .and_then(Value::as_object)
                {
                    records.push(parse_package(main_package, &self.id, warnings, None)?);
                    return Ok(());
                }
                if object.get("name").is_some()
                    || object.get("package").is_some()
                    || object.get("id").is_some()
                {
                    records.push(parse_package(object, &self.id, warnings, None)?);
                    return Ok(());
                }
                if records.len().saturating_add(object.len()) > MAX_RECORDS {
                    return Err(super::runtime_security_error(
                        &self.id,
                        "Python package listing exceeds the package limit",
                    ));
                }
                for (name, entry) in object {
                    let entry_object = entry.as_object().ok_or_else(|| {
                        super::runtime_parse_error(
                            &self.id,
                            "Python package map entry is not an object",
                        )
                    })?;
                    let package_object = entry_object
                        .get("metadata")
                        .and_then(Value::as_object)
                        .and_then(|metadata| metadata.get("main_package"))
                        .and_then(Value::as_object)
                        .unwrap_or(entry_object);
                    records.push(parse_package(
                        package_object,
                        &self.id,
                        warnings,
                        Some(name),
                    )?);
                }
                Ok(())
            }
            _ => Err(super::runtime_parse_error(
                &self.id,
                "Python package collection is not an array or object",
            )),
        }
    }

    fn runtime_observation_from_version(
        &self,
        process: &ProcessResult,
        abi: Option<&str>,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<Observation> {
        let text = if process.stdout.trim().is_empty() {
            process.stderr.as_str()
        } else {
            process.stdout.as_str()
        };
        let version = text
            .split_whitespace()
            .find(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
            })
            .ok_or_else(|| {
                super::runtime_parse_error(&self.id, "Python version output has no version")
            })?;
        let version = version.trim_start_matches("Python").trim();
        if version.is_empty() || version.len() > MAX_TEXT_BYTES {
            return Err(super::runtime_parse_error(
                &self.id,
                "Python version output has an invalid version",
            ));
        }
        let abi_locator = abi.map(|value| format!("|abi={value}")).unwrap_or_default();
        let summary = if abi.is_some() {
            "Python interpreter version and ABI were read from reviewed built-in probes"
        } else {
            "Python interpreter version was read from a reviewed built-in probe"
        };
        Ok(Observation::Runtime {
            spec: RuntimeSpec {
                id: RUNTIME_ID.to_owned(),
                version: Some(version.to_owned()),
                architecture: None,
            },
            evidence: vec![runtime_make_evidence(
                EvidenceSource::Python,
                format!("python-version{abi_locator}"),
                summary,
                80,
                "python-runtime",
                observed_at,
            )],
        })
    }

    async fn enumerate_python(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let version_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Python),
            [OsString::from("--version")],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let version_process = context
            .runner
            .run(&version_command, context.cancellation)
            .await?;
        runtime_process_result(&version_process, &self.id, "Python version probe")?;

        let list_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Python),
            [
                OsString::from("-m"),
                OsString::from("pip"),
                OsString::from("list"),
                OsString::from("--format=json"),
            ],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let list_process = context
            .runner
            .run(&list_command, context.cancellation)
            .await?;
        let mut result =
            self.parse_capture(&list_process, list_process.stdout.as_bytes(), Utc::now())?;
        let abi_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Python),
            [
                OsString::from("-c"),
                OsString::from(
                    "import sysconfig; value = sysconfig.get_config_var('SOABI'); print(value or '')",
                ),
            ],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let abi_process = context
            .runner
            .run(&abi_command, context.cancellation)
            .await?;
        let abi = if abi_process.cancelled {
            runtime_process_result(&abi_process, &self.id, "Python ABI probe")?;
            None
        } else if abi_process.exit_code == Some(0) && !abi_process.timed_out {
            let abi_text = runtime_output_text(
                abi_process.stdout.as_bytes(),
                MAX_OUTPUT_BYTES,
                &self.id,
                "Python ABI probe",
            )?
            .trim();
            if abi_text.is_empty()
                || abi_text.len() > MAX_TEXT_BYTES
                || abi_text
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                None
            } else {
                Some(abi_text)
            }
        } else {
            runtime_warning(
                &mut result.warnings,
                "Python ABI probe was unavailable; interpreter version was retained",
            );
            None
        };
        result.observations.insert(
            0,
            self.runtime_observation_from_version(&version_process, abi, Utc::now())?,
        );

        let inspect_command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Python),
            [
                OsString::from("-m"),
                OsString::from("pip"),
                OsString::from("inspect"),
            ],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let inspect_process = context
            .runner
            .run(&inspect_command, context.cancellation)
            .await?;
        if inspect_process.cancelled {
            runtime_process_result(&inspect_process, &self.id, "Python package inspection")?;
        } else if inspect_process.exit_code == Some(0) && !inspect_process.timed_out {
            let inspected = self.parse_capture(
                &inspect_process,
                inspect_process.stdout.as_bytes(),
                Utc::now(),
            )?;
            for observation in inspected.observations {
                let duplicate = match &observation {
                    Observation::Runtime { .. } => true,
                    Observation::Package { spec, .. } => result.observations.iter().any(
                        |existing| matches!(existing, Observation::Package { spec: existing_spec, .. } if existing_spec.id == spec.id),
                    ),
                    _ => false,
                };
                if !duplicate {
                    result.observations.push(observation);
                }
            }
            result.warnings.extend(inspected.warnings);
        } else {
            runtime_warning(
                &mut result.warnings,
                "pip inspect was unavailable; pip list results were retained",
            );
        }
        Ok(result)
    }

    fn parse_uv_lines(
        &self,
        text: &str,
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        let mut observations = Vec::new();
        for line in text.lines() {
            if line.trim_start().starts_with("No tools") {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(name) = fields.next() else { continue };
            let Some(version) = fields.next() else {
                continue;
            };
            if matches!(name, "Package" | "Tool" | "-") {
                continue;
            }
            let version = version.trim_start_matches('v');
            if version.is_empty() {
                continue;
            }
            if observations.len() >= MAX_RECORDS {
                return Err(super::runtime_security_error(
                    &self.id,
                    "uv tool listing exceeds the package limit",
                ));
            }
            if name.len() > MAX_TEXT_BYTES
                || name.trim() != name
                || name
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
                || version.len() > MAX_TEXT_BYTES
                || version.trim() != version
                || version.chars().any(char::is_control)
            {
                return Err(super::runtime_parse_error(
                    &self.id,
                    "uv tool record is outside the reviewed grammar",
                ));
            }
            let spec = PackageSpec {
                provider: self.id.clone(),
                id: name.to_owned(),
                version: Some(version.to_owned()),
                source_name: None,
                source_identifier: None,
                source: None,
                architecture: None,
                installer_hash: None,
            };
            observations.push(Observation::Package {
                version: Some(VersionValue {
                    raw: version.to_owned(),
                    normalized: None,
                }),
                evidence: vec![runtime_make_evidence(
                    EvidenceSource::Python,
                    format!("uv-tool:{name}"),
                    "uv tool metadata was collected from the reviewed tool listing",
                    65,
                    "python-packages",
                    observed_at,
                )],
                spec,
            });
        }
        Ok(ProviderEnumeration {
            observations,
            warnings: Vec::new(),
        })
    }

    async fn enumerate_pipx(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Pipx),
            [OsString::from("list"), OsString::from("--json")],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let process = context.runner.run(&command, context.cancellation).await?;
        self.parse_capture(&process, process.stdout.as_bytes(), Utc::now())
    }

    async fn enumerate_uv(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let command = CommandSpec::new(
            TrustedExecutable::Builtin(BuiltinExecutable::Uv),
            [OsString::from("tool"), OsString::from("list")],
            PROCESS_TIMEOUT,
            PROCESS_OUTPUT_BYTES,
        )?;
        let process = context.runner.run(&command, context.cancellation).await?;
        runtime_process_result(&process, &self.id, "uv tool listing")?;
        let text = runtime_output_text(
            process.stdout.as_bytes(),
            MAX_OUTPUT_BYTES,
            &self.id,
            "uv tool listing",
        )?;
        self.parse_uv_lines(text, Utc::now())
    }
}

impl Default for PythonAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for PythonAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        let executables = [
            (BuiltinExecutable::Python, "python.exe"),
            (BuiltinExecutable::Pipx, "pipx.exe"),
            (BuiltinExecutable::Uv, "uv.exe"),
        ];
        let available: Vec<_> = executables
            .into_iter()
            .filter(|(executable, _)| context.runner.builtin_available(*executable))
            .collect();
        if available.is_empty() {
            return DetectionResult::unavailable();
        }
        let evidence = available
            .iter()
            .map(|(_, name)| {
                runtime_make_evidence(
                    EvidenceSource::Python,
                    format!("PATH:{name}"),
                    "A reviewed Python ecosystem executable resolves from PATH",
                    60,
                    "python-provider",
                    Utc::now(),
                )
            })
            .collect();
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
        let mut result = ProviderEnumeration::empty();
        let mut discovered = false;
        if context.runner.builtin_available(BuiltinExecutable::Python) {
            result = self.enumerate_python(context).await?;
            discovered = true;
        }
        if context.runner.builtin_available(BuiltinExecutable::Pipx) {
            let pipx = self.enumerate_pipx(context).await?;
            result.observations.extend(pipx.observations);
            result.warnings.extend(pipx.warnings);
            discovered = true;
        }
        if context.runner.builtin_available(BuiltinExecutable::Uv) {
            let uv = self.enumerate_uv(context).await?;
            result.observations.extend(uv.observations);
            result.warnings.extend(uv.warnings);
            discovered = true;
        }
        if discovered {
            Ok(result)
        } else {
            Ok(ProviderEnumeration::empty())
        }
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

fn parse_runtime(
    value: &Value,
    provider: &ProviderId,
) -> ProviderResult<(RuntimeSpec, Option<String>)> {
    let object = value.as_object().ok_or_else(|| {
        super::runtime_parse_error(provider, "Python runtime record is not an object")
    })?;
    let version = object
        .get("version")
        .or_else(|| object.get("python_version"))
        .or_else(|| object.get("pythonVersion"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let architecture = object
        .get("architecture")
        .or_else(|| object.get("arch"))
        .and_then(Value::as_str)
        .map(parse_architecture);
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(RUNTIME_ID);
    if id != RUNTIME_ID {
        return Err(super::runtime_parse_error(
            provider,
            "Python runtime record uses an unexpected runtime ID",
        ));
    }
    let abi = object
        .get("abi")
        .or_else(|| object.get("implementation"))
        .or_else(|| object.get("implementation_name"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((
        RuntimeSpec {
            id: RUNTIME_ID.to_owned(),
            version,
            architecture,
        },
        abi,
    ))
}

fn parse_package(
    object: &serde_json::Map<String, Value>,
    provider: &ProviderId,
    warnings: &mut Vec<String>,
    name_hint: Option<&str>,
) -> ProviderResult<PackageRecord> {
    let metadata = object.get("metadata").and_then(Value::as_object);
    let name = metadata
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .or_else(|| object.get("name").and_then(Value::as_str))
        .or_else(|| object.get("package").and_then(Value::as_str))
        .or_else(|| object.get("id").and_then(Value::as_str))
        .or_else(|| {
            object
                .get("package_or_url")
                .and_then(Value::as_str)
                .filter(|value| !value.contains("://"))
        })
        .or(name_hint)
        .ok_or_else(|| super::runtime_parse_error(provider, "Python package has no name"))?;
    let version = metadata
        .and_then(|value| value.get("version"))
        .and_then(Value::as_str)
        .or_else(|| object.get("version").and_then(Value::as_str))
        .or_else(|| object.get("package_version").and_then(Value::as_str))
        .map(str::to_owned);
    let direct_url = object.get("direct_url");
    let source_kind = object
        .get("source_kind")
        .or_else(|| object.get("source_type"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            direct_url.and_then(|value| {
                let direct = value.as_object()?;
                if direct
                    .get("dir_info")
                    .and_then(Value::as_object)
                    .and_then(|dir| dir.get("editable"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    Some("editable".to_owned())
                } else if direct.get("vcs_info").is_some() {
                    Some("git".to_owned())
                } else if direct.get("dir_info").is_some() {
                    Some("path".to_owned())
                } else {
                    None
                }
            })
        });
    let source_kind = source_kind.map(|kind| match kind.to_ascii_lowercase().as_str() {
        "pypi" | "pip" | "registry" | "index" => "pypi".to_owned(),
        "editable" => "editable".to_owned(),
        "path" | "directory" => "path".to_owned(),
        "git" | "vcs" => "git".to_owned(),
        other => other.to_owned(),
    });
    let source_value = object
        .get("source")
        .or_else(|| object.get("url"))
        .or_else(|| direct_url.and_then(|value| value.get("url")));
    let source = source_value
        .and_then(Value::as_str)
        .and_then(|raw| match Url::parse(raw) {
            Ok(url)
                if matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none() =>
            {
                Some(url)
            }
            _ => {
                runtime_warning(
                    warnings,
                    "A Python package source URL was omitted because it was not safe to retain",
                );
                None
            }
        });
    let source_identifier = object
        .get("source_identifier")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_TEXT_BYTES
                && value.trim() == *value
                && super::runtime_safe_source_identifier(value)
                && !value
                    .chars()
                    .any(|character| character.is_control() || character == '\\')
        })
        .map(str::to_owned);
    let required_abi = object
        .get("abi")
        .or_else(|| object.get("requires_abi"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if name.is_empty()
        || name.len() > MAX_TEXT_BYTES
        || name.trim() != name
        || name.chars().any(char::is_whitespace)
    {
        return Err(super::runtime_parse_error(
            provider,
            "Python package name is outside the reviewed grammar",
        ));
    }
    if let Some(version) = &version
        && (version.is_empty() || version.len() > MAX_TEXT_BYTES || version.trim() != version)
    {
        return Err(super::runtime_parse_error(
            provider,
            "Python package version is outside the reviewed grammar",
        ));
    }
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
        required_abi,
    })
}

fn parse_architecture(value: &str) -> Architecture {
    match value.to_ascii_lowercase().as_str() {
        "x86" | "i386" | "i686" | "32" => Architecture::X86,
        "x64" | "amd64" | "x86_64" | "64" => Architecture::X64,
        "arm64" | "aarch64" => Architecture::Arm64,
        "neutral" | "any" => Architecture::Neutral,
        _ => Architecture::Unknown,
    }
}
