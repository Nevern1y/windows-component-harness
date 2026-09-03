//! JavaScript package-manager discovery for global tools and project artifacts.
//!
//! The adapter intentionally consumes only bounded, structured package-manager
//! output. Package installation is represented as a typed operation; lifecycle
//! scripts remain visible as a restore risk and are never executed here.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind,
    Confidence, ConfigScope, ContentType, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, ManualAction,
    ManualActionState, ObjectId, Operation, OperationId, OperationKind, PackageInstallPolicy,
    PackageSpec, PathToken, Portability, Precondition, Provenance, ProviderId, RedactionPolicy,
    ReforgeErrorCode, RestoreDescriptor, RestoreStrategy, RiskLevel, RunId, SelectionMetadata,
    TargetFacts, VerificationRule, VersionValue,
};
use reforge_platform_windows::{
    BoundedFileReader, BuiltinExecutable, CommandSpec, ProcessResult, SafePath, TrustedExecutable,
};
use serde_json::Value;
use url::Url;

use super::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const PROCESS_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_GLOBAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROJECT_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 100_000;
const MAX_PACKAGE_NAME_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 256;
const MAX_INTEGRITY_BYTES: usize = 512;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const MAX_DEPENDENCY_DEPTH: usize = 64;
const MAX_YARN_LINES: usize = 100_000;
const LIFECYCLE_RISK_WARNING: &str =
    "JavaScript package installs may execute lifecycle scripts; review before restore";
const YARN_SCOPE_WARNING: &str = "Yarn Classic and modern Yarn have different global semantics; unsupported global state remains manual";
const PROJECT_ARTIFACTS: [(&str, ContentType); 7] = [
    ("package.json", ContentType::Json),
    ("package-lock.json", ContentType::Json),
    ("npm-shrinkwrap.json", ContentType::Json),
    ("pnpm-lock.yaml", ContentType::Utf8Text),
    ("yarn.lock", ContentType::Utf8Text),
    ("bun.lock", ContentType::Utf8Text),
    ("bun.lockb", ContentType::Binary),
];

/// A supported JavaScript package manager with a reviewed executable identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NodePackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl NodePackageManager {
    /// All managers in stable provider-registration order.
    pub const ALL: [Self; 4] = [Self::Npm, Self::Pnpm, Self::Yarn, Self::Bun];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
        }
    }

    pub fn executable(self) -> BuiltinExecutable {
        match self {
            Self::Npm => BuiltinExecutable::Npm,
            Self::Pnpm => BuiltinExecutable::Pnpm,
            Self::Yarn => BuiltinExecutable::Yarn,
            Self::Bun => BuiltinExecutable::Bun,
        }
    }

    pub fn evidence_source(self) -> EvidenceSource {
        match self {
            Self::Npm => EvidenceSource::Npm,
            Self::Pnpm => EvidenceSource::Pnpm,
            Self::Yarn => EvidenceSource::Yarn,
            Self::Bun => EvidenceSource::Bun,
        }
    }

    pub fn provider_id(self) -> ProviderId {
        ProviderId::new(self.as_str()).expect("constant JavaScript provider ID")
    }

    fn list_args(self) -> Vec<OsString> {
        match self {
            Self::Npm | Self::Pnpm => ["ls", "--global", "--json", "--depth=0"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            Self::Yarn => ["global", "list", "--json", "--depth=0"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            Self::Bun => ["pm", "ls", "--json", "--global"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        }
    }

    fn docs_url(self) -> &'static str {
        match self {
            Self::Npm => "https://docs.npmjs.com/cli/v11/commands/npm-install/",
            Self::Pnpm => "https://pnpm.io/cli/add",
            Self::Yarn => "https://classic.yarnpkg.com/lang/en/docs/cli/global/",
            Self::Bun => "https://bun.sh/docs/pm/cli/add",
        }
    }
}

/// Scope attached to a discovered JavaScript package or project artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodePackageScope {
    Global,
    Project(PathToken),
}

impl NodePackageScope {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project(_) => "project",
        }
    }
}

/// A dependency reference retained from a structured package-manager listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptDependency {
    pub name: String,
    pub version: Option<String>,
    pub required: bool,
}

/// A package-manager package record, including its scope and dependency edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavaScriptPackage {
    pub manager: NodePackageManager,
    pub scope: NodePackageScope,
    pub spec: PackageSpec,
    pub dependencies: Vec<JavaScriptDependency>,
    pub top_level: bool,
}

/// Discovery adapter for one JavaScript package manager.
#[derive(Clone, Debug)]
pub struct JavaScriptAdapter {
    manager: NodePackageManager,
    id: ProviderId,
    project_roots: Vec<PathToken>,
    global_packages: Arc<RwLock<BTreeMap<String, JavaScriptPackage>>>,
}

impl JavaScriptAdapter {
    pub fn new(manager: NodePackageManager) -> Self {
        Self {
            manager,
            id: manager.provider_id(),
            project_roots: Vec::new(),
            global_packages: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Construct an adapter that also captures selected project manifests and lockfiles.
    pub fn with_project_roots(
        manager: NodePackageManager,
        project_roots: impl IntoIterator<Item = PathToken>,
    ) -> Self {
        Self {
            manager,
            id: manager.provider_id(),
            project_roots: project_roots.into_iter().collect(),
            global_packages: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn npm() -> Self {
        Self::new(NodePackageManager::Npm)
    }

    pub fn pnpm() -> Self {
        Self::new(NodePackageManager::Pnpm)
    }

    pub fn yarn() -> Self {
        Self::new(NodePackageManager::Yarn)
    }

    pub fn bun() -> Self {
        Self::new(NodePackageManager::Bun)
    }

    pub fn manager(&self) -> NodePackageManager {
        self.manager
    }

    pub fn project_roots(&self) -> &[PathToken] {
        &self.project_roots
    }

    /// Parse one completed structured global-list command capture.
    pub fn parse_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        validate_process_result(process, "global package listing", self.manager)?;
        self.parse_global_output(output, observed_at)
    }

    /// Alias named after the package scope for callers handling multiple captures.
    pub fn parse_global_capture(
        &self,
        process: &ProcessResult,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        self.parse_capture(process, output, observed_at)
    }

    fn parse_global_output(
        &self,
        output: &[u8],
        observed_at: DateTime<Utc>,
    ) -> ProviderResult<ProviderEnumeration> {
        if output.len() > MAX_GLOBAL_BYTES {
            return Err(security_error(
                "JavaScript global package listing exceeds the reviewed byte limit",
            ));
        }
        let text = std::str::from_utf8(output)
            .map_err(|_| parse_error(self.manager, "global package listing is not UTF-8"))?;

        let mut state = ParseState::new(self.manager);
        if self.manager == NodePackageManager::Yarn {
            self.parse_yarn_output(text, &mut state)?;
        } else {
            let value: Value = serde_json::from_str(text).map_err(|_| {
                parse_error(
                    self.manager,
                    "global package listing is not valid structured JSON",
                )
            })?;
            self.parse_json_root(&value, &mut state)?;
        }

        let (packages, warnings) = state.into_packages(self.manager);
        self.remember_packages(&packages)?;
        let observations = packages
            .into_iter()
            .map(|package| {
                let version = package.spec.version.as_ref().map(|raw| VersionValue {
                    raw: raw.clone(),
                    normalized: None,
                });
                let version_label = package.spec.version.as_deref().unwrap_or("unversioned");
                let evidence = vec![make_evidence(
                    self.manager.evidence_source(),
                    format!("global-package:{}@{}", package.spec.id, version_label),
                    &format!(
                        "{} global listing recorded package {} version {}",
                        self.manager.as_str(),
                        package.spec.id,
                        version_label
                    ),
                    if package.top_level { 75 } else { 65 },
                    &format!("javascript-{}-global", self.manager.as_str()),
                    observed_at,
                )];
                Observation::Package {
                    spec: package.spec,
                    version,
                    evidence,
                }
            })
            .collect();
        Ok(ProviderEnumeration {
            observations,
            warnings,
        })
    }

    fn remember_packages(&self, packages: &[JavaScriptPackage]) -> ProviderResult<()> {
        let mut metadata = self.global_packages.write().map_err(|_| {
            schema_error(self.manager, "JavaScript package metadata lock is poisoned")
        })?;
        for package in packages {
            metadata.insert(
                package_key(&package.spec.id, package.spec.version.as_deref()),
                package.clone(),
            );
        }
        Ok(())
    }

    fn remembered_package(&self, spec: &PackageSpec) -> ProviderResult<Option<JavaScriptPackage>> {
        let metadata = self.global_packages.read().map_err(|_| {
            schema_error(self.manager, "JavaScript package metadata lock is poisoned")
        })?;
        Ok(metadata
            .get(&package_key(&spec.id, spec.version.as_deref()))
            .cloned())
    }

    fn parse_json_root(&self, value: &Value, state: &mut ParseState) -> ProviderResult<()> {
        match value {
            Value::Array(entries) => {
                if entries.len() > MAX_PACKAGES {
                    return Err(security_error(
                        "JavaScript global package listing exceeds the package limit",
                    ));
                }
                for entry in entries {
                    if let Some(dependencies) = entry.get("dependencies") {
                        let is_listing_root = entry.get("name").is_none()
                            || entry.get("path").is_some()
                            || entry.get("private").is_some()
                            || entry
                                .get("name")
                                .and_then(Value::as_str)
                                .is_some_and(|name| name.eq_ignore_ascii_case("global"));
                        if is_listing_root {
                            self.collect_dependency_map(dependencies, state, true, 0)?;
                            continue;
                        }
                    }
                    self.collect_entry(None, entry, state, true, true, 0)?;
                }
            }
            Value::Object(object) => {
                if let Some(data) = object.get("data")
                    && object.get("type").is_some()
                {
                    self.parse_structured_data(data, state)?;
                } else if let Some(dependencies) = object.get("dependencies") {
                    self.collect_dependency_map(dependencies, state, true, 0)?;
                    if object.get("problems").is_some() {
                        state.warning(
                            "The package manager reported incomplete or invalid package entries",
                        );
                    }
                } else if let Some(packages) = object.get("packages") {
                    self.collect_package_list(packages, state)?;
                } else if object.get("name").is_some() {
                    self.collect_entry(None, value, state, true, true, 0)?;
                } else if object
                    .values()
                    .all(|entry| matches!(entry, Value::Object(_) | Value::String(_) | Value::Null))
                {
                    self.collect_dependency_map(value, state, true, 0)?;
                } else {
                    return Err(parse_error(
                        self.manager,
                        "global package listing has no reviewed package collection",
                    ));
                }
            }
            _ => {
                return Err(parse_error(
                    self.manager,
                    "global package listing root is not an object or array",
                ));
            }
        }
        Ok(())
    }

    fn parse_structured_data(&self, data: &Value, state: &mut ParseState) -> ProviderResult<()> {
        match data {
            Value::Array(_) | Value::Object(_) => self.parse_json_root(data, state),
            Value::String(_) | Value::Null => Ok(()),
            _ => Err(parse_error(
                self.manager,
                "structured package listing data has an unsupported shape",
            )),
        }
    }

    fn collect_package_list(&self, value: &Value, state: &mut ParseState) -> ProviderResult<()> {
        match value {
            Value::Array(entries) => {
                for entry in entries {
                    self.collect_entry(None, entry, state, true, true, 0)?;
                }
            }
            Value::Object(_) => self.collect_dependency_map(value, state, true, 0)?,
            _ => {
                return Err(parse_error(
                    self.manager,
                    "global package list is not an array or object",
                ));
            }
        }
        Ok(())
    }

    fn collect_dependency_map(
        &self,
        value: &Value,
        state: &mut ParseState,
        top_level: bool,
        depth: usize,
    ) -> ProviderResult<()> {
        let Value::Object(entries) = value else {
            return Err(parse_error(
                self.manager,
                "package dependencies are not an object",
            ));
        };
        if entries.len() > MAX_PACKAGES {
            return Err(security_error(
                "JavaScript dependency map exceeds the package limit",
            ));
        }
        let mut names: Vec<_> = entries.keys().collect();
        names.sort();
        for name in names {
            let entry = entries
                .get(name)
                .expect("dependency map key collected from the same object");
            self.collect_entry(Some(name), entry, state, top_level, true, depth)?;
        }
        Ok(())
    }

    fn collect_entry(
        &self,
        name_hint: Option<&str>,
        value: &Value,
        state: &mut ParseState,
        top_level: bool,
        _required: bool,
        depth: usize,
    ) -> ProviderResult<Option<usize>> {
        if depth > MAX_DEPENDENCY_DEPTH {
            return Err(security_error(
                "JavaScript dependency nesting exceeds the reviewed depth",
            ));
        }

        let (name, version, source, integrity, dependencies) = match value {
            Value::Object(object) => {
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .or(name_hint)
                    .ok_or_else(|| {
                        parse_error(
                            self.manager,
                            "package record has no name and no dependency-map key",
                        )
                    })?;
                let version = object
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let (source, source_rejected) = package_source(object);
                if source_rejected {
                    state.warning(
                        "A package source URL was omitted because it was not safe to retain",
                    );
                }
                let integrity = package_integrity(object);
                let dependencies = dependency_entries(object, self.manager)?;
                (name.to_owned(), version, source, integrity, dependencies)
            }
            Value::String(version) => (
                name_hint
                    .ok_or_else(|| parse_error(self.manager, "version-only package has no name"))?
                    .to_owned(),
                Some(version.clone()),
                None,
                None,
                Vec::new(),
            ),
            Value::Null => (
                name_hint
                    .ok_or_else(|| parse_error(self.manager, "null package has no name"))?
                    .to_owned(),
                None,
                None,
                None,
                Vec::new(),
            ),
            _ => {
                return Err(parse_error(
                    self.manager,
                    "package record has an unsupported JSON value",
                ));
            }
        };

        validate_package_name(&name, self.manager)?;
        if let Some(version) = &version {
            validate_package_version(version, self.manager)?;
        }
        let index = state.upsert(PackageRecord {
            name,
            version,
            source,
            integrity,
            dependencies: BTreeMap::new(),
            top_level,
        })?;

        for (dependency_name, dependency_value, dependency_required) in dependencies {
            let child_index = self.collect_entry(
                Some(&dependency_name),
                &dependency_value,
                state,
                false,
                dependency_required,
                depth + 1,
            )?;
            let (dependency_version, fallback_name) = child_index
                .and_then(|child| state.records.get(child))
                .map(|child| (child.version.clone(), child.name.clone()))
                .unwrap_or((None, dependency_name.clone()));
            state.add_dependency(
                index,
                fallback_name,
                dependency_version,
                dependency_required,
            )?;
        }
        Ok(Some(index))
    }

    fn parse_yarn_output(&self, text: &str, state: &mut ParseState) -> ProviderResult<()> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            state.warning(YARN_SCOPE_WARNING);
            return Ok(());
        }

        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if value
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("error"))
            {
                state.yarn_modern = true;
                state.warning(YARN_SCOPE_WARNING);
                return Ok(());
            }
            if value.get("type").is_some() && value.get("data").is_some() {
                self.parse_yarn_event(&value, state)?;
            } else {
                self.parse_json_root(&value, state)?;
            }
            if state.records.is_empty() {
                state.warning(YARN_SCOPE_WARNING);
            }
            return Ok(());
        }

        for (line_count, line) in text.lines().enumerate() {
            if line_count >= MAX_YARN_LINES {
                return Err(security_error("Yarn global listing exceeds the line limit"));
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).map_err(|_| {
                parse_error(
                    self.manager,
                    "Yarn global listing contains a non-JSON log line",
                )
            })?;
            self.parse_yarn_event(&event, state)?;
        }
        state.warning(YARN_SCOPE_WARNING);
        Ok(())
    }

    fn parse_yarn_event(&self, event: &Value, state: &mut ParseState) -> ProviderResult<()> {
        let Some(object) = event.as_object() else {
            return Err(parse_error(
                self.manager,
                "Yarn global listing event is not an object",
            ));
        };
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let data = object.get("data");
        if kind.eq_ignore_ascii_case("error") || kind.eq_ignore_ascii_case("warning") {
            if kind.eq_ignore_ascii_case("error") {
                state.yarn_modern = true;
            }
            return Ok(());
        }
        let Some(data) = data else {
            return Ok(());
        };
        match data {
            Value::Object(_) | Value::Array(_) => self.parse_structured_data(data, state),
            Value::String(text) => {
                if let Some((name, version)) = parse_yarn_package_text(text) {
                    state.upsert(PackageRecord {
                        name,
                        version,
                        source: None,
                        integrity: None,
                        dependencies: BTreeMap::new(),
                        top_level: true,
                    })?;
                }
                Ok(())
            }
            Value::Null => Ok(()),
            _ => Err(parse_error(
                self.manager,
                "Yarn global listing event data has an unsupported shape",
            )),
        }
    }

    pub fn project_artifacts(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        if self.project_roots.len() > MAX_PACKAGES {
            return Err(security_error(
                "selected JavaScript project roots exceed the reviewed limit",
            ));
        }
        let mut observations = Vec::new();
        let mut warnings = Vec::new();
        for root_token in &self.project_roots {
            let root = match context.known_folders.resolve(root_token) {
                Ok(root) => root,
                Err(_) => {
                    push_warning(
                        &mut warnings,
                        "A selected JavaScript project root could not be resolved",
                    );
                    continue;
                }
            };
            for (file_name, content_type) in PROJECT_ARTIFACTS {
                let safe_path = SafePath::new(file_name)?;
                let mut reader =
                    match BoundedFileReader::open(&root, &safe_path, MAX_PROJECT_ARTIFACT_BYTES) {
                        Ok(reader) => reader,
                        Err(error) if error.code == ReforgeErrorCode::PathNotFound => continue,
                        Err(_) => {
                            push_warning(
                                &mut warnings,
                                "A selected JavaScript project artifact could not be read safely",
                            );
                            continue;
                        }
                    };
                let mut bytes = Vec::new();
                let summary = match reader.stream_into(&mut bytes) {
                    Ok(summary) => summary,
                    Err(_) => {
                        push_warning(
                            &mut warnings,
                            "A selected JavaScript project artifact exceeded safe read limits",
                        );
                        continue;
                    }
                };
                let relative = join_token_path(&root_token.relative, file_name);
                let source_path = PathToken::new(root_token.root.clone(), relative)
                    .map_err(|_| schema_error(self.manager, "project artifact path is invalid"))?;
                let object = ObjectId::from_content(&bytes);
                let artifact = ArtifactRef {
                    id: artifact_id(self.manager, &source_path, &object),
                    source_path: source_path.clone(),
                    scope: ConfigScope::Project,
                    size_bytes: summary.bytes,
                    content_type,
                    policy: ArtifactPolicy::Data,
                    object: Some(object),
                };
                let evidence = vec![make_evidence(
                    self.manager.evidence_source(),
                    format!("project-artifact:{}", source_path.relative),
                    &format!(
                        "{} project artifact was captured as bounded data",
                        file_name
                    ),
                    80,
                    "javascript-project-artifact",
                    Utc::now(),
                )];
                observations.push(Observation::Artifact { artifact, evidence });
            }
        }
        Ok(ProviderEnumeration {
            observations,
            warnings: normalized_warnings(warnings),
        })
    }
}

impl Default for JavaScriptAdapter {
    fn default() -> Self {
        Self::npm()
    }
}

#[async_trait]
impl ProviderAdapter for JavaScriptAdapter {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        let manager_available = context.runner.builtin_available(self.manager.executable());
        let project_available = !self.project_roots.is_empty();
        if !manager_available && !project_available {
            return DetectionResult::unavailable();
        }

        let mut evidence = Vec::new();
        if manager_available {
            evidence.push(make_evidence(
                self.manager.evidence_source(),
                format!("PATH:{}.exe", self.manager.as_str()),
                &format!(
                    "The reviewed {} executable resolves from PATH",
                    self.manager.as_str()
                ),
                60,
                "javascript-manager-path",
                Utc::now(),
            ));
        }
        if project_available {
            for root in &self.project_roots {
                evidence.push(make_evidence(
                    EvidenceSource::UserSelected,
                    format!("project-root:{}", root.relative),
                    "A user-selected project root is available for manifest and lockfile capture",
                    70,
                    "javascript-project-root",
                    Utc::now(),
                ));
            }
        }
        let mut warnings = Vec::new();
        if self.manager == NodePackageManager::Yarn && manager_available {
            warnings.push(YARN_SCOPE_WARNING.to_owned());
        }
        DetectionResult {
            available: true,
            version: None,
            evidence,
            warnings: normalized_warnings(warnings),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let manager_available = context.runner.builtin_available(self.manager.executable());
        let mut result = ProviderEnumeration::empty();
        if manager_available {
            let command = CommandSpec::new(
                TrustedExecutable::Builtin(self.manager.executable()),
                self.manager.list_args(),
                PROCESS_TIMEOUT,
                PROCESS_OUTPUT_BYTES,
            )?;
            let process = context
                .runner
                .run(&command, context.cancellation)
                .await
                .map_err(map_runner_error)?;
            if process.cancelled {
                return Err(Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::Cancelled,
                    format!(
                        "{} global package listing was cancelled",
                        self.manager.as_str()
                    ),
                )));
            }
            if process.timed_out {
                return Err(operation_error(
                    self.manager,
                    &format!("{} global package listing timed out", self.manager.as_str()),
                ));
            }
            if process.exit_code == Some(0) {
                let captured =
                    self.parse_capture(&process, process.stdout.as_bytes(), Utc::now())?;
                result.observations.extend(captured.observations);
                result.warnings.extend(captured.warnings);
            } else {
                push_warning(
                    &mut result.warnings,
                    &format!(
                        "{} did not provide a supported global package listing; global restore remains manual",
                        self.manager.as_str()
                    ),
                );
                if self.manager == NodePackageManager::Yarn {
                    push_warning(&mut result.warnings, YARN_SCOPE_WARNING);
                }
            }
        }

        if !self.project_roots.is_empty() {
            let artifacts = self.project_artifacts(context)?;
            result.observations.extend(artifacts.observations);
            result.warnings.extend(artifacts.warnings);
        }
        result.warnings = normalized_warnings(result.warnings);
        Ok(result)
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        match observation {
            Observation::Package {
                spec,
                version: _version,
                evidence,
            } => {
                if spec.provider != self.id {
                    return Err(schema_error(
                        self.manager,
                        "JavaScript adapter received a package from another manager",
                    ));
                }
                let mut package = self
                    .remembered_package(&spec)?
                    .unwrap_or(JavaScriptPackage {
                        manager: self.manager,
                        scope: NodePackageScope::Global,
                        spec: spec.clone(),
                        dependencies: Vec::new(),
                        top_level: true,
                    });
                package.spec = spec;
                self.normalize_package(package, evidence)
            }
            Observation::Artifact { artifact, evidence } => {
                self.normalize_artifact(artifact, evidence)
            }
            _ => Err(schema_error(
                self.manager,
                "JavaScript adapter received an observation owned by another adapter",
            )),
        }
    }

    fn plan_install(
        &self,
        component: &Component,
        target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        let package = package_from_component(component, &self.id, self.manager)?;
        let provider_available = target
            .providers
            .iter()
            .any(|provider| provider.id == self.id && provider.available);
        if !provider_available {
            return Ok(vec![manual_operation(
                component,
                package,
                "The recorded JavaScript package manager is unavailable on the target",
                run_id,
                first_ordinal,
                self.manager,
            )?]);
        }
        if !is_exact_version(package.version.as_deref()) {
            return Ok(vec![manual_operation(
                component,
                package,
                "The global package listing did not provide an exact version for safe restore",
                run_id,
                first_ordinal,
                self.manager,
            )?]);
        }

        let verification = VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: package.clone(),
        };
        let operation_id = OperationId::for_run(run_id, first_ordinal)
            .map_err(|_| schema_error(self.manager, "JavaScript operation ID is invalid"))?;
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
            idempotency_key: operation_key("install", package, self.manager),
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
        if component.kind == ComponentKind::DataArtifact {
            let artifact = artifact_from_component(component, &self.id, self.manager)?;
            return Ok(vec![VerificationRule::File {
                destination: artifact.source_path.clone(),
                object: artifact.object.clone(),
            }]);
        }
        let package = package_from_component(component, &self.id, self.manager)?;
        Ok(vec![VerificationRule::ProviderIdentity {
            provider: self.id.clone(),
            package: package.clone(),
        }])
    }
}

#[derive(Clone, Debug)]
struct PackageRecord {
    name: String,
    version: Option<String>,
    source: Option<Url>,
    integrity: Option<String>,
    dependencies: BTreeMap<String, JavaScriptDependency>,
    top_level: bool,
}

struct ParseState {
    manager: NodePackageManager,
    records: Vec<PackageRecord>,
    indexes: BTreeMap<String, usize>,
    warnings: Vec<String>,
    yarn_modern: bool,
}

impl ParseState {
    fn new(manager: NodePackageManager) -> Self {
        Self {
            manager,
            records: Vec::new(),
            indexes: BTreeMap::new(),
            warnings: Vec::new(),
            yarn_modern: false,
        }
    }

    fn upsert(&mut self, mut incoming: PackageRecord) -> ProviderResult<usize> {
        let key = package_key(&incoming.name, incoming.version.as_deref());
        if let Some(index) = self.indexes.get(&key).copied() {
            let existing = self
                .records
                .get_mut(index)
                .expect("package index points into package records");
            if existing.source != incoming.source
                && existing.source.is_some()
                && incoming.source.is_some()
            {
                return Err(parse_error(
                    self.manager,
                    "package listing repeats a package with conflicting source metadata",
                ));
            }
            if existing.integrity != incoming.integrity
                && existing.integrity.is_some()
                && incoming.integrity.is_some()
            {
                return Err(parse_error(
                    self.manager,
                    "package listing repeats a package with conflicting integrity metadata",
                ));
            }
            if existing.source.is_none() {
                existing.source = incoming.source.take();
            }
            if existing.integrity.is_none() {
                existing.integrity = incoming.integrity.take();
            }
            existing.top_level |= incoming.top_level;
            return Ok(index);
        }
        if self.records.len() >= MAX_PACKAGES {
            return Err(security_error(
                "JavaScript global package listing exceeds the package limit",
            ));
        }
        let index = self.records.len();
        self.indexes.insert(key, index);
        self.records.push(incoming);
        Ok(index)
    }

    fn add_dependency(
        &mut self,
        parent: usize,
        name: String,
        version: Option<String>,
        required: bool,
    ) -> ProviderResult<()> {
        let package = self
            .records
            .get_mut(parent)
            .ok_or_else(|| security_error("package dependency parent index is invalid"))?;
        let key = package_key(&name, version.as_deref());
        package
            .dependencies
            .entry(key)
            .and_modify(|dependency| dependency.required |= required)
            .or_insert(JavaScriptDependency {
                name,
                version,
                required,
            });
        Ok(())
    }

    fn warning(&mut self, warning: &str) {
        push_warning(&mut self.warnings, warning);
    }

    fn into_packages(
        mut self,
        manager: NodePackageManager,
    ) -> (Vec<JavaScriptPackage>, Vec<String>) {
        self.records.sort_by(|left, right| {
            package_key(&left.name, left.version.as_deref())
                .cmp(&package_key(&right.name, right.version.as_deref()))
        });
        let packages: Vec<JavaScriptPackage> = self
            .records
            .into_iter()
            .map(|record| JavaScriptPackage {
                manager,
                scope: NodePackageScope::Global,
                spec: PackageSpec {
                    provider: manager.provider_id(),
                    id: record.name,
                    version: record.version,
                    source_name: None,
                    source_identifier: None,
                    source: record.source,
                    architecture: None,
                    installer_hash: record.integrity,
                },
                dependencies: record.dependencies.into_values().collect(),
                top_level: record.top_level,
            })
            .collect();
        let mut warnings = self.warnings;
        if !packages.is_empty() {
            push_warning(&mut warnings, LIFECYCLE_RISK_WARNING);
        }
        if self.yarn_modern {
            push_warning(&mut warnings, YARN_SCOPE_WARNING);
        }
        (packages, normalized_warnings(warnings))
    }
}

fn dependency_entries(
    object: &serde_json::Map<String, Value>,
    manager: NodePackageManager,
) -> ProviderResult<Vec<(String, Value, bool)>> {
    let mut entries = BTreeMap::<String, (Value, bool)>::new();
    for (field, required) in [
        ("dependencies", true),
        ("peerDependencies", true),
        ("optionalDependencies", false),
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Value::Object(values) = value else {
            return Err(parse_error(
                manager,
                "package dependency field is not an object",
            ));
        };
        for (name, value) in values {
            entries.insert(name.clone(), (value.clone(), required));
        }
    }
    Ok(entries
        .into_iter()
        .map(|(name, (value, required))| (name, value, required))
        .collect())
}

fn package_source(object: &serde_json::Map<String, Value>) -> (Option<Url>, bool) {
    let raw = object.get("resolved").and_then(Value::as_str).or_else(|| {
        object
            .get("resolution")
            .and_then(Value::as_object)
            .and_then(|resolution| resolution.get("tarball"))
            .and_then(Value::as_str)
    });
    let Some(raw) = raw else {
        return (None, false);
    };
    let Ok(url) = Url::parse(raw) else {
        return (None, true);
    };
    let safe = matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !raw
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    if safe {
        (Some(url), false)
    } else {
        (None, true)
    }
}

fn package_integrity(object: &serde_json::Map<String, Value>) -> Option<String> {
    let raw = object
        .get("integrity")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("resolution")
                .and_then(Value::as_object)
                .and_then(|resolution| resolution.get("integrity"))
                .and_then(Value::as_str)
        })?;
    if raw.is_empty()
        || raw.len() > MAX_INTEGRITY_BYTES
        || raw
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return None;
    }
    Some(raw.to_owned())
}

fn parse_yarn_package_text(text: &str) -> Option<(String, Option<String>)> {
    let mut candidates = Vec::new();
    let mut start = None;
    for (index, character) in text.char_indices() {
        if character == '"' || character == '\'' {
            if let Some(begin) = start.take() {
                candidates.push(&text[begin..index]);
            } else {
                start = Some(index + character.len_utf8());
            }
        }
    }
    candidates.extend(text.split_whitespace());
    candidates.into_iter().find_map(|candidate| {
        let candidate = candidate.trim_matches(|character: char| {
            matches!(
                character,
                '"' | '\'' | ',' | ';' | '(' | ')' | '├' | '─' | '└' | '│'
            )
        });
        let (name, version) = split_package_token(candidate)?;
        validate_package_name(&name, NodePackageManager::Yarn).ok()?;
        if let Some(version) = &version {
            validate_package_version(version, NodePackageManager::Yarn).ok()?;
        }
        Some((name, version))
    })
}

fn split_package_token(token: &str) -> Option<(String, Option<String>)> {
    if token.is_empty() || token.contains(['/', '\\']) && !token.starts_with('@') {
        return None;
    }
    let separator = if token.starts_with('@') {
        token.rfind('@').filter(|index| *index > 0)
    } else {
        token.rfind('@')
    }?;
    let (name, version) = token.split_at(separator);
    let version = version.strip_prefix('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_owned(), Some(version.to_owned())))
}

fn validate_package_name(name: &str, manager: NodePackageManager) -> ProviderResult<()> {
    if name.is_empty()
        || name.len() > MAX_PACKAGE_NAME_BYTES
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || name.contains(['\\', ':'])
        || name == "."
        || name == ".."
    {
        return Err(parse_error(
            manager,
            "package name is outside the reviewed grammar",
        ));
    }
    if name.starts_with('@') {
        let mut parts = name.split('/');
        let scope = parts.next().unwrap_or_default();
        let package = parts.next().unwrap_or_default();
        if !scope.starts_with('@')
            || scope.len() == 1
            || package.is_empty()
            || parts.next().is_some()
        {
            return Err(parse_error(
                manager,
                "scoped package name is outside the reviewed grammar",
            ));
        }
    } else if name.contains('/') {
        return Err(parse_error(
            manager,
            "unscoped package name contains a path separator",
        ));
    }
    Ok(())
}

fn validate_package_version(version: &str, manager: NodePackageManager) -> ProviderResult<()> {
    if version.is_empty()
        || version.len() > MAX_VERSION_BYTES
        || version.trim() != version
        || version
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(parse_error(
            manager,
            "package version is outside the reviewed grammar",
        ));
    }
    Ok(())
}

fn is_exact_version(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return false;
    };
    !version.eq_ignore_ascii_case("latest")
        && !version.eq_ignore_ascii_case("next")
        && !version.contains(['^', '~', '*', '<', '>', '|', '=', ' '])
}

fn package_key(name: &str, version: Option<&str>) -> String {
    format!(
        "{}\u{0}{}",
        name.to_ascii_lowercase(),
        version.unwrap_or_default()
    )
}

fn package_identity(provider: &ProviderId, package_id: &str, source: &str) -> Identity {
    Identity {
        provider_package: Some((provider.clone(), package_id.to_owned())),
        provider_source: Some(source.to_owned()),
        package_family: None,
        product_name: None,
        executable_name: None,
        publisher: None,
        executable_hash: None,
        install_role: Some(source.to_owned()),
        identity_quality: IdentityQuality::Provider,
    }
}

fn package_component_id(
    provider: &ProviderId,
    package_id: &str,
    source: &str,
    manager: NodePackageManager,
) -> ProviderResult<ComponentId> {
    ComponentId::from_identity(&package_identity(provider, package_id, source), None)
        .map(|canonical| canonical.id)
        .map_err(|_| schema_error(manager, "JavaScript package identity is not canonical"))
}

impl JavaScriptAdapter {
    fn normalize_package(
        &self,
        package: JavaScriptPackage,
        evidence: Vec<Evidence>,
    ) -> ProviderResult<Vec<Component>> {
        if package.manager != self.manager
            || package.spec.provider != self.id
            || !matches!(package.scope, NodePackageScope::Global)
        {
            return Err(schema_error(
                self.manager,
                "JavaScript package observation belongs to another manager or scope",
            ));
        }
        validate_package_name(&package.spec.id, self.manager)?;
        if let Some(version) = &package.spec.version {
            validate_package_version(version, self.manager)?;
        }
        if evidence.is_empty() {
            return Err(schema_error(
                self.manager,
                "JavaScript package observation has no supporting evidence",
            ));
        }

        let identity = package_identity(&self.id, &package.spec.id, "global");
        let canonical = ComponentId::from_identity(&identity, None).map_err(|_| {
            schema_error(self.manager, "JavaScript package identity is not canonical")
        })?;
        let exact_restore = is_exact_version(package.spec.version.as_deref());
        let mut rationale = vec![LIFECYCLE_RISK_WARNING.to_owned()];
        if !exact_restore {
            rationale.push(
                "The global listing lacks a safe exact version; latest-version substitution is disabled"
                    .to_owned(),
            );
        }
        let dependencies = package
            .dependencies
            .iter()
            .map(|dependency| {
                Ok(DependencyEdge {
                    from: canonical.id.clone(),
                    to: package_component_id(&self.id, &dependency.name, "global", self.manager)?,
                    kind: if dependency.required {
                        DependencyKind::RequiredPackage
                    } else {
                        DependencyKind::OptionalFeature
                    },
                    required: dependency.required,
                    evidence: evidence_refs(&evidence)
                        .into_iter()
                        .map(|reference| reference.id)
                        .collect(),
                    confidence: confidence_from_evidence(&evidence),
                })
            })
            .collect::<ProviderResult<Vec<_>>>()?;
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "package_manager".to_owned(),
            Value::String(self.manager.as_str().to_owned()),
        );
        extensions.insert(
            "scope".to_owned(),
            Value::String(NodePackageScope::Global.as_str().to_owned()),
        );
        extensions.insert("top_level".to_owned(), Value::Bool(package.top_level));
        extensions.insert(
            "lifecycle_risk".to_owned(),
            serde_json::json!({
                "install_scripts_may_execute": true,
                "review_required": true,
            }),
        );

        Ok(vec![Component {
            id: canonical.id,
            kind: ComponentKind::Package,
            identity,
            display_name: package.spec.id.clone(),
            version: package.spec.version.as_ref().map(|raw| VersionValue {
                raw: raw.clone(),
                normalized: None,
            }),
            architecture: package.spec.architecture.clone(),
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some(package.spec.id.clone()),
                source_url: package.spec.source.clone(),
                observed_version: package.spec.version.clone(),
                adapter_id: format!("javascript-{}", self.manager.as_str()),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs(&evidence),
            confidence: confidence_from_evidence(&evidence),
            dependencies,
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
                portability: if package.spec.source.is_some() {
                    Portability::SupportedExport
                } else {
                    Portability::PartiallyPortable
                },
                requires_elevation: false,
                requires_user_action: true,
                rationale,
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: package.spec.architecture.clone(),
                requires_provider: Some(self.id.clone()),
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: vec![VerificationRule::ProviderIdentity {
                provider: self.id.clone(),
                package: package.spec,
            }],
            selection: SelectionMetadata {
                recommended: false,
                score: 0,
                selected_by_default: false,
                sensitive: false,
                size_bytes: 0,
            },
            extensions,
        }])
    }

    fn normalize_artifact(
        &self,
        artifact: ArtifactRef,
        evidence: Vec<Evidence>,
    ) -> ProviderResult<Vec<Component>> {
        if artifact.scope != ConfigScope::Project || evidence.is_empty() {
            return Err(schema_error(
                self.manager,
                "JavaScript project artifact has an invalid scope or no evidence",
            ));
        }
        artifact
            .source_path
            .validate()
            .map_err(|_| schema_error(self.manager, "JavaScript artifact path is invalid"))?;
        let package_id = format!("project-artifact:{}", artifact.id);
        let identity = package_identity(&self.id, &package_id, "project");
        let canonical = ComponentId::from_identity(&identity, None).map_err(|_| {
            schema_error(
                self.manager,
                "JavaScript artifact identity is not canonical",
            )
        })?;
        let display_name = artifact
            .source_path
            .relative
            .rsplit('/')
            .next()
            .unwrap_or("project artifact")
            .to_owned();
        let verification = VerificationRule::File {
            destination: artifact.source_path.clone(),
            object: artifact.object.clone(),
        };
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "package_manager".to_owned(),
            Value::String(self.manager.as_str().to_owned()),
        );
        extensions.insert("scope".to_owned(), Value::String("project".to_owned()));
        Ok(vec![Component {
            id: canonical.id,
            kind: ComponentKind::DataArtifact,
            identity,
            display_name,
            version: None,
            architecture: None,
            publisher: None,
            provenance: Some(Provenance {
                provider: Some(self.id.clone()),
                package_id: Some(package_id),
                source_url: None,
                observed_version: None,
                adapter_id: format!("javascript-{}", self.manager.as_str()),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs(&evidence),
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: vec![artifact.clone()],
            restore: RestoreDescriptor {
                primary: RestoreStrategy::DataPortable,
                alternatives: vec![RestoreStrategy::Manual],
                portability: Portability::PartiallyPortable,
                requires_elevation: false,
                requires_user_action: true,
                rationale: vec![
                    "Project package manifests and lockfiles are retained as data artifacts; package contents are not inferred from them"
                        .to_owned(),
                ],
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
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
                size_bytes: artifact.size_bytes,
            },
            extensions,
        }])
    }
}

fn package_from_component<'a>(
    component: &'a Component,
    provider: &ProviderId,
    manager: NodePackageManager,
) -> ProviderResult<&'a PackageSpec> {
    if component.kind != ComponentKind::Package
        || component.provenance.as_ref().is_none_or(|provenance| {
            provenance.adapter_id != format!("javascript-{}", manager.as_str())
        })
        || component.identity.install_role.as_deref() != Some("global")
    {
        return Err(schema_error(
            manager,
            "JavaScript component is not a global package owned by this adapter",
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
        .ok_or_else(|| schema_error(manager, "JavaScript component has no provider identity"))?;
    if packages.next().is_some() {
        return Err(schema_error(
            manager,
            "JavaScript component has multiple provider identities",
        ));
    }
    validate_package_name(&package.id, manager)?;
    if package.provider != *provider {
        return Err(schema_error(
            manager,
            "JavaScript package provider does not match the adapter",
        ));
    }
    Ok(package)
}

fn artifact_from_component<'a>(
    component: &'a Component,
    provider: &ProviderId,
    manager: NodePackageManager,
) -> ProviderResult<&'a ArtifactRef> {
    if component.kind != ComponentKind::DataArtifact
        || component.provenance.as_ref().is_none_or(|provenance| {
            provenance.adapter_id != format!("javascript-{}", manager.as_str())
        })
        || component.artifacts.len() != 1
    {
        return Err(schema_error(
            manager,
            "JavaScript component is not one project artifact owned by this adapter",
        ));
    }
    let artifact = &component.artifacts[0];
    if component
        .identity
        .provider_package
        .as_ref()
        .is_none_or(|(id, package)| {
            id != provider || package != &format!("project-artifact:{}", artifact.id)
        })
    {
        return Err(schema_error(
            manager,
            "JavaScript artifact identity is inconsistent",
        ));
    }
    Ok(artifact)
}

fn manual_operation(
    component: &Component,
    package: &PackageSpec,
    reason: &str,
    run_id: &RunId,
    ordinal: u64,
    manager: NodePackageManager,
) -> ProviderResult<Operation> {
    let verification = VerificationRule::ProviderIdentity {
        provider: package.provider.clone(),
        package: package.clone(),
    };
    let idempotency_key = operation_key("manual", package, manager);
    let operation_id = OperationId::for_run(run_id, ordinal)
        .map_err(|_| schema_error(manager, "JavaScript manual operation ID is invalid"))?;
    Ok(Operation {
        id: operation_id,
        component: component.id.clone(),
        kind: OperationKind::OpenManualAction {
            action: ManualAction {
                id: idempotency_key.clone(),
                component: Some(component.id.clone()),
                title: format!("Review {} global package restore", manager.as_str()),
                reason: reason.to_owned(),
                risk: RiskLevel::High,
                instructions: vec![
                    "Confirm the package source, exact version, and lifecycle-script risk"
                        .to_owned(),
                    "Restore the package in global scope through the recorded package manager"
                        .to_owned(),
                ],
                docs_url: Some(
                    Url::parse(manager.docs_url()).expect("constant package-manager URL"),
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

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn operation_key(role: &str, package: &PackageSpec, manager: NodePackageManager) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, manager.as_str());
    hash_field(&mut hasher, role);
    hash_field(&mut hasher, package.provider.as_str());
    hash_field(&mut hasher, &package.id);
    hash_field(&mut hasher, package.version.as_deref().unwrap_or_default());
    format!("javascript-{role}-{}", hasher.finalize().to_hex())
}

fn artifact_id(manager: NodePackageManager, path: &PathToken, object: &ObjectId) -> ArtifactId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(manager.as_str().as_bytes());
    hasher.update(path.relative.as_bytes());
    hasher.update(object.as_str().as_bytes());
    ArtifactId::new(format!(
        "javascript-artifact-{}",
        hasher.finalize().to_hex()
    ))
    .expect("hashed JavaScript artifact ID")
}

fn join_token_path(root: &str, child: &str) -> String {
    if root.is_empty() {
        child.to_owned()
    } else {
        format!("{root}/{child}")
    }
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
        .unwrap_or_else(|| "JavaScript provider evidence was redacted".to_owned());
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
        "javascript-evidence-{}",
        hasher.finalize().to_hex()
    ))
    .expect("hashed JavaScript evidence ID")
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
    RedactionPolicy::with_max_bytes(max_bytes).redact_text(value.trim())
}

fn push_warning(warnings: &mut Vec<String>, warning: &str) {
    if let Some(warning) = safe_text(warning, MAX_WARNING_BYTES) {
        warnings.push(warning);
    }
}

fn normalized_warnings(mut warnings: Vec<String>) -> Vec<String> {
    warnings.sort();
    warnings.dedup();
    warnings.truncate(MAX_WARNINGS);
    warnings
}

fn validate_process_result(
    result: &ProcessResult,
    operation: &str,
    manager: NodePackageManager,
) -> ProviderResult<()> {
    if result.cancelled {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::Cancelled,
            format!("{} {operation} was cancelled", manager.as_str()),
        )));
    }
    if result.timed_out {
        return Err(operation_error(
            manager,
            &format!("{} {operation} timed out", manager.as_str()),
        ));
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(operation_error(
            manager,
            &format!("{} {operation} exited with code {code}", manager.as_str()),
        )),
        None => Err(operation_error(
            manager,
            &format!(
                "{} {operation} ended without an exit code",
                manager.as_str()
            ),
        )),
    }
}

fn map_runner_error(error: Box<ErrorEnvelope>) -> Box<ErrorEnvelope> {
    if error.code == ReforgeErrorCode::PathNotFound {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ProviderUnavailable,
            "The JavaScript package manager is unavailable on this Windows target",
        ))
    } else {
        error
    }
}

fn schema_error(manager: NodePackageManager, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            format!("{} provider data is invalid", manager.as_str()),
        )
        .with_technical_detail(detail),
    )
}

fn parse_error(manager: NodePackageManager, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            format!(
                "{} global package listing did not match the reviewed structured shape",
                manager.as_str()
            ),
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "JavaScript provider output exceeded a reviewed safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(manager: NodePackageManager, detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            format!("{} package-manager operation failed", manager.as_str()),
        )
        .with_technical_detail(detail),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_package_token_keeps_scope() {
        assert_eq!(
            split_package_token("@acme/tool@1.2.3"),
            Some(("@acme/tool".to_owned(), Some("1.2.3".to_owned())))
        );
    }

    #[test]
    fn unsafe_source_is_not_retained() {
        let object = serde_json::json!({"resolved": "https://user:pass@example.invalid/pkg.tgz"});
        let object = object.as_object().expect("object");
        assert_eq!(package_source(object), (None, true));
    }
}
