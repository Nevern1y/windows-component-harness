//! Bounded discovery and correlation for Windows executables that have no
//! reviewed package-provider source.
//!
//! Generic discovery is intentionally conservative: it inspects only
//! tokenizable paths below known folders, never executes a candidate, and
//! never turns a name match into a download source. A candidate is useful
//! even when its source is unknown because its local identity, PE metadata,
//! and provenance remain available for explicit portable-binary review.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    ffi::OsString,
    fs,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use chrono::Utc;
use reforge_domain::{
    Compatibility, Component, ComponentId, ComponentKind, Confidence, ErrorEnvelope, Evidence,
    EvidenceId, EvidenceRef, EvidenceSource, Identity, IdentityQuality, KnownFolderToken,
    ManualAction, ManualActionState, Operation, OperationId, OperationKind, PathToken, Portability,
    Precondition, Provenance, Publisher, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy,
    RiskLevel, RunId, SelectionMetadata, TargetFacts, VerificationRule, VersionValue,
};
use reforge_platform_windows::{
    KnownFolderMap, PeMetadata, RegistryQuery, RegistryRoot, RegistryScope, RegistryView,
    SignerStatus, enumerate_registry_with, enumerate_shell_links, inspect_pe,
};
use tokio::task;

use crate::providers::{
    DetectionResult, Observation, ProviderAdapter, ProviderContext, ProviderEnumeration,
    ProviderResult,
};

const PROVIDER_ID: &str = "generic-executables";
const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_PATH_SEGMENTS: usize = 512;
const MAX_ROOTS: usize = 64;
const MAX_ROOT_ENTRIES: usize = 20_000;
const MAX_ROOT_DEPTH: usize = 3;
const MAX_CANDIDATES: usize = 50_000;
const MAX_WARNINGS: usize = 4_096;
const MAX_WARNING_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 512;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Evidence that a candidate was reachable through one bounded local path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathEvidence {
    pub source: EvidenceSource,
    pub locator: String,
    pub summary: String,
    pub strength: u8,
    pub independent_group: String,
}

impl PathEvidence {
    fn into_evidence(self) -> Evidence {
        let id = evidence_id(&self.source, &self.locator, &self.summary);
        Evidence {
            id,
            source: self.source,
            locator: self.locator,
            observed_at: Utc::now(),
            summary: self.summary,
            strength: self.strength,
            independent_group: self.independent_group,
        }
    }
}

/// The local identity and PE facts for one executable candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalIdentity {
    pub identity: Identity,
    pub version: Option<VersionValue>,
    pub publisher: Option<Publisher>,
    pub signature: SignerStatus,
}

/// A tokenized executable candidate before it becomes a domain observation.
///
/// Absolute paths are deliberately not part of this public type. They remain
/// private to the enumeration pass and are discarded after PE inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableCandidate {
    pub path: PathToken,
    pub local_identity: LocalIdentity,
    pub evidence: Vec<PathEvidence>,
}

/// Result of attempting to correlate a local executable with a reinstall
/// source. Generic discovery has no package identity, so it is always local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCorrelationDecision {
    SourceUnproven,
}

/// Merge equivalent local candidates without inventing a source package.
///
/// Candidates with the same executable hash represent the same observed
/// binary even when PATH and a shortcut exposed it through different routes.
/// Candidates without a hash are kept separate; generic discovery currently
/// only emits hashed PE candidates.
pub fn correlate_candidates(
    candidates: impl IntoIterator<Item = ExecutableCandidate>,
) -> Vec<ExecutableCandidate> {
    let mut grouped = BTreeMap::<String, ExecutableCandidate>::new();
    for candidate in candidates {
        let key = candidate
            .local_identity
            .identity
            .executable_hash
            .clone()
            .unwrap_or_else(|| token_locator(&candidate.path));
        if let Some(existing) = grouped.get_mut(&key) {
            let candidate_key = token_sort_key(&candidate.path);
            let existing_key = token_sort_key(&existing.path);
            if candidate_key < existing_key {
                let evidence = std::mem::take(&mut existing.evidence);
                let mut replacement = candidate;
                replacement.evidence.extend(evidence);
                *existing = replacement;
            } else {
                existing.evidence.extend(candidate.evidence);
            }
        } else {
            grouped.insert(key, candidate);
        }
    }

    let mut output: Vec<_> = grouped.into_values().collect();
    for candidate in &mut output {
        candidate.evidence.sort_by(|left, right| {
            left.locator
                .cmp(&right.locator)
                .then_with(|| left.summary.cmp(&right.summary))
                .then_with(|| format!("{:?}", left.source).cmp(&format!("{:?}", right.source)))
        });
        candidate.evidence.dedup_by(|left, right| {
            left.source == right.source
                && left.locator == right.locator
                && left.summary == right.summary
        });
    }
    output.sort_by_key(|left| token_sort_key(&left.path));
    output
}

/// Generic executable adapter for the `GenericExecutables` scan phase.
#[derive(Clone)]
pub struct GenericExecutableAdapter {
    id: reforge_domain::ProviderId,
}

impl GenericExecutableAdapter {
    pub fn new() -> Self {
        Self {
            id: reforge_domain::ProviderId::new(PROVIDER_ID)
                .expect("constant generic executable provider ID"),
        }
    }

    /// Return the source decision for a generic candidate.
    pub fn source_correlation(
        &self,
        _candidate: &ExecutableCandidate,
    ) -> SourceCorrelationDecision {
        SourceCorrelationDecision::SourceUnproven
    }
}

impl Default for GenericExecutableAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for GenericExecutableAdapter {
    fn id(&self) -> reforge_domain::ProviderId {
        self.id.clone()
    }

    fn detect(&self, context: &ProviderContext<'_>) -> DetectionResult {
        let path_available = env::var_os("PATH").is_some_and(|value| !value.is_empty());
        let known_folder_available = !context.known_folders.entries.is_empty();
        DetectionResult {
            available: path_available || known_folder_available,
            version: None,
            evidence: vec![Evidence {
                id: EvidenceId::new("generic-executables-bounded-roots")
                    .expect("constant generic executable evidence ID"),
                source: EvidenceSource::FileMetadata,
                locator: "bounded-path-roots".to_owned(),
                observed_at: Utc::now(),
                summary: "Generic executable discovery uses bounded PATH and known-folder roots"
                    .to_owned(),
                strength: 30,
                independent_group: "generic-root-policy".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    async fn enumerate(
        &self,
        context: &ProviderContext<'_>,
    ) -> ProviderResult<ProviderEnumeration> {
        let known_folders = context.known_folders.clone();
        let cancellation = context.cancellation.clone();
        task::spawn_blocking(move || enumerate_bounded(&known_folders, &cancellation))
            .await
            .map_err(|_| operation_error("generic executable worker failed"))?
    }

    fn normalize(&self, observation: Observation) -> ProviderResult<Vec<Component>> {
        let Observation::Executable {
            path,
            identity,
            version,
            evidence,
        } = observation
        else {
            return Err(schema_error(
                "generic executable adapter received a non-executable observation",
            ));
        };
        if evidence.is_empty() {
            return Err(schema_error(
                "generic executable observation has no supporting evidence",
            ));
        }
        if identity.executable_hash.is_none() {
            return Err(schema_error(
                "generic executable observation is missing its local hash",
            ));
        }

        let publisher = identity.publisher.clone().map(|name| Publisher {
            name,
            certificate_thumbprint: None,
        });
        let canonical = ComponentId::from_identity(&identity, publisher.as_ref())
            .map_err(|_| schema_error("generic executable identity is not canonical"))?;
        let display_name = identity
            .product_name
            .clone()
            .or_else(|| identity.executable_name.clone())
            .unwrap_or_else(|| "Unknown executable".to_owned());
        let evidence_refs = evidence_refs(&evidence);
        let destination = path.clone();
        let mut identity = identity;
        identity.identity_quality = canonical.quality.clone();
        let source_decision = SourceCorrelationDecision::SourceUnproven;
        let (primary, alternatives, rationale) = match source_decision {
            SourceCorrelationDecision::SourceUnproven => (
                RestoreStrategy::Manual,
                vec![RestoreStrategy::PortableBinary],
                vec![
                    "No trusted reinstall or package-provider source was established".to_owned(),
                    "Portable binary restore is available only after explicit user selection"
                        .to_owned(),
                ],
            ),
        };

        Ok(vec![Component {
            id: canonical.id,
            kind: ComponentKind::PortableBinary,
            identity,
            display_name,
            version: version.clone(),
            architecture: None,
            publisher: publisher.clone(),
            provenance: Some(Provenance {
                provider: None,
                package_id: None,
                source_url: None,
                observed_version: version.as_ref().map(|value| value.raw.clone()),
                adapter_id: PROVIDER_ID.to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            }),
            evidence: evidence_refs,
            confidence: confidence_from_evidence(&evidence),
            dependencies: Vec::new(),
            artifacts: Vec::new(),
            restore: RestoreDescriptor {
                primary,
                alternatives,
                portability: Portability::PartiallyPortable,
                requires_elevation: false,
                requires_user_action: true,
                rationale,
            },
            compatibility: Compatibility {
                required_os: Some("Windows".to_owned()),
                required_architecture: None,
                requires_provider: None,
                requires_runtime: None,
                requires_elevation: false,
                requires_wsl: false,
                requires_docker: false,
            },
            verification: vec![VerificationRule::FileVersion {
                destination,
                version,
                publisher: publisher.clone(),
            }],
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
        _target: &TargetFacts,
        run_id: &RunId,
        first_ordinal: u64,
    ) -> ProviderResult<Vec<Operation>> {
        if component.kind != ComponentKind::PortableBinary
            || component
                .provenance
                .as_ref()
                .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
        {
            return Err(schema_error(
                "generic executable plan received a foreign component",
            ));
        }
        let operation_id = OperationId::for_run(run_id, first_ordinal).map_err(|_| {
            schema_error("generic executable operation ID could not be constructed")
        })?;
        let idempotency_key = operation_key(component);
        let action = ManualAction {
            id: idempotency_key.clone(),
            component: Some(component.id.clone()),
            title: "Review portable executable".to_owned(),
            reason: "No trusted reinstall source was established; copying an executable requires explicit review"
                .to_owned(),
            risk: RiskLevel::Medium,
            instructions: vec![
                "Confirm the executable identity, publisher, and source before selecting portable restore"
                    .to_owned(),
                "Review runtime dependencies and target compatibility manually".to_owned(),
                "Do not execute command text from package or discovery metadata".to_owned(),
            ],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: None,
        };
        Ok(vec![Operation {
            id: operation_id,
            component: component.id.clone(),
            kind: OperationKind::OpenManualAction { action },
            prerequisites: Vec::new(),
            precondition: Precondition::ComponentAbsent {
                component: component.id.clone(),
            },
            idempotency_key,
            verification: component.verification.clone(),
            requires_elevation: false,
            non_idempotent: false,
        }])
    }

    fn verify(
        &self,
        component: &Component,
        _target: &TargetFacts,
    ) -> ProviderResult<Vec<VerificationRule>> {
        if component.kind != ComponentKind::PortableBinary
            || component
                .provenance
                .as_ref()
                .is_none_or(|provenance| provenance.adapter_id != PROVIDER_ID)
        {
            return Err(schema_error(
                "generic executable verification received a foreign component",
            ));
        }
        Ok(component.verification.clone())
    }
}

#[derive(Clone, Debug)]
struct RootInput {
    path: PathBuf,
    token: Option<PathToken>,
    path_source: bool,
}

#[derive(Clone, Debug)]
struct RawCandidate {
    path: PathBuf,
    token: PathToken,
    evidence: Vec<PathEvidence>,
}

fn enumerate_bounded(
    known_folders: &KnownFolderMap,
    cancellation: &reforge_platform_windows::CancellationToken,
) -> ProviderResult<ProviderEnumeration> {
    let mut warnings = Vec::new();
    let app_paths = registered_app_path_names(&mut warnings);
    let roots = bounded_roots(known_folders, &mut warnings);
    let mut candidates = BTreeMap::<String, RawCandidate>::new();

    for root in roots {
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }
        if let Some(token) = root.token.as_ref() {
            let entries = if root.path_source {
                direct_executables(&root.path, token, &mut warnings)
            } else {
                shallow_executables(&root.path, token, &mut warnings)
            };
            for (path, token, mut evidence) in entries {
                let token = token_for_absolute_path(known_folders, &path).unwrap_or(token);
                if app_paths.contains(&file_name_key(&path)) {
                    evidence.push(path_evidence(
                        EvidenceSource::AppPaths,
                        format!("app-paths:{}", file_name_key(&path)),
                        "Executable name also appears in a Windows App Paths registration",
                        70,
                        "registry-app-paths",
                    ));
                }
                insert_raw_candidate(&mut candidates, path, token, evidence, &mut warnings);
                if candidates.len() >= MAX_CANDIDATES {
                    warnings.push("generic executable candidate bound reached".to_owned());
                    break;
                }
            }
        }
        if candidates.len() >= MAX_CANDIDATES {
            break;
        }
    }

    append_shortcut_candidates(known_folders, &mut candidates, &mut warnings);
    let mut inspected = Vec::new();
    for raw in candidates.into_values() {
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }
        match inspect_raw_candidate(raw) {
            Ok(candidate) => inspected.push(candidate),
            Err(error) => push_warning(&mut warnings, error_summary(&error)),
        }
    }

    let observations = correlate_candidates(inspected)
        .into_iter()
        .map(|candidate| Observation::Executable {
            path: candidate.path,
            identity: candidate.local_identity.identity,
            version: candidate.local_identity.version,
            evidence: candidate
                .evidence
                .into_iter()
                .map(PathEvidence::into_evidence)
                .collect(),
        })
        .collect();
    warnings.sort();
    warnings.dedup();
    warnings.truncate(MAX_WARNINGS);
    Ok(ProviderEnumeration {
        observations,
        warnings,
    })
}

fn bounded_roots(known_folders: &KnownFolderMap, warnings: &mut Vec<String>) -> Vec<RootInput> {
    let mut roots = BTreeMap::<String, RootInput>::new();
    for (token, path) in &known_folders.entries {
        if !generic_root(token) {
            continue;
        }
        insert_root(
            &mut roots,
            path.clone(),
            PathToken::new(token.clone(), "").ok(),
            false,
            warnings,
        );
    }

    match env::var_os("PATH") {
        Some(value) => {
            let segments: Vec<OsString> = value
                .to_string_lossy()
                .split(';')
                .map(OsString::from)
                .collect();
            if segments.len() > MAX_PATH_SEGMENTS {
                warnings.push("PATH contains more than the reviewed segment bound".to_owned());
            }
            for (index, segment) in segments.into_iter().take(MAX_PATH_SEGMENTS).enumerate() {
                let segment = segment.to_string_lossy().trim().to_owned();
                if segment.is_empty() {
                    continue;
                }
                let path = PathBuf::from(&segment);
                if !path.is_absolute() {
                    warnings.push(format!(
                        "PATH segment {index} is not absolute and was skipped"
                    ));
                    continue;
                }
                let token = token_for_absolute_path(known_folders, &path);
                if token.is_none() {
                    warnings.push(format!(
                        "PATH segment {index} is outside the available known-folder token roots"
                    ));
                    continue;
                }
                insert_root(&mut roots, path, token, true, warnings);
            }
        }
        None => {
            warnings.push("PATH was unavailable during generic executable discovery".to_owned())
        }
    }

    let mut output: Vec<_> = roots.into_values().collect();
    output.sort_by_key(|left| path_key(&left.path));
    output.truncate(MAX_ROOTS);
    output
}

fn insert_root(
    roots: &mut BTreeMap<String, RootInput>,
    path: PathBuf,
    token: Option<PathToken>,
    path_source: bool,
    warnings: &mut Vec<String>,
) {
    if !path.is_absolute() {
        warnings.push("generic executable root was not absolute and was skipped".to_owned());
        return;
    }
    let key = path_key(&path);
    if let Some(existing) = roots.get_mut(&key) {
        existing.path_source &= path_source;
        return;
    }
    if roots.len() >= MAX_ROOTS {
        return;
    }
    roots.insert(
        key,
        RootInput {
            path,
            token,
            path_source,
        },
    );
}

fn direct_executables(
    root: &Path,
    token: &PathToken,
    warnings: &mut Vec<String>,
) -> Vec<(PathBuf, PathToken, Vec<PathEvidence>)> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_warning(
                warnings,
                format!("PATH root could not be inspected: {error}"),
            );
            return Vec::new();
        }
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        push_warning(
            warnings,
            "PATH root was not a regular directory and was skipped".to_owned(),
        );
        return Vec::new();
    }

    let mut children = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            push_warning(
                warnings,
                format!("PATH root could not be enumerated: {error}"),
            );
            return Vec::new();
        }
    };
    for entry in entries {
        match entry {
            Ok(entry) => children.push(entry.path()),
            Err(error) => push_warning(warnings, format!("PATH entry could not be read: {error}")),
        }
    }
    children.sort_by_key(|path| path_key(path));
    children
        .into_iter()
        .filter_map(|path| executable_path(path, root, token, "PATH", warnings))
        .collect()
}

fn shallow_executables(
    root: &Path,
    token: &PathToken,
    warnings: &mut Vec<String>,
) -> Vec<(PathBuf, PathToken, Vec<PathEvidence>)> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_warning(
                warnings,
                format!("known-folder root could not be inspected: {error}"),
            );
            return Vec::new();
        }
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        push_warning(
            warnings,
            "known-folder root was not a regular directory and was skipped".to_owned(),
        );
        return Vec::new();
    }

    let mut pending = VecDeque::from([(root.to_path_buf(), String::new(), 0usize)]);
    let mut entries_seen = 0usize;
    let mut output = Vec::new();
    while let Some((directory, parent, depth)) = pending.pop_front() {
        if entries_seen >= MAX_ROOT_ENTRIES {
            push_warning(warnings, "known-folder entry bound reached".to_owned());
            break;
        }
        let mut children = Vec::new();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                push_warning(
                    warnings,
                    format!("known-folder directory could not be enumerated: {error}"),
                );
                continue;
            }
        };
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        push_warning(
                            warnings,
                            "known-folder entry name was not valid Unicode".to_owned(),
                        );
                        continue;
                    };
                    children.push((name, entry.path()));
                }
                Err(error) => push_warning(
                    warnings,
                    format!("known-folder entry could not be read: {error}"),
                ),
            }
        }
        children.sort_by(|left, right| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
                .then_with(|| left.0.cmp(&right.0))
        });
        for (name, path) in children {
            if entries_seen >= MAX_ROOT_ENTRIES {
                push_warning(warnings, "known-folder entry bound reached".to_owned());
                break;
            }
            entries_seen += 1;
            let relative = if parent.is_empty() {
                name.clone()
            } else {
                format!("{parent}/{name}")
            };
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    push_warning(
                        warnings,
                        format!("known-folder entry could not be inspected: {error}"),
                    );
                    continue;
                }
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                continue;
            }
            if metadata.is_file() && is_executable_name(&name) {
                let Some(path_token) = PathToken::new(token.root.clone(), &relative).ok() else {
                    push_warning(
                        warnings,
                        "executable path could not be represented as a path token".to_owned(),
                    );
                    continue;
                };
                output.push((
                    path,
                    path_token,
                    vec![path_evidence(
                        if matches!(&token.root, KnownFolderToken::UserSelected { .. }) {
                            EvidenceSource::UserSelected
                        } else {
                            EvidenceSource::FileMetadata
                        },
                        format!("known-folder:{}", known_folder_label(&token.root)),
                        "Executable discovered in a bounded known-folder scan",
                        45,
                        "bounded-root",
                    )],
                ));
            } else if metadata.is_dir() && depth < MAX_ROOT_DEPTH {
                pending.push_back((path, relative, depth + 1));
            }
        }
    }
    output
}

fn executable_path(
    path: PathBuf,
    root: &Path,
    token: &PathToken,
    source_label: &str,
    warnings: &mut Vec<String>,
) -> Option<(PathBuf, PathToken, Vec<PathEvidence>)> {
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            push_warning(
                warnings,
                format!("candidate entry could not be inspected: {error}"),
            );
            return None;
        }
    };
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || !is_executable_name(path.to_string_lossy().as_ref())
    {
        return None;
    }
    let file_relative = path
        .strip_prefix(root)
        .ok()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .replace('\\', "/");
    let relative = if token.relative.is_empty() {
        file_relative
    } else if file_relative.is_empty() {
        token.relative.clone()
    } else {
        format!("{}/{}", token.relative.trim_end_matches('/'), file_relative)
    };
    let path_token = PathToken::new(token.root.clone(), relative).ok()?;
    Some((
        path,
        path_token,
        vec![path_evidence(
            EvidenceSource::FileMetadata,
            format!("{source_label}:{}", known_folder_label(&token.root)),
            "Executable name resolved from a bounded PATH root",
            60,
            "path-resolution",
        )],
    ))
}

fn append_shortcut_candidates(
    known_folders: &KnownFolderMap,
    candidates: &mut BTreeMap<String, RawCandidate>,
    warnings: &mut Vec<String>,
) {
    let snapshot = enumerate_shell_links(known_folders);
    for error in snapshot.errors {
        push_warning(
            warnings,
            format!("shortcut {:?} observation failed", error.operation),
        );
    }
    for shortcut in snapshot.observations {
        let Some(target) = shortcut.target else {
            continue;
        };
        let path = match known_folders.resolve(&target) {
            Ok(path) => path,
            Err(error) => {
                push_warning(warnings, error_summary(&error));
                continue;
            }
        };
        if !is_executable_name(path.to_string_lossy().as_ref()) {
            continue;
        }
        let token = token_for_absolute_path(known_folders, &path).unwrap_or(target);
        insert_raw_candidate(
            candidates,
            path,
            token,
            vec![path_evidence(
                EvidenceSource::Shortcut,
                format!("shortcut:{}", token_locator(&shortcut.source)),
                "Executable target was observed through a Windows shortcut",
                70,
                "shortcut-registration",
            )],
            warnings,
        );
    }
}

fn registered_app_path_names(warnings: &mut Vec<String>) -> BTreeSet<String> {
    let snapshot = enumerate_registry_with(&RegistryQuery {
        scopes: vec![RegistryScope::CurrentUser, RegistryScope::LocalMachine],
        views: vec![RegistryView::View32, RegistryView::View64],
        roots: vec![RegistryRoot::AppPaths],
    });
    for error in snapshot.errors {
        push_warning(
            warnings,
            format!("App Paths observation failed: {}", error.error.message),
        );
    }
    snapshot
        .observations
        .into_iter()
        .filter_map(|observation| {
            let name = observation.key_path.rsplit(['\\', '/']).next()?.trim();
            is_executable_name(name).then(|| name.to_ascii_lowercase())
        })
        .collect()
}

fn insert_raw_candidate(
    candidates: &mut BTreeMap<String, RawCandidate>,
    path: PathBuf,
    token: PathToken,
    evidence: Vec<PathEvidence>,
    warnings: &mut Vec<String>,
) {
    if candidates.len() >= MAX_CANDIDATES {
        return;
    }
    if !path.is_absolute() {
        push_warning(
            warnings,
            "generic candidate path was not absolute".to_owned(),
        );
        return;
    }
    let key = canonical_path_key(&path);
    if let Some(existing) = candidates.get_mut(&key) {
        existing.evidence.extend(evidence);
        return;
    }
    candidates.insert(
        key,
        RawCandidate {
            path,
            token,
            evidence,
        },
    );
}

fn inspect_raw_candidate(raw: RawCandidate) -> ProviderResult<ExecutableCandidate> {
    let metadata = fs::symlink_metadata(&raw.path)
        .map_err(|error| io_error("inspect generic executable", &error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(security_error(
            "generic executable candidate is a reparse point",
        ));
    }
    if !metadata.is_file() {
        return Err(operation_error(
            "generic executable candidate is not a file",
        ));
    }
    let pe = inspect_pe(&raw.path)?;
    let local_identity = local_identity(&raw.token, &pe)?;
    let mut evidence = raw.evidence;
    evidence.push(path_evidence(
        EvidenceSource::FileMetadata,
        format!("file:{}", token_locator(&raw.token)),
        &pe_summary(&pe),
        75,
        "pe-metadata",
    ));
    evidence.push(path_evidence(
        EvidenceSource::Authenticode,
        format!("authenticode:{}", token_locator(&raw.token)),
        &signature_summary(&pe),
        signature_strength(pe.signature.status),
        "authenticode",
    ));
    Ok(ExecutableCandidate {
        path: raw.token,
        local_identity,
        evidence,
    })
}

fn local_identity(token: &PathToken, pe: &PeMetadata) -> ProviderResult<LocalIdentity> {
    let executable_name = token
        .relative
        .rsplit('/')
        .next()
        .and_then(|value| safe_text(value, MAX_TEXT_BYTES))
        .ok_or_else(|| schema_error("generic executable path has no safe basename"))?;
    let product_name = pe
        .product_name
        .as_deref()
        .and_then(|value| safe_text(value, MAX_TEXT_BYTES));
    let publisher_name = pe
        .publisher
        .as_deref()
        .and_then(|value| safe_text(value, MAX_TEXT_BYTES));
    let publisher = match publisher_name.clone() {
        Some(name) => Some(Publisher {
            name,
            certificate_thumbprint: pe.signature.certificate_fingerprint.clone(),
        }),
        None => pe
            .signature
            .certificate_fingerprint
            .clone()
            .map(|thumbprint| Publisher {
                name: "Authenticode signer".to_owned(),
                certificate_thumbprint: Some(thumbprint),
            }),
    };
    let identity = Identity {
        provider_package: None,
        provider_source: None,
        package_family: None,
        product_name,
        executable_name: Some(executable_name),
        publisher: publisher.as_ref().map(|value| value.name.clone()),
        executable_hash: Some(pe.executable_hash.clone()),
        install_role: Some("generic-executable".to_owned()),
        identity_quality: IdentityQuality::Local,
    };
    let version = pe
        .product_version
        .as_ref()
        .or(pe.file_version.as_ref())
        .map(|value| VersionValue {
            raw: value.as_string(),
            normalized: None,
        });
    Ok(LocalIdentity {
        identity,
        version,
        publisher,
        signature: pe.signature.status,
    })
}

fn is_executable_name(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
}

fn token_for_absolute_path(known_folders: &KnownFolderMap, path: &Path) -> Option<PathToken> {
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    known_folders
        .entries
        .iter()
        .filter_map(|(token, root)| {
            let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            let relative = relative_path_case_insensitive(&canonical_root, &candidate)?;
            let token = PathToken::new(token.clone(), relative).ok()?;
            Some((path_key(&canonical_root).len(), token))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, token)| token)
}

fn relative_path_case_insensitive(root: &Path, candidate: &Path) -> Option<String> {
    let root_text = path_text(root)?;
    let candidate_text = path_text(candidate)?;
    let root_trimmed = root_text.trim_end_matches('/');
    let candidate_trimmed = candidate_text.trim_end_matches('/');
    let root_key = root_trimmed.to_ascii_lowercase();
    let candidate_key = candidate_trimmed.to_ascii_lowercase();
    if candidate_key == root_key {
        return Some(String::new());
    }
    let prefix = format!("{root_key}/");
    if !candidate_key.starts_with(&prefix) {
        return None;
    }
    Some(candidate_trimmed[root_trimmed.len() + 1..].to_owned())
}

fn path_text(path: &Path) -> Option<String> {
    let value = path.to_str()?.replace('\\', "/");
    (!value.is_empty()).then_some(value)
}

fn path_key(path: &Path) -> String {
    path_text(path)
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn canonical_path_key(path: &Path) -> String {
    path_key(&fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
}

fn token_sort_key(token: &PathToken) -> (KnownFolderToken, String) {
    (token.root.clone(), token.relative.clone())
}

fn token_locator(token: &PathToken) -> String {
    format!("{}:{}", known_folder_label(&token.root), token.relative)
}

fn known_folder_label(token: &KnownFolderToken) -> String {
    match token {
        KnownFolderToken::UserProfile => "user-profile".to_owned(),
        KnownFolderToken::RoamingAppData => "roaming-app-data".to_owned(),
        KnownFolderToken::LocalAppData => "local-app-data".to_owned(),
        KnownFolderToken::ProgramData => "program-data".to_owned(),
        KnownFolderToken::ProgramFiles => "program-files".to_owned(),
        KnownFolderToken::ProgramFilesX86 => "program-files-x86".to_owned(),
        KnownFolderToken::StartMenu => "start-menu".to_owned(),
        KnownFolderToken::Startup => "startup".to_owned(),
        KnownFolderToken::Desktop => "desktop".to_owned(),
        KnownFolderToken::Documents => "documents".to_owned(),
        KnownFolderToken::UserSelected { id } => format!("user-selected-{id}"),
    }
}

fn generic_root(token: &KnownFolderToken) -> bool {
    matches!(
        token,
        KnownFolderToken::UserProfile
            | KnownFolderToken::RoamingAppData
            | KnownFolderToken::LocalAppData
            | KnownFolderToken::ProgramData
            | KnownFolderToken::ProgramFiles
            | KnownFolderToken::ProgramFilesX86
            | KnownFolderToken::UserSelected { .. }
    )
}

fn path_evidence(
    source: EvidenceSource,
    locator: String,
    summary: &str,
    strength: u8,
    independent_group: &str,
) -> PathEvidence {
    PathEvidence {
        source,
        locator,
        summary: safe_text(summary, MAX_TEXT_BYTES)
            .unwrap_or_else(|| "Generic executable evidence was redacted".to_owned()),
        strength,
        independent_group: independent_group.to_owned(),
    }
}

fn pe_summary(pe: &PeMetadata) -> String {
    let product = pe
        .product_name
        .as_deref()
        .and_then(|value| safe_text(value, MAX_TEXT_BYTES))
        .unwrap_or_else(|| "Unknown product".to_owned());
    let publisher = pe
        .publisher
        .as_deref()
        .and_then(|value| safe_text(value, MAX_TEXT_BYTES))
        .unwrap_or_else(|| "Unknown publisher".to_owned());
    let version = pe
        .product_version
        .as_ref()
        .or(pe.file_version.as_ref())
        .map(|value| value.as_string())
        .unwrap_or_else(|| "Unavailable version".to_owned());
    format!("PE metadata product={product}; publisher={publisher}; version={version}")
}

fn signature_summary(pe: &PeMetadata) -> String {
    format!(
        "Authenticode status={}",
        match pe.signature.status {
            SignerStatus::Trusted => "Trusted",
            SignerStatus::Unsigned => "Unsigned",
            SignerStatus::Untrusted => "Untrusted",
        }
    )
}

fn signature_strength(status: SignerStatus) -> u8 {
    match status {
        SignerStatus::Trusted => 85,
        SignerStatus::Unsigned => 25,
        SignerStatus::Untrusted => 20,
    }
}

fn evidence_id(source: &EvidenceSource, locator: &str, summary: &str) -> EvidenceId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("{source:?}").as_bytes());
    hasher.update(&(locator.len() as u64).to_le_bytes());
    hasher.update(locator.as_bytes());
    hasher.update(&(summary.len() as u64).to_le_bytes());
    hasher.update(summary.as_bytes());
    EvidenceId::new(format!(
        "generic-executable-evidence-{}",
        hasher.finalize().to_hex()
    ))
    .expect("hashed generic executable evidence ID")
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
    if score >= 90 {
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

fn operation_key(component: &Component) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(component.id.as_str().as_bytes());
    format!("generic-executable-manual-{}", hasher.finalize().to_hex())
}

fn safe_text(value: &str, max_bytes: usize) -> Option<String> {
    reforge_domain::RedactionPolicy::with_max_bytes(max_bytes)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
}

fn file_name_key(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if let Some(warning) = safe_text(&warning, MAX_WARNING_BYTES) {
        warnings.push(warning);
    }
}

fn error_summary(error: &ErrorEnvelope) -> String {
    let mut summary = error.message.clone();
    if let Some(detail) = &error.technical_detail {
        summary.push_str(": ");
        summary.push_str(detail);
    }
    summary
}

fn schema_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Generic executable observation is invalid",
        )
        .with_technical_detail(detail),
    )
}

fn operation_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::OperationFailed,
            "Generic executable discovery failed",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Generic executable discovery exceeded a safety bound",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &std::io::Error) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::from_io_error(error, operation.to_owned()))
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::Cancelled,
        "Generic executable discovery was cancelled",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::{
        EvidenceSource, Identity, IdentityQuality, KnownFolderToken, PathToken, RestoreStrategy,
    };

    fn candidate(
        root: KnownFolderToken,
        relative: &str,
        hash: &str,
        publisher: &str,
    ) -> ExecutableCandidate {
        ExecutableCandidate {
            path: PathToken::new(root, relative).expect("candidate path"),
            local_identity: LocalIdentity {
                identity: Identity {
                    provider_package: None,
                    provider_source: None,
                    package_family: None,
                    product_name: Some("Tool".to_owned()),
                    executable_name: Some("foo.exe".to_owned()),
                    publisher: Some(publisher.to_owned()),
                    executable_hash: Some(hash.to_owned()),
                    install_role: Some("generic-executable".to_owned()),
                    identity_quality: IdentityQuality::Local,
                },
                version: None,
                publisher: Some(Publisher {
                    name: publisher.to_owned(),
                    certificate_thumbprint: None,
                }),
                signature: SignerStatus::Unsigned,
            },
            evidence: vec![path_evidence(
                EvidenceSource::FileMetadata,
                format!("test:{relative}"),
                "fixture executable",
                50,
                "fixture",
            )],
        }
    }

    #[test]
    fn same_binary_from_path_and_shortcut_merges_evidence() {
        let mut left = candidate(KnownFolderToken::UserProfile, "bin/foo.exe", "same", "Acme");
        let right = candidate(
            KnownFolderToken::Desktop,
            "shortcut-target/foo.exe",
            "same",
            "Acme",
        );
        left.evidence.push(path_evidence(
            EvidenceSource::Shortcut,
            "shortcut:desktop:foo.lnk".to_owned(),
            "Executable target was observed through a Windows shortcut",
            70,
            "shortcut-registration",
        ));
        let merged = correlate_candidates([left, right]);
        assert_eq!(merged.len(), 1);
        assert!(
            merged[0]
                .evidence
                .iter()
                .any(|evidence| evidence.source == EvidenceSource::Shortcut)
        );
    }

    #[test]
    fn same_name_with_different_publishers_stays_separate() {
        let first = candidate(
            KnownFolderToken::UserProfile,
            "one/foo.exe",
            "hash-a",
            "Acme",
        );
        let second = candidate(
            KnownFolderToken::ProgramFiles,
            "two/foo.exe",
            "hash-b",
            "Other",
        );
        let result = correlate_candidates([first, second]);
        assert_eq!(result.len(), 2);
        assert_ne!(
            result[0].local_identity.identity.publisher,
            result[1].local_identity.identity.publisher
        );
    }

    #[test]
    fn unproven_source_is_manual_with_explicit_portable_alternative() {
        let adapter = GenericExecutableAdapter::new();
        let candidate = candidate(KnownFolderToken::UserProfile, "bin/foo.exe", "hash", "Acme");
        let observation = Observation::Executable {
            path: candidate.path,
            identity: candidate.local_identity.identity,
            version: candidate.local_identity.version,
            evidence: candidate
                .evidence
                .into_iter()
                .map(PathEvidence::into_evidence)
                .collect(),
        };
        let component = adapter
            .normalize(observation)
            .expect("generic normalization")
            .remove(0);
        assert_eq!(component.kind, ComponentKind::PortableBinary);
        assert_eq!(component.restore.primary, RestoreStrategy::Manual);
        assert_eq!(
            component.restore.alternatives,
            vec![RestoreStrategy::PortableBinary]
        );
        assert!(component.provenance.as_ref().unwrap().source_url.is_none());
        assert!(matches!(
            component.verification[0],
            VerificationRule::FileVersion { .. }
        ));
    }

    #[test]
    fn generic_adapter_never_assigns_a_github_source() {
        let adapter = GenericExecutableAdapter::new();
        let candidate = candidate(KnownFolderToken::UserProfile, "bin/foo.exe", "hash", "Acme");
        assert_eq!(
            adapter.source_correlation(&candidate),
            SourceCorrelationDecision::SourceUnproven
        );
    }
}
