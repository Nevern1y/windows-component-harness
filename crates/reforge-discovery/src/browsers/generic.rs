//! Common browser discovery, profile portability, and safe component output.
//!
//! Browser adapters are observation-only. They inspect bounded, documented
//! profile roots, never copy cookies/logins/session state, and expose browser
//! shutdown/reauth requirements as manual actions.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    time::Duration,
};

use chrono::{DateTime, Utc};
use reforge_domain::{
    ArtifactPolicy, ArtifactRef, Compatibility, Component, ComponentId, ComponentKind, Confidence,
    ConfigScope, DependencyEdge, DependencyKind, ErrorEnvelope, Evidence, EvidenceId, EvidenceRef,
    EvidenceSource, Identity, IdentityQuality, KnownFolderToken, ManualAction, ManualActionState,
    PathToken, Portability, Publisher, ReforgeErrorCode, RestoreDescriptor, RestoreStrategy,
    RiskLevel, SelectionMetadata, VerificationRule, VersionValue,
};
use reforge_platform_windows::{
    BuiltinExecutable, CancellationToken, CommandSpec, KnownFolderMap, ProcessRunner,
    RegistryKeyObservation, RegistryRoot, RegistryScope, RegistryValueData, RegistryView,
    TrustedExecutable, enumerate_registry_with, enumerate_shell_links,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{chromium, firefox};

const ADAPTER_ID: &str = "browsers";
const BROWSER_DOCS_URL: &str = "https://support.google.com/chrome/answer/96816";
const MAX_ARTIFACTS: usize = 4_096;
const MAX_WARNINGS: usize = 4_096;
const MAX_PATH_ENTRIES: usize = 256;
const MAX_MANUAL_ACTIONS: usize = 4_096;

/// Browser family identified from independent registration/profile evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Chrome,
    Edge,
    Chromium,
    Firefox,
    Thorium,
    Unknown,
}

impl BrowserFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Chromium => "chromium",
            Self::Firefox => "firefox",
            Self::Thorium => "thorium",
            Self::Unknown => "unknown",
        }
    }
}
/// Activity confidence. Unknown recent use remains `Installed`, never guessed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserActivity {
    Installed,
    RecentlyActive,
    Running,
}

/// Independent source for a browser installation observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEvidenceSource {
    Registry,
    AppPath,
    Path,
    Shortcut,
    Profile,
    Unknown,
}
impl BrowserEvidenceSource {
    fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::AppPath => "app_path",
            Self::Path => "path",
            Self::Shortcut => "shortcut",
            Self::Profile => "profile",
            Self::Unknown => "unknown",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::AppPath => 5,
            Self::Registry => 4,
            Self::Path => 3,
            Self::Shortcut => 1,
            Self::Profile | Self::Unknown => 0,
        }
    }
}

/// One registration/path observation used to identify an installed browser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserRegistration {
    pub family: BrowserFamily,
    pub display_name: String,
    pub version: Option<String>,
    pub executable: Option<PathToken>,
    pub source: BrowserEvidenceSource,
}
#[derive(Clone, Debug)]
struct RegistrationGroup {
    family: BrowserFamily,
    display_name: String,
    version: Option<String>,
    version_source: Option<BrowserEvidenceSource>,
    executable: Option<PathToken>,
    executable_source: Option<BrowserEvidenceSource>,
    source: BrowserEvidenceSource,
    registrations: Vec<BrowserRegistration>,
}

/// Extension identity observed in a browser profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserExtension {
    pub id: String,
    pub version: Option<String>,
    pub name: Option<String>,
}

/// A bounded browser profile result with protected state explicitly excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserProfile {
    pub family: BrowserFamily,
    pub name: String,
    pub path: PathToken,
    pub activity: BrowserActivity,
    pub locked: bool,
    pub portability: Portability,
    pub artifacts: Vec<ArtifactRef>,
    pub extensions: Vec<BrowserExtension>,
    pub excluded_protected_state: Vec<String>,
}

/// An installed browser result assembled from independent evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserInstallation {
    pub family: BrowserFamily,
    pub display_name: String,
    pub version: Option<String>,
    pub executable: Option<PathToken>,
    pub source: BrowserEvidenceSource,
    pub activity: BrowserActivity,
    pub is_default: bool,
}

/// Deterministic inputs for browser discovery tests and callers with already
/// collected process/default-association observations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BrowserDiscoveryInputs {
    pub registrations: Vec<BrowserRegistration>,
    pub running_processes: BTreeSet<String>,
    pub default_browser: Option<BrowserFamily>,
    pub default_association_queried: bool,
}

/// Complete browser discovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserDiscovery {
    pub components: Vec<Component>,
    pub edges: Vec<DependencyEdge>,
    pub evidence: Vec<Evidence>,
    pub artifacts: Vec<ArtifactRef>,
    pub installations: Vec<BrowserInstallation>,
    pub profiles: Vec<BrowserProfile>,
    pub default_browser: Option<BrowserFamily>,
    pub default_association_queried: bool,
    pub manual_actions: Vec<ManualAction>,
    pub warnings: Vec<ErrorEnvelope>,
}

/// Browser adapter using registry, bounded profile-root, and optional process
/// evidence. No profile or browser process is ever killed.
#[derive(Clone, Debug, Default)]
pub struct BrowserAdapter;

impl BrowserAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Discover browsers using local registry/PATH/profile evidence. Default
    /// association and process queries require [`Self::discover_with_runner`].
    pub fn discover(
        &self,
        known_folders: &KnownFolderMap,
    ) -> Result<BrowserDiscovery, Box<ErrorEnvelope>> {
        let (registrations, mut warnings) = registry_registrations(known_folders);
        let mut inputs = BrowserDiscoveryInputs {
            registrations,
            ..BrowserDiscoveryInputs::default()
        };
        append_path_registrations(known_folders, &mut inputs.registrations);
        let mut discovery = self.discover_with_inputs(known_folders, inputs)?;
        discovery.warnings.append(&mut warnings);
        discovery.warnings.truncate(MAX_WARNINGS);
        Ok(discovery)
    }

    /// Discover browsers after read-only PowerShell queries for UserChoice and
    /// running browser process names. The script is fixed, argument-vector
    /// based, and never writes protected UserChoice registry state.
    pub async fn discover_with_runner(
        &self,
        known_folders: &KnownFolderMap,
        runner: &ProcessRunner,
        cancellation: &CancellationToken,
    ) -> Result<BrowserDiscovery, Box<ErrorEnvelope>> {
        let (registrations, mut warnings) = registry_registrations(known_folders);
        let mut inputs = BrowserDiscoveryInputs {
            registrations,
            default_association_queried: false,
            ..BrowserDiscoveryInputs::default()
        };
        append_path_registrations(known_folders, &mut inputs.registrations);

        if runner.builtin_available(BuiltinExecutable::PowerShell) {
            match run_powershell(
                runner,
                cancellation,
                "foreach($association in @('http','https','.html')) { $path = if($association.StartsWith('.')) { 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\' + $association + '\\UserChoice' } else { 'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\' + $association + '\\UserChoice' }; $value = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).ProgId; if($value){$value} }",
            )
            .await {
                Ok(output) if output.exit_code == Some(0) && !output.cancelled && !output.timed_out => {
                    inputs.default_browser = parse_default_browser(&output.stdout);
                    inputs.default_association_queried = true;
                }
                Ok(output) if output.cancelled => return Err(cancelled_error()),
                Ok(_) | Err(_) => warnings.push(ErrorEnvelope::new(
                    ReforgeErrorCode::ManualActionRequired,
                    "The default browser association could not be queried safely",
                )),
            }
            match run_powershell(
                runner,
                cancellation,
                "Get-Process -Name chrome,msedge,chromium,firefox,thorium -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName",
            )
            .await {
                Ok(output) if output.exit_code == Some(0) && !output.cancelled && !output.timed_out => {
                    inputs.running_processes = output
                        .stdout
                        .lines()
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase)
                        .collect();
                }
                Ok(output) if output.cancelled => return Err(cancelled_error()),
                Ok(_) | Err(_) => warnings.push(ErrorEnvelope::new(
                    ReforgeErrorCode::ManualActionRequired,
                    "Running browser processes could not be queried safely",
                )),
            }
        } else {
            warnings.push(ErrorEnvelope::new(
                ReforgeErrorCode::ProviderUnavailable,
                "PowerShell is unavailable; default browser/process evidence was not queried",
            ));
        }

        let mut discovery = self.discover_with_inputs(known_folders, inputs)?;
        discovery.warnings.extend(warnings);
        discovery.warnings.truncate(MAX_WARNINGS);
        Ok(discovery)
    }

    /// Assemble a discovery result from deterministic observations.
    pub fn discover_with_inputs(
        &self,
        known_folders: &KnownFolderMap,
        mut inputs: BrowserDiscoveryInputs,
    ) -> Result<BrowserDiscovery, Box<ErrorEnvelope>> {
        let mut state = DiscoveryState::new(Utc::now());
        let mut candidates = Vec::new();
        match chromium::discover_profiles(known_folders) {
            Ok(mut profiles) => candidates.append(&mut profiles),
            Err(error) => state.push_warning(*error),
        }
        match firefox::discover_profiles(known_folders) {
            Ok(mut profiles) => candidates.append(&mut profiles),
            Err(error) => state.push_warning(*error),
        }

        inputs.registrations.sort_by_key(registration_key);
        inputs
            .registrations
            .dedup_by(|left, right| registration_key(left) == registration_key(right));
        let mut registrations = inputs.registrations;
        let mut registered_families: BTreeSet<BrowserFamily> = registrations
            .iter()
            .map(|registration| registration.family)
            .collect();
        for candidate in &candidates {
            if registered_families.insert(candidate.family) {
                registrations.push(BrowserRegistration {
                    family: candidate.family,
                    display_name: candidate.family.label().to_owned(),
                    version: None,
                    executable: None,
                    source: BrowserEvidenceSource::Unknown,
                });
            }
        }
        registrations.sort_by_key(registration_key);
        let registrations = group_registrations(registrations);
        let mut artifact_requests = Vec::new();
        let mut locked_by_path = BTreeMap::new();
        for candidate in &candidates {
            let running = process_running(&inputs.running_processes, candidate.family);
            let locked = candidate
                .lock_paths
                .iter()
                .any(|path| path_present(known_folders, path))
                || running;
            locked_by_path.insert(token_string(&candidate.path), locked);
            if locked {
                continue;
            }
            for artifact in &candidate.artifacts {
                if entry_kind(known_folders, &artifact.path).ok().flatten() == Some(EntryKind::File)
                {
                    artifact_requests.push(crate::ArtifactRequest::new(
                        artifact.path.clone(),
                        ConfigScope::User,
                        artifact.policy.clone(),
                    ));
                }
            }
        }
        artifact_requests.truncate(MAX_ARTIFACTS);
        let collection =
            crate::ArtifactCollector::default().collect(known_folders, &artifact_requests)?;
        state.warnings.extend(collection.warnings);
        let artifact_by_path: BTreeMap<String, ArtifactRef> = collection
            .artifacts
            .iter()
            .cloned()
            .map(|artifact| (token_string(&artifact.source_path), artifact))
            .collect();

        let mut result = BrowserDiscovery {
            components: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            artifacts: sorted_artifacts(collection.artifacts),
            installations: Vec::new(),
            profiles: Vec::new(),
            default_browser: inputs
                .default_association_queried
                .then_some(inputs.default_browser)
                .flatten(),
            default_association_queried: inputs.default_association_queried,
            manual_actions: Vec::new(),
            warnings: Vec::new(),
        };

        if !result.default_association_queried {
            state.push_warning(ErrorEnvelope::new(
                ReforgeErrorCode::ManualActionRequired,
                "The default browser association was not queried; installed state is not recent-use evidence",
            ));
        }

        for group in registrations {
            let registration = group.registration();
            let is_default = result.default_browser == Some(registration.family);
            let running = process_running(&inputs.running_processes, registration.family);
            let activity = if running {
                BrowserActivity::Running
            } else {
                BrowserActivity::Installed
            };
            let mut evidence = group
                .registrations
                .iter()
                .map(|registration| state.registration_evidence(registration))
                .collect::<Vec<_>>();
            if running {
                evidence.push(state.process_evidence(registration.family));
            }
            if is_default {
                evidence.push(state.default_association_evidence(registration.family));
            }
            let source_is_unknown = source_requires_manual(registration.source);
            let component = build_installation_component(
                &registration,
                activity,
                is_default,
                &evidence,
                source_is_unknown,
            )?;
            let component_id = component.id.clone();
            result.components.push(component);
            result.installations.push(BrowserInstallation {
                family: registration.family,
                display_name: registration.display_name.clone(),
                version: registration.version.clone(),
                executable: registration.executable.clone(),
                source: registration.source,
                activity,
                is_default,
            });
            if source_is_unknown {
                add_review_action(
                    &mut result.manual_actions,
                    &component_id,
                    "unknown-source",
                    "Review browser source before restore",
                    "The browser was identified from local/profile evidence without a trusted reinstall source",
                );
            }
            if is_default {
                add_review_action(
                    &mut result.manual_actions,
                    &component_id,
                    "default-browser",
                    "Choose the default browser in Windows Settings",
                    "Protected UserChoice associations are never written automatically",
                );
            }
        }

        for candidate in candidates {
            let locked = locked_by_path
                .get(&token_string(&candidate.path))
                .copied()
                .unwrap_or(false);
            let profile_artifacts = candidate
                .artifacts
                .iter()
                .filter_map(|artifact| artifact_by_path.get(&token_string(&artifact.path)).cloned())
                .collect::<Vec<_>>();
            let activity = if process_running(&inputs.running_processes, candidate.family) {
                BrowserActivity::Running
            } else {
                BrowserActivity::Installed
            };
            let mut evidence = vec![state.evidence(
                Some(&candidate.path),
                "Browser profile discovered from a bounded documented profile root",
            )];
            if activity == BrowserActivity::Running {
                evidence.push(state.process_evidence(candidate.family));
            }
            let profile_component = build_profile_component(
                &candidate,
                &profile_artifacts,
                locked,
                activity,
                &evidence,
            )?;
            let profile_component_id = profile_component.id.clone();
            result.components.push(profile_component);
            result.profiles.push(BrowserProfile {
                family: candidate.family,
                name: candidate.name.clone(),
                path: candidate.path.clone(),
                activity,
                locked,
                portability: Portability::PartiallyPortable,
                artifacts: profile_artifacts,
                extensions: candidate.extensions.clone(),
                excluded_protected_state: candidate.excluded_protected_state.clone(),
            });
            let installation_component_id = installation_id(&candidate.family, &result.components);
            let profile_dependency_evidence = state.evidence(
                Some(&candidate.path),
                "Browser profile belongs to an installed browser family",
            );
            add_dependency(
                &mut result,
                profile_component_id.clone(),
                installation_component_id,
                DependencyKind::Contains,
                &profile_dependency_evidence,
            );
            if locked {
                add_review_action(
                    &mut result.manual_actions,
                    &profile_component_id,
                    "close-browser",
                    "Close the browser before capturing this profile",
                    "A browser process or profile lock prevents a safe portable capture; Reforge never kills it",
                );
            }
            let protected_component_id = profile_component_id.clone();
            add_review_action(
                &mut result.manual_actions,
                &protected_component_id,
                "browser-reauth",
                "Sign in again after restoring browser configuration",
                "Cookies, logins, session tokens, and application-bound secrets are excluded",
            );
            for extension in &candidate.extensions {
                let extension_evidence = state.evidence_with_key(
                    Some(&candidate.path),
                    &format!("extension:{}:{}", candidate.family.label(), extension.id),
                    "Browser extension identity discovered from profile metadata",
                    "browser-extension",
                );
                let extension_component =
                    build_extension_component(&candidate, extension, &extension_evidence)?;
                let extension_id = extension_component.id.clone();
                result.components.push(extension_component);
                let dependency_evidence = state.evidence_with_key(
                    Some(&candidate.path),
                    &format!("extension-parent:{}", extension.id),
                    "Browser extension belongs to profile",
                    "browser-profile",
                );
                add_dependency(
                    &mut result,
                    extension_id,
                    protected_component_id.clone(),
                    DependencyKind::Contains,
                    &dependency_evidence,
                );
            }
        }

        if result.installations.is_empty() && result.profiles.is_empty() {
            state.push_warning(ErrorEnvelope::new(
                ReforgeErrorCode::ProviderUnavailable,
                "No documented browser installation or profile evidence was found",
            ));
        }
        result.evidence = state.evidence_records;
        result
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        result
            .components
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
        });
        result
            .manual_actions
            .sort_by(|left, right| left.id.cmp(&right.id));
        result.manual_actions.truncate(MAX_MANUAL_ACTIONS);
        result.warnings.extend(state.warnings);
        result.warnings.truncate(MAX_WARNINGS);
        Ok(result)
    }
}

/// Convenience parser for a default-association ProgId returned by the
/// read-only Windows UserChoice query.
pub fn parse_default_browser(value: &str) -> Option<BrowserFamily> {
    let value = value.trim().to_ascii_lowercase();
    if value.contains("firefox") {
        Some(BrowserFamily::Firefox)
    } else if value.contains("edge") || value.contains("microsoftedge") {
        Some(BrowserFamily::Edge)
    } else if value.contains("thorium") {
        Some(BrowserFamily::Thorium)
    } else if value.contains("chromium") {
        Some(BrowserFamily::Chromium)
    } else if value.contains("chrome") {
        Some(BrowserFamily::Chrome)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub(super) struct ProfileCandidate {
    pub family: BrowserFamily,
    pub name: String,
    pub path: PathToken,
    pub lock_paths: Vec<PathToken>,
    pub artifacts: Vec<ProfileArtifactCandidate>,
    pub extensions: Vec<BrowserExtension>,
    pub excluded_protected_state: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct ProfileArtifactCandidate {
    pub path: PathToken,
    pub policy: ArtifactPolicy,
}

#[derive(Clone, Debug)]
struct DiscoveryState {
    observed_at: DateTime<Utc>,
    evidence_records: Vec<Evidence>,
    evidence_ids: BTreeSet<EvidenceId>,
    warnings: Vec<ErrorEnvelope>,
}

impl DiscoveryState {
    fn new(observed_at: DateTime<Utc>) -> Self {
        Self {
            observed_at,
            evidence_records: Vec::new(),
            evidence_ids: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn push_warning(&mut self, warning: ErrorEnvelope) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(warning);
        }
    }

    fn evidence(&mut self, path: Option<&PathToken>, summary: &str) -> Evidence {
        self.evidence_with_key(path, summary, summary, "browser-discovery")
    }

    fn registration_evidence(&mut self, registration: &BrowserRegistration) -> Evidence {
        let key = format!(
            "registration:{}:{}:{}:{}",
            registration.family.label(),
            registration.source.label(),
            registration.display_name,
            registration.version.as_deref().unwrap_or("unknown")
        );
        let summary = format!(
            "Browser installation discovered from {} registration evidence",
            registration.source.label()
        );
        self.evidence_with_key(
            registration.executable.as_ref(),
            &key,
            &summary,
            &format!("browser-registration-{}", registration.source.label()),
        )
    }

    fn process_evidence(&mut self, family: BrowserFamily) -> Evidence {
        self.evidence_with_key(
            None,
            &format!("process:{}", family.label()),
            "A running browser process was observed; profile capture is quiescence-gated",
            "browser-process",
        )
    }

    fn default_association_evidence(&mut self, family: BrowserFamily) -> Evidence {
        self.evidence_with_key(
            None,
            &format!("default-association:{}", family.label()),
            "The browser was returned by the read-only default association query",
            "browser-default-association",
        )
    }

    fn evidence_with_key(
        &mut self,
        path: Option<&PathToken>,
        key: &str,
        summary: &str,
        independent_group: &str,
    ) -> Evidence {
        let locator = format!(
            "browser:{}:{}",
            path.map(token_string)
                .unwrap_or_else(|| "registry".to_owned()),
            key
        );
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &locator);
        let id = EvidenceId::new(format!("browser-evidence-{}", hasher.finalize().to_hex()))
            .expect("hashed browser evidence ID");
        let evidence = Evidence {
            id: id.clone(),
            source: EvidenceSource::Browser,
            locator,
            observed_at: self.observed_at,
            summary: summary.to_owned(),
            strength: 80,
            independent_group: independent_group.to_owned(),
        };
        if self.evidence_ids.insert(id) {
            self.evidence_records.push(evidence.clone());
        }
        evidence
    }
}

impl RegistrationGroup {
    fn registration(&self) -> BrowserRegistration {
        BrowserRegistration {
            family: self.family,
            display_name: self.display_name.clone(),
            version: self.version.clone(),
            executable: self.executable.clone(),
            source: self.source,
        }
    }
}

fn group_registrations(registrations: Vec<BrowserRegistration>) -> Vec<RegistrationGroup> {
    let mut groups = BTreeMap::<BrowserFamily, RegistrationGroup>::new();
    for registration in registrations {
        let group = groups
            .entry(registration.family)
            .or_insert_with(|| RegistrationGroup {
                family: registration.family,
                display_name: registration.display_name.clone(),
                version: registration.version.clone(),
                version_source: registration.version.as_ref().map(|_| registration.source),
                executable: registration.executable.clone(),
                executable_source: registration
                    .executable
                    .as_ref()
                    .map(|_| registration.source),
                source: registration.source,
                registrations: Vec::new(),
            });

        if browser_name_score(&registration.display_name, registration.family)
            > browser_name_score(&group.display_name, group.family)
        {
            group.display_name = registration.display_name.clone();
        }
        if registration.version.is_some()
            && source_is_stronger(registration.source, group.version_source)
        {
            group.version = registration.version.clone();
            group.version_source = Some(registration.source);
        }
        if registration.executable.is_some()
            && source_is_stronger(registration.source, group.executable_source)
        {
            group.executable = registration.executable.clone();
            group.executable_source = Some(registration.source);
        }
        if source_is_stronger(registration.source, Some(group.source)) {
            group.source = registration.source;
        }
        group.registrations.push(registration);
    }

    groups
        .into_values()
        .map(|mut group| {
            group.registrations.sort_by_key(registration_key);
            group
        })
        .collect()
}

fn browser_name_score(name: &str, family: BrowserFamily) -> (u8, usize) {
    let normalized = name.trim().to_ascii_lowercase();
    let generic = normalized == family.label() || normalized == format!("{}.exe", family.label());
    ((!generic) as u8, normalized.len())
}
fn source_is_stronger(
    candidate: BrowserEvidenceSource,
    current: Option<BrowserEvidenceSource>,
) -> bool {
    current.is_none_or(|current| {
        (candidate.priority(), candidate.label()) > (current.priority(), current.label())
    })
}

fn source_requires_manual(source: BrowserEvidenceSource) -> bool {
    matches!(
        source,
        BrowserEvidenceSource::Shortcut | BrowserEvidenceSource::Unknown
    )
}

fn evidence_refs(evidence: &[Evidence]) -> Vec<EvidenceRef> {
    let mut references = evidence
        .iter()
        .map(|record| EvidenceRef {
            id: record.id.clone(),
            strength: record.strength,
        })
        .collect::<Vec<_>>();
    references.sort_by(|left, right| left.id.cmp(&right.id));
    references.dedup_by(|left, right| left.id == right.id);
    references
}

fn build_installation_component(
    registration: &BrowserRegistration,
    activity: BrowserActivity,
    is_default: bool,
    evidence: &[Evidence],
    unknown_source: bool,
) -> Result<Component, Box<ErrorEnvelope>> {
    let restore = if unknown_source {
        RestoreDescriptor {
            primary: RestoreStrategy::Manual,
            alternatives: vec![RestoreStrategy::PortableBinary],
            portability: Portability::Unknown,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "No trusted browser reinstall source was established from local evidence"
                    .to_owned(),
            ],
        }
    } else {
        RestoreDescriptor {
            primary: RestoreStrategy::Reinstall,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: false,
            rationale: vec![
                "Browser installation identity is recorded without copying profile secrets"
                    .to_owned(),
            ],
        }
    };
    build_component(
        ComponentKind::Browser,
        &format!(
            "installation:{}:{}",
            registration.family.label(),
            registration.display_name,
        ),
        &registration.display_name,
        registration.version.as_deref().map(version_value),
        Vec::new(),
        evidence,
        restore,
        Vec::new(),
        false,
        json_map([
            ("family", json!(registration.family.label())),
            ("source", json!(format!("{:?}", registration.source))),
            ("activity", json!(format!("{:?}", activity))),
            ("default", json!(is_default)),
            ("protected_state_copied", json!(false)),
        ]),
    )
}

fn build_profile_component(
    candidate: &ProfileCandidate,
    artifacts: &[ArtifactRef],
    locked: bool,
    activity: BrowserActivity,
    evidence: &[Evidence],
) -> Result<Component, Box<ErrorEnvelope>> {
    let restore = RestoreDescriptor {
        primary: RestoreStrategy::Partial,
        alternatives: vec![RestoreStrategy::Manual],
        portability: Portability::PartiallyPortable,
        requires_elevation: false,
        requires_user_action: locked,
        rationale: vec![
            "Only documented bookmarks/preferences/profile metadata are portable; protected session data is excluded".to_owned(),
        ],
    };
    build_component(
        ComponentKind::BrowserProfile,
        &format!(
            "profile:{}:{}",
            candidate.family.label(),
            token_string(&candidate.path)
        ),
        &format!("{} profile {}", candidate.family.label(), candidate.name),
        None,
        artifacts.to_vec(),
        evidence,
        restore,
        artifacts
            .iter()
            .map(|artifact| VerificationRule::BrowserArtifact {
                profile: artifact.source_path.clone(),
            })
            .collect(),
        false,
        json_map([
            ("family", json!(candidate.family.label())),
            ("profile", json!(candidate.name.clone())),
            ("activity", json!(format!("{:?}", activity))),
            ("locked", json!(locked)),
            (
                "excluded_protected_state",
                json!(candidate.excluded_protected_state.clone()),
            ),
            ("protected_state_copied", json!(false)),
        ]),
    )
}

fn build_extension_component(
    candidate: &ProfileCandidate,
    extension: &BrowserExtension,
    evidence: &Evidence,
) -> Result<Component, Box<ErrorEnvelope>> {
    build_component(
        ComponentKind::Extension,
        &format!("extension:{}:{}", candidate.family.label(), extension.id),
        &format!("{} extension {}", candidate.family.label(), extension.id),
        extension.version.as_deref().map(version_value),
        Vec::new(),
        std::slice::from_ref(evidence),
        RestoreDescriptor {
            primary: RestoreStrategy::Reinstall,
            alternatives: vec![RestoreStrategy::Manual],
            portability: Portability::PartiallyPortable,
            requires_elevation: false,
            requires_user_action: true,
            rationale: vec![
                "Browser extensions are restored by stable identity/source, not by copying protected profile databases".to_owned(),
            ],
        },
        Vec::new(),
        false,
        json_map([
            ("id", json!(extension.id.clone())),
            ("version", json!(extension.version.clone())),
            ("name", json!(extension.name.clone())),
            ("protected_state_copied", json!(false)),
        ]),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_component(
    kind: ComponentKind,
    key: &str,
    display_name: &str,
    version: Option<VersionValue>,
    artifacts: Vec<ArtifactRef>,
    evidence: &[Evidence],
    restore: RestoreDescriptor,
    verification: Vec<VerificationRule>,
    sensitive: bool,
    extensions: BTreeMap<String, Value>,
) -> Result<Component, Box<ErrorEnvelope>> {
    let publisher = Publisher {
        name: "Browser".to_owned(),
        certificate_thumbprint: None,
    };
    let mut identity = Identity {
        provider_package: None,
        provider_source: None,
        package_family: Some(format!("browser:{key}")),
        product_name: Some(display_name.to_owned()),
        executable_name: None,
        publisher: Some(publisher.name.clone()),
        executable_hash: None,
        install_role: Some(format!("{kind:?}")),
        identity_quality: IdentityQuality::PackageFamily,
    };
    let canonical = ComponentId::from_identity(&identity, Some(&publisher)).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::SchemaInvalid,
            "Browser component identity could not be canonicalized",
        )
    })?;
    identity.identity_quality = canonical.quality;
    let size_bytes = artifacts
        .iter()
        .map(|artifact| artifact.size_bytes)
        .fold(0u64, u64::saturating_add);
    Ok(Component {
        id: canonical.id,
        kind,
        identity,
        display_name: display_name.to_owned(),
        version: version.clone(),
        architecture: None,
        publisher: Some(publisher),
        provenance: Some(reforge_domain::Provenance {
            provider: None,
            package_id: Some("browser".to_owned()),
            source_url: None,
            observed_version: version.as_ref().map(|value| value.raw.clone()),
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        }),
        evidence: evidence_refs(evidence),
        confidence: Confidence::High,
        dependencies: Vec::new(),
        artifacts,
        restore,
        compatibility: Compatibility {
            required_os: Some("Windows 10 22H2+".to_owned()),
            required_architecture: None,
            requires_provider: None,
            requires_runtime: None,
            requires_elevation: false,
            requires_wsl: false,
            requires_docker: false,
        },
        verification,
        selection: SelectionMetadata {
            recommended: false,
            score: 0,
            selected_by_default: false,
            sensitive,
            size_bytes,
        },
        extensions,
    })
}

fn registry_registrations(
    known_folders: &KnownFolderMap,
) -> (Vec<BrowserRegistration>, Vec<ErrorEnvelope>) {
    let snapshot = enumerate_registry_with(&reforge_platform_windows::RegistryQuery {
        scopes: vec![RegistryScope::CurrentUser, RegistryScope::LocalMachine],
        views: vec![RegistryView::View32, RegistryView::View64],
        roots: vec![RegistryRoot::Uninstall, RegistryRoot::AppPaths],
    });
    let mut registrations = Vec::new();
    for observation in snapshot.observations {
        let default_value = registry_text(&observation, "");
        let display = registry_text(&observation, "DisplayName")
            .or_else(|| browser_display_from_key(&observation.key_path));
        let family = display
            .as_deref()
            .and_then(browser_family_from_text)
            .or_else(|| browser_family_from_text(&observation.key_path))
            .or_else(|| default_value.as_deref().and_then(browser_family_from_text));
        let Some(family) = family else {
            continue;
        };
        registrations.push(BrowserRegistration {
            family,
            display_name: display.unwrap_or_else(|| family.label().to_owned()),
            version: registry_text(&observation, "DisplayVersion"),
            executable: default_value
                .as_deref()
                .and_then(|value| token_for_registry_path(known_folders, value)),
            source: if observation.root == RegistryRoot::AppPaths {
                BrowserEvidenceSource::AppPath
            } else {
                BrowserEvidenceSource::Registry
            },
        });
    }
    let mut warnings: Vec<ErrorEnvelope> = snapshot
        .errors
        .into_iter()
        .map(|error| error.error)
        .collect();

    let shortcut_snapshot = enumerate_shell_links(known_folders);
    for observation in shortcut_snapshot.observations {
        let target_name = observation.target_name.clone().or_else(|| {
            observation
                .target
                .as_ref()
                .and_then(|target| target.relative.rsplit('/').next().map(ToOwned::to_owned))
        });
        let family = observation
            .description
            .as_deref()
            .and_then(browser_family_from_text)
            .or_else(|| target_name.as_deref().and_then(browser_family_from_text));
        let Some(family) = family else {
            continue;
        };
        registrations.push(BrowserRegistration {
            family,
            display_name: observation
                .description
                .or(target_name)
                .unwrap_or_else(|| family.label().to_owned()),
            version: None,
            executable: observation.target,
            source: BrowserEvidenceSource::Shortcut,
        });
    }
    warnings.extend(
        shortcut_snapshot
            .errors
            .into_iter()
            .map(|error| error.error),
    );
    (registrations, warnings)
}

fn browser_display_from_key(key_path: &str) -> Option<String> {
    key_path
        .rsplit('\\')
        .next()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn token_for_registry_path(known_folders: &KnownFolderMap, value: &str) -> Option<PathToken> {
    let value = value.trim().trim_matches('"');
    if value.contains(' ') && !value.contains("\\") {
        return None;
    }
    let mut expanded = value.to_owned();
    for (variable, token) in [
        ("%ProgramFiles%", KnownFolderToken::ProgramFiles),
        ("%ProgramFiles(x86)%", KnownFolderToken::ProgramFilesX86),
        ("%LocalAppData%", KnownFolderToken::LocalAppData),
        ("%AppData%", KnownFolderToken::RoamingAppData),
    ] {
        if let Some(root) = known_folders.entries.get(&token) {
            expanded = expanded.replace(variable, &root.to_string_lossy());
        }
    }
    token_for_absolute_path(known_folders, Path::new(&expanded))
}

fn append_path_registrations(
    known_folders: &KnownFolderMap,
    registrations: &mut Vec<BrowserRegistration>,
) {
    let candidates = [
        (BrowserFamily::Chrome, "chrome.exe"),
        (BrowserFamily::Edge, "msedge.exe"),
        (BrowserFamily::Chromium, "chromium.exe"),
        (BrowserFamily::Thorium, "thorium.exe"),
        (BrowserFamily::Firefox, "firefox.exe"),
    ];
    let Some(path) = env::var_os("PATH") else {
        return;
    };
    for directory in env::split_paths(&path)
        .filter(|directory| !directory.as_os_str().is_empty())
        .take(MAX_PATH_ENTRIES)
    {
        for (family, executable) in candidates {
            let absolute = directory.join(executable);
            if !absolute.is_file() {
                continue;
            }
            if let Some(token) = token_for_absolute_path(known_folders, &absolute) {
                registrations.push(BrowserRegistration {
                    family,
                    display_name: family.label().to_owned(),
                    version: None,
                    executable: Some(token),
                    source: BrowserEvidenceSource::Path,
                });
            }
        }
    }
}

fn browser_family_from_text(value: &str) -> Option<BrowserFamily> {
    let value = value.to_ascii_lowercase();
    if value.contains("thorium") {
        Some(BrowserFamily::Thorium)
    } else if value.contains("microsoft edge") || value.contains("msedge") {
        Some(BrowserFamily::Edge)
    } else if value.contains("firefox") || value.contains("mozilla") {
        Some(BrowserFamily::Firefox)
    } else if value.contains("chromium") {
        Some(BrowserFamily::Chromium)
    } else if value.contains("google chrome") || value.contains("chrome") {
        Some(BrowserFamily::Chrome)
    } else {
        None
    }
}

fn registry_text(observation: &RegistryKeyObservation, name: &str) -> Option<String> {
    observation
        .values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
        .and_then(|value| match &value.data {
            RegistryValueData::Text(text) => text.redacted.clone(),
            RegistryValueData::MultiString(values) => {
                values.first().and_then(|text| text.redacted.clone())
            }
            _ => None,
        })
        .filter(|value| !value.trim().is_empty())
}

fn registration_key(
    registration: &BrowserRegistration,
) -> (
    BrowserFamily,
    String,
    Option<String>,
    Option<String>,
    BrowserEvidenceSource,
) {
    (
        registration.family,
        registration.display_name.to_ascii_lowercase(),
        registration.version.clone(),
        registration.executable.as_ref().map(token_string),
        registration.source,
    )
}

fn process_running(processes: &BTreeSet<String>, family: BrowserFamily) -> bool {
    let process = match family {
        BrowserFamily::Chrome => "chrome",
        BrowserFamily::Edge => "msedge",
        BrowserFamily::Chromium => "chromium",
        BrowserFamily::Firefox => "firefox",
        BrowserFamily::Thorium => "thorium",
        BrowserFamily::Unknown => "",
    };
    !process.is_empty()
        && processes.iter().any(|name| {
            let name = name
                .rsplit_once('.')
                .filter(|(_, extension)| extension.eq_ignore_ascii_case("exe"))
                .map_or(name.as_str(), |(base, _)| base);
            name.eq_ignore_ascii_case(process)
        })
}
fn installation_id(family: &BrowserFamily, components: &[Component]) -> ComponentId {
    let package_prefix = format!("browser:installation:{}:", family.label());
    components
        .iter()
        .find(|component| {
            component.kind == ComponentKind::Browser
                && component
                    .identity
                    .package_family
                    .as_deref()
                    .is_some_and(|package_family| package_family.starts_with(&package_prefix))
        })
        .expect("profile family has an installation component")
        .id
        .clone()
}

fn add_dependency(
    result: &mut BrowserDiscovery,
    from: ComponentId,
    to: ComponentId,
    kind: DependencyKind,
    evidence: &Evidence,
) {
    let dependency = DependencyEdge {
        from: from.clone(),
        to,
        kind,
        required: true,
        evidence: vec![evidence.id.clone()],
        confidence: Confidence::High,
    };
    if let Some(component) = result
        .components
        .iter_mut()
        .find(|component| component.id == from)
    {
        component.dependencies.push(dependency.clone());
    }
    result.edges.push(dependency);
}

fn add_review_action(
    actions: &mut Vec<ManualAction>,
    component: &ComponentId,
    kind: &str,
    title: &str,
    reason: &str,
) {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, component.as_str());
    hash_field(&mut hasher, kind);
    let action = ManualAction {
        id: format!("browser-manual-{}", hasher.finalize().to_hex()),
        component: Some(component.clone()),
        title: title.to_owned(),
        reason: reason.to_owned(),
        risk: RiskLevel::High,
        instructions: vec!["Review this browser item explicitly before restore".to_owned()],
        docs_url: url::Url::parse(BROWSER_DOCS_URL).ok(),
        state: ManualActionState::Pending,
        independent_operations_may_continue: true,
        acknowledged_at: None,
        verification: None,
    };
    if actions.len() < MAX_MANUAL_ACTIONS
        && !actions.iter().any(|existing| existing.id == action.id)
    {
        actions.push(action);
    }
}

async fn run_powershell(
    runner: &ProcessRunner,
    cancellation: &CancellationToken,
    script: &str,
) -> Result<reforge_platform_windows::ProcessResult, Box<ErrorEnvelope>> {
    let command = CommandSpec::new(
        TrustedExecutable::Builtin(BuiltinExecutable::PowerShell),
        ["-NoProfile", "-NonInteractive", "-Command", script],
        Duration::from_secs(15),
        256 * 1024,
    )?;
    runner.run(&command, cancellation).await
}

fn entry_kind(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Option<EntryKind>, Box<ErrorEnvelope>> {
    let absolute = known_folders.resolve(path)?;
    match fs::symlink_metadata(absolute) {
        Ok(metadata) if metadata.is_file() => Ok(Some(EntryKind::File)),
        Ok(metadata) if metadata.is_dir() => Ok(Some(EntryKind::Directory)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Inspect browser path",
        ))),
    }
}

fn path_present(known_folders: &KnownFolderMap, path: &PathToken) -> bool {
    match known_folders.resolve(path) {
        Ok(absolute) => fs::symlink_metadata(absolute).is_ok(),
        Err(error) => error.code == ReforgeErrorCode::ReparsePoint,
    }
}

pub(super) fn direct_child_directories(
    known_folders: &KnownFolderMap,
    directory: &PathToken,
    max_entries: usize,
) -> Result<Vec<(String, PathToken)>, Box<ErrorEnvelope>> {
    let Some(EntryKind::Directory) = entry_kind(known_folders, directory)? else {
        return Ok(Vec::new());
    };
    let absolute = known_folders.resolve(directory)?;
    let mut children = Vec::new();
    for entry in fs::read_dir(absolute).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Enumerate browser profile root",
        ))
    })? {
        if children.len() >= max_entries {
            return Err(discovery_error(
                ReforgeErrorCode::SecurityPolicy,
                "Browser profile directory exceeds the reviewed entry bound",
            ));
        }
        let entry = entry.map_err(|error| {
            Box::new(ErrorEnvelope::from_io_error(
                &error,
                "Read browser profile entry",
            ))
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            Box::new(ErrorEnvelope::from_io_error(
                &error,
                "Inspect browser profile entry",
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|_| {
            discovery_error(
                ReforgeErrorCode::InvalidPath,
                "Browser profile name is not valid Unicode",
            )
        })?;
        let token = join_token(directory, &name)?;
        children.push((name, token));
    }
    children.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
    });
    Ok(children)
}

pub(super) fn join_token(
    base: &PathToken,
    relative: &str,
) -> Result<PathToken, Box<ErrorEnvelope>> {
    let value = if base.relative.is_empty() {
        relative.to_owned()
    } else {
        format!("{}/{}", base.relative, relative)
    };
    PathToken::new(base.root.clone(), value).map_err(|_| {
        discovery_error(
            ReforgeErrorCode::InvalidPath,
            "Browser path could not be tokenized",
        )
    })
}

pub(super) fn path_if_file(
    known_folders: &KnownFolderMap,
    base: &PathToken,
    relative: &str,
    policy: ArtifactPolicy,
) -> Option<ProfileArtifactCandidate> {
    let path = join_token(base, relative).ok()?;
    (entry_kind(known_folders, &path).ok().flatten() == Some(EntryKind::File))
        .then_some(ProfileArtifactCandidate { path, policy })
}

pub(super) fn token_string(path: &PathToken) -> String {
    format!("{:?}/{}", path.root, path.relative)
}

pub(super) fn read_bounded(
    known_folders: &KnownFolderMap,
    path: &PathToken,
) -> Result<Vec<u8>, Box<ErrorEnvelope>> {
    let root = known_folders.entries.get(&path.root).ok_or_else(|| {
        discovery_error(
            ReforgeErrorCode::PathNotFound,
            "Browser path root is unavailable",
        )
    })?;
    let safe_path = reforge_platform_windows::SafePath::from_token(path)?;
    let mut reader =
        reforge_platform_windows::BoundedFileReader::open(root, &safe_path, 8 * 1024 * 1024)?;
    let mut bytes = Vec::new();
    reader.stream_into(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn token_for_absolute_path(
    known_folders: &KnownFolderMap,
    path: &Path,
) -> Option<PathToken> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return None;
    }
    let candidate = path
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    known_folders.entries.iter().find_map(|(root, root_path)| {
        let root_text = root_path
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        if candidate == root_text {
            return PathToken::new(root.clone(), "").ok();
        }
        candidate
            .strip_prefix(&(root_text + "/"))
            .and_then(|relative| PathToken::new(root.clone(), relative).ok())
    })
}

fn version_value(value: &str) -> VersionValue {
    VersionValue {
        raw: value.to_owned(),
        normalized: Some(value.to_ascii_lowercase()),
    }
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn sorted_artifacts(mut artifacts: Vec<ArtifactRef>) -> Vec<ArtifactRef> {
    artifacts.sort_by(|left, right| {
        token_string(&left.source_path)
            .cmp(&token_string(&right.source_path))
            .then_with(|| left.id.cmp(&right.id))
    });
    artifacts
}

fn json_map<const N: usize>(entries: [(&str, Value); N]) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn discovery_error(code: ReforgeErrorCode, message: &str) -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(code, message))
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    discovery_error(
        ReforgeErrorCode::Cancelled,
        "Browser discovery was cancelled",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug)]
pub(super) struct BrowserRootSpec {
    pub family: BrowserFamily,
    pub root: PathToken,
}
pub(super) fn profile_root_spec(family: BrowserFamily, root: PathToken) -> BrowserRootSpec {
    BrowserRootSpec { family, root }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_browser_parser_never_guesses_unknown_progid() {
        assert_eq!(
            parse_default_browser("MSEdgeHTM"),
            Some(BrowserFamily::Edge)
        );
        assert_eq!(
            parse_default_browser("ChromeHTML"),
            Some(BrowserFamily::Chrome)
        );
        assert_eq!(parse_default_browser("unknown-progid"), None);
    }

    #[test]
    fn process_names_are_case_insensitive_and_exe_safe() {
        let processes = BTreeSet::from(["MSedge.EXE".to_owned()]);
        assert!(process_running(&processes, BrowserFamily::Edge));
    }
}
