//! Adapter-approved configuration and data artifact collection.
//!
//! The collector accepts only typed [`ArtifactRequest`] values. It resolves
//! their [`PathToken`] values through the current target's
//! [`KnownFolderMap`], never emits an absolute source path, and records
//! per-file metadata without materializing file contents.

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
};

use reforge_domain::{
    ArtifactId, ArtifactPolicy, ArtifactRef, ConfigScope, ContentType, ErrorEnvelope, PathToken,
    ReforgeErrorCode,
};
use reforge_platform_windows::{
    BoundedFileReader, FileObservationKind, KnownFolderMap, SafePath, WalkLimits, walk_reparse_safe,
};

const DEFAULT_MAX_REQUESTS: usize = 100_000;
const DEFAULT_MAX_ARTIFACTS: usize = 100_000;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_LARGE_FILE_THRESHOLD: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 64;
const MAX_WARNINGS: usize = 4_096;
const MAX_HARD_REQUESTS: usize = 1_000_000;
const MAX_HARD_ARTIFACTS: usize = 1_000_000;

/// Bounds applied before any selected artifact is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactLimits {
    pub max_requests: usize,
    pub max_artifacts: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub large_file_threshold: u64,
    pub max_depth: usize,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_requests: DEFAULT_MAX_REQUESTS,
            max_artifacts: DEFAULT_MAX_ARTIFACTS,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            large_file_threshold: DEFAULT_LARGE_FILE_THRESHOLD,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl ArtifactLimits {
    fn validate(self) -> Result<(), Box<ErrorEnvelope>> {
        if self.max_requests == 0
            || self.max_requests > MAX_HARD_REQUESTS
            || self.max_artifacts == 0
            || self.max_artifacts > MAX_HARD_ARTIFACTS
            || self.max_total_bytes == 0
            || self.max_file_bytes == 0
            || self.large_file_threshold == 0
            || self.max_depth == 0
        {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "Artifact collection limits are outside the reviewed bounds",
            )));
        }
        Ok(())
    }
}

/// One adapter-approved tokenized file or directory root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRequest {
    pub path: PathToken,
    pub scope: ConfigScope,
    pub policy: ArtifactPolicy,
}

impl ArtifactRequest {
    pub fn new(path: PathToken, scope: ConfigScope, policy: ArtifactPolicy) -> Self {
        Self {
            path,
            scope,
            policy,
        }
    }
}

/// Newline convention observed while reading a text artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewlineStyle {
    None,
    Lf,
    CrLf,
    Mixed,
}

/// Metadata that is not represented directly by [`ArtifactRef`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactInspection {
    pub id: ArtifactId,
    pub newline: NewlineStyle,
}

/// Result of a bounded artifact collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactCollection {
    pub artifacts: Vec<ArtifactRef>,
    pub inspections: Vec<ArtifactInspection>,
    pub warnings: Vec<ErrorEnvelope>,
    pub total_size_bytes: u64,
}

/// Collects explicitly selected, adapter-approved artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactCollector {
    limits: ArtifactLimits,
}

impl ArtifactCollector {
    pub fn new(limits: ArtifactLimits) -> Self {
        Self { limits }
    }

    pub fn limits(&self) -> ArtifactLimits {
        self.limits
    }

    /// Resolve and inspect selected files/directories under known-folder roots.
    ///
    /// A single inaccessible, locked, oversized, or reparse-backed entry is
    /// retained as a warning and does not abort other selected requests.
    pub fn collect(
        &self,
        known_folders: &KnownFolderMap,
        requests: &[ArtifactRequest],
    ) -> Result<ArtifactCollection, Box<ErrorEnvelope>> {
        self.limits.validate()?;
        let mut collection = ArtifactCollection {
            artifacts: Vec::new(),
            inspections: Vec::new(),
            warnings: Vec::new(),
            total_size_bytes: 0,
        };
        let mut seen = BTreeSet::new();
        let request_count = requests.len().min(self.limits.max_requests);
        for request in &requests[..request_count] {
            if request.path.validate().is_err() {
                push_warning(
                    &mut collection,
                    None,
                    ReforgeErrorCode::InvalidPath,
                    "An artifact request used an invalid tokenized path",
                );
                continue;
            }
            let resolved = match known_folders.resolve(&request.path) {
                Ok(path) => path,
                Err(error) => {
                    push_warning(
                        &mut collection,
                        Some(&request.path),
                        error.code.clone(),
                        "A selected artifact root could not be resolved safely",
                    );
                    continue;
                }
            };
            let metadata = match fs::symlink_metadata(&resolved) {
                Ok(metadata) => metadata,
                Err(_error) => {
                    self.collect_file(
                        known_folders,
                        request,
                        &request.path,
                        0,
                        &mut seen,
                        &mut collection,
                    )?;
                    continue;
                }
            };
            if metadata.is_file() {
                self.collect_file(
                    known_folders,
                    request,
                    &request.path,
                    metadata.len(),
                    &mut seen,
                    &mut collection,
                )?;
                continue;
            }
            if !metadata.is_dir() {
                push_warning(
                    &mut collection,
                    Some(&request.path),
                    ReforgeErrorCode::InvalidPath,
                    "A selected artifact path is not a regular file or directory",
                );
                continue;
            }

            let remaining_entries = self
                .limits
                .max_artifacts
                .saturating_sub(collection.artifacts.len())
                .max(1);
            let observations = match walk_reparse_safe(
                &resolved,
                WalkLimits {
                    max_entries: remaining_entries,
                    max_depth: self.limits.max_depth,
                },
            ) {
                Ok(observations) => observations,
                Err(error) => {
                    push_warning(
                        &mut collection,
                        Some(&request.path),
                        error.code.clone(),
                        "A selected artifact directory could not be walked safely",
                    );
                    continue;
                }
            };
            for observation in observations {
                let child_path = match join_path(&request.path, observation.path.as_str()) {
                    Ok(path) => path,
                    Err(_) => {
                        push_warning(
                            &mut collection,
                            Some(&request.path),
                            ReforgeErrorCode::InvalidPath,
                            "A discovered artifact path failed token validation",
                        );
                        continue;
                    }
                };
                match observation.kind {
                    FileObservationKind::File => self.collect_file(
                        known_folders,
                        request,
                        &child_path,
                        observation.size_bytes,
                        &mut seen,
                        &mut collection,
                    )?,
                    FileObservationKind::ReparsePoint => push_warning(
                        &mut collection,
                        Some(&child_path),
                        ReforgeErrorCode::ReparsePoint,
                        "A reparse point was recorded and not followed",
                    ),
                    FileObservationKind::Directory | FileObservationKind::Other => {}
                }
                if collection.artifacts.len() >= self.limits.max_artifacts {
                    break;
                }
            }
        }
        if requests.len() > request_count {
            push_warning(
                &mut collection,
                None,
                ReforgeErrorCode::SecurityPolicy,
                "Artifact request count exceeded the reviewed collection limit",
            );
        }
        Ok(collection)
    }

    fn collect_file(
        &self,
        known_folders: &KnownFolderMap,
        request: &ArtifactRequest,
        path: &PathToken,
        observed_size: u64,
        seen: &mut BTreeSet<ArtifactId>,
        collection: &mut ArtifactCollection,
    ) -> Result<(), Box<ErrorEnvelope>> {
        if collection.artifacts.len() >= self.limits.max_artifacts {
            return Ok(());
        }
        let id = artifact_id(path)?;
        if seen.contains(&id) {
            return Ok(());
        }
        if observed_size > self.limits.max_file_bytes {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::SecurityPolicy,
                "A selected artifact exceeded the per-file size limit",
            );
            return Ok(());
        }
        if observed_size > self.limits.large_file_threshold
            && request.policy != ArtifactPolicy::LargeOptIn
        {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::SecurityPolicy,
                "A large artifact requires explicit LargeOptIn selection",
            );
            return Ok(());
        }
        if collection
            .total_size_bytes
            .checked_add(observed_size)
            .is_none_or(|total| total > self.limits.max_total_bytes)
        {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::SecurityPolicy,
                "Selected artifacts exceeded the total size limit",
            );
            return Ok(());
        }
        if let Err(error) = known_folders.resolve(path) {
            push_warning(
                collection,
                Some(path),
                error.code.clone(),
                "An artifact was rejected during final path validation",
            );
            return Ok(());
        }

        let (content_type, newline, size_bytes) = match request.policy {
            ArtifactPolicy::Manual | ArtifactPolicy::SecretReference => {
                let resolved = match known_folders.resolve(path) {
                    Ok(path) => path,
                    Err(error) => {
                        push_warning(
                            collection,
                            Some(path),
                            error.code.clone(),
                            "A metadata-only artifact failed final path validation",
                        );
                        return Ok(());
                    }
                };
                let metadata = match fs::symlink_metadata(&resolved) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        push_warning(
                            collection,
                            Some(path),
                            classify_io_error(&error),
                            "A metadata-only artifact could not be inspected",
                        );
                        return Ok(());
                    }
                };
                if !metadata.is_file() {
                    push_warning(
                        collection,
                        Some(path),
                        ReforgeErrorCode::InvalidPath,
                        "A metadata-only artifact is not a regular file",
                    );
                    return Ok(());
                }
                (
                    classify_extension(&path.relative),
                    NewlineStyle::None,
                    metadata.len(),
                )
            }
            _ => {
                let root = known_folders.entries.get(&path.root).ok_or_else(|| {
                    Box::new(ErrorEnvelope::new(
                        ReforgeErrorCode::PathNotFound,
                        "The artifact known-folder root is unavailable",
                    ))
                })?;
                let safe_path = SafePath::from_token(path).inspect_err(|error| {
                    push_warning(
                        collection,
                        Some(path),
                        error.code.clone(),
                        "An artifact path failed filesystem validation",
                    );
                });
                let safe_path = match safe_path {
                    Ok(path) => path,
                    Err(_) => return Ok(()),
                };
                let mut reader =
                    match BoundedFileReader::open(root, &safe_path, self.limits.max_file_bytes) {
                        Ok(reader) => reader,
                        Err(error) => {
                            push_warning(
                                collection,
                                Some(path),
                                error.code.clone(),
                                "An artifact could not be opened safely",
                            );
                            return Ok(());
                        }
                    };
                let mut probe = ContentProbe::new();
                let summary = match reader.stream_into(&mut probe) {
                    Ok(summary) => summary,
                    Err(error) => {
                        push_warning(
                            collection,
                            Some(path),
                            error.code.clone(),
                            "An artifact could not be read within the reviewed bounds",
                        );
                        return Ok(());
                    }
                };
                let probe = probe.finish();
                (
                    classify_content(&path.relative, &probe),
                    probe.newline,
                    summary.bytes,
                )
            }
        };
        if size_bytes > self.limits.max_file_bytes {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::SecurityPolicy,
                "An artifact grew beyond the per-file size limit while being read",
            );
            return Ok(());
        }
        if size_bytes > self.limits.large_file_threshold
            && request.policy != ArtifactPolicy::LargeOptIn
        {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::SecurityPolicy,
                "A large artifact requires explicit LargeOptIn selection",
            );
            return Ok(());
        }
        let new_total = match collection.total_size_bytes.checked_add(size_bytes) {
            Some(total) if total <= self.limits.max_total_bytes => total,
            _ => {
                push_warning(
                    collection,
                    Some(path),
                    ReforgeErrorCode::SecurityPolicy,
                    "Selected artifacts exceeded the total size limit after inspection",
                );
                return Ok(());
            }
        };
        let policy = if content_type == ContentType::Unknown {
            push_warning(
                collection,
                Some(path),
                ReforgeErrorCode::ManualActionRequired,
                "An artifact has an unknown content class and requires review",
            );
            ArtifactPolicy::Manual
        } else {
            request.policy.clone()
        };
        let artifact = ArtifactRef {
            id: id.clone(),
            source_path: path.clone(),
            scope: request.scope.clone(),
            size_bytes,
            content_type,
            policy,
            object: None,
        };
        collection.total_size_bytes = new_total;
        seen.insert(id.clone());
        collection
            .inspections
            .push(ArtifactInspection { id, newline });
        collection.artifacts.push(artifact);
        Ok(())
    }
}

impl Default for ArtifactCollector {
    fn default() -> Self {
        Self::new(ArtifactLimits::default())
    }
}

/// Convenience entry point using the reviewed default bounds.
pub fn collect_artifacts(
    known_folders: &KnownFolderMap,
    requests: &[ArtifactRequest],
) -> Result<ArtifactCollection, Box<ErrorEnvelope>> {
    ArtifactCollector::default().collect(known_folders, requests)
}

fn artifact_id(path: &PathToken) -> Result<ArtifactId, Box<ErrorEnvelope>> {
    let bytes = serde_json::to_vec(path).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "An artifact path could not be serialized deterministically",
        ))
    })?;
    ArtifactId::new(format!("artifact-{}", blake3::hash(&bytes).to_hex())).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "An artifact identifier could not be constructed",
        ))
    })
}

fn join_path(base: &PathToken, child: &str) -> Result<PathToken, String> {
    let relative = if base.relative.is_empty() {
        child.to_owned()
    } else {
        format!("{}/{}", base.relative, child)
    };
    PathToken::new(base.root.clone(), relative)
}

fn push_warning(
    collection: &mut ArtifactCollection,
    path: Option<&PathToken>,
    code: ReforgeErrorCode,
    message: &str,
) {
    if collection.warnings.len() >= MAX_WARNINGS {
        return;
    }
    let mut warning = ErrorEnvelope::new(code, message);
    if let Some(path) = path
        && let Ok(id) = artifact_id(path)
    {
        warning = warning.with_context_id(id.as_str());
    }
    collection.warnings.push(warning);
}

fn classify_io_error(error: &io::Error) -> ReforgeErrorCode {
    match error.raw_os_error().map(|code| code as u32) {
        Some(5) => ReforgeErrorCode::AccessDenied,
        Some(32 | 33) => ReforgeErrorCode::FileLocked,
        Some(2 | 3) => ReforgeErrorCode::PathNotFound,
        _ => reforge_domain::classify_io_error(error.kind()),
    }
}

fn classify_content(relative: &str, probe: &ProbeSummary) -> ContentType {
    let extension = extension(relative);
    if extension.is_some_and(is_archive_extension) {
        return ContentType::Archive;
    }
    if probe.has_nul || !probe.valid_utf8 {
        return ContentType::Binary;
    }
    match extension {
        Some(extension) if extension.eq_ignore_ascii_case("json") => ContentType::Json,
        Some(extension) if extension.eq_ignore_ascii_case("jsonc") => ContentType::Jsonc,
        Some(extension) if extension.eq_ignore_ascii_case("toml") => ContentType::Toml,
        _ => ContentType::Utf8Text,
    }
}

fn classify_extension(relative: &str) -> ContentType {
    match extension(relative) {
        Some(extension) if extension.eq_ignore_ascii_case("json") => ContentType::Json,
        Some(extension) if extension.eq_ignore_ascii_case("jsonc") => ContentType::Jsonc,
        Some(extension) if extension.eq_ignore_ascii_case("toml") => ContentType::Toml,
        Some(extension) if is_archive_extension(extension) => ContentType::Archive,
        _ => ContentType::Unknown,
    }
}

fn extension(relative: &str) -> Option<&str> {
    let name = relative.rsplit('/').next()?;
    let (_, extension) = name.rsplit_once('.')?;
    if extension.is_empty() {
        None
    } else {
        Some(extension)
    }
}

fn is_archive_extension(extension: &str) -> bool {
    [
        "7z", "appx", "cab", "gz", "msix", "nupkg", "rar", "tar", "whl", "xz", "zip", "zst",
    ]
    .iter()
    .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

struct ContentProbe {
    has_nul: bool,
    valid_utf8: bool,
    utf8_remaining: u8,
    utf8_first_min: u8,
    utf8_first_max: u8,
    utf8_first_pending: bool,
    lf: u64,
    crlf: u64,
    lone_cr: u64,
    pending_cr: bool,
}

struct ProbeSummary {
    has_nul: bool,
    valid_utf8: bool,
    newline: NewlineStyle,
}

impl ContentProbe {
    fn new() -> Self {
        Self {
            has_nul: false,
            valid_utf8: true,
            utf8_remaining: 0,
            utf8_first_min: 0,
            utf8_first_max: 0,
            utf8_first_pending: false,
            lf: 0,
            crlf: 0,
            lone_cr: 0,
            pending_cr: false,
        }
    }

    fn finish(mut self) -> ProbeSummary {
        if self.pending_cr {
            self.lone_cr = self.lone_cr.saturating_add(1);
        }
        ProbeSummary {
            has_nul: self.has_nul,
            valid_utf8: self.valid_utf8 && self.utf8_remaining == 0,
            newline: match (self.lf, self.crlf, self.lone_cr) {
                (0, 0, 0) => NewlineStyle::None,
                (lf, 0, 0) if lf > 0 => NewlineStyle::Lf,
                (0, crlf, 0) if crlf > 0 => NewlineStyle::CrLf,
                _ => NewlineStyle::Mixed,
            },
        }
    }

    fn observe_utf8(&mut self, byte: u8) {
        if !self.valid_utf8 {
            return;
        }
        if self.utf8_remaining == 0 {
            match byte {
                0x00..=0x7F => {}
                0xC2..=0xDF => {
                    self.utf8_remaining = 1;
                    self.utf8_first_min = 0x80;
                    self.utf8_first_max = 0xBF;
                    self.utf8_first_pending = true;
                }
                0xE0 => {
                    self.utf8_remaining = 2;
                    self.utf8_first_min = 0xA0;
                    self.utf8_first_max = 0xBF;
                    self.utf8_first_pending = true;
                }
                0xE1..=0xEC | 0xEE..=0xEF => {
                    self.utf8_remaining = 2;
                    self.utf8_first_min = 0x80;
                    self.utf8_first_max = 0xBF;
                    self.utf8_first_pending = true;
                }
                0xED => {
                    self.utf8_remaining = 2;
                    self.utf8_first_min = 0x80;
                    self.utf8_first_max = 0x9F;
                    self.utf8_first_pending = true;
                }
                0xF0 => {
                    self.utf8_remaining = 3;
                    self.utf8_first_min = 0x90;
                    self.utf8_first_max = 0xBF;
                    self.utf8_first_pending = true;
                }
                0xF1..=0xF3 => {
                    self.utf8_remaining = 3;
                    self.utf8_first_min = 0x80;
                    self.utf8_first_max = 0xBF;
                    self.utf8_first_pending = true;
                }
                0xF4 => {
                    self.utf8_remaining = 3;
                    self.utf8_first_min = 0x80;
                    self.utf8_first_max = 0x8F;
                    self.utf8_first_pending = true;
                }
                _ => self.valid_utf8 = false,
            }
            return;
        }
        let (minimum, maximum) = if self.utf8_first_pending {
            (self.utf8_first_min, self.utf8_first_max)
        } else {
            (0x80, 0xBF)
        };
        if !(minimum..=maximum).contains(&byte) {
            self.valid_utf8 = false;
            self.utf8_remaining = 0;
            self.utf8_first_pending = false;
            return;
        }
        self.utf8_remaining -= 1;
        self.utf8_first_pending = false;
    }
}

impl Write for ContentProbe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for &byte in bytes {
            self.has_nul |= byte == 0;
            self.observe_utf8(byte);
            if self.pending_cr {
                if byte == b'\n' {
                    self.crlf = self.crlf.saturating_add(1);
                    self.pending_cr = false;
                    continue;
                }
                self.lone_cr = self.lone_cr.saturating_add(1);
                self.pending_cr = false;
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => self.lf = self.lf.saturating_add(1),
                _ => {}
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../tests/fixtures/mod.rs"]
mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::FixtureRoot;
    use reforge_domain::KnownFolderToken;
    use std::collections::BTreeMap;

    fn known_folders(fixture: &FixtureRoot) -> KnownFolderMap {
        let mut entries = BTreeMap::new();
        entries.insert(
            KnownFolderToken::UserProfile,
            fixture.tokens().user_profile.clone(),
        );
        entries.insert(
            KnownFolderToken::RoamingAppData,
            fixture.tokens().roaming_app_data.clone(),
        );
        KnownFolderMap::from_entries(entries)
    }

    #[test]
    fn collects_tokenized_json_with_newline_metadata() {
        let fixture = FixtureRoot::new("artifact-json").expect("fixture root");
        fixture
            .write_tokenized(
                KnownFolderToken::UserProfile,
                "App/config.json",
                b"{\r\n  \"ok\": true\r\n}\r\n",
            )
            .expect("artifact file");
        let token =
            PathToken::new(KnownFolderToken::UserProfile, "App/config.json").expect("valid token");
        let result = ArtifactCollector::default()
            .collect(
                &known_folders(&fixture),
                &[ArtifactRequest::new(
                    token,
                    ConfigScope::User,
                    ArtifactPolicy::Config,
                )],
            )
            .expect("collection");
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].content_type, ContentType::Json);
        assert_eq!(result.artifacts[0].source_path.relative, "App/config.json");
        assert_eq!(result.inspections[0].newline, NewlineStyle::CrLf);
        let serialized = serde_json::to_string(&result.artifacts[0]).expect("artifact JSON");
        assert!(!serialized.contains(fixture.root().to_string_lossy().as_ref()));
    }

    #[test]
    fn inaccessible_file_is_a_warning_and_does_not_abort_other_files() {
        let fixture = FixtureRoot::new("artifact-lock").expect("fixture root");
        let locked = fixture
            .locked_file("App/locked.json", b"locked")
            .expect("locked fixture");
        fixture
            .write_tokenized(KnownFolderToken::UserProfile, "App/open.json", b"{}")
            .expect("open fixture");
        let requests = [
            ArtifactRequest::new(
                PathToken::new(KnownFolderToken::UserProfile, "App/locked.json")
                    .expect("locked token"),
                ConfigScope::User,
                ArtifactPolicy::Config,
            ),
            ArtifactRequest::new(
                PathToken::new(KnownFolderToken::UserProfile, "App/open.json").expect("open token"),
                ConfigScope::User,
                ArtifactPolicy::Config,
            ),
        ];
        let result = ArtifactCollector::default()
            .collect(&known_folders(&fixture), &requests)
            .expect("collection");
        assert_eq!(result.artifacts.len(), 1);
        assert!(result.warnings.iter().any(|warning| matches!(
            warning.code,
            ReforgeErrorCode::FileLocked
                | ReforgeErrorCode::AccessDenied
                | ReforgeErrorCode::PathNotFound
        )));
        drop(locked);
    }

    #[test]
    fn large_files_require_opt_in_and_invalid_token_is_skipped() {
        let fixture = FixtureRoot::new("artifact-bounds").expect("fixture root");
        fixture
            .write_tokenized(KnownFolderToken::UserProfile, "large.bin", b"123456")
            .expect("large fixture");
        let collector = ArtifactCollector::new(ArtifactLimits {
            max_file_bytes: 64,
            large_file_threshold: 4,
            ..ArtifactLimits::default()
        });
        let large = ArtifactRequest::new(
            PathToken::new(KnownFolderToken::UserProfile, "large.bin").expect("large token"),
            ConfigScope::User,
            ArtifactPolicy::Config,
        );
        let invalid = ArtifactRequest::new(
            PathToken {
                root: KnownFolderToken::UserProfile,
                relative: "../escape".to_owned(),
            },
            ConfigScope::User,
            ArtifactPolicy::Config,
        );
        let result = collector
            .collect(&known_folders(&fixture), &[large, invalid])
            .expect("collection");
        assert!(result.artifacts.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.code == ReforgeErrorCode::SecurityPolicy)
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.code == ReforgeErrorCode::InvalidPath)
        );
    }
}
