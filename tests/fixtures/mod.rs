//! Deterministic, isolated fixtures shared by non-VM tests.
//!
//! Every helper owns a directory below the process temporary directory. Paths
//! are validated lexically and against existing symlink targets before any
//! filesystem operation is performed.

use std::{
    env, fmt, fs,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use reforge_domain::{
    AccountScope, Architecture, DriveFact, DriveFreeSpace, EnvironmentFact, HostFacts,
    InstalledFact, KnownFolderToken, PathToken, ProviderFact, ProviderId, RuntimeFact, TargetFacts,
};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

/// Error returned when a fixture operation would leave its owned root.
#[derive(Debug)]
pub enum FixtureError {
    Io(io::Error),
    InvalidPath(String),
    OutsideRoot(PathBuf),
    InvalidToken(String),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "fixture I/O error: {error}"),
            Self::InvalidPath(path) => write!(formatter, "invalid fixture-relative path: {path}"),
            Self::OutsideRoot(path) => {
                write!(
                    formatter,
                    "fixture path escapes the owned root: {}",
                    path.display()
                )
            }
            Self::InvalidToken(token) => write!(formatter, "invalid fixture token: {token}"),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<io::Error> for FixtureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Temporary known-folder roots used by tokenized-path tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TempTokenMap {
    pub user_profile: PathBuf,
    pub roaming_app_data: PathBuf,
    pub local_app_data: PathBuf,
    pub program_data: PathBuf,
    pub program_files: PathBuf,
    pub program_files_x86: PathBuf,
    pub start_menu: PathBuf,
    pub startup: PathBuf,
    pub desktop: PathBuf,
    pub documents: PathBuf,
}

impl TempTokenMap {
    fn create(root: &Path) -> io::Result<Self> {
        let user_profile = create_token_root(root, "user-profile")?;
        let roaming_app_data = create_token_root(root, "roaming-app-data")?;
        let local_app_data = create_token_root(root, "local-app-data")?;
        let program_data = create_token_root(root, "program-data")?;
        let program_files = create_token_root(root, "program-files")?;
        let program_files_x86 = create_token_root(root, "program-files-x86")?;
        let start_menu = create_token_root(root, "start-menu")?;
        let desktop = create_token_root(root, "desktop")?;
        let startup = create_token_root(root, "startup")?;
        let documents = create_token_root(root, "documents")?;
        Ok(Self {
            user_profile,
            roaming_app_data,
            local_app_data,
            program_data,
            program_files,
            program_files_x86,
            start_menu,
            desktop,
            startup,
            documents,
        })
    }

    fn root_for(&self, token: &KnownFolderToken) -> Option<PathBuf> {
        match token {
            KnownFolderToken::UserProfile => Some(self.user_profile.clone()),
            KnownFolderToken::RoamingAppData => Some(self.roaming_app_data.clone()),
            KnownFolderToken::LocalAppData => Some(self.local_app_data.clone()),
            KnownFolderToken::ProgramData => Some(self.program_data.clone()),
            KnownFolderToken::ProgramFiles => Some(self.program_files.clone()),
            KnownFolderToken::ProgramFilesX86 => Some(self.program_files_x86.clone()),
            KnownFolderToken::StartMenu => Some(self.start_menu.clone()),
            KnownFolderToken::Desktop => Some(self.desktop.clone()),
            KnownFolderToken::Startup => Some(self.startup.clone()),
            KnownFolderToken::Documents => Some(self.documents.clone()),
            KnownFolderToken::UserSelected { .. } => None,
        }
    }
}

/// Owned temporary root with cleanup on normal return and panic unwinding.
pub struct FixtureRoot {
    root: PathBuf,
    tokens: TempTokenMap,
    cleaned: bool,
}

impl fmt::Debug for FixtureRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureRoot")
            .field("root", &self.root)
            .field("tokens", &self.tokens)
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

impl FixtureRoot {
    /// Create an isolated fixture tree with deterministic token subdirectories.
    pub fn new(label: &str) -> Result<Self, FixtureError> {
        let base = env::temp_dir().join("reforge-fixtures");
        fs::create_dir_all(&base)?;
        let label = safe_label(label);
        let process_id = std::process::id();
        let root = loop {
            let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!("{label}-{process_id}-{id}"));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };

        let tokens = match TempTokenMap::create(&root) {
            Ok(tokens) => tokens,
            Err(error) => {
                let _ = fs::remove_dir_all(&root);
                return Err(error.into());
            }
        };
        Ok(Self {
            root,
            tokens,
            cleaned: false,
        })
    }

    /// Return the owned fixture root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the deterministic token-root map for this fixture.
    pub fn tokens(&self) -> &TempTokenMap {
        &self.tokens
    }

    /// Validate and resolve a relative path beneath the fixture root.
    pub fn path(&self, relative: impl AsRef<Path>) -> Result<PathBuf, FixtureError> {
        let relative = relative.as_ref();
        let raw = relative
            .to_str()
            .ok_or_else(|| FixtureError::InvalidPath(relative.display().to_string()))?;
        if raw.is_empty() {
            return Ok(self.root.clone());
        }
        if raw.starts_with('/')
            || raw.starts_with('\\')
            || (raw.len() >= 2 && raw.as_bytes()[1] == b':')
            || raw.contains('\0')
        {
            return Err(FixtureError::InvalidPath(raw.to_owned()));
        }

        let mut normalized = PathBuf::new();
        for segment in raw.split(['/', '\\']) {
            match segment {
                "" | "." => {}
                ".." => return Err(FixtureError::InvalidPath(raw.to_owned())),
                segment if segment.contains(':') => {
                    return Err(FixtureError::InvalidPath(raw.to_owned()));
                }
                segment => normalized.push(segment),
            }
        }
        let candidate = self.root.join(normalized);
        self.ensure_inside(candidate)
    }

    /// Create a directory beneath the fixture root.
    pub fn create_dir(&self, relative: impl AsRef<Path>) -> Result<PathBuf, FixtureError> {
        let path = self.path(relative)?;
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Write a file beneath the fixture root, creating its parents.
    pub fn write_file(
        &self,
        relative: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<PathBuf, FixtureError> {
        let path = self.path(relative)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)?;
        Ok(path)
    }

    /// Read a fixture file after root and symlink containment checks.
    pub fn read_file(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, FixtureError> {
        let path = self.path(relative)?;
        Ok(fs::read(path)?)
    }

    /// Remove any existing entry and return a guaranteed-missing fixture path.
    pub fn missing_file(&self, relative: impl AsRef<Path>) -> Result<PathBuf, FixtureError> {
        let path = self.path(relative)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path)?,
            Ok(_) => fs::remove_file(&path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }

    /// Create a file and retain a no-share handle for lock simulation.
    pub fn locked_file(
        &self,
        relative: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<LockedFile, FixtureError> {
        let path = self.write_file(relative, contents)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let handle = options.open(&path)?;
        Ok(LockedFile { path, handle })
    }

    /// Resolve a tokenized path into this fixture's temporary token root.
    pub fn resolve_token(
        &self,
        root: KnownFolderToken,
        relative: impl AsRef<str>,
    ) -> Result<PathBuf, FixtureError> {
        let base = match self.tokens.root_for(&root) {
            Some(path) => path,
            None => match &root {
                KnownFolderToken::UserSelected { id } => {
                    let id = safe_token_component(id)?;
                    let path = self.root.join("user-selected").join(id);
                    fs::create_dir_all(&path)?;
                    path
                }
                _ => unreachable!("all fixed known folders have token roots"),
            },
        };
        let token = PathToken::new(root, relative.as_ref()).map_err(FixtureError::InvalidToken)?;
        self.ensure_inside(base.join(token.relative))
    }

    /// Write an artifact at a validated tokenized path.
    pub fn write_tokenized(
        &self,
        root: KnownFolderToken,
        relative: impl AsRef<str>,
        contents: impl AsRef<[u8]>,
    ) -> Result<PathBuf, FixtureError> {
        let path = self.resolve_token(root, relative)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)?;
        Ok(path)
    }

    /// Remove the owned tree explicitly. Drop retries cleanup if this fails.
    pub fn cleanup(mut self) -> Result<(), FixtureError> {
        fs::remove_dir_all(&self.root)?;
        self.cleaned = true;
        Ok(())
    }

    fn ensure_inside(&self, candidate: PathBuf) -> Result<PathBuf, FixtureError> {
        let canonical_root = fs::canonicalize(&self.root)?;
        let mut existing = candidate.clone();
        loop {
            match fs::symlink_metadata(&existing) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !existing.pop() {
                        return Err(FixtureError::OutsideRoot(candidate));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        let canonical_existing = fs::canonicalize(existing)?;
        if !canonical_existing.starts_with(&canonical_root) {
            return Err(FixtureError::OutsideRoot(candidate));
        }
        Ok(candidate)
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

/// File handle retained to make a fixture path unavailable to other writers.
pub struct LockedFile {
    path: PathBuf,
    handle: File,
}

impl LockedFile {
    /// Return the locked path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly release the lock before fixture cleanup.
    pub fn unlock(self) {
        drop(self.handle);
    }
}

/// Deterministic provider output used instead of invoking a real package tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeProviderOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl FakeProviderOutput {
    /// Construct successful provider output.
    pub fn success(stdout: impl AsRef<[u8]>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.as_ref().to_vec(),
            stderr: Vec::new(),
        }
    }

    /// Construct failed provider output with deterministic exit/status bytes.
    pub fn failure(exit_code: i32, stdout: impl AsRef<[u8]>, stderr: impl AsRef<[u8]>) -> Self {
        Self {
            exit_code,
            stdout: stdout.as_ref().to_vec(),
            stderr: stderr.as_ref().to_vec(),
        }
    }
}

/// Deterministic package-export fixture for adapter tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakePackageExport {
    pub provider: ProviderId,
    pub output: FakeProviderOutput,
}

impl FakePackageExport {
    /// Construct a provider export from fixed output bytes.
    pub fn new(
        provider: impl Into<String>,
        output: FakeProviderOutput,
    ) -> Result<Self, FixtureError> {
        let provider = ProviderId::new(provider.into())
            .map_err(|error| FixtureError::InvalidToken(error.to_string()))?;
        Ok(Self { provider, output })
    }

    /// Fixed tabular export representative of a successful WinGet query.
    pub fn winget() -> Self {
        Self {
            provider: ProviderId::new("winget").expect("fixture provider ID"),
            output: FakeProviderOutput::success(
                "Name\tId\tVersion\nContoso Editor\tContoso.Editor\t1.2.3\n",
            ),
        }
    }
}

/// Build deterministic target facts without reading the host or user profile.
pub fn target_facts() -> TargetFacts {
    TargetFacts {
        host: host_facts(),
        installed: Vec::<InstalledFact>::new(),
        providers: vec![ProviderFact {
            id: ProviderId::new("winget").expect("fixture provider ID"),
            version: None,
            available: true,
        }],
        runtimes: Vec::<RuntimeFact>::new(),
        environment: Vec::<EnvironmentFact>::new(),
        fingerprint: "fixture-target-v1".to_owned(),
    }
}

/// Alias emphasizing that the fixture represents a target inventory input.
pub fn target_inventory() -> TargetFacts {
    target_facts()
}

/// Fixed host facts used by deterministic target and compatibility tests.
pub fn host_facts() -> HostFacts {
    let known_folders = [
        KnownFolderToken::UserProfile,
        KnownFolderToken::RoamingAppData,
        KnownFolderToken::LocalAppData,
        KnownFolderToken::ProgramData,
        KnownFolderToken::ProgramFiles,
        KnownFolderToken::ProgramFilesX86,
        KnownFolderToken::StartMenu,
        KnownFolderToken::Desktop,
        KnownFolderToken::Documents,
        KnownFolderToken::Startup,
    ]
    .into_iter()
    .map(|root| PathToken::new(root, "").expect("empty fixture token"))
    .collect();

    HostFacts {
        os_version: "Windows 11".to_owned(),
        os_build: "fixture-build".to_owned(),
        architecture: Architecture::X64,
        elevated: false,
        account_scope: AccountScope::User,
        sid_fingerprint: Some("fixture-sid".to_owned()),
        known_folders,
        drives: vec![DriveFact {
            token: "C:".to_owned(),
            filesystem: Some("NTFS".to_owned()),
        }],
        free_bytes: vec![DriveFreeSpace {
            token: "C:".to_owned(),
            bytes: 100 * 1024 * 1024 * 1024,
        }],
    }
}

fn create_token_root(root: &Path, name: &str) -> io::Result<PathBuf> {
    let path = root.join(name);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn safe_label(label: &str) -> String {
    let mut value: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect();
    if value.is_empty() {
        value.push_str("case");
    }
    value
}

fn safe_token_component(value: &str) -> Result<String, FixtureError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\', ':'])
        || value.chars().any(char::is_control)
    {
        return Err(FixtureError::InvalidToken(value.to_owned()));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn cleanup_runs_after_success_and_panic_unwind() {
        let fixture = FixtureRoot::new("cleanup-success").unwrap();
        let success_root = fixture.root().to_path_buf();
        fixture.cleanup().unwrap();
        assert!(!success_root.exists());

        let mut panic_root = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let fixture = FixtureRoot::new("cleanup-panic").unwrap();
            panic_root = Some(fixture.root().to_path_buf());
            panic!("exercise fixture drop during unwind");
        }));
        assert!(result.is_err());
        assert!(!panic_root.unwrap().exists());
    }

    #[test]
    fn path_operations_are_root_contained() {
        let fixture = FixtureRoot::new("contained").unwrap();
        assert!(fixture.path("../outside").is_err());
        assert!(fixture.path(r"C:\outside").is_err());
        assert!(fixture.write_file("safe/value.txt", b"value").is_ok());
        assert_eq!(fixture.read_file("safe/value.txt").unwrap(), b"value");
    }

    #[test]
    fn token_and_failure_fixtures_are_isolated() {
        let fixture = FixtureRoot::new("tokens").unwrap();
        let token_path = fixture
            .write_tokenized(KnownFolderToken::RoamingAppData, "tool/config.json", b"{}")
            .unwrap();
        assert!(token_path.starts_with(&fixture.tokens().roaming_app_data));

        let missing = fixture.missing_file("missing/file.txt").unwrap();
        assert!(!missing.exists());
        let locked = fixture.locked_file("locked/file.txt", b"locked").unwrap();
        assert!(locked.path().exists());
        locked.unlock();

        let export = FakePackageExport::winget();
        assert_eq!(export.provider.as_str(), "winget");
        assert_eq!(export.output.exit_code, 0);
    }

    #[test]
    fn target_inventory_is_host_independent_and_repeatable() {
        let first = target_facts();
        let second = target_inventory();
        assert_eq!(first, second);
        assert_eq!(first.host.os_version, "Windows 11");
        assert_eq!(first.fingerprint, "fixture-target-v1");
        assert_eq!(first.host.architecture, Architecture::X64);
        assert_eq!(first.host.account_scope, AccountScope::User);
        assert_eq!(first.host.known_folders.len(), 10);
    }
}
