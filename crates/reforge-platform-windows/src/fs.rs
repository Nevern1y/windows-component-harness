//! Reparse-safe path, streaming read, walk, and atomic replacement primitives.
//!
//! Every path accepted from package or restore data is represented by
//! [`SafePath`]. Absolute host roots remain local to this Windows boundary.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::windows::ffi::OsStrExt,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use reforge_domain::{ErrorEnvelope, PathToken, ReforgeErrorCode};
use windows::{
    Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
            ERROR_INVALID_NAME, ERROR_LOCK_VIOLATION, ERROR_PATH_NOT_FOUND,
            ERROR_SHARING_VIOLATION,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_READONLY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACE_FILE_FLAGS, ReplaceFileW,
            SetFileAttributesW,
        },
    },
    core::PCWSTR,
};

use crate::process::next_process_local_id;

const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const GENERATED_NAME_ATTEMPTS: usize = 128;

/// A normalized, UTF-8, relative Windows path that cannot name another root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SafePath {
    normalized: String,
}

impl SafePath {
    /// Validate and normalize a package or restore file path.
    ///
    /// Both separators are accepted and normalized to `/`; empty and `.`
    /// segments disappear. Absolute, drive, UNC, parent, device, stream, and
    /// Windows-normalized alias forms are rejected.
    pub fn new(value: impl AsRef<str>) -> Result<Self, Box<ErrorEnvelope>> {
        let normalized = normalize_safe_path(value.as_ref())?;
        Ok(Self { normalized })
    }

    /// Revalidate a domain token at the filesystem boundary.
    pub fn from_token(token: &PathToken) -> Result<Self, Box<ErrorEnvelope>> {
        token
            .validate()
            .map_err(|_| invalid_path_error("path token failed domain validation"))?;
        Self::new(&token.relative)
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Case-folded key used for Windows collision checks.
    pub fn comparison_key(&self) -> String {
        self.normalized.to_lowercase()
    }

    /// Convert to a relative host path without changing its validated segments.
    pub fn to_path_buf(&self) -> PathBuf {
        self.segments().collect()
    }

    fn segments(&self) -> impl Iterator<Item = &str> {
        self.normalized.split('/')
    }

    fn parent(&self) -> Option<&str> {
        self.normalized.rsplit_once('/').map(|(parent, _)| parent)
    }

    fn generated_sibling(&self, role: &str) -> Result<Self, Box<ErrorEnvelope>> {
        let name = format!(".reforge-{role}-{}", next_process_local_id());
        let value = self
            .parent()
            .map_or(name.clone(), |parent| format!("{parent}/{name}"));
        Self::new(value)
    }
}

impl fmt::Display for SafePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.normalized)
    }
}

/// Safe subset of Windows file attributes that may cross a package boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileAttributes {
    pub read_only: bool,
    pub hidden: bool,
    pub archive: bool,
    pub not_content_indexed: bool,
}

impl FileAttributes {
    pub fn from_metadata(metadata: &Metadata) -> Self {
        let bits = metadata.file_attributes();
        Self {
            read_only: bits & FILE_ATTRIBUTE_READONLY.0 != 0,
            hidden: bits & FILE_ATTRIBUTE_HIDDEN.0 != 0,
            archive: bits & FILE_ATTRIBUTE_ARCHIVE.0 != 0,
            not_content_indexed: bits & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0 != 0,
        }
    }

    fn windows_bits(self) -> FILE_FLAGS_AND_ATTRIBUTES {
        let mut bits = 0u32;
        if self.read_only {
            bits |= FILE_ATTRIBUTE_READONLY.0;
        }
        if self.hidden {
            bits |= FILE_ATTRIBUTE_HIDDEN.0;
        }
        if self.archive {
            bits |= FILE_ATTRIBUTE_ARCHIVE.0;
        }
        if self.not_content_indexed {
            bits |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0;
        }
        if bits == 0 {
            bits = FILE_ATTRIBUTE_NORMAL.0;
        }
        FILE_FLAGS_AND_ATTRIBUTES(bits)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileObservationKind {
    File,
    Directory,
    ReparsePoint,
    Other,
}

/// A root-relative observation; no absolute host path leaves this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservation {
    pub path: SafePath,
    pub kind: FileObservationKind,
    pub size_bytes: u64,
    pub attributes: FileAttributes,
}

/// Explicit bounds for recursive filesystem enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalkLimits {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_depth: 64,
        }
    }
}

/// Enumerate a root without following reparse points.
pub fn walk_reparse_safe(
    root: impl AsRef<Path>,
    limits: WalkLimits,
) -> Result<Vec<FileObservation>, Box<ErrorEnvelope>> {
    if limits.max_entries == 0 || limits.max_depth == 0 {
        return Err(security_error("filesystem walk limits must be nonzero"));
    }
    let root = root.as_ref();
    validate_root(root)?;

    let mut observations = Vec::new();
    let mut seen = BTreeSet::new();
    let mut pending = VecDeque::from([(root.to_path_buf(), None::<SafePath>, 0usize)]);

    while let Some((directory, parent, depth)) = pending.pop_front() {
        let mut children = Vec::new();
        let read_dir =
            fs::read_dir(&directory).map_err(|error| io_error("enumerate directory", &error))?;
        for entry in read_dir {
            let entry = entry.map_err(|error| io_error("read directory entry", &error))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_path_error("filesystem entry name is not valid Unicode"))?;
            children.push((name, entry.path()));
        }
        children.sort_by(|left, right| {
            left.0
                .to_lowercase()
                .cmp(&right.0.to_lowercase())
                .then_with(|| left.0.cmp(&right.0))
        });

        for (name, absolute) in children {
            let relative = match &parent {
                Some(parent) => SafePath::new(format!("{parent}/{name}"))?,
                None => SafePath::new(name)?,
            };
            if !seen.insert(relative.comparison_key()) {
                return Err(Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::TargetConflict,
                    "The filesystem contains a case-insensitive path collision",
                )));
            }
            if observations.len() == limits.max_entries {
                return Err(security_error("filesystem walk entry limit exceeded"));
            }

            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| io_error("inspect directory entry", &error))?;
            let attributes = FileAttributes::from_metadata(&metadata);
            let reparse = is_reparse_point(&metadata);
            let kind = if reparse {
                FileObservationKind::ReparsePoint
            } else if metadata.is_dir() {
                FileObservationKind::Directory
            } else if metadata.is_file() {
                FileObservationKind::File
            } else {
                FileObservationKind::Other
            };
            observations.push(FileObservation {
                path: relative.clone(),
                kind,
                size_bytes: metadata.len(),
                attributes,
            });

            if kind == FileObservationKind::Directory {
                let child_depth = depth + 1;
                if child_depth >= limits.max_depth {
                    return Err(security_error("filesystem walk depth limit exceeded"));
                }
                pending.push_back((absolute, Some(relative), child_depth));
            }
        }
    }

    Ok(observations)
}

/// Summary produced by a complete bounded stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamSummary {
    pub bytes: u64,
    pub blake3: [u8; 32],
}

/// A regular file opened without traversing a final reparse point.
pub struct BoundedFileReader {
    file: File,
    max_bytes: u64,
}

impl BoundedFileReader {
    pub fn open(
        root: impl AsRef<Path>,
        path: &SafePath,
        max_bytes: u64,
    ) -> Result<Self, Box<ErrorEnvelope>> {
        let absolute = resolve_existing(root.as_ref(), path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        let file = options
            .open(&absolute)
            .map_err(|error| io_error("open bounded file", &error))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect bounded file handle", &error))?;
        if is_reparse_point(&metadata) {
            return Err(reparse_error("bounded file is a reparse point"));
        }
        if !metadata.is_file() {
            return Err(invalid_path_error("bounded reader requires a regular file"));
        }
        if metadata.len() > max_bytes {
            return Err(security_error(
                "bounded file exceeds the configured size limit",
            ));
        }
        Ok(Self { file, max_bytes })
    }

    /// Stream the complete file through a fixed-size buffer and fail rather
    /// than truncate if it grows beyond the configured limit.
    pub fn stream_into(
        &mut self,
        writer: &mut impl Write,
    ) -> Result<StreamSummary, Box<ErrorEnvelope>> {
        let mut buffer = [0u8; STREAM_BUFFER_BYTES];
        let mut bytes = 0u64;
        let mut hasher = blake3::Hasher::new();
        loop {
            let read = self
                .file
                .read(&mut buffer)
                .map_err(|error| io_error("read bounded file", &error))?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| security_error("bounded file length overflow"))?;
            if bytes > self.max_bytes {
                return Err(security_error(
                    "bounded file exceeded the configured size limit",
                ));
            }
            writer
                .write_all(&buffer[..read])
                .map_err(|error| io_error("write bounded stream", &error))?;
            hasher.update(&buffer[..read]);
        }
        Ok(StreamSummary {
            bytes,
            blake3: *hasher.finalize().as_bytes(),
        })
    }
}

/// Required validation and portable attributes for an atomic file write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicWriteSpec {
    pub expected_bytes: u64,
    pub expected_blake3: [u8; 32],
    pub attributes: FileAttributes,
}

/// Root-relative record of the original target retained by replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRecord {
    pub path: SafePath,
    pub original_bytes: u64,
    pub original_attributes: FileAttributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicReplaceResult {
    pub destination: SafePath,
    pub bytes_written: u64,
    pub blake3: [u8; 32],
    pub backup: Option<BackupRecord>,
}

/// Write, flush, validate, back up, and atomically install one file.
///
/// Existing files are replaced only through `ReplaceFileW` with a sibling
/// backup name. A new destination is installed with a same-directory,
/// write-through rename. Temp files are removed on every pre-commit failure.
pub fn atomic_replace(
    root: impl AsRef<Path>,
    destination: &SafePath,
    mut source: impl Read,
    spec: AtomicWriteSpec,
) -> Result<AtomicReplaceResult, Box<ErrorEnvelope>> {
    let root = root.as_ref();
    let destination_absolute = prepare_destination(root, destination)?;
    let (temp_absolute, mut temp_file) = create_temp_file(root, destination)?;
    let mut temp_guard = TempFileGuard::new(temp_absolute.clone());

    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    let mut bytes_written = 0u64;
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| io_error("read atomic source", &error))?;
        if read == 0 {
            break;
        }
        bytes_written = bytes_written
            .checked_add(read as u64)
            .ok_or_else(|| verification_error("atomic source length overflow"))?;
        if bytes_written > spec.expected_bytes {
            return Err(verification_error("atomic source is longer than expected"));
        }
        temp_file
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write atomic temp file", &error))?;
        hasher.update(&buffer[..read]);
    }
    temp_file
        .flush()
        .map_err(|error| io_error("flush atomic temp file", &error))?;
    temp_file
        .sync_all()
        .map_err(|error| io_error("synchronize atomic temp file", &error))?;

    if bytes_written != spec.expected_bytes {
        return Err(verification_error("atomic source length does not match"));
    }
    let digest = *hasher.finalize().as_bytes();
    if digest != spec.expected_blake3 {
        return Err(verification_error("atomic source hash does not match"));
    }
    drop(temp_file);
    apply_selected_attributes(&temp_absolute, spec.attributes)?;

    // Recheck every existing path component immediately before mutation.
    let checked_destination = prepare_destination(root, destination)?;
    if checked_destination != destination_absolute {
        return Err(invalid_path_error("destination changed during validation"));
    }

    let committed_backup = match fs::symlink_metadata(&destination_absolute) {
        Ok(metadata) => {
            if is_reparse_point(&metadata) {
                return Err(reparse_error("destination is a reparse point"));
            }
            if !metadata.is_file() {
                return Err(Box::new(ErrorEnvelope::new(
                    ReforgeErrorCode::TargetConflict,
                    "The destination is not a regular file",
                )));
            }
            let (backup_path, backup_absolute) = unused_sibling(destination, root, "backup")?;
            let destination_wide = wide_path(&destination_absolute);
            let temp_wide = wide_path(&temp_absolute);
            let backup_wide = wide_path(&backup_absolute);
            unsafe {
                ReplaceFileW(
                    PCWSTR(destination_wide.as_ptr()),
                    PCWSTR(temp_wide.as_ptr()),
                    PCWSTR(backup_wide.as_ptr()),
                    REPLACE_FILE_FLAGS(0),
                    None,
                    None,
                )
            }
            .map_err(|error| windows_error("atomically replace destination", &error))?;
            temp_guard.disarm();
            Some((
                BackupRecord {
                    path: backup_path,
                    original_bytes: metadata.len(),
                    original_attributes: FileAttributes::from_metadata(&metadata),
                },
                backup_absolute,
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let temp_wide = wide_path(&temp_absolute);
            let destination_wide = wide_path(&destination_absolute);
            unsafe {
                MoveFileExW(
                    PCWSTR(temp_wide.as_ptr()),
                    PCWSTR(destination_wide.as_ptr()),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
            .map_err(|error| windows_error("atomically create destination", &error))?;
            temp_guard.disarm();
            None
        }
        Err(error) => return Err(io_error("inspect atomic destination", &error)),
    };

    if let Some((backup, backup_absolute)) = &committed_backup
        && let Err(attribute_error) =
            apply_selected_attributes(&destination_absolute, spec.attributes)
    {
        let destination_wide = wide_path(&destination_absolute);
        let backup_wide = wide_path(backup_absolute);
        let rollback_wide = wide_path(&temp_absolute);
        unsafe {
            ReplaceFileW(
                PCWSTR(destination_wide.as_ptr()),
                PCWSTR(backup_wide.as_ptr()),
                PCWSTR(rollback_wide.as_ptr()),
                REPLACE_FILE_FLAGS(0),
                None,
                None,
            )
        }
        .map_err(|error| windows_error("roll back destination attributes", &error))?;
        drop(TempFileGuard::new(temp_absolute.clone()));
        apply_selected_attributes(&destination_absolute, backup.original_attributes)?;
        return Err(attribute_error);
    }

    Ok(AtomicReplaceResult {
        destination: destination.clone(),
        bytes_written,
        blake3: digest,
        backup: committed_backup.map(|(record, _)| record),
    })
}

fn normalize_safe_path(value: &str) -> Result<String, Box<ErrorEnvelope>> {
    if value.is_empty() {
        return Err(invalid_path_error("file path must not be empty"));
    }
    if value.starts_with(['/', '\\']) {
        return Err(invalid_path_error("absolute and UNC paths are prohibited"));
    }
    if value.as_bytes().get(1) == Some(&b':') {
        return Err(invalid_path_error("drive-prefixed paths are prohibited"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_path_error(
            "control characters are prohibited in file paths",
        ));
    }

    let mut segments = Vec::new();
    for segment in value.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => return Err(invalid_path_error("parent path segments are prohibited")),
            segment => {
                validate_segment(segment)?;
                segments.push(segment);
            }
        }
    }
    if segments.is_empty() {
        return Err(invalid_path_error("file path must identify an entry"));
    }
    Ok(segments.join("/"))
}

fn validate_segment(segment: &str) -> Result<(), Box<ErrorEnvelope>> {
    if segment.contains([':', '"', '<', '>', '|', '?', '*']) {
        return Err(invalid_path_error(
            "file path contains a prohibited Windows character",
        ));
    }
    if segment.ends_with(' ') || segment.ends_with('.') {
        return Err(invalid_path_error(
            "file path contains a Windows-normalized alias",
        ));
    }
    let base = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_uppercase();
    let numbered_device = (base.starts_with("COM") || base.starts_with("LPT"))
        && base.len() == 4
        && matches!(base.as_bytes()[3], b'1'..=b'9');
    if matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || numbered_device
    {
        return Err(invalid_path_error(
            "reserved Windows device names are prohibited",
        ));
    }
    Ok(())
}

fn validate_root(root: &Path) -> Result<(), Box<ErrorEnvelope>> {
    if !root.is_absolute() {
        return Err(invalid_path_error("filesystem root must be absolute"));
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|error| io_error("inspect filesystem root", &error))?;
    if is_reparse_point(&metadata) {
        return Err(reparse_error("filesystem root is a reparse point"));
    }
    if !metadata.is_dir() {
        return Err(invalid_path_error("filesystem root is not a directory"));
    }
    Ok(())
}

fn resolve_existing(root: &Path, path: &SafePath) -> Result<PathBuf, Box<ErrorEnvelope>> {
    validate_root(root)?;
    let mut current = root.to_path_buf();
    let segment_count = path.segments().count();
    for (index, segment) in path.segments().enumerate() {
        current.push(segment);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| io_error("inspect safe path component", &error))?;
        if is_reparse_point(&metadata) {
            return Err(reparse_error("safe path contains a reparse point"));
        }
        if index + 1 < segment_count && !metadata.is_dir() {
            return Err(invalid_path_error("safe path parent is not a directory"));
        }
    }
    Ok(current)
}

fn prepare_destination(root: &Path, path: &SafePath) -> Result<PathBuf, Box<ErrorEnvelope>> {
    validate_root(root)?;
    let mut current = root.to_path_buf();
    let segment_count = path.segments().count();
    for (index, segment) in path.segments().enumerate() {
        current.push(segment);
        let is_destination = index + 1 == segment_count;
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse_point(&metadata) => {
                return Err(reparse_error("destination path contains a reparse point"));
            }
            Ok(metadata) if !is_destination && !metadata.is_dir() => {
                return Err(invalid_path_error("destination parent is not a directory"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && !is_destination => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(io_error("create destination directory", &error)),
                }
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|error| io_error("verify destination directory", &error))?;
                if is_reparse_point(&metadata) {
                    return Err(reparse_error(
                        "created destination directory became a reparse point",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(invalid_path_error(
                        "created destination parent is not a directory",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("inspect destination path", &error)),
        }
    }
    Ok(current)
}

fn create_temp_file(
    root: &Path,
    destination: &SafePath,
) -> Result<(PathBuf, File), Box<ErrorEnvelope>> {
    for _ in 0..GENERATED_NAME_ATTEMPTS {
        let path = destination.generated_sibling("temp")?;
        let absolute = root.join(path.to_path_buf());
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_WRITE_THROUGH.0);
        match options.open(&absolute) {
            Ok(file) => return Ok((absolute, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("create atomic temp file", &error)),
        }
    }
    Err(Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::TargetConflict,
        "A unique atomic temp file could not be created",
    )))
}

fn unused_sibling(
    destination: &SafePath,
    root: &Path,
    role: &str,
) -> Result<(SafePath, PathBuf), Box<ErrorEnvelope>> {
    for _ in 0..GENERATED_NAME_ATTEMPTS {
        let path = destination.generated_sibling(role)?;
        let absolute = root.join(path.to_path_buf());
        match fs::symlink_metadata(&absolute) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((path, absolute)),
            Ok(_) => continue,
            Err(error) => return Err(io_error("inspect generated sibling path", &error)),
        }
    }
    Err(Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::TargetConflict,
        "A unique backup file name could not be created",
    )))
}

fn apply_selected_attributes(
    path: &Path,
    attributes: FileAttributes,
) -> Result<(), Box<ErrorEnvelope>> {
    let wide = wide_path(path);
    unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), attributes.windows_bits()) }
        .map_err(|error| windows_error("apply selected file attributes", &error))
}

fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && !is_reparse_point(&metadata)
            && metadata.file_attributes() & FILE_ATTRIBUTE_READONLY.0 != 0
        {
            let mut bits = metadata.file_attributes() & !FILE_ATTRIBUTE_READONLY.0;
            if bits == 0 {
                bits = FILE_ATTRIBUTE_NORMAL.0;
            }
            let wide = wide_path(&self.path);
            let _ = unsafe {
                SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(bits))
            };
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn invalid_path_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(ReforgeErrorCode::InvalidPath, "The file path is not safe")
            .with_technical_detail(detail),
    )
}

fn reparse_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::ReparsePoint,
            "The file operation stopped at a reparse point",
        )
        .with_technical_detail(detail),
    )
}

fn security_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "The filesystem safety limit was exceeded",
        )
        .with_technical_detail(detail),
    )
}

fn verification_error(detail: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(
            ReforgeErrorCode::VerificationFailed,
            "The file content did not match its expected identity",
        )
        .with_technical_detail(detail),
    )
}

fn io_error(operation: &str, error: &io::Error) -> Box<ErrorEnvelope> {
    let code = error
        .raw_os_error()
        .map(|value| classify_win32(value as u32))
        .unwrap_or_else(|| reforge_domain::classify_io_error(error.kind()));
    Box::new(
        ErrorEnvelope::new(code, format!("{operation} failed"))
            .with_technical_detail(error.to_string()),
    )
}

fn windows_error(operation: &str, error: &windows::core::Error) -> Box<ErrorEnvelope> {
    let hresult = error.code().0 as u32;
    let raw = if hresult & 0xFFFF_0000 == 0x8007_0000 {
        hresult & 0xFFFF
    } else {
        hresult
    };
    Box::new(
        ErrorEnvelope::new(classify_win32(raw), format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT 0x{hresult:08X}")),
    )
}

fn classify_win32(code: u32) -> ReforgeErrorCode {
    match code {
        value if value == ERROR_SHARING_VIOLATION.0 || value == ERROR_LOCK_VIOLATION.0 => {
            ReforgeErrorCode::FileLocked
        }
        value if value == ERROR_FILE_NOT_FOUND.0 || value == ERROR_PATH_NOT_FOUND.0 => {
            ReforgeErrorCode::PathNotFound
        }
        value if value == ERROR_ACCESS_DENIED.0 => ReforgeErrorCode::AccessDenied,
        value if value == ERROR_ALREADY_EXISTS.0 || value == ERROR_FILE_EXISTS.0 => {
            ReforgeErrorCode::TargetConflict
        }
        value if value == ERROR_INVALID_NAME.0 => ReforgeErrorCode::InvalidPath,
        _ => ReforgeErrorCode::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::FixtureRoot;
    use std::{io::Cursor, os::windows::fs::symlink_dir, process::Command};

    fn write_spec(bytes: &[u8]) -> AtomicWriteSpec {
        AtomicWriteSpec {
            expected_bytes: bytes.len() as u64,
            expected_blake3: *blake3::hash(bytes).as_bytes(),
            attributes: FileAttributes::default(),
        }
    }
    fn create_directory_reparse(target: &Path, link: &Path) {
        if symlink_dir(target, link).is_ok() {
            return;
        }
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/j"])
            .arg(link)
            .arg(target)
            .output()
            .expect("cmd.exe must be available on the Windows test host");
        assert!(
            output.status.success(),
            "junction fixture creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn safe_path_rejects_traversal_roots_drives_and_devices() {
        for unsafe_path in [
            "../escape",
            "a/../escape",
            r"C:\escape",
            r"\\server\share\escape",
            "/absolute",
            r"\absolute",
            "stream:name",
            "NUL.txt",
            "trailing. ",
        ] {
            assert!(SafePath::new(unsafe_path).is_err(), "{unsafe_path}");
        }
        let path = SafePath::new(r"Config\.\Editor/settings.json").unwrap();
        assert_eq!(path.as_str(), "Config/Editor/settings.json");
        assert_eq!(path.comparison_key(), "config/editor/settings.json");
    }

    #[test]
    fn walker_records_but_does_not_follow_reparse_points() {
        let fixture = FixtureRoot::new("reparse-walk").unwrap();
        let walk_root = fixture.create_dir("walk").unwrap();
        fixture.write_file("walk/safe.txt", b"safe").unwrap();
        let outside = fixture.create_dir("outside").unwrap();
        fixture.write_file("outside/secret.txt", b"secret").unwrap();
        let link = walk_root.join("linked");
        create_directory_reparse(&outside, &link);

        let observations = walk_reparse_safe(
            &walk_root,
            WalkLimits {
                max_entries: 16,
                max_depth: 8,
            },
        )
        .unwrap();
        assert!(observations.iter().any(|entry| {
            entry.path.as_str() == "linked" && entry.kind == FileObservationKind::ReparsePoint
        }));
        assert!(
            observations
                .iter()
                .all(|entry| entry.path.as_str() != "linked/secret.txt")
        );
        let through_link = SafePath::new("linked/secret.txt").unwrap();
        let read_error = BoundedFileReader::open(&walk_root, &through_link, 1024)
            .err()
            .expect("bounded reads through a reparse point must fail");
        assert_eq!(read_error.code, ReforgeErrorCode::ReparsePoint);
        let write_error = atomic_replace(
            &walk_root,
            &through_link,
            Cursor::new(b"changed"),
            write_spec(b"changed"),
        )
        .unwrap_err();
        assert_eq!(write_error.code, ReforgeErrorCode::ReparsePoint);
    }

    struct CountingWriter {
        bytes: u64,
        largest_write: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes += buffer.len() as u64;
            self.largest_write = self.largest_write.max(buffer.len());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bounded_reader_streams_large_files_in_fixed_chunks() {
        let fixture = FixtureRoot::new("bounded-large").unwrap();
        let bytes = vec![0x5a; STREAM_BUFFER_BYTES * 3 + 17];
        fixture.write_file("large.bin", &bytes).unwrap();
        let path = SafePath::new("large.bin").unwrap();
        let mut reader =
            BoundedFileReader::open(fixture.root(), &path, bytes.len() as u64).unwrap();
        let mut writer = CountingWriter {
            bytes: 0,
            largest_write: 0,
        };
        let summary = reader.stream_into(&mut writer).unwrap();
        assert_eq!(summary.bytes, bytes.len() as u64);
        assert_eq!(summary.blake3, *blake3::hash(&bytes).as_bytes());
        assert_eq!(writer.bytes, bytes.len() as u64);
        assert!(writer.largest_write <= STREAM_BUFFER_BYTES);
    }

    #[test]
    fn atomic_replace_keeps_destination_backup() {
        let fixture = FixtureRoot::new("atomic-backup").unwrap();
        fixture.write_file("config/settings.json", b"old").unwrap();
        let destination = SafePath::new("config/settings.json").unwrap();
        let new_bytes = b"new-content";

        let result = atomic_replace(
            fixture.root(),
            &destination,
            Cursor::new(new_bytes),
            write_spec(new_bytes),
        )
        .unwrap();
        assert_eq!(
            fixture.read_file("config/settings.json").unwrap(),
            new_bytes
        );
        assert_eq!(
            FileAttributes::from_metadata(
                &fs::metadata(fixture.root().join("config/settings.json")).unwrap(),
            ),
            FileAttributes::default()
        );
        let backup = result
            .backup
            .expect("existing destination must be backed up");
        assert_eq!(
            fs::read(fixture.root().join(backup.path.to_path_buf())).unwrap(),
            b"old"
        );
    }
    #[test]
    fn hash_mismatch_never_replaces_destination() {
        let fixture = FixtureRoot::new("atomic-hash-mismatch").unwrap();
        fixture.write_file("state.txt", b"original").unwrap();
        let destination = SafePath::new("state.txt").unwrap();
        let expected = b"expected";
        let actual = b"tampered";

        let error = atomic_replace(
            fixture.root(),
            &destination,
            Cursor::new(actual),
            write_spec(expected),
        )
        .unwrap_err();
        assert_eq!(error.code, ReforgeErrorCode::VerificationFailed);
        assert_eq!(fixture.read_file("state.txt").unwrap(), b"original");
        assert!(fs::read_dir(fixture.root()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".reforge-temp-")
        }));
    }

    struct InterruptedReader {
        emitted: bool,
    }

    impl Read for InterruptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "fixture interruption",
                ));
            }
            self.emitted = true;
            let chunk = b"partial";
            buffer[..chunk.len()].copy_from_slice(chunk);
            Ok(chunk.len())
        }
    }

    #[test]
    fn interrupted_temp_write_leaves_destination_and_no_temp_file() {
        let fixture = FixtureRoot::new("atomic-interrupted").unwrap();
        fixture.write_file("state.txt", b"original").unwrap();
        let destination = SafePath::new("state.txt").unwrap();
        let expected = b"partial-and-complete";

        let error = atomic_replace(
            fixture.root(),
            &destination,
            InterruptedReader { emitted: false },
            write_spec(expected),
        )
        .unwrap_err();
        assert_eq!(error.code, ReforgeErrorCode::Interrupted);
        assert_eq!(fixture.read_file("state.txt").unwrap(), b"original");
        assert!(fs::read_dir(fixture.root()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".reforge-temp-")
        }));
    }

    #[test]
    fn locked_destination_returns_file_locked_without_overwrite() {
        let fixture = FixtureRoot::new("atomic-locked").unwrap();
        let locked = fixture.locked_file("locked.txt", b"original").unwrap();
        let destination = SafePath::new("locked.txt").unwrap();
        let replacement = b"replacement";

        let error = atomic_replace(
            fixture.root(),
            &destination,
            Cursor::new(replacement),
            write_spec(replacement),
        )
        .unwrap_err();
        assert_eq!(error.code, ReforgeErrorCode::FileLocked);
        locked.unlock();
        assert_eq!(fixture.read_file("locked.txt").unwrap(), b"original");
    }
}
