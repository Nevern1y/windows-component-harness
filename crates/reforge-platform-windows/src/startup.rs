//! Read-only Startup-folder discovery.
//!
//! Only direct regular-file entries are observed. Reparse points are never
//! traversed, and `.lnk` files remain owned by the shell-link parser so that a
//! shortcut is not represented twice.

use std::{fs, io, os::windows::fs::MetadataExt};

use reforge_domain::{ErrorEnvelope, KnownFolderToken, PathToken, ReforgeErrorCode};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::{known_folders::KnownFolderMap, shell_links::is_shortcut_path};

const MAX_STARTUP_ENTRIES: usize = 4_096;

/// One direct, non-shortcut file observed in the current user's Startup folder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupEntryObservation {
    /// The relative path is a validated token and is never resolved outside the
    /// Startup known-folder root.
    pub source: PathToken,
}

/// The Startup-folder operation that failed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StartupOperation {
    ResolveRoot,
    InspectRoot,
    EnumerateRoot,
    InspectEntry,
}

/// A bounded error with no raw Startup folder path or entry name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupAccessError {
    pub root: KnownFolderToken,
    pub operation: StartupOperation,
    pub error: ErrorEnvelope,
}

/// Deterministic result of Startup-folder enumeration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StartupEntrySnapshot {
    pub observations: Vec<StartupEntryObservation>,
    pub errors: Vec<StartupAccessError>,
}

/// Enumerate direct regular-file Startup entries without following reparse
/// points. Missing or inaccessible folders become typed errors rather than a
/// panic or an automatic restore action.
pub fn enumerate_startup_entries(known_folders: &KnownFolderMap) -> StartupEntrySnapshot {
    let mut snapshot = StartupEntrySnapshot::default();
    let root_token = KnownFolderToken::Startup;
    let Some(root) = known_folders.entries.get(&root_token) else {
        snapshot.errors.push(StartupAccessError {
            root: root_token,
            operation: StartupOperation::ResolveRoot,
            error: ErrorEnvelope::new(
                ReforgeErrorCode::PathNotFound,
                "Windows Startup folder is unavailable",
            ),
        });
        return snapshot;
    };

    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            snapshot
                .errors
                .push(io_error(&root_token, StartupOperation::InspectRoot, &error));
            return snapshot;
        }
    };
    if root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        snapshot.errors.push(StartupAccessError {
            root: root_token,
            operation: StartupOperation::InspectRoot,
            error: ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "Windows Startup folder reparse point was not traversed",
            ),
        });
        return snapshot;
    }

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            snapshot.errors.push(io_error(
                &root_token,
                StartupOperation::EnumerateRoot,
                &error,
            ));
            return snapshot;
        }
    };

    let mut direct_entries = Vec::new();
    let mut exceeds_entry_limit = false;
    for (entry_count, entry) in entries.enumerate() {
        if entry_count >= MAX_STARTUP_ENTRIES {
            exceeds_entry_limit = true;
            break;
        }
        match entry {
            Ok(entry) => direct_entries.push(entry),
            Err(error) => snapshot.errors.push(io_error(
                &root_token,
                StartupOperation::EnumerateRoot,
                &error,
            )),
        }
    }
    direct_entries.sort_by_key(|entry| entry.file_name());

    for entry in direct_entries {
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                snapshot.errors.push(io_error(
                    &root_token,
                    StartupOperation::InspectEntry,
                    &error,
                ));
                continue;
            }
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            snapshot.errors.push(StartupAccessError {
                root: root_token.clone(),
                operation: StartupOperation::InspectEntry,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "Windows Startup folder reparse point was not traversed",
                ),
            });
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            snapshot.errors.push(StartupAccessError {
                root: root_token.clone(),
                operation: StartupOperation::InspectEntry,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::InvalidPath,
                    "Windows Startup entry name was not valid Unicode",
                ),
            });
            continue;
        };
        if is_shortcut_path(file_name) {
            continue;
        }
        let source = match PathToken::new(root_token.clone(), file_name) {
            Ok(source) => source,
            Err(_) => {
                snapshot.errors.push(StartupAccessError {
                    root: root_token.clone(),
                    operation: StartupOperation::InspectEntry,
                    error: ErrorEnvelope::new(
                        ReforgeErrorCode::InvalidPath,
                        "Windows Startup entry path was rejected",
                    ),
                });
                continue;
            }
        };
        snapshot
            .observations
            .push(StartupEntryObservation { source });
    }

    if exceeds_entry_limit {
        snapshot.errors.push(StartupAccessError {
            root: root_token,
            operation: StartupOperation::EnumerateRoot,
            error: ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "Windows Startup folder discovery limit was reached",
            )
            .with_technical_detail(format!("Maximum direct entries: {MAX_STARTUP_ENTRIES}")),
        });
    }

    snapshot.sort_deterministically();
    snapshot
}

fn io_error(
    root: &KnownFolderToken,
    operation: StartupOperation,
    error: &io::Error,
) -> StartupAccessError {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ReforgeErrorCode::PathNotFound,
        io::ErrorKind::PermissionDenied => ReforgeErrorCode::AccessDenied,
        io::ErrorKind::InvalidInput => ReforgeErrorCode::InvalidPath,
        _ => ReforgeErrorCode::OperationFailed,
    };
    StartupAccessError {
        root: root.clone(),
        operation,
        error: ErrorEnvelope::new(code, "Windows Startup folder discovery failed")
            .with_technical_detail(format!("I/O error kind: {:?}", error.kind())),
    }
}

impl StartupEntrySnapshot {
    fn sort_deterministically(&mut self) {
        self.observations
            .sort_by(|left, right| left.source.relative.cmp(&right.source.relative));
        self.observations
            .dedup_by(|left, right| left.source == right.source);
        self.errors.sort_by(|left, right| {
            (left.root.clone(), left.operation, &left.error.message).cmp(&(
                right.root.clone(),
                right.operation,
                &right.error.message,
            ))
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, os::windows::fs::symlink_dir, path::Path, process::Command};

    use super::*;
    use crate::fixtures::FixtureRoot;

    fn startup_map(root: std::path::PathBuf) -> KnownFolderMap {
        KnownFolderMap::from_entries(BTreeMap::from([(KnownFolderToken::Startup, root)]))
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
    fn startup_discovery_skips_shortcuts_and_never_traverses_reparse_points() {
        let fixture = FixtureRoot::new("startup-discovery").unwrap();
        let startup = fixture.create_dir("startup").unwrap();
        fixture
            .write_file("startup/launch.cmd", b"ignored command text")
            .unwrap();
        fixture
            .write_file("startup/handled.lnk", b"shell-link owner handles this")
            .unwrap();
        fixture.create_dir("startup/nested").unwrap();
        fixture
            .write_file("startup/nested/ignored.cmd", b"must not be traversed")
            .unwrap();
        let target = fixture.create_dir("outside").unwrap();
        fixture
            .write_file("outside/escaped.cmd", b"must not be observed")
            .unwrap();
        create_directory_reparse(&target, &startup.join("outside-link"));

        let snapshot = enumerate_startup_entries(&startup_map(startup));
        assert_eq!(snapshot.observations.len(), 1);
        assert_eq!(snapshot.observations[0].source.relative, "launch.cmd");
        assert!(snapshot.errors.iter().any(|error| {
            error.operation == StartupOperation::InspectEntry
                && error.error.code == ReforgeErrorCode::SecurityPolicy
        }));
    }

    #[test]
    fn unavailable_startup_folder_is_a_typed_failure() {
        let fixture = FixtureRoot::new("startup-errors").unwrap();
        let missing = fixture.path("missing-startup").unwrap();
        let snapshot = enumerate_startup_entries(&startup_map(missing));

        assert!(snapshot.observations.is_empty());
        assert_eq!(snapshot.errors.len(), 1);
        assert_eq!(snapshot.errors[0].operation, StartupOperation::InspectRoot);
        assert_eq!(
            snapshot.errors[0].error.code,
            ReforgeErrorCode::PathNotFound
        );
    }

    #[test]
    fn errors_do_not_disclose_startup_entry_names() {
        let error = io_error(
            &KnownFolderToken::Startup,
            StartupOperation::InspectEntry,
            &io::Error::new(io::ErrorKind::PermissionDenied, "credential-file.cmd"),
        );
        assert!(!error.error.message.contains("credential-file.cmd"));
        assert!(
            !error
                .error
                .technical_detail
                .as_deref()
                .unwrap_or_default()
                .contains("credential-file.cmd")
        );
    }
}
