use chrono::Utc;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

use reforge_domain::{
    ArtifactPolicy, Component, ComponentId, ComponentKind, ErrorEnvelope, Portability,
    RestoreStrategy, SelectionInput,
};
use serde::{Deserialize, Serialize};

use super::{
    boxed_error, default_backup_directory, default_backup_path, default_selection, read_json_state,
    state_paths, write_json_state,
};

pub(crate) const LARGE_ARTIFACT_THRESHOLD: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct UiPreferences {
    pub backup_directory: Option<PathBuf>,
    pub last_preset: BackupPreset,
    pub unicode: bool,
    pub all_warnings: bool,
    pub welcomed: bool,
}

impl UiPreferences {
    pub fn load() -> Result<Self, Box<ErrorEnvelope>> {
        let path = state_paths()?.root.join("preferences.json");
        let preferences: Self = match path.try_exists() {
            Ok(false) => return Ok(Self::default()),
            Ok(true) => read_json_state(&path)?,
            Err(error) => {
                return Err(Box::new(ErrorEnvelope::from_io_error(
                    &error,
                    "Read terminal preferences",
                )));
            }
        };
        preferences.validate()?;
        Ok(preferences)
    }

    pub fn save(&self) -> Result<(), Box<ErrorEnvelope>> {
        self.validate()?;
        write_json_state(&state_paths()?.root.join("preferences.json"), self)
    }
    fn validate(&self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(path) = &self.backup_directory else {
            return Ok(());
        };
        if !path.is_absolute() {
            return Err(boxed_error(
                reforge_domain::ReforgeErrorCode::InvalidPath,
                "The backup directory must be an absolute path",
            ));
        }

        let mut candidate = path.as_path();
        loop {
            match fs::symlink_metadata(candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(boxed_error(
                        reforge_domain::ReforgeErrorCode::ReparsePoint,
                        "The backup directory cannot contain a symbolic link or reparse point",
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(boxed_error(
                        reforge_domain::ReforgeErrorCode::InvalidPath,
                        "The backup directory path contains a file instead of a directory",
                    ));
                }
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    candidate = candidate.parent().ok_or_else(|| {
                        boxed_error(
                            reforge_domain::ReforgeErrorCode::InvalidPath,
                            "The backup directory has no existing parent directory",
                        )
                    })?;
                }
                Err(error) => {
                    return Err(Box::new(ErrorEnvelope::from_io_error(
                        &error,
                        "Inspect backup directory",
                    )));
                }
            }
        }
    }

    pub fn backup_directory(&self) -> Result<PathBuf, Box<ErrorEnvelope>> {
        self.backup_directory
            .clone()
            .map(Ok)
            .unwrap_or_else(default_backup_directory)
    }

    pub fn backup_path(&self) -> Result<PathBuf, Box<ErrorEnvelope>> {
        if let Some(directory) = &self.backup_directory {
            let filename = format!("Reforge-{}.reforge", Utc::now().format("%Y-%m-%d-%H%M%S"));
            return Ok(directory.join(filename));
        }
        default_backup_path()
    }
}

/// Cosmetic history only; restore always re-inspects the package itself.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupHistoryRecord {
    pub components: usize,
    pub preset: BackupPreset,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
}

pub(crate) fn backup_history_records()
-> Result<BTreeMap<PathBuf, BackupHistoryRecord>, Box<ErrorEnvelope>> {
    let path = state_paths()?.root.join("backup-history.json");
    if !path
        .try_exists()
        .map_err(|error| Box::new(ErrorEnvelope::from_io_error(&error, "Read backup history")))?
    {
        return Ok(BTreeMap::new());
    }
    read_json_state(&path)
}

pub(crate) fn remember_backup(
    path: &Path,
    components: usize,
    preset: BackupPreset,
) -> Result<(), Box<ErrorEnvelope>> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        Box::new(ErrorEnvelope::from_io_error(
            &error,
            "Inspect completed backup",
        ))
    })?;
    let modified = metadata
        .modified()
        .map_err(|error| Box::new(ErrorEnvelope::from_io_error(&error, "Read backup time")))?;
    let mut records = backup_history_records()?;
    records.retain(|path, _| path.is_file());
    records.insert(
        path.to_owned(),
        BackupHistoryRecord {
            components,
            preset,
            bytes: metadata.len(),
            modified,
        },
    );
    write_json_state(&state_paths()?.root.join("backup-history.json"), &records)
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackupPreset {
    #[default]
    Recommended,
    Developer,
    AiDevelopment,
    AiWorkstation,
    FullSafe,
    Minimal,
    Custom,
}

impl BackupPreset {
    pub const ALL: [Self; 7] = [
        Self::Recommended,
        Self::Developer,
        Self::AiDevelopment,
        Self::AiWorkstation,
        Self::FullSafe,
        Self::Minimal,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Recommended => "Recommended",
            Self::Developer => "Developer PC",
            Self::AiDevelopment => "AI Development",
            Self::AiWorkstation => "AI Workstation",
            Self::FullSafe => "Full Safe Backup",
            Self::Minimal => "Minimal",
            Self::Custom => "Custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CategoryKind {
    Programs,
    DeveloperTools,
    AiHarnesses,
    McpServers,
    Configurations,
    Runtimes,
    Packages,
    Docker,
    Wsl,
    Windows,
    Other,
}

pub(crate) struct Category {
    pub(crate) kind: CategoryKind,
    pub(crate) label: &'static str,
    pub(crate) shortcut: char,
}

pub(crate) fn categories() -> &'static [Category] {
    &[
        Category {
            kind: CategoryKind::Programs,
            label: "Programs",
            shortcut: '1',
        },
        Category {
            kind: CategoryKind::DeveloperTools,
            label: "Developer Tools",
            shortcut: '2',
        },
        Category {
            kind: CategoryKind::AiHarnesses,
            label: "AI Harnesses",
            shortcut: '3',
        },
        Category {
            kind: CategoryKind::McpServers,
            label: "MCP Servers",
            shortcut: '4',
        },
        Category {
            kind: CategoryKind::Configurations,
            label: "Configurations",
            shortcut: '5',
        },
        Category {
            kind: CategoryKind::Runtimes,
            label: "Language Runtimes",
            shortcut: '6',
        },
        Category {
            kind: CategoryKind::Packages,
            label: "Package Manager Packages",
            shortcut: '7',
        },
        Category {
            kind: CategoryKind::Docker,
            label: "Docker",
            shortcut: '8',
        },
        Category {
            kind: CategoryKind::Wsl,
            label: "WSL",
            shortcut: '9',
        },
        Category {
            kind: CategoryKind::Windows,
            label: "Windows Components",
            shortcut: 'A',
        },
        Category {
            kind: CategoryKind::Other,
            label: "Advanced / Manual",
            shortcut: 'M',
        },
    ]
}

pub(crate) fn category_label(kind: CategoryKind) -> &'static str {
    categories()
        .iter()
        .find(|category| category.kind == kind)
        .map(|category| category.label)
        .unwrap_or("Components")
}

pub(crate) fn category_components(components: &[Component], kind: CategoryKind) -> Vec<&Component> {
    let mut output = components
        .iter()
        .filter(|component| component_category(component) == kind)
        .collect::<Vec<_>>();
    output.sort_by(|left, right| {
        left.display_name
            .cmp(&right.display_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    output
}

pub(crate) fn component_category(component: &Component) -> CategoryKind {
    match component.kind {
        ComponentKind::Application
        | ComponentKind::Editor
        | ComponentKind::Browser
        | ComponentKind::Extension => CategoryKind::Programs,
        ComponentKind::Tool | ComponentKind::Shell => CategoryKind::DeveloperTools,
        ComponentKind::Harness
        | ComponentKind::Skill
        | ComponentKind::Agent
        | ComponentKind::Hook
        | ComponentKind::Plugin => CategoryKind::AiHarnesses,
        ComponentKind::McpServer => CategoryKind::McpServers,
        ComponentKind::Configuration
        | ComponentKind::EnvironmentVariable
        | ComponentKind::BrowserProfile
        | ComponentKind::DataArtifact => CategoryKind::Configurations,
        ComponentKind::Runtime => CategoryKind::Runtimes,
        ComponentKind::Package => CategoryKind::Packages,
        ComponentKind::DockerContext | ComponentKind::DockerImage | ComponentKind::DockerVolume => {
            CategoryKind::Docker
        }
        ComponentKind::WslDistribution => CategoryKind::Wsl,
        ComponentKind::SystemFeature | ComponentKind::Service | ComponentKind::ScheduledTask => {
            CategoryKind::Windows
        }
        _ => CategoryKind::Other,
    }
}
pub(crate) fn component_is_catalog_only(component: &Component) -> bool {
    component
        .extensions
        .get("catalog_only")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

pub(crate) fn component_is_safe_for_default(component: &Component) -> bool {
    !component.selection.sensitive
        && !component_is_catalog_only(component)
        && !matches!(
            component.kind,
            ComponentKind::SecretReference | ComponentKind::Hook
        )
        && !component_has_secret_artifact(component)
        && !component_has_large_data(component)
        && !component_is_unknown_binary(component)
}

pub(crate) fn component_is_safely_portable(component: &Component) -> bool {
    component_is_safe_for_default(component)
        && matches!(
            component.restore.portability,
            Portability::Portable | Portability::SupportedExport | Portability::SyncRestorable
        )
}

pub(crate) fn component_has_secret_artifact(component: &Component) -> bool {
    component
        .artifacts
        .iter()
        .any(|artifact| artifact.policy == ArtifactPolicy::SecretReference)
}

pub(crate) fn component_has_large_data(component: &Component) -> bool {
    component.selection.size_bytes > LARGE_ARTIFACT_THRESHOLD
        || component.artifacts.iter().any(|artifact| {
            artifact.policy == ArtifactPolicy::LargeOptIn
                || artifact.size_bytes > LARGE_ARTIFACT_THRESHOLD
        })
}

pub(crate) fn component_is_unknown_binary(component: &Component) -> bool {
    matches!(
        &component.kind,
        ComponentKind::Unknown | ComponentKind::PortableBinary
    ) || component.restore.primary == RestoreStrategy::PortableBinary
        || component
            .artifacts
            .iter()
            .any(|artifact| artifact.policy == ArtifactPolicy::PortableBinary)
}
pub(crate) fn selection_from_ids(ids: &BTreeSet<ComponentId>) -> SelectionInput {
    let components = ids.iter().cloned().collect::<Vec<_>>();
    SelectionInput {
        components,

        artifacts: Vec::new(),
        policy: reforge_domain::SelectionPolicy {
            secrets: reforge_domain::SecretSelectionPolicy::Exclude,
            large_data: reforge_domain::LargeDataSelectionPolicy::Exclude,
            unknown_binaries: reforge_domain::UnknownBinarySelectionPolicy::Exclude,
            max_bytes: None,
        },
    }
}
pub(crate) fn preset_selection(
    graph: &reforge_domain::PackageGraph,
    preset: BackupPreset,
) -> SelectionInput {
    let recommended = default_selection(graph)
        .components
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::new();
    for component in &graph.components {
        if !component_is_safe_for_default(component) {
            continue;
        }
        let category = component_category(component);
        let include = match preset {
            BackupPreset::Recommended => recommended.contains(&component.id),
            BackupPreset::Developer => matches!(
                category,
                CategoryKind::Programs
                    | CategoryKind::DeveloperTools
                    | CategoryKind::Runtimes
                    | CategoryKind::Packages
                    | CategoryKind::Configurations
            ),
            BackupPreset::AiDevelopment => matches!(
                category,
                CategoryKind::AiHarnesses
                    | CategoryKind::McpServers
                    | CategoryKind::Configurations
                    | CategoryKind::Runtimes
                    | CategoryKind::DeveloperTools
            ),
            BackupPreset::AiWorkstation => {
                component_is_safely_portable(component)
                    && (matches!(
                        category,
                        CategoryKind::AiHarnesses
                            | CategoryKind::McpServers
                            | CategoryKind::Configurations
                            | CategoryKind::Runtimes
                            | CategoryKind::DeveloperTools
                            | CategoryKind::Packages
                    ) || component
                        .extensions
                        .get("ai_workstation")
                        .is_some_and(|value| value == &serde_json::Value::Bool(true)))
            }
            BackupPreset::FullSafe => component_is_safely_portable(component),
            BackupPreset::Minimal => {
                recommended.contains(&component.id)
                    && matches!(
                        category,
                        CategoryKind::Programs | CategoryKind::Configurations
                    )
            }
            BackupPreset::Custom => false,
        };
        if include {
            selected.insert(component.id.clone());
        }
    }
    selection_from_ids(&selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_preferences_require_absolute_directories() {
        let preferences = UiPreferences {
            backup_directory: Some(PathBuf::from("backups")),
            ..UiPreferences::default()
        };
        let error = preferences
            .validate()
            .expect_err("relative directory must be rejected");
        assert_eq!(error.code, reforge_domain::ReforgeErrorCode::InvalidPath);
    }

    #[test]
    fn backup_preferences_reject_existing_file_as_directory() {
        let path = std::env::temp_dir().join(format!(
            "reforge-preferences-file-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::write(&path, b"not a directory").expect("create file fixture");
        let preferences = UiPreferences {
            backup_directory: Some(path.clone()),
            ..UiPreferences::default()
        };
        let error = preferences
            .validate()
            .expect_err("file path must be rejected");
        assert_eq!(error.code, reforge_domain::ReforgeErrorCode::InvalidPath);
        fs::remove_file(path).expect("remove file fixture");
    }
}
