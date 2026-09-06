//! Windows platform integration boundary for Reforge.
//!
//! Platform adapters expose typed, read-only host observations. Absolute
//! paths remain local to this crate and are resolved from domain path tokens.

mod appx;
mod features;
mod fs;
mod keyboard;
mod known_folders;
mod pe;
mod privilege;
mod process;
mod registry;
mod services;
mod shell_links;
mod startup;
mod tasks;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../tests/fixtures/mod.rs"]
pub(crate) mod fixtures;
pub use appx::{
    AppxAccessError, AppxOperation, AppxPackageObservation, AppxPackageSnapshot,
    enumerate_current_user_appx_packages,
};
pub use features::{FeatureObservation, FeatureState, feature_probe_command, parse_feature_output};
pub use fs::{
    AtomicReplaceResult, AtomicWriteSpec, BackupRecord, BoundedFileReader, FileAttributes,
    FileObservation, FileObservationKind, SafePath, StreamSummary, WalkLimits, atomic_replace,
    publish_new_file, walk_reparse_safe,
};
pub use keyboard::is_physical_c_key;
pub use known_folders::{
    HostPreflight, KnownFolderAccessError, KnownFolderMap, collect_host_facts, host_preflight,
};
pub use pe::{FileVersion, PeMetadata, SignatureInfo, SignerStatus, inspect_pe};
pub use privilege::{
    ElevationOutcome, ElevationRequest, PrivilegeBroker, RejectionReason,
    relaunch_current_process_elevated,
};
pub use process::{
    BuiltinExecutable, CancellationToken, CommandSpec, ProcessResult, ProcessRunner,
    TrustedExecutable,
};
pub use registry::{
    RegistryAccessError, RegistryKeyObservation, RegistryOperation, RegistryQuery, RegistryRoot,
    RegistryScope, RegistrySnapshot, RegistryTextValue, RegistryValueData,
    RegistryValueObservation, RegistryValueType, RegistryView, enumerate_registry,
    enumerate_registry_with,
};
pub use services::{
    ServiceAccessError, ServiceObservation, ServiceOperation, ServiceSnapshot, ServiceStartMode,
    ServiceState, enumerate_services,
};
pub use shell_links::{
    DefaultAssociationAccessError, DefaultAssociationKind, DefaultAssociationObservation,
    DefaultAssociationOperation, DefaultAssociationSnapshot, ShellLinkAccessError,
    ShellLinkObservation, ShellLinkOperation, ShellLinkSnapshot, enumerate_default_associations,
    enumerate_shell_links, is_shortcut_path,
};
pub use startup::{
    StartupAccessError, StartupEntryObservation, StartupEntrySnapshot, StartupOperation,
    enumerate_startup_entries,
};
pub use tasks::{
    ScheduledTaskObservation, ScheduledTaskState, TaskAccessError, TaskOperation, TaskSnapshot,
    enumerate_scheduled_tasks,
};
