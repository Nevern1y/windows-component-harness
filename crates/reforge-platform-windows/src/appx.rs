//! Read-only current-user AppX/MSIX package discovery.
//!
//! This module deliberately records only safe package identity and display
//! metadata. It never exposes package install paths, package full names, or
//! registration commands as restore instructions.

use reforge_domain::{ErrorEnvelope, RedactionPolicy, ReforgeErrorCode};
use windows::{
    ApplicationModel::Package,
    Management::Deployment::PackageManager,
    Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    core::{Error as WindowsError, HSTRING},
};

const MAX_APPX_PACKAGES: usize = 20_000;
const MAX_PACKAGE_METADATA_BYTES: usize = 512;

/// A safe, current-user AppX/MSIX package observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppxPackageObservation {
    pub package_name: String,
    pub package_family: String,
    pub display_name: Option<String>,
    pub publisher: Option<String>,
}

/// The AppX/WinRT operation that failed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AppxOperation {
    InitializeRuntime,
    CreatePackageManager,
    EnumeratePackages,
    ReadPackage,
    ReadPackageId,
    ReadPackageMetadata,
}

/// A bounded, redacted AppX discovery failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppxAccessError {
    pub package_family: Option<String>,
    pub operation: AppxOperation,
    pub hresult: u32,
    pub error: ErrorEnvelope,
}

/// Deterministic result of current-user AppX/MSIX enumeration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppxPackageSnapshot {
    pub observations: Vec<AppxPackageObservation>,
    pub errors: Vec<AppxAccessError>,
}

/// Enumerate current-user AppX/MSIX packages through the WinRT package API.
///
/// Each package is independent: failure to read one package's metadata does
/// not prevent observations for the remaining packages. The result never
/// contains package locations, full names, or installer/activation commands.
pub fn enumerate_current_user_appx_packages() -> AppxPackageSnapshot {
    let mut snapshot = AppxPackageSnapshot::default();

    // Keep the apartment alive until PackageManager and its WinRT iterators drop.
    let _apartment = match WinRtApartment::initialize() {
        Ok(apartment) => apartment,
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::InitializeRuntime, error));
            return snapshot;
        }
    };

    let manager = match PackageManager::new() {
        Ok(manager) => manager,
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::CreatePackageManager, error));
            return snapshot;
        }
    };
    // WinRT names FindPackagesForUser as FindPackagesByUserSecurityId in the
    // generated Rust binding. An empty selector means the current user and is
    // intentionally kept only on this stack frame.
    let current_user = HSTRING::new();
    let packages = match manager.FindPackagesByUserSecurityId(&current_user) {
        Ok(packages) => packages,
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::EnumeratePackages, error));
            return snapshot;
        }
    };
    let iterator = match packages.First() {
        Ok(iterator) => iterator,
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::EnumeratePackages, error));
            return snapshot;
        }
    };

    let mut inspected = 0usize;
    loop {
        let has_current = match iterator.HasCurrent() {
            Ok(value) => value,
            Err(error) => {
                snapshot
                    .errors
                    .push(appx_error(None, AppxOperation::EnumeratePackages, error));
                break;
            }
        };
        if !has_current {
            break;
        }
        if inspected >= MAX_APPX_PACKAGES {
            snapshot.errors.push(limit_error());
            break;
        }
        inspected += 1;

        match iterator.Current() {
            Ok(package) => collect_package(&mut snapshot, &package),
            Err(error) => snapshot
                .errors
                .push(appx_error(None, AppxOperation::ReadPackage, error)),
        }

        match iterator.MoveNext() {
            Ok(_) => {}
            Err(error) => {
                snapshot
                    .errors
                    .push(appx_error(None, AppxOperation::EnumeratePackages, error));
                break;
            }
        }
    }

    snapshot.sort_deterministically();
    snapshot
}

fn collect_package(snapshot: &mut AppxPackageSnapshot, package: &Package) {
    let package_id = match package.Id() {
        Ok(package_id) => package_id,
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::ReadPackageId, error));
            return;
        }
    };
    let package_name = match package_id.Name() {
        Ok(value) => match safe_package_identifier(&value.to_string()) {
            Some(value) => value,
            None => {
                snapshot.errors.push(invalid_metadata_error(
                    None,
                    "PackageId.Name was not a safe package identifier",
                ));
                return;
            }
        },
        Err(error) => {
            snapshot
                .errors
                .push(appx_error(None, AppxOperation::ReadPackageId, error));
            return;
        }
    };
    let package_family = match package_id.FamilyName() {
        Ok(value) => match safe_package_identifier(&value.to_string()) {
            Some(value) => value,
            None => {
                snapshot.errors.push(invalid_metadata_error(
                    Some(package_name),
                    "PackageId.FamilyName was not a safe package identifier",
                ));
                return;
            }
        },
        Err(error) => {
            snapshot.errors.push(appx_error(
                Some(package_name),
                AppxOperation::ReadPackageId,
                error,
            ));
            return;
        }
    };

    let display_name = read_optional_metadata(
        snapshot,
        &package_family,
        package.DisplayName(),
        "Package.DisplayName",
    );
    let publisher = read_optional_metadata(
        snapshot,
        &package_family,
        package.PublisherDisplayName(),
        "Package.PublisherDisplayName",
    );

    snapshot.observations.push(AppxPackageObservation {
        package_name,
        package_family,
        display_name,
        publisher,
    });
}

fn read_optional_metadata(
    snapshot: &mut AppxPackageSnapshot,
    package_family: &str,
    value: windows::core::Result<windows::core::HSTRING>,
    property: &str,
) -> Option<String> {
    match value {
        Ok(value) => {
            let value = safe_metadata_text(&value.to_string());
            if value.is_none() {
                snapshot.errors.push(invalid_metadata_error(
                    Some(package_family.to_owned()),
                    property,
                ));
            }
            value
        }
        Err(error) => {
            snapshot.errors.push(appx_error(
                Some(package_family.to_owned()),
                AppxOperation::ReadPackageMetadata,
                error,
            ));
            None
        }
    }
}

fn safe_package_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_PACKAGE_METADATA_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then(|| value.to_owned())
}

fn safe_metadata_text(value: &str) -> Option<String> {
    RedactionPolicy::with_max_bytes(MAX_PACKAGE_METADATA_BYTES)
        .redact_text(value.trim())
        .filter(|value| !value.is_empty())
}

fn appx_error(
    package_family: Option<String>,
    operation: AppxOperation,
    error: WindowsError,
) -> AppxAccessError {
    let hresult = error.code().0 as u32;
    AppxAccessError {
        package_family,
        operation,
        hresult,
        error: ErrorEnvelope::new(
            classify_hresult(hresult),
            "Windows AppX/MSIX package discovery failed",
        )
        .with_technical_detail(format!("HRESULT 0x{hresult:08X}")),
    }
}

fn invalid_metadata_error(package_family: Option<String>, property: &str) -> AppxAccessError {
    AppxAccessError {
        package_family,
        operation: AppxOperation::ReadPackageMetadata,
        hresult: 0,
        error: ErrorEnvelope::new(
            ReforgeErrorCode::SchemaInvalid,
            "Windows AppX/MSIX package metadata was rejected",
        )
        .with_technical_detail(format!("Rejected metadata property: {property}")),
    }
}

fn limit_error() -> AppxAccessError {
    AppxAccessError {
        package_family: None,
        operation: AppxOperation::EnumeratePackages,
        hresult: 0,
        error: ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "Windows AppX/MSIX package discovery limit was reached",
        )
        .with_technical_detail(format!("Maximum packages: {MAX_APPX_PACKAGES}")),
    }
}

fn classify_hresult(hresult: u32) -> ReforgeErrorCode {
    if hresult & 0xFFFF == 5 {
        ReforgeErrorCode::AccessDenied
    } else {
        ReforgeErrorCode::OperationFailed
    }
}

impl AppxPackageSnapshot {
    fn sort_deterministically(&mut self) {
        self.observations.sort_by(|left, right| {
            (
                &left.package_family,
                &left.package_name,
                &left.display_name,
                &left.publisher,
            )
                .cmp(&(
                    &right.package_family,
                    &right.package_name,
                    &right.display_name,
                    &right.publisher,
                ))
        });
        self.observations
            .dedup_by(|left, right| left.package_family == right.package_family);
        self.errors.sort_by(|left, right| {
            (
                left.package_family.as_deref(),
                left.operation,
                left.hresult,
                &left.error.message,
            )
                .cmp(&(
                    right.package_family.as_deref(),
                    right.operation,
                    right.hresult,
                    &right.error.message,
                ))
        });
    }
}

struct WinRtApartment;

impl WinRtApartment {
    fn initialize() -> windows::core::Result<Self> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map(|_| Self)
    }
}

impl Drop for WinRtApartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_identifiers_reject_command_and_path_shapes() {
        assert_eq!(
            safe_package_identifier("Microsoft.WindowsStore_8wekyb3d8bbwe"),
            Some("Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned())
        );
        assert!(safe_package_identifier(r"C:\\Program Files\\Store").is_none());
        assert!(safe_package_identifier("store --activate").is_none());
        assert!(safe_package_identifier("token=secret").is_none());
    }

    #[test]
    fn package_metadata_is_bounded_and_redacted() {
        assert_eq!(safe_metadata_text("  Store  "), Some("Store".to_owned()));
        let bounded = safe_metadata_text(&"a".repeat(MAX_PACKAGE_METADATA_BYTES + 1))
            .expect("overlong metadata is safely bounded");
        assert!(bounded.len() <= MAX_PACKAGE_METADATA_BYTES);
        assert_ne!(bounded, "a".repeat(MAX_PACKAGE_METADATA_BYTES + 1));
        assert_ne!(
            safe_metadata_text("api_key=secret-value"),
            Some("api_key=secret-value".to_owned())
        );
    }

    #[test]
    fn access_errors_preserve_hresult_without_native_error_text() {
        let error = invalid_metadata_error(
            Some("Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned()),
            "Package.DisplayName",
        );
        assert_eq!(error.error.code, ReforgeErrorCode::SchemaInvalid);
        assert!(!error.error.message.contains("Microsoft.WindowsStore"));
        assert_eq!(
            error.package_family.as_deref(),
            Some("Microsoft.WindowsStore_8wekyb3d8bbwe")
        );
    }
}
