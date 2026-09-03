//! Browser portable-subset restore and quiescence checks.
//!
//! Generic planner operations still own the actual tokenized file write/merge.
//! This module narrows browser files to the documented portable subset, checks
//! profile quiescence before delegating, and exposes explicit reauthentication
//! and default-browser actions without touching cookies, logins, sessions, or
//! protected `UserChoice` registry state.

use std::{fs, io, path::Path};

use async_trait::async_trait;
use reforge_domain::{
    ManualAction, ManualActionState, MergePolicy, Operation, OperationKind, PathToken,
    Precondition, ReforgeErrorCode, RiskLevel,
};
use reforge_platform_windows::{CancellationToken, KnownFolderMap};
use serde_json::json;

use super::{ConfigRestoreHandler, FileRestoreHandler, operation_error, resolve_destination};
use crate::{
    ExecutionContext, OperationHandler, OperationOutcome, OperationSatisfaction, RestoreResult,
};

/// Browser handler restricted to the documented portable profile files.
#[derive(Clone, Debug)]
pub struct BrowserRestoreHandler {
    roots: KnownFolderMap,
    files: FileRestoreHandler,
    config: ConfigRestoreHandler,
}

impl BrowserRestoreHandler {
    /// Construct a handler bound to the current target's known-folder map.
    pub fn new(roots: KnownFolderMap) -> Self {
        Self {
            files: FileRestoreHandler::new(roots.clone()),
            config: ConfigRestoreHandler::new(roots.clone()),
            roots,
        }
    }

    /// Return the target roots used for token resolution.
    pub fn roots(&self) -> &KnownFolderMap {
        &self.roots
    }

    /// Return whether an operation targets any documented browser profile
    /// root, including protected items that must be kept out of the generic
    /// file/config path.
    pub fn is_browser_profile_operation(&self, operation: &Operation) -> bool {
        operation_destination(operation).is_some_and(browser_profile_path)
    }

    /// Return whether an operation is a documented browser portable-subset
    /// write.
    pub fn handles_browser_operation(&self, operation: &Operation) -> bool {
        operation_destination(operation)
            .is_some_and(|destination| browser_artifact_kind(destination).is_some())
    }

    /// Restore one browser portable-subset operation after quiescence.
    pub async fn restore_portable_subset(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        let destination = operation_destination(operation).ok_or_else(|| {
            operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "browser handler received an unsupported operation kind",
            )
        })?;
        let Some(kind) = browser_artifact_kind(destination) else {
            return Ok(unsupported_profile_item(destination));
        };
        validate_browser_operation(operation, kind)?;
        if cancellation.is_cancelled() {
            return Ok(OperationOutcome::cancelled(Some(json!({
                "browser_artifact": kind.label(),
                "cancelled": true,
            }))));
        }
        let destination = resolve_destination(&self.roots, destination)?;
        if let Some(lock) = profile_lock(&destination.absolute, kind)? {
            return Ok(OperationOutcome::waiting_for_user(Some(json!({
                "browser_artifact": kind.label(),
                "destination": destination.relative.as_str(),
                "manual_action_required": true,
                "reauth_required": false,
                "reason": "browser profile is active or locked; close the browser before restore",
                "lock": lock,
            }))));
        }
        match operation.kind {
            OperationKind::WriteFile { .. } => {
                self.files.execute(operation, context, cancellation).await
            }
            OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. } => {
                self.config.execute(operation, context, cancellation).await
            }
            _ => Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "browser handler received an unsupported operation kind",
            )),
        }
    }

    /// Re-check one portable subset item without mutating the profile.
    pub async fn portable_subset_satisfaction(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        let Some(destination) = operation_destination(operation) else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        let Some(kind) = browser_artifact_kind(destination) else {
            return Ok(OperationSatisfaction::NotSatisfied);
        };
        validate_browser_operation(operation, kind)?;
        let destination = resolve_destination(&self.roots, destination)?;
        if profile_lock(&destination.absolute, kind)?.is_some() {
            return Ok(OperationSatisfaction::NotSatisfied);
        }
        match operation.kind {
            OperationKind::WriteFile { .. } => {
                self.files
                    .is_satisfied(operation, context, cancellation)
                    .await
            }
            OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. } => {
                self.config
                    .is_satisfied(operation, context, cancellation)
                    .await
            }
            _ => Ok(OperationSatisfaction::NotSatisfied),
        }
    }

    /// Create the explicit sign-in action required because protected browser
    /// state is never copied.
    pub fn reauth_action(component: reforge_domain::ComponentId) -> ManualAction {
        ManualAction {
            id: format!(
                "browser-reauth-{}",
                blake3::hash(component.as_str().as_bytes()).to_hex()
            ),
            component: Some(component),
            title: "Sign in to the restored browser profile".to_owned(),
            reason: "Cookies, logins, session tokens, and application-bound secrets were excluded"
                .to_owned(),
            risk: RiskLevel::High,
            instructions: vec![
                "Open the browser after portable configuration restore".to_owned(),
                "Sign in through the browser's supported account flow".to_owned(),
            ],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: None,
        }
    }

    /// Create the manual Windows Settings action for default-browser choice.
    /// Reforge never writes the protected UserChoice registry association.
    pub fn default_browser_action(component: reforge_domain::ComponentId) -> ManualAction {
        ManualAction {
            id: format!(
                "browser-default-{}",
                blake3::hash(component.as_str().as_bytes()).to_hex()
            ),
            component: Some(component),
            title: "Choose the default browser in Windows Settings".to_owned(),
            reason: "Protected UserChoice associations are never written automatically".to_owned(),
            risk: RiskLevel::High,
            instructions: vec![
                "Open Windows Settings > Apps > Default apps".to_owned(),
                "Choose the restored browser for the required link and file types".to_owned(),
            ],
            docs_url: None,
            state: ManualActionState::Pending,
            independent_operations_may_continue: true,
            acknowledged_at: None,
            verification: None,
        }
    }
}

/// `BrowserRestoreHandler` is intentionally not directly routable because
/// executor selection is keyed only by operation kind. Register
/// [`BrowserAwareRestoreHandler`] for the generic file/config branches so it
/// can make the path-sensitive browser decision before delegating.
#[async_trait]
impl OperationHandler for BrowserRestoreHandler {
    fn handles(&self, _kind: &OperationKind) -> bool {
        false
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        self.restore_portable_subset(operation, context, cancellation)
            .await
    }
}

/// Routes generic file/config operations through browser safety checks before
/// delegating non-browser destinations to the established generic handlers.
///
/// This is the single handler registered for the generic operation kinds: the
/// executor rejects multiple handlers for one kind, while browser recognition
/// necessarily depends on the operation destination.
#[derive(Clone, Debug)]
pub struct BrowserAwareRestoreHandler {
    browser: BrowserRestoreHandler,
}

impl BrowserAwareRestoreHandler {
    /// Construct the generic operation handler bound to the current target's
    /// known-folder map.
    pub fn new(roots: KnownFolderMap) -> Self {
        Self {
            browser: BrowserRestoreHandler::new(roots),
        }
    }
}

#[async_trait]
impl OperationHandler for BrowserAwareRestoreHandler {
    fn handles(&self, kind: &OperationKind) -> bool {
        matches!(
            kind,
            OperationKind::WriteFile { .. }
                | OperationKind::MergeJson { .. }
                | OperationKind::MergeToml { .. }
        )
    }

    async fn is_satisfied(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationSatisfaction> {
        if self.browser.is_browser_profile_operation(operation) {
            return self
                .browser
                .portable_subset_satisfaction(operation, context, cancellation)
                .await;
        }
        match &operation.kind {
            OperationKind::WriteFile { .. } => {
                self.browser
                    .files
                    .is_satisfied(operation, context, cancellation)
                    .await
            }
            OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. } => {
                self.browser
                    .config
                    .is_satisfied(operation, context, cancellation)
                    .await
            }
            _ => Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "browser-aware handler received an unsupported operation kind",
            )),
        }
    }

    async fn execute(
        &self,
        operation: &Operation,
        context: &ExecutionContext<'_>,
        cancellation: &CancellationToken,
    ) -> RestoreResult<OperationOutcome> {
        if self.browser.is_browser_profile_operation(operation) {
            return self
                .browser
                .restore_portable_subset(operation, context, cancellation)
                .await;
        }
        match &operation.kind {
            OperationKind::WriteFile { .. } => {
                self.browser
                    .files
                    .execute(operation, context, cancellation)
                    .await
            }
            OperationKind::MergeJson { .. } | OperationKind::MergeToml { .. } => {
                self.browser
                    .config
                    .execute(operation, context, cancellation)
                    .await
            }
            _ => Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "browser-aware handler received an unsupported operation kind",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserArtifactKind {
    ChromiumBookmarks,
    ChromiumPreferences,
    FirefoxPreferences,
    FirefoxPlaces,
    FirefoxExtensions,
}

impl BrowserArtifactKind {
    fn label(self) -> &'static str {
        match self {
            Self::ChromiumBookmarks => "chromium-bookmarks",
            Self::ChromiumPreferences => "chromium-preferences",
            Self::FirefoxPreferences => "firefox-preferences",
            Self::FirefoxPlaces => "firefox-places",
            Self::FirefoxExtensions => "firefox-extensions",
        }
    }

    fn is_chromium(self) -> bool {
        matches!(self, Self::ChromiumBookmarks | Self::ChromiumPreferences)
    }
}

fn operation_destination(operation: &Operation) -> Option<&PathToken> {
    match &operation.kind {
        OperationKind::WriteFile { destination, .. }
        | OperationKind::MergeJson { destination, .. }
        | OperationKind::MergeToml { destination, .. } => Some(destination),
        _ => None,
    }
}

fn browser_profile_path(destination: &PathToken) -> bool {
    let normalized = destination.relative.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    chromium_profile_path(&lower) || firefox_profile_path(&lower)
}

fn browser_artifact_kind(destination: &PathToken) -> Option<BrowserArtifactKind> {
    let normalized = destination.relative.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let file = lower.rsplit('/').next()?;
    if chromium_profile_path(&lower) {
        return match file {
            "bookmarks" => Some(BrowserArtifactKind::ChromiumBookmarks),
            "preferences" => Some(BrowserArtifactKind::ChromiumPreferences),
            _ => None,
        };
    }
    if firefox_profile_path(&lower) {
        return match file {
            "prefs.js" => Some(BrowserArtifactKind::FirefoxPreferences),
            "places.sqlite" => Some(BrowserArtifactKind::FirefoxPlaces),
            "extensions.json" => Some(BrowserArtifactKind::FirefoxExtensions),
            _ => None,
        };
    }
    None
}

fn chromium_profile_path(path: &str) -> bool {
    [
        "google/chrome/user data/",
        "microsoft/edge/user data/",
        "chromium/user data/",
        "thorium/user data/",
    ]
    .into_iter()
    .any(|root| {
        path.contains(root)
            && (path.contains("/default/")
                || path.split('/').any(|segment| {
                    segment.strip_prefix("profile ").is_some_and(|value| {
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                    })
                }))
    })
}

fn firefox_profile_path(path: &str) -> bool {
    path.contains("mozilla/firefox/profiles/")
}

fn validate_browser_operation(
    operation: &Operation,
    kind: BrowserArtifactKind,
) -> RestoreResult<()> {
    match (&operation.kind, kind) {
        (
            OperationKind::MergeJson {
                policy:
                    MergePolicy::PreserveUnknown
                    | MergePolicy::AppendUnique
                    | MergePolicy::ManualOnConflict,
                ..
            },
            BrowserArtifactKind::ChromiumBookmarks
            | BrowserArtifactKind::ChromiumPreferences
            | BrowserArtifactKind::FirefoxExtensions,
        ) => Ok(()),
        (OperationKind::WriteFile { .. }, BrowserArtifactKind::FirefoxPreferences)
        | (OperationKind::WriteFile { .. }, BrowserArtifactKind::FirefoxPlaces)
        | (OperationKind::WriteFile { .. }, BrowserArtifactKind::ChromiumBookmarks) => Ok(()),
        (OperationKind::MergeToml { .. }, _) => Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "browser portable subset does not contain TOML configuration",
        )),
        (OperationKind::MergeJson { .. }, BrowserArtifactKind::FirefoxPreferences)
        | (OperationKind::MergeJson { .. }, BrowserArtifactKind::FirefoxPlaces) => {
            Err(operation_error(
                ReforgeErrorCode::SchemaInvalid,
                "this browser artifact is not a JSON merge target",
            ))
        }
        (OperationKind::MergeJson { .. }, _) => Err(operation_error(
            ReforgeErrorCode::SecurityPolicy,
            "browser JSON replacement policy could overwrite protected target state",
        )),
        _ => Err(operation_error(
            ReforgeErrorCode::SchemaInvalid,
            "browser handler received an unsupported operation kind",
        )),
    }
}

fn profile_lock(
    destination: &Path,
    kind: BrowserArtifactKind,
) -> RestoreResult<Option<&'static str>> {
    let Some(profile) = destination.parent() else {
        return Err(operation_error(
            ReforgeErrorCode::InvalidPath,
            "browser artifact has no profile directory",
        ));
    };
    let root = if kind.is_chromium() {
        profile.parent().unwrap_or(profile)
    } else {
        profile
    };
    let lock_names: &[&str] = if kind.is_chromium() {
        &[
            "SingletonLock",
            "SingletonCookie",
            "SingletonSocket",
            "LOCK",
        ]
    } else {
        &["parent.lock", ".parentlock", "lock"]
    };
    for name in lock_names {
        for base in [profile, root] {
            let candidate = base.join(name);
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                    return Ok(Some(name));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Box::new(reforge_domain::ErrorEnvelope::from_io_error(
                        &error,
                        "inspect browser profile lock",
                    )));
                }
            }
        }
    }
    Ok(None)
}

fn unsupported_profile_item(destination: &PathToken) -> OperationOutcome {
    OperationOutcome::waiting_for_user(Some(json!({
        "changed": false,
        "destination": destination.relative,
        "manual_action_required": true,
        "reauth_required": true,
        "reason": "browser profile item is outside the documented portable subset",
    })))
}

/// Create a typed manual-action operation for the default-browser association.
pub fn default_browser_operation(template: &Operation, action: ManualAction) -> Operation {
    Operation {
        id: template.id.clone(),
        component: template.component.clone(),
        kind: OperationKind::OpenManualAction { action },
        prerequisites: template.prerequisites.clone(),
        precondition: Precondition::Always,
        idempotency_key: template.idempotency_key.clone(),
        verification: Vec::new(),
        requires_elevation: false,
        non_idempotent: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reforge_domain::KnownFolderToken;

    #[test]
    fn recognizes_only_documented_browser_subset_paths() {
        let bookmarks = PathToken::new(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Bookmarks",
        )
        .expect("token");
        let cookie = PathToken::new(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Cookies",
        )
        .expect("token");
        assert_eq!(
            browser_artifact_kind(&bookmarks),
            Some(BrowserArtifactKind::ChromiumBookmarks)
        );
        assert_eq!(browser_artifact_kind(&cookie), None);
        assert!(browser_profile_path(&cookie));
    }

    #[test]
    fn manual_actions_never_claim_protected_state_restore() {
        let component = reforge_domain::ComponentId::new(format!("cmp_{}", "b".repeat(52)))
            .expect("component ID");
        let reauth = BrowserRestoreHandler::reauth_action(component.clone());
        let default = BrowserRestoreHandler::default_browser_action(component);
        assert!(reauth.reason.contains("excluded"));
        assert!(default.reason.contains("never written"));
        assert_eq!(reauth.state, ManualActionState::Pending);
        assert_eq!(default.state, ManualActionState::Pending);
    }
}
