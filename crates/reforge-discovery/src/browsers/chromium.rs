//! Chromium-family profile discovery.
//!
//! The adapter follows documented per-user profile roots only. It reads
//! bounded JSON metadata for extension identity and asks the shared artifact
//! collector to classify bookmarks/preferences files. Cookies, login data,
//! session storage, and application-bound secrets are never selected.

use std::collections::BTreeMap;

use reforge_domain::{
    ArtifactPolicy, ErrorEnvelope, KnownFolderToken, PathToken, ReforgeErrorCode,
};
use reforge_platform_windows::KnownFolderMap;
use serde_json::Value;

use super::generic::{
    BrowserExtension, BrowserFamily, ProfileCandidate, direct_child_directories, join_token,
    path_if_file, profile_root_spec, read_bounded,
};

const MAX_EXTENSIONS: usize = 512;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const PROTECTED_STATE: &[&str] = &[
    "Cookies",
    "Login Data",
    "Web Data",
    "History session databases",
    "Session Storage",
    "Local Storage credentials",
    "GPUCache and code cache",
    "browser session and authentication state",
];

/// Public adapter facade for Chromium, Chrome, Edge, and Thorium profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChromiumAdapter;

impl ChromiumAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_profile_metadata(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<BrowserExtension>, Box<ErrorEnvelope>> {
        parse_extensions(bytes)
    }
}

#[derive(Clone, Debug)]
struct ChromiumRoot {
    family: BrowserFamily,
    token: PathToken,
}

pub(super) fn discover_profiles(
    known_folders: &KnownFolderMap,
) -> Result<Vec<ProfileCandidate>, Box<ErrorEnvelope>> {
    let roots = [
        profile_root_spec(
            BrowserFamily::Chrome,
            PathToken::new(KnownFolderToken::LocalAppData, "Google/Chrome/User Data")
                .map_err(|_| invalid_path())?,
        ),
        profile_root_spec(
            BrowserFamily::Edge,
            PathToken::new(KnownFolderToken::LocalAppData, "Microsoft/Edge/User Data")
                .map_err(|_| invalid_path())?,
        ),
        profile_root_spec(
            BrowserFamily::Chromium,
            PathToken::new(KnownFolderToken::LocalAppData, "Chromium/User Data")
                .map_err(|_| invalid_path())?,
        ),
        profile_root_spec(
            BrowserFamily::Thorium,
            PathToken::new(KnownFolderToken::LocalAppData, "Thorium/User Data")
                .map_err(|_| invalid_path())?,
        ),
    ];
    let mut profiles = Vec::new();
    for root in roots {
        profiles.extend(discover_root(
            known_folders,
            ChromiumRoot {
                family: root.family,
                token: root.root,
            },
        )?);
    }
    profiles.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
            .then_with(|| left.path.relative.cmp(&right.path.relative))
    });
    Ok(profiles)
}

fn discover_root(
    known_folders: &KnownFolderMap,
    root: ChromiumRoot,
) -> Result<Vec<ProfileCandidate>, Box<ErrorEnvelope>> {
    let children = direct_child_directories(known_folders, &root.token, 256)?;
    let mut profiles = Vec::new();
    for (name, path) in children {
        if name != "Default"
            && !name
                .strip_prefix("Profile ")
                .is_some_and(|suffix| suffix.chars().all(|character| character.is_ascii_digit()))
        {
            continue;
        }
        let mut artifacts = Vec::new();
        if let Some(artifact) =
            path_if_file(known_folders, &path, "Bookmarks", ArtifactPolicy::Data)
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            path_if_file(known_folders, &path, "Preferences", ArtifactPolicy::Config)
        {
            artifacts.push(artifact);
        }
        let extensions = path_if_file(known_folders, &path, "Preferences", ArtifactPolicy::Config)
            .and_then(|_| read_bounded(known_folders, &join_token(&path, "Preferences").ok()?).ok())
            .filter(|bytes| bytes.len() <= MAX_METADATA_BYTES)
            .and_then(|bytes| parse_extensions(&bytes).ok())
            .unwrap_or_default();
        let mut lock_paths = vec![
            join_token(&root.token, "SingletonLock")?,
            join_token(&root.token, "SingletonCookie")?,
            join_token(&root.token, "SingletonSocket")?,
        ];
        if let Ok(lock) = join_token(&path, "LOCK") {
            lock_paths.push(lock);
        }
        profiles.push(ProfileCandidate {
            family: root.family,
            name,
            path,
            lock_paths,
            artifacts,
            extensions,
            excluded_protected_state: PROTECTED_STATE
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        });
    }
    Ok(profiles)
}

/// Parse Chrome/Chromium `Preferences` extension metadata. The parser accepts
/// both `extensions.settings` maps and simple fixture arrays, while rejecting
/// malformed/untrusted IDs instead of inventing identities.
pub fn parse_extensions(bytes: &[u8]) -> Result<Vec<BrowserExtension>, Box<ErrorEnvelope>> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Chromium profile metadata is not valid JSON",
        ))
    })?;
    let mut extensions = BTreeMap::<String, BrowserExtension>::new();
    if let Some(settings) = value
        .get("extensions")
        .and_then(|extensions| extensions.get("settings"))
        .and_then(Value::as_object)
    {
        for (id, metadata) in settings {
            if !valid_extension_id(id) {
                continue;
            }
            extensions.insert(
                id.clone(),
                BrowserExtension {
                    id: id.clone(),
                    version: metadata
                        .get("manifest")
                        .and_then(|manifest| manifest.get("version"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .or_else(|| {
                            metadata
                                .get("version")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                    name: metadata
                        .get("manifest")
                        .and_then(|manifest| manifest.get("name"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                },
            );
            if extensions.len() >= MAX_EXTENSIONS {
                break;
            }
        }
    }
    if let Some(items) = value.as_array() {
        for item in items {
            let Some(id) = item
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| item.get("extension_id").and_then(Value::as_str))
            else {
                continue;
            };
            if !valid_extension_id(id) {
                continue;
            }
            extensions
                .entry(id.to_owned())
                .or_insert_with(|| BrowserExtension {
                    id: id.to_owned(),
                    version: item
                        .get("version")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    name: item
                        .get("name")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                });
            if extensions.len() >= MAX_EXTENSIONS {
                break;
            }
        }
    }
    Ok(extensions.into_values().collect())
}

fn valid_extension_id(value: &str) -> bool {
    value.len() >= 8
        && value.len() <= 128
        && value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || character == b'_' || character == b'-'
        })
}

fn invalid_path() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::InvalidPath,
        "The documented Chromium profile path could not be tokenized",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extension_settings_without_copying_session_state() {
        let bytes = br#"{
            "extensions": {"settings": {
                "abcdefghijklmnopabcdefghijklmnop": {
                    "manifest": {"name": "Example", "version": "1.2.3"}
                }
            }}
        }"#;
        let extensions = parse_extensions(bytes).expect("metadata parses");
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn malformed_metadata_is_typed_failure() {
        let error = parse_extensions(b"not-json").expect_err("malformed metadata fails");
        assert_eq!(error.code, ReforgeErrorCode::ProviderParseFailed);
    }
}
