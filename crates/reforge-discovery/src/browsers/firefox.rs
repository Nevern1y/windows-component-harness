//! Firefox profile discovery and extension metadata parsing.

use std::collections::BTreeMap;

use reforge_domain::{
    ArtifactPolicy, ErrorEnvelope, KnownFolderToken, PathToken, ReforgeErrorCode,
};
use reforge_platform_windows::KnownFolderMap;
use serde_json::Value;

use super::generic::{
    BrowserExtension, BrowserFamily, ProfileCandidate, direct_child_directories, join_token,
    path_if_file, read_bounded,
};

const MAX_EXTENSIONS: usize = 512;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const PROTECTED_STATE: &[&str] = &[
    "cookies.sqlite",
    "logins.json and key4.db",
    "sessionstore.jsonlz4",
    "formhistory.sqlite",
    "permissions.sqlite authentication state",
    "browser profile lock state",
];

/// Public adapter facade for Firefox profile observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct FirefoxAdapter;

impl FirefoxAdapter {
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

pub(super) fn discover_profiles(
    known_folders: &KnownFolderMap,
) -> Result<Vec<ProfileCandidate>, Box<ErrorEnvelope>> {
    let root = PathToken::new(KnownFolderToken::RoamingAppData, "Mozilla/Firefox/Profiles")
        .map_err(|_| invalid_path())?;
    let children = direct_child_directories(known_folders, &root, 256)?;
    let mut profiles = Vec::new();
    for (name, path) in children {
        let mut artifacts = Vec::new();
        if let Some(artifact) =
            path_if_file(known_folders, &path, "prefs.js", ArtifactPolicy::Config)
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            path_if_file(known_folders, &path, "places.sqlite", ArtifactPolicy::Data)
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) = path_if_file(
            known_folders,
            &path,
            "extensions.json",
            ArtifactPolicy::Config,
        ) {
            artifacts.push(artifact);
        }
        let extensions = path_if_file(
            known_folders,
            &path,
            "extensions.json",
            ArtifactPolicy::Config,
        )
        .and_then(|_| read_bounded(known_folders, &join_token(&path, "extensions.json").ok()?).ok())
        .filter(|bytes| bytes.len() <= MAX_METADATA_BYTES)
        .and_then(|bytes| parse_extensions(&bytes).ok())
        .unwrap_or_default();
        let lock_paths = ["parent.lock", ".parentlock", "lock"]
            .into_iter()
            .filter_map(|name| join_token(&path, name).ok())
            .collect();
        profiles.push(ProfileCandidate {
            family: BrowserFamily::Firefox,
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
    profiles.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });
    Ok(profiles)
}

/// Parse the documented Firefox `extensions.json` add-on inventory.
pub fn parse_extensions(bytes: &[u8]) -> Result<Vec<BrowserExtension>, Box<ErrorEnvelope>> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::ProviderParseFailed,
            "Firefox extension metadata is not valid JSON",
        ))
    })?;
    let Some(addons) = value.get("addons").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut extensions = BTreeMap::<String, BrowserExtension>::new();
    for addon in addons {
        let Some(id) = addon.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !valid_extension_id(id) {
            continue;
        }
        let name = addon
            .get("defaultLocale")
            .and_then(|locale| locale.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                addon
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
        extensions.insert(
            id.to_owned(),
            BrowserExtension {
                id: id.to_owned(),
                version: addon
                    .get("version")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                name,
            },
        );
        if extensions.len() >= MAX_EXTENSIONS {
            break;
        }
    }
    Ok(extensions.into_values().collect())
}

fn valid_extension_id(value: &str) -> bool {
    value.len() <= 512
        && !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn invalid_path() -> Box<ErrorEnvelope> {
    Box::new(ErrorEnvelope::new(
        ReforgeErrorCode::InvalidPath,
        "The documented Firefox profile path could not be tokenized",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addon_inventory_and_keeps_identity_only() {
        let bytes = br#"{"addons":[
            {"id":"example@mozilla.org","version":"4.0","defaultLocale":{"name":"Example"}},
            {"id":"bad id","version":"1"}
        ]}"#;
        let extensions = parse_extensions(bytes).expect("metadata parses");
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].id, "example@mozilla.org");
        assert_eq!(extensions[0].name.as_deref(), Some("Example"));
    }

    #[test]
    fn missing_addons_is_empty_not_an_invented_extension() {
        assert!(
            parse_extensions(br#"{"schemaVersion":33}"#)
                .expect("metadata parses")
                .is_empty()
        );
    }
}
