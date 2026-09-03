#![allow(dead_code)]

#[path = "support.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};

use reforge_discovery::browsers::{
    BrowserAdapter, BrowserDiscoveryInputs, BrowserEvidenceSource, BrowserFamily,
    BrowserRegistration, ChromiumAdapter, FirefoxAdapter,
};
use reforge_domain::{ComponentKind, KnownFolderToken, RestoreStrategy};
use reforge_platform_windows::KnownFolderMap;

use crate::support::fixtures::FixtureRoot;

const CHROMIUM_PROFILE: &[u8] =
    include_bytes!("../../../tests/fixtures/browsers/chromium/profile.json");
const FIREFOX_PROFILE: &[u8] =
    include_bytes!("../../../tests/fixtures/browsers/firefox/profile.json");

fn fixture_context(label: &str) -> (FixtureRoot, KnownFolderMap) {
    let fixture = FixtureRoot::new(label).expect("fixture root");
    let tokens = fixture.tokens();
    let entries = BTreeMap::from([
        (KnownFolderToken::UserProfile, tokens.user_profile.clone()),
        (
            KnownFolderToken::RoamingAppData,
            tokens.roaming_app_data.clone(),
        ),
        (
            KnownFolderToken::LocalAppData,
            tokens.local_app_data.clone(),
        ),
    ]);
    (fixture, KnownFolderMap::from_entries(entries))
}

fn registration(family: BrowserFamily, display_name: &str) -> BrowserRegistration {
    BrowserRegistration {
        family,
        display_name: display_name.to_owned(),
        version: Some("1.0.0".to_owned()),
        executable: None,
        source: BrowserEvidenceSource::Registry,
    }
}

#[test]
fn discovers_browser_families_and_separates_portable_from_protected_state() {
    let (fixture, known_folders) = fixture_context("browser-discovery");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Bookmarks",
            br#"{"roots":{"bookmark_bar":{"children":[]}}}"#,
        )
        .expect("Chrome bookmarks");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Preferences",
            CHROMIUM_PROFILE,
        )
        .expect("Chrome preferences");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Google/Chrome/User Data/Default/Cookies",
            b"protected session data",
        )
        .expect("Chrome protected fixture");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Microsoft/Edge/User Data/Profile 1/Bookmarks",
            b"{}",
        )
        .expect("Edge bookmarks");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Mozilla/Firefox/Profiles/fixture.default/prefs.js",
            b"user_pref(\"browser.startup.homepage\", \"https://example.invalid\");\n",
        )
        .expect("Firefox preferences");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Mozilla/Firefox/Profiles/fixture.default/places.sqlite",
            b"sqlite fixture",
        )
        .expect("Firefox places");
    fixture
        .write_tokenized(
            KnownFolderToken::RoamingAppData,
            "Mozilla/Firefox/Profiles/fixture.default/extensions.json",
            FIREFOX_PROFILE,
        )
        .expect("Firefox extensions");
    fixture
        .write_tokenized(
            KnownFolderToken::LocalAppData,
            "Thorium/User Data/Default/Bookmarks",
            b"{}",
        )
        .expect("Thorium profile");

    let inputs = BrowserDiscoveryInputs {
        registrations: vec![
            registration(BrowserFamily::Chrome, "Google Chrome"),
            registration(BrowserFamily::Edge, "Microsoft Edge"),
        ],
        running_processes: BTreeSet::from(["chrome.exe".to_owned()]),
        default_browser: Some(BrowserFamily::Chrome),
        default_association_queried: true,
    };
    let discovery = BrowserAdapter::new()
        .discover_with_inputs(&known_folders, inputs)
        .expect("browser discovery");
    let evidence_ids = discovery
        .evidence
        .iter()
        .map(|record| record.id.clone())
        .collect::<BTreeSet<_>>();
    assert!(discovery.components.iter().all(|component| {
        component
            .evidence
            .iter()
            .all(|reference| evidence_ids.contains(&reference.id))
    }));
    assert!(discovery.edges.iter().all(|edge| {
        edge.evidence
            .iter()
            .all(|evidence| evidence_ids.contains(evidence))
    }));

    assert_eq!(discovery.default_browser, Some(BrowserFamily::Chrome));
    assert!(discovery.default_association_queried);
    assert!(discovery.profiles.iter().any(|profile| {
        profile.family == BrowserFamily::Chrome && profile.locked && profile.extensions.len() == 2
    }));
    assert!(discovery.profiles.iter().any(|profile| {
        profile.family == BrowserFamily::Edge && !profile.locked && !profile.artifacts.is_empty()
    }));
    assert!(discovery.profiles.iter().any(|profile| {
        profile.family == BrowserFamily::Firefox && profile.extensions.len() == 1
    }));
    assert!(
        discovery
            .installations
            .iter()
            .any(|installation| installation.family == BrowserFamily::Thorium
                && installation.source == BrowserEvidenceSource::Unknown)
    );
    assert!(discovery.components.iter().any(|component| {
        component.kind == ComponentKind::Browser
            && component.display_name == "thorium"
            && component.restore.primary == RestoreStrategy::Manual
    }));
    assert!(
        discovery
            .manual_actions
            .iter()
            .any(|action| action.title.contains("Close the browser"))
    );
    assert!(
        discovery
            .manual_actions
            .iter()
            .any(|action| action.title.contains("Sign in again"))
    );
    assert!(
        discovery
            .artifacts
            .iter()
            .all(|artifact| !artifact.source_path.relative.ends_with("Cookies"))
    );
}

#[test]
fn browser_fixture_parsers_keep_extension_identity_and_reject_bad_json() {
    let chromium = ChromiumAdapter::new()
        .parse_profile_metadata(CHROMIUM_PROFILE)
        .expect("Chromium fixture");
    assert_eq!(chromium.len(), 2);
    assert_eq!(chromium[0].version.as_deref(), Some("1.2.3"));

    let firefox = FirefoxAdapter::new()
        .parse_profile_metadata(FIREFOX_PROFILE)
        .expect("Firefox fixture");
    assert_eq!(firefox.len(), 1);
    assert_eq!(firefox[0].id, "fixture@example.invalid");

    let invalid = ChromiumAdapter::new()
        .parse_profile_metadata(b"{invalid")
        .expect_err("invalid fixture must fail closed");
    assert_eq!(
        invalid.code,
        reforge_domain::ReforgeErrorCode::ProviderParseFailed
    );
}
