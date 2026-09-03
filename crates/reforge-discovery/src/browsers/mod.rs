//! Browser discovery adapters and profile metadata handling.

pub mod chromium;
pub mod firefox;
pub mod generic;

pub use chromium::ChromiumAdapter;
pub use firefox::FirefoxAdapter;
pub use generic::{
    BrowserActivity, BrowserAdapter, BrowserDiscovery, BrowserDiscoveryInputs,
    BrowserEvidenceSource, BrowserExtension, BrowserFamily, BrowserInstallation, BrowserProfile,
    BrowserRegistration,
};
