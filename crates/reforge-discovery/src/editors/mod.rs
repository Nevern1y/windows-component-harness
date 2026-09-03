//! Editor discovery adapters.

pub mod vscode;

pub use vscode::{VSCodeAdapter, VSCodeDiscovery, VSCodeExtension, VSCodeObservations};
