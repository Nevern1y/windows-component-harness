//! Shared Reforge application orchestration used by the CLI and Tauri shell.
//!
//! The binary remains the user-facing command surface; this library re-exports
//! the same service implementation so desktop commands cannot drift from CLI
//! behavior.

#[allow(dead_code)]
#[path = "main.rs"]
mod implementation;

pub use implementation::{ApplicationRunDetails, ApplicationService};
