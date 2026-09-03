//! Workspace integration-test harness entry point.
//!
//! Feature integration tests should import [`fixtures`] rather than touching
//! the real profile, registry, or host state.

#[path = "../fixtures/mod.rs"]
pub mod fixtures;

pub use fixtures::*;
