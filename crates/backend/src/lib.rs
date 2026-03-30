//! Pasion backend — HTTP server, state management, lifecycle, and telemetry.
//!
//! This crate provides the runtime infrastructure for the Pasion platform.
//! It is consumed by the CLI binary (`pasion`) and can also be used to
//! embed Pasion as a library.

pub mod app_state;
pub mod lifecycle;
pub mod server;
pub mod sync;
pub mod telemetry;
pub mod util;

use std::sync::OnceLock;

/// Application version string, set once at startup by the binary crate.
static VERSION: OnceLock<&'static str> = OnceLock::new();

/// Set the application version string.
///
/// Must be called exactly once, before any code that reads `version()`.
/// Typically called from `main()` in the CLI binary.
///
/// # Panics
///
/// Panics if called more than once.
pub fn set_version(v: &'static str) {
    VERSION
        .set(v)
        .expect("pasion_backend::set_version called more than once");
}

/// Get the application version string.
///
/// # Panics
///
/// Panics if [`set_version`] has not been called yet.
pub fn version() -> &'static str {
    VERSION
        .get()
        .expect("pasion_backend::set_version was not called")
}
