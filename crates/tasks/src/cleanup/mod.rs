//! Database cleanup tasks
//!
//! Periodic jobs that remove stale rows from the database. Each submodule
//! targets a particular domain:
//!
//! - [`tokens`]: Revoked / expired OAuth access and refresh tokens
//! - [`sessions`]: Finished OAuth2 and browser sessions, plus inactive session IPs
//! - [`oauth`]: Authorization grants, device-code grants, upstream OAuth sessions and links
//! - [`user`]: Abandoned registrations, recovery sessions, email authentication codes
//! - [`misc`]: Completed queue jobs and stale policy data

mod misc;
mod oauth;
mod sessions;
mod tokens;
mod user;

pub(crate) const BATCH_SIZE: usize = 1000;
