//! HTTP request handlers for the Pasion authentication service.
//!
//! This module contains all the HTTP handler logic, organized by protocol and
//! concern area:
//!
//! - [`admin`] — Admin API handlers for managing users, sessions, and clients
//! - [`health`] — Health-check endpoint
//! - [`oauth2`] — OAuth 2.0 / OpenID Connect endpoints (token, authorization,
//!   discovery, userinfo, etc.)
//! - [`rest`] — REST API endpoints for the account management frontend (JSON)
//! - [`spa`] — SPA shell handler (serves the Dioxus frontend HTML wrapper)
//! - [`upstream_oauth2`] — Upstream SSO / federated identity provider flows
//! - [`passwords`] — Password hashing and verification utilities
//!
//! All user-facing pages are rendered by the Dioxus frontend (`crates/frontend`).
//! The backend serves only REST API endpoints and the SPA shell.

/// Implement `From<E>` for `RouteError`, for "internal server error" kind of
/// errors.
macro_rules! impl_from_error_for_route {
    ($route_error:ty : $error:ty) => {
        impl From<$error> for $route_error {
            fn from(e: $error) -> Self {
                Self::Internal(Box::new(e))
            }
        }
    };
    ($error:ty) => {
        impl_from_error_for_route!(self::RouteError: $error);
    };
}

use std::sync::LazyLock;

use opentelemetry::metrics::Meter;

/// Admin API handlers (JSON API, cursor-paginated).
pub mod admin;
/// Flow execution engine for multi-step user interaction flows.
pub mod flow;
/// Health-check endpoint (`/health`).
pub mod health;
/// OAuth 2.0 and OpenID Connect protocol endpoints.
pub mod oauth2;
/// Password hashing, verification, and complexity checking.
pub mod passwords;
/// Post-authentication action utilities (shared across handlers).
pub mod post_auth;
/// REST API endpoints consumed by the account-management frontend.
pub mod rest;
/// SPA shell serving (renders the Dioxus frontend HTML wrapper).
pub mod spa;
/// Upstream (federated) OAuth 2.0 / OIDC provider integration.
pub mod upstream_oauth2;
/// Cookie management for user registration sessions.
pub mod user_registration_cookie;

pub(crate) mod admin_audit_helper;
mod account_access;
mod account_connections;
mod account_contacts;
mod account_password;
mod account_profile;
mod account_recovery;
mod account_registration;
mod account_sessions;
mod activity_tracker;
mod captcha;
mod notification_dispatch;
mod notification_language;
mod oauth2_access;
mod oauth2_introspection;
mod oauth2_revocation;
mod oauth2_token_service;
mod preferred_language;
mod rate_limit;
mod session;
#[cfg(test)]
mod test_utils;
mod upstream_link_workflow;

static METER: LazyLock<Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});

pub use crate::salvo_utils::cookies::CookieManager;

pub use self::{
    activity_tracker::{ActivityTracker, Bound as BoundActivityTracker},
    notification_language::notification_language,
    preferred_language::preferred_language,
    rate_limit::{Limiter, RequesterFingerprint},
    upstream_oauth2::cache::MetadataCache,
};
