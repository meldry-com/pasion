//! Core data model types for the Pasion authentication service.
//!
//! This crate defines the domain objects that are persisted in the database
//! and shared across the application. Types here are storage-backend agnostic —
//! they describe *what* is stored, not *how*.
//!
//! # Main type categories
//!
//! - **Users** — [`User`], [`BrowserSession`], [`Password`], [`UserEmail`],
//!   [`UserRegistration`], [`UserRecoveryTicket`]
//! - **OAuth 2.0** — [`Client`], [`Session`], [`AuthorizationGrant`],
//!   [`AccessToken`], [`RefreshToken`], [`DeviceCodeGrant`]
//! - **Compatibility** — [`CompatSession`], [`CompatAccessToken`],
//!   [`CompatSsoLogin`] (legacy Matrix login support)
//! - **Upstream SSO** — [`UpstreamOAuthProvider`], [`UpstreamOAuthLink`],
//!   [`UpstreamOAuthAuthorizationSession`]
//! - **Configuration** — [`SiteConfig`], [`PolicyData`], [`AppVersion`]
//! - **Utilities** — [`Clock`], [`BoxClock`], [`BoxRng`]

#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// Clock abstraction for testability (`SystemClock` in production, mock clock in tests).
pub mod clock;
pub(crate) mod compat;
/// OAuth 2.0 client and session models.
pub mod oauth2;
/// Personal access token types.
pub mod personal;
pub(crate) mod policy_data;
mod site_config;
pub(crate) mod tokens;
pub(crate) mod upstream_oauth2;
pub(crate) mod user_agent;
pub(crate) mod users;
mod utils;
mod version;

/// Error when an invalid state transition is attempted.
#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

pub use ulid::Ulid;

pub use self::{
    clock::{Clock, SystemClock},
    compat::{
        CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
        CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device, ToScopeTokenError,
    },
    oauth2::{
        AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
        DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, Pkce, Session, SessionState,
    },
    policy_data::PolicyData,
    site_config::{
        CaptchaConfig, CaptchaService, SessionExpirationConfig, SessionLimitConfig, SiteConfig,
    },
    tokens::{
        AccessToken, AccessTokenState, RefreshToken, RefreshTokenState, TokenFormatError, TokenType,
    },
    upstream_oauth2::{
        UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState,
        UpstreamOAuthLink, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderImportAction,
        UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderLocalpartPreference,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderOnConflict,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderResponseMode,
        UpstreamOAuthProviderSubjectPreference, UpstreamOAuthProviderTokenAuthMethod,
    },
    user_agent::{DeviceType, UserAgent},
    users::{
        Authentication, AuthenticationMethod, BrowserSession, MatrixUser, Password, User,
        UserEmail, UserEmailAuthentication, UserEmailAuthenticationCode, UserRecoverySession,
        UserRecoveryTicket, UserRegistration, UserRegistrationPassword, UserRegistrationToken,
    },
    utils::{BoxClock, BoxRng},
    version::AppVersion,
};
