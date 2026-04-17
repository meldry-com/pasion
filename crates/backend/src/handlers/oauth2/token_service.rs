//! Business logic for OAuth 2.0 token endpoint grant types.
//!
//! This module extracts the core grant-type handling out of the token endpoint
//! HTTP handler (`oauth2::token`) so that the handler is responsible only for
//! HTTP-level concerns (request parsing, client authentication, metrics,
//! response formatting) while the actual authorization/token logic lives here.

use std::sync::Arc;

use chrono::Duration;
use oauth2_types::{
    pkce::CodeChallengeError,
    requests::{
        AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant, DeviceCodeGrant,
        GrantType, RefreshTokenGrant,
    },
    scope,
};
use pasion_data::{
    AuthorizationGrantStage, BoxRepository, Client, Clock, DeviceCodeGrantState, RepositoryAccess,
    RepositoryError, SiteConfig, TokenType, UrlBuilder,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    user::BrowserSessionRepository,
};
use pasion_i18n::DataLocale;
use pasion_keystore::Keystore;
use pasion_matrix::HomeserverAdmin;
use pasion_policy::Policy;
use pasion_templates::{DeviceNameContext, TemplateContext, Templates};
use thiserror::Error;
use tracing::{debug, info, warn};
use ulid::Ulid;

use crate::{
    handlers::{
        BoundActivityTracker,
        oauth2::{IdTokenSignatureError, generate_id_token, generate_token_pair},
    },
    oidc_client::types::scope::ScopeToken,
};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during authorization code exchange.
#[derive(Debug, Error)]
pub enum AuthorizationCodeExchangeError {
    #[error("client is not authorized to use the authorization_code grant type")]
    UnauthorizedClient(Ulid),

    #[error("authorization grant not found")]
    GrantNotFound,

    #[error("invalid grant {0}")]
    InvalidGrant(Ulid),

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("bad request (missing or mismatched PKCE)")]
    BadRequest,

    #[error("unexpected client {was} (expected {expected})")]
    UnexpectedClient { was: Ulid, expected: Ulid },

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<pasion_i18n::DataError> for AuthorizationCodeExchangeError {
    fn from(e: pasion_i18n::DataError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<pasion_i18n::icu_locid::ParseError> for AuthorizationCodeExchangeError {
    fn from(e: pasion_i18n::icu_locid::ParseError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<pasion_templates::TemplateError> for AuthorizationCodeExchangeError {
    fn from(e: pasion_templates::TemplateError) -> Self {
        Self::Internal(Box::new(e))
    }
}

impl From<IdTokenSignatureError> for AuthorizationCodeExchangeError {
    fn from(e: IdTokenSignatureError) -> Self {
        Self::Internal(Box::new(e))
    }
}

/// Errors that can occur during refresh token exchange.
#[derive(Debug, Error)]
pub enum RefreshTokenExchangeError {
    #[error("client is not authorized to use the refresh_token grant type")]
    UnauthorizedClient(Ulid),

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIdMismatch { expected: Ulid, actual: Ulid },

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error(
        "failed to load the next refresh token ({next:?}) from the previous one ({previous:?})"
    )]
    NoSuchNextRefreshToken { next: Ulid, previous: Ulid },

    #[error(
        "failed to load the access token ({access_token:?}) associated with the next refresh token ({refresh_token:?})"
    )]
    NoSuchNextAccessToken {
        access_token: Ulid,
        refresh_token: Ulid,
    },

    #[error("no access token associated with the refresh token {refresh_token:?}")]
    NoAccessTokenOnRefreshToken { refresh_token: Ulid },

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Errors that can occur during client credentials grant.
#[derive(Debug, Error)]
pub enum ClientCredentialsGrantError {
    #[error("client is not authorized to use the client_credentials grant type")]
    UnauthorizedClient(Ulid),

    #[error("policy denied the request: {0}")]
    DeniedByPolicy(pasion_policy::EvaluationResult),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<pasion_policy::EvaluationError> for ClientCredentialsGrantError {
    fn from(e: pasion_policy::EvaluationError) -> Self {
        Self::Internal(Box::new(e))
    }
}

/// Errors that can occur during device code exchange.
#[derive(Debug, Error)]
pub enum DeviceCodeExchangeError {
    #[error("client is not authorized to use the device_code grant type")]
    UnauthorizedClient(Ulid),

    #[error("grant not found")]
    GrantNotFound,

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIdMismatch { expected: Ulid, actual: Ulid },

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<IdTokenSignatureError> for DeviceCodeExchangeError {
    fn from(e: IdTokenSignatureError) -> Self {
        Self::Internal(Box::new(e))
    }
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/// Exchange an authorization code for tokens.
///
/// Validates the authorization grant state, verifies PKCE if applicable,
/// generates access/refresh tokens (and optionally an ID token), provisions
/// the Matrix device, and marks the grant as exchanged.
///
/// The returned `BoxRepository` must be saved by the caller after recording
/// metrics / activity.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_authorization_code(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverAdmin>,
    templates: &Templates,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), AuthorizationCodeExchangeError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(AuthorizationCodeExchangeError::UnauthorizedClient(
            client.id,
        ));
    }

    let authz_grant = repo
        .oauth2_authorization_grant()
        .find_by_code(&grant.code)
        .await?
        .ok_or(AuthorizationCodeExchangeError::GrantNotFound)?;

    let now = clock.now();

    let session_id = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session_id,
        } => {
            warn!(%exchanged_at, %fulfilled_at, "Authorization code was already exchanged");

            // Ending the session if the token was already exchanged more than 20s ago
            if now - exchanged_at > Duration::microseconds(20 * 1000 * 1000) {
                warn!(oauth_session.id = %session_id, "Ending potentially compromised session");
                let session = repo.oauth2_session().lookup(session_id).await?.ok_or(
                    AuthorizationCodeExchangeError::NoSuchOAuthSession(session_id),
                )?;

                repo.oauth2_session().finish(clock, session).await?;
                repo.save().await?;
            }

            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Pending => {
            warn!("Authorization grant has not been fulfilled yet");
            return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Fulfilled {
            session_id,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::microseconds(10 * 60 * 1000 * 1000) {
                warn!("Code exchange took more than 10 minutes");
                return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
            }

            session_id
        }
    };

    let mut session = repo.oauth2_session().lookup(session_id).await?.ok_or(
        AuthorizationCodeExchangeError::NoSuchOAuthSession(session_id),
    )?;

    // Generate a device name
    let lang: DataLocale = authz_grant.locale.as_deref().unwrap_or("en").parse()?;
    let ctx = DeviceNameContext::new(client.clone(), user_agent.clone()).with_language(lang);
    let device_name = templates.render_device_name(&ctx)?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    // This should never happen, since we looked up in the database using the code
    let code = authz_grant
        .code
        .as_ref()
        .ok_or(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id))?;

    if client.id != session.client_id {
        return Err(AuthorizationCodeExchangeError::UnexpectedClient {
            was: client.id,
            expected: session.client_id,
        });
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => {
            return Err(AuthorizationCodeExchangeError::BadRequest);
        }
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            pkce.verify(verifier)?;
        }
    }

    let Some(user_session_id) = session.user_session_id else {
        tracing::warn!("No user session associated with this OAuth2 session");
        return Err(AuthorizationCodeExchangeError::InvalidGrant(authz_grant.id));
    };

    let browser_session = repo
        .browser_session()
        .lookup(user_session_id)
        .await?
        .ok_or(AuthorizationCodeExchangeError::NoSuchBrowserSession(
            user_session_id,
        ))?;

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = site_config.access_token_ttl;
    let (access_token, refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        Some(generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&authz_grant),
            &browser_session,
            Some(&access_token),
            last_authentication.as_ref(),
        )?)
    } else {
        None
    };

    let mut params = AccessTokenResponse::new(access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.refresh_token)
        .with_scope(session.scope.clone());

    if let Some(id_token) = id_token {
        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    for scope in &*session.scope {
        let s = scope.as_str();
        let device_id = s
            .strip_prefix("urn:matrix:client:device:")
            .or_else(|| s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"));
        if let Some(device_id) = device_id {
            homeserver
                .upsert_device(
                    &browser_session.user.username,
                    device_id,
                    Some(&device_name),
                )
                .await
                .map_err(AuthorizationCodeExchangeError::ProvisionDeviceFailed)?;
        }
    }

    repo.oauth2_authorization_grant()
        .exchange(clock, authz_grant)
        .await?;

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    Ok((params, repo))
}

/// Exchange a refresh token for a new access/refresh token pair.
///
/// Validates the refresh token, handles double-refresh detection (where the
/// client lost the previous response), revokes old tokens, and issues
/// replacements.
#[allow(clippy::too_many_arguments)]
pub async fn handle_refresh_token(
    rng: &mut (impl rand_core::RngCore + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &RefreshTokenGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RefreshTokenExchangeError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(RefreshTokenExchangeError::UnauthorizedClient(client.id));
    }

    let refresh_token = repo
        .oauth2_refresh_token()
        .find_by_token(&grant.refresh_token)
        .await?
        .ok_or(RefreshTokenExchangeError::RefreshTokenNotFound)?;

    let mut session = repo
        .oauth2_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RefreshTokenExchangeError::NoSuchOAuthSession(
            refresh_token.session_id,
        ))?;

    // Let's for now record the user agent on each refresh, that should be
    // responsive enough and not too much of a burden on the database.
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    if !session.is_valid() {
        return Err(RefreshTokenExchangeError::SessionInvalid(session.id));
    }

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RefreshTokenExchangeError::ClientIdMismatch {
            expected: session.client_id,
            actual: client.id,
        });
    }

    if !refresh_token.is_valid() {
        // We're seeing a refresh token that already has been consumed, this might be a
        // double-refresh or a replay attack

        // First, get the next refresh token
        let Some(next_refresh_token_id) = refresh_token.next_refresh_token_id() else {
            // If we don't have a 'next' refresh token, it may just be because this was
            // before we were recording those. Let's just treat it as a replay.
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                refresh_token.id,
            ));
        };

        let Some(next_refresh_token) = repo
            .oauth2_refresh_token()
            .lookup(next_refresh_token_id)
            .await?
        else {
            return Err(RefreshTokenExchangeError::NoSuchNextRefreshToken {
                next: next_refresh_token_id,
                previous: refresh_token.id,
            });
        };

        // Check if the next refresh token was already consumed or not
        if !next_refresh_token.is_valid() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                next_refresh_token.id,
            ));
        }

        // Check if the associated access token was already used
        let Some(access_token_id) = next_refresh_token.access_token_id else {
            // This should in theory not happen: this means an access token got cleaned up,
            // but the refresh token was still valid.
            return Err(RefreshTokenExchangeError::NoAccessTokenOnRefreshToken {
                refresh_token: next_refresh_token.id,
            });
        };

        // Load it
        let next_access_token = repo
            .oauth2_access_token()
            .lookup(access_token_id)
            .await?
            .ok_or(RefreshTokenExchangeError::NoSuchNextAccessToken {
                access_token: access_token_id,
                refresh_token: next_refresh_token_id,
            })?;

        if next_access_token.is_used() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RefreshTokenExchangeError::RefreshTokenInvalid(
                next_refresh_token.id,
            ));
        }

        // Looks like it's a double-refresh, client lost their refresh token on
        // the way back. Let's revoke the unused access and refresh tokens, and
        // issue new ones
        info!(
            oauth2_session.id = %session.id,
            oauth2_client.id = %client.id,
            %refresh_token.id,
            "Refresh token already used, but issued refresh and access tokens are unused. Assuming those were lost; revoking those and reissuing new ones."
        );

        repo.oauth2_access_token()
            .revoke(clock, next_access_token)
            .await?;

        repo.oauth2_refresh_token()
            .revoke(clock, next_refresh_token)
            .await?;
    }

    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    let ttl = site_config.access_token_ttl;
    let (new_access_token, new_refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let refresh_token = repo
        .oauth2_refresh_token()
        .consume(clock, refresh_token, &new_refresh_token)
        .await?;

    if let Some(access_token_id) = refresh_token.access_token_id {
        let access_token = repo.oauth2_access_token().lookup(access_token_id).await?;
        if let Some(access_token) = access_token {
            // If it is a double-refresh, it might already be revoked
            if !access_token.state.is_revoked() {
                repo.oauth2_access_token()
                    .revoke(clock, access_token)
                    .await?;
            }
        }
    }

    let params = AccessTokenResponse::new(new_access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(new_refresh_token.refresh_token)
        .with_scope(session.scope);

    Ok((params, repo))
}

/// Handle a client credentials grant.
///
/// Validates the client's authorization, runs the request through the policy
/// engine, creates a new client-credentials session, and issues an access
/// token (no refresh token for this grant type).
#[allow(clippy::too_many_arguments)]
pub async fn handle_client_credentials(
    rng: &mut (impl rand_core::RngCore + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &ClientCredentialsGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), ClientCredentialsGrantError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(ClientCredentialsGrantError::UnauthorizedClient(client.id));
    }

    // Default to an empty scope if none is provided
    let scope = grant
        .scope
        .clone()
        .unwrap_or_else(|| std::iter::empty::<ScopeToken>().collect());

    // Make the request go through the policy engine
    let res = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: None,
            client,
            session_counts: None,
            scope: &scope,
            grant_type: pasion_policy::GrantType::ClientCredentials,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent: user_agent.clone(),
                ..Default::default()
            },
        })
        .await?;
    if !res.valid() {
        return Err(ClientCredentialsGrantError::DeniedByPolicy(res));
    }

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_client_credentials(rng, clock, client, scope)
        .await?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params = AccessTokenResponse::new(access_token.access_token).with_expires_in(ttl);

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

/// Exchange a device code for tokens.
///
/// Validates the device code grant state, creates an OAuth 2.0 session,
/// generates tokens (including an optional ID token and refresh token),
/// and provisions the Matrix device.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_device_code(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &DeviceCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverAdmin>,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), DeviceCodeExchangeError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(DeviceCodeExchangeError::UnauthorizedClient(client.id));
    }

    let grant = repo
        .oauth2_device_code_grant()
        .find_by_device_code(&grant.device_code)
        .await?
        .ok_or(DeviceCodeExchangeError::GrantNotFound)?;

    // Check that the client match
    if client.id != grant.client_id {
        return Err(DeviceCodeExchangeError::ClientIdMismatch {
            expected: grant.client_id,
            actual: client.id,
        });
    }

    if grant.expires_at < clock.now() {
        return Err(DeviceCodeExchangeError::DeviceCodeExpired);
    }

    let browser_session_id = match &grant.state {
        DeviceCodeGrantState::Pending => {
            return Err(DeviceCodeExchangeError::DeviceCodePending);
        }
        DeviceCodeGrantState::Rejected { .. } => {
            return Err(DeviceCodeExchangeError::DeviceCodeRejected);
        }
        DeviceCodeGrantState::Exchanged { .. } => {
            return Err(DeviceCodeExchangeError::DeviceCodeExchanged);
        }
        DeviceCodeGrantState::Fulfilled {
            browser_session_id, ..
        } => *browser_session_id,
    };

    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or(DeviceCodeExchangeError::NoSuchBrowserSession(
            browser_session_id,
        ))?;

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_browser_session(rng, clock, client, &browser_session, grant.scope.clone())
        .await?;

    repo.oauth2_device_code_grant()
        .exchange(clock, grant, &session)
        .await?;

    // XXX: should we get the user agent from the device code grant instead?
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params =
        AccessTokenResponse::new(access_token.access_token.clone()).with_expires_in(ttl);

    // If the client uses the refresh token grant type, we also generate a refresh
    // token
    if client.grant_types.contains(&GrantType::RefreshToken) {
        let refresh_token_str = TokenType::RefreshToken.generate(rng);

        let refresh_token = repo
            .oauth2_refresh_token()
            .add(rng, clock, &session, &access_token, refresh_token_str)
            .await?;

        params = params.with_refresh_token(refresh_token.refresh_token);
    }

    // If the client asked for an ID token, we generate one
    if session.scope.contains(&scope::OPENID) {
        let id_token = generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            None,
            &browser_session,
            Some(&access_token),
            None,
        )?;

        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    for scope in &*session.scope {
        let s = scope.as_str();
        let device_id = s
            .strip_prefix("urn:matrix:client:device:")
            .or_else(|| s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"));
        if let Some(device_id) = device_id {
            homeserver
                .upsert_device(&browser_session.user.username, device_id, None)
                .await
                .map_err(DeviceCodeExchangeError::ProvisionDeviceFailed)?;
        }
    }

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}
