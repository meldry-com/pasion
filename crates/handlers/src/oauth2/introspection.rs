use std::{
    collections::BTreeSet,
    sync::{Arc, LazyLock},
};

use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{IntrospectionRequest, IntrospectionResponse},
    scope::{Scope, ScopeToken},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use pasion_data_model::{
    BoxClock, Clock, Device, SystemClock, TokenFormatError, TokenType,
    personal::session::PersonalSessionOwner,
};
use pasion_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use pasion_keystore::Encrypter;
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
    sentry::SentryEventID,
};
use pasion_storage::{
    BoxRepository, BoxRepositoryFactory,
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    user::UserRepository,
};
use salvo::prelude::*;
use thiserror::Error;
use ulid::Ulid;

use crate::{ActivityTracker, METER, impl_from_error_for_route};

static INTROSPECTION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.oauth2.introspection_request")
        .with_description("Number of OAuth 2.0 introspection requests")
        .with_unit("{request}")
        .build()
});

const KIND: Key = Key::from_static_str("kind");
const ACTIVE: Key = Key::from_static_str("active");

#[derive(Debug, Error)]
pub enum RouteError {
    /// An internal error occurred.
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The client could not be found.
    #[error("could not find client")]
    ClientNotFound,

    /// The client is not allowed to introspect.
    #[error("client {0} is not allowed to introspect")]
    NotAllowed(Ulid),

    /// The token type is not the one expected.
    #[error("unexpected token type")]
    UnexpectedTokenType,

    /// The overall token format is invalid.
    #[error("invalid token format")]
    InvalidTokenFormat(#[from] TokenFormatError),

    /// The token could not be found in the database.
    #[error("unknown {0}")]
    UnknownToken(TokenType),

    /// The token is not valid.
    #[error("{0} is not valid")]
    InvalidToken(TokenType),

    /// The OAuth session is not valid.
    #[error("invalid oauth session {0}")]
    InvalidOAuthSession(Ulid),

    /// The OAuth session could not be found in the database.
    #[error("unknown oauth session {0}")]
    CantLoadOAuthSession(Ulid),

    /// The compat session is not valid.
    #[error("invalid compat session {0}")]
    InvalidCompatSession(Ulid),

    /// The compat session could not be found in the database.
    #[error("unknown compat session {0}")]
    CantLoadCompatSession(Ulid),

    /// The personal access token session is not valid.
    #[error("invalid personal access token session {0}")]
    InvalidPersonalSession(Ulid),

    /// The personal access token session could not be found in the database.
    #[error("unknown personal access token session {0}")]
    CantLoadPersonalSession(Ulid),

    /// The Device ID in the compat session can't be encoded as a scope
    #[error("device ID contains characters that are not allowed in a scope")]
    CantEncodeDeviceID(#[from] pasion_data_model::ToScopeTokenError),

    #[error("invalid user {0}")]
    InvalidUser(Ulid),

    #[error("unknown user {0}")]
    CantLoadUser(Ulid),

    #[error("unknown OAuth2 client {0}")]
    CantLoadOAuth2Client(Ulid),

    #[error("bad request")]
    BadRequest,

    #[error("failed to verify token")]
    FailedToVerifyToken(#[source] anyhow::Error),

    #[error(transparent)]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("bearer token presented is invalid")]
    InvalidBearerToken,
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            e @ (Self::Internal(_)
            | Self::CantLoadCompatSession(_)
            | Self::CantLoadOAuthSession(_)
            | Self::CantLoadPersonalSession(_)
            | Self::CantLoadUser(_)
            | Self::CantLoadOAuth2Client(_)
            | Self::FailedToVerifyToken(_)) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ));
            }
            Self::ClientNotFound => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }
            Self::ClientCredentialsVerification(e) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClient)
                        .with_description(e.to_string()),
                ));
            }
            e @ Self::InvalidBearerToken => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(
                    ClientError::from(ClientErrorCode::AccessDenied)
                        .with_description(e.to_string()),
                ));
            }

            Self::UnknownToken(_)
            | Self::UnexpectedTokenType
            | Self::InvalidToken(_)
            | Self::InvalidUser(_)
            | Self::InvalidCompatSession(_)
            | Self::InvalidOAuthSession(_)
            | Self::InvalidPersonalSession(_)
            | Self::InvalidTokenFormat(_)
            | Self::CantEncodeDeviceID(_) => {
                INTROSPECTION_COUNTER.add(1, &[KeyValue::new(ACTIVE.clone(), false)]);
                res.render(Json(INACTIVE));
            }

            Self::NotAllowed(_) => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::AccessDenied)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }
        }

        let sentry_event_id = pasion_salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(pasion_salvo_utils::client_authorization::ClientAuthorizationError);

const INACTIVE: IntrospectionResponse = IntrospectionResponse {
    active: false,
    scope: None,
    client_id: None,
    username: None,
    token_type: None,
    exp: None,
    expires_in: None,
    iat: None,
    nbf: None,
    sub: None,
    aud: None,
    iss: None,
    jti: None,
    device_id: None,
};

const UNSTABLE_API_SCOPE: ScopeToken =
    ScopeToken::from_static("urn:matrix:org.matrix.msc2967.client:api:*");
const STABLE_API_SCOPE: ScopeToken = ScopeToken::from_static("urn:matrix:client:api:*");
const PALPO_ADMIN_SCOPE: ScopeToken = ScopeToken::from_static("urn:palpo:admin:*");

/// Normalize a scope by adding the stable and unstable API scopes equivalents
/// if missing
fn normalize_scope(mut scope: Scope) -> Scope {
    // Here we abuse the fact that the scope is a BTreeSet to not care about
    // duplicates
    let mut to_add = BTreeSet::new();
    for token in &*scope {
        if token == &STABLE_API_SCOPE {
            to_add.insert(UNSTABLE_API_SCOPE);
        } else if token == &UNSTABLE_API_SCOPE {
            to_add.insert(STABLE_API_SCOPE);
        } else if let Some(device) = Device::from_scope_token(token) {
            let tokens = device
                .to_scope_token()
                .expect("from/to scope token rountrip should never fail");
            to_add.extend(tokens);
        }
    }
    scope.append(&mut to_add);
    scope
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.introspection.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(reply) => {
            res.render(Json(reply));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &Depot,
) -> Result<IntrospectionResponse, RouteError> {
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .expect("reqwest::Client not found in depot");
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let homeserver = depot
        .get::<Arc<dyn HomeserverConnection>>("homeserver_connection")
        .expect("HomeserverConnection not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = depot
        .get::<ActivityTracker>("activity_tracker")
        .expect("ActivityTracker not found in depot");

    let clock: BoxClock = Box::new(SystemClock::default());

    let mut repo: BoxRepository = repo_factory.create().await?;

    let ClientAuthorization { credentials, form } =
        ClientAuthorization::<IntrospectionRequest>::extract_from_request(req).await?;

    if let Some(token) = credentials.bearer_token() {
        // If the client presented a bearer token, we check with the homeserver
        // configuration if it is allowed to use the introspection endpoint
        if !homeserver
            .verify_token(token)
            .await
            .map_err(RouteError::FailedToVerifyToken)?
        {
            return Err(RouteError::InvalidBearerToken);
        }
    } else {
        // Otherwise, it presented regular client credentials, so we verify them
        let client = credentials
            .fetch(&mut repo)
            .await?
            .ok_or(RouteError::ClientNotFound)?;

        // Only confidential clients are allowed to introspect
        let method = match &client.token_endpoint_auth_method {
            None | Some(OAuthClientAuthenticationMethod::None) => {
                return Err(RouteError::NotAllowed(client.id));
            }
            Some(c) => c,
        };

        credentials
            .verify(http_client, encrypter, method, &client)
            .await?;
    }

    let Some(form) = form else {
        return Err(RouteError::BadRequest);
    };

    let token = &form.token;
    let token_type = TokenType::check(token)?;
    if let Some(hint) = form.token_type_hint
        && token_type != hint
    {
        return Err(RouteError::UnexpectedTokenType);
    }

    // Not all device IDs can be encoded as scope. On OAuth 2.0 sessions, we
    // don't have this problem, as the device ID *is* already encoded as a scope.
    // But on compatibility sessions, it's possible to have device IDs with
    // spaces in them, or other weird characters.
    // In those cases, we prefer explicitly giving out the device ID as a separate
    // field. The client introspecting tells us whether it supports having the
    // device ID as a separate field through this header.
    let supports_explicit_device_id = req
        .header::<String>("X-Pasion-Supports-Device-Id")
        .map(|v| v == "1")
        .unwrap_or(false);

    // XXX: we should get the IP from the client introspecting the token
    let ip = None;

    let reply = match token_type {
        TokenType::AccessToken => {
            let mut access_token = repo
                .oauth2_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadOAuthSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession(session.id));
            }

            // If this is the first time we're using this token, mark it as used
            if !access_token.is_used() {
                access_token = repo
                    .oauth2_access_token()
                    .mark_used(&clock, access_token)
                    .await?;
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser(user.id));
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "oauth2_access_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            let scope = normalize_scope(session.scope);

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(access_token.jti()),
                device_id: None,
            }
        }

        TokenType::RefreshToken => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::RefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::RefreshToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadOAuthSession(refresh_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession(session.id));
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser(user.id));
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "oauth2_refresh_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            let scope = normalize_scope(session.scope);

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                expires_in: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(refresh_token.jti()),
                device_id: None,
            }
        }

        TokenType::CompatAccessToken => {
            let access_token = repo
                .compat_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatAccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::CompatAccessToken));
            }

            let session = repo
                .compat_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession(session.id));
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser(session.user_id))?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser(user.id))?;
            }

            // Grant the palpo admin scope if the session has the admin flag set.
            let palpo_admin_scope_opt = session.is_palpo_admin.then_some(PALPO_ADMIN_SCOPE);

            // If the client supports explicitly giving the device ID in the response, skip
            // encoding it in the scope
            let device_scope_opt = if supports_explicit_device_id {
                None
            } else {
                session
                    .device
                    .as_ref()
                    .map(Device::to_scope_token)
                    .transpose()?
            };

            let scope = [STABLE_API_SCOPE, UNSTABLE_API_SCOPE]
                .into_iter()
                .chain(device_scope_opt.into_iter().flatten())
                .chain(palpo_admin_scope_opt)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "compat_access_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
                device_id: session.device.map(Device::into),
            }
        }

        TokenType::CompatRefreshToken => {
            let refresh_token = repo
                .compat_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatRefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::CompatRefreshToken));
            }

            let session = repo
                .compat_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession(refresh_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession(session.id));
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser(session.user_id))?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser(user.id))?;
            }

            // Grant the palpo admin scope if the session has the admin flag set.
            let palpo_admin_scope_opt = session.is_palpo_admin.then_some(PALPO_ADMIN_SCOPE);

            // If the client supports explicitly giving the device ID in the response, skip
            // encoding it in the scope
            let device_scope_opt = if supports_explicit_device_id {
                None
            } else {
                session
                    .device
                    .as_ref()
                    .map(Device::to_scope_token)
                    .transpose()?
            };

            let scope = [STABLE_API_SCOPE, UNSTABLE_API_SCOPE]
                .into_iter()
                .chain(device_scope_opt.into_iter().flatten())
                .chain(palpo_admin_scope_opt)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "compat_refresh_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                expires_in: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
                device_id: session.device.map(Device::into),
            }
        }

        TokenType::PersonalAccessToken => {
            let access_token = repo
                .personal_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .personal_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadPersonalSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidPersonalSession(session.id));
            }

            let actor_user = repo
                .user()
                .lookup(session.actor_user_id)
                .await?
                .ok_or(RouteError::CantLoadUser(session.actor_user_id))?;

            if !actor_user.is_valid() {
                return Err(RouteError::InvalidUser(actor_user.id));
            }

            let client_id = match session.owner {
                PersonalSessionOwner::User(owner_user_id) => {
                    let owner_user = repo
                        .user()
                        .lookup(owner_user_id)
                        .await?
                        .ok_or(RouteError::CantLoadUser(owner_user_id))?;

                    if !owner_user.is_valid() {
                        return Err(RouteError::InvalidUser(owner_user.id));
                    }

                    None
                }
                PersonalSessionOwner::OAuth2Client(owner_client_id) => {
                    let owner_client = repo
                        .oauth2_client()
                        .lookup(owner_client_id)
                        .await?
                        .ok_or(RouteError::CantLoadOAuth2Client(owner_client_id))?;

                    // OAuth2 clients are always valid if they're in the database
                    Some(owner_client.client_id.clone())
                }
            };

            activity_tracker
                .record_personal_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "personal_access_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            let scope = normalize_scope(session.scope);

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id,
                username: Some(actor_user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(actor_user.sub),
                aud: None,
                iss: None,
                jti: None,
                device_id: None,
            }
        }
    };

    repo.save().await?;

    Ok(reply)
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
