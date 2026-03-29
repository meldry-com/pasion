use std::sync::{Arc, LazyLock};

use chrono::Duration;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce::CodeChallengeError,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant,
        DeviceCodeGrant, GrantType, RefreshTokenGrant,
    },
    scope,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use pasion_data_model::{
    AuthorizationGrantStage, BoxClock, BoxRng, Client, Clock, DeviceCodeGrantState, SiteConfig,
    SystemClock, TokenType,
};
use pasion_i18n::DataLocale;
use pasion_keystore::{Encrypter, Keystore};
use pasion_matrix::HomeserverConnection;
use pasion_oidc_client::types::scope::ScopeToken;
use pasion_policy::Policy;
use pasion_router::UrlBuilder;
use pasion_salvo_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
    sentry::SentryEventID,
};
use pasion_storage::{
    BoxRepository, BoxRepositoryFactory, RepositoryAccess,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    user::BrowserSessionRepository,
};
use pasion_templates::{DeviceNameContext, TemplateContext, Templates};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use thiserror::Error;
use tracing::{debug, info, warn};
use ulid::Ulid;

use super::{generate_id_token, generate_token_pair};
use crate::{BoundActivityTracker, METER, impl_from_error_for_route};

static TOKEN_REQUEST_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.oauth2.token_request")
        .with_description("How many OAuth 2.0 token requests have gone through")
        .with_unit("{request}")
        .build()
});
const GRANT_TYPE: Key = Key::from_static_str("grant_type");
const RESULT: Key = Key::from_static_str("successful");

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed to use the token endpoint: {0}")]
    ClientNotAllowed(Ulid),

    #[error("invalid client credentials for client {client_id}")]
    InvalidClientCredentials {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("could not verify client credentials for client {client_id}")]
    ClientCredentialsVerification {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("grant not found")]
    GrantNotFound,

    #[error("invalid grant {0}")]
    InvalidGrant(Ulid),

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIDMismatch { expected: Ulid, actual: Ulid },

    #[error("policy denied the request: {0}")]
    DeniedByPolicy(pasion_policy::EvaluationResult),

    #[error("unsupported grant type")]
    UnsupportedGrantType,

    #[error("client {0} is not authorized to use this grant type")]
    UnauthorizedClient(Ulid),

    #[error("unexpected client {was} (expected {expected})")]
    UnexptectedClient { was: Ulid, expected: Ulid },

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

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

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        TOKEN_REQUEST_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);

        match self {
            Self::Internal(_)
            | Self::ClientCredentialsVerification { .. }
            | Self::NoSuchBrowserSession(_)
            | Self::NoSuchOAuthSession(_)
            | Self::ProvisionDeviceFailed(_)
            | Self::NoSuchNextRefreshToken { .. }
            | Self::NoSuchNextAccessToken { .. }
            | Self::NoAccessTokenOnRefreshToken { .. } => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }

            Self::PkceVerification(ref err) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description(format!("PKCE verification failed: {err}")),
                ));
            }

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }

            Self::ClientNotAllowed(_)
            | Self::UnauthorizedClient(_)
            | Self::UnexptectedClient { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::UnauthorizedClient)));
            }

            Self::DeniedByPolicy(ref evaluation) => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidScope).with_description(
                        evaluation
                            .violations
                            .iter()
                            .map(|violation| violation.msg.clone())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ));
            }

            Self::DeviceCodeRejected => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(ClientErrorCode::AccessDenied)));
            }

            Self::DeviceCodeExpired => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(ClientErrorCode::ExpiredToken)));
            }

            Self::DeviceCodePending => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(ClientError::from(
                    ClientErrorCode::AuthorizationPending,
                )));
            }

            Self::InvalidGrant(_)
            | Self::DeviceCodeExchanged
            | Self::RefreshTokenNotFound
            | Self::RefreshTokenInvalid(_)
            | Self::SessionInvalid(_)
            | Self::ClientIDMismatch { .. }
            | Self::GrantNotFound => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidGrant)));
            }

            Self::UnsupportedGrantType => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(
                    ClientErrorCode::UnsupportedGrantType,
                )));
            }
        }

        let sentry_event_id = pasion_salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(pasion_i18n::DataError);
impl_from_error_for_route!(pasion_templates::TemplateError);
impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(pasion_policy::EvaluationError);
impl_from_error_for_route!(super::IdTokenSignatureError);
impl_from_error_for_route!(pasion_salvo_utils::client_authorization::ClientAuthorizationError);

#[handler]
#[tracing::instrument(name = "handlers.oauth2.token.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(reply) => {
            res.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            res.headers_mut().insert(
                http::header::PRAGMA,
                http::HeaderValue::from_static("no-cache"),
            );
            res.render(Json(reply));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(req: &mut Request, depot: &Depot) -> Result<AccessTokenResponse, RouteError> {
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .expect("reqwest::Client not found in depot");
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let homeserver = depot
        .get::<Arc<dyn HomeserverConnection>>("homeserver_connection")
        .expect("HomeserverConnection not found in depot");
    let site_config = depot
        .get::<SiteConfig>("site_config")
        .expect("SiteConfig not found in depot");
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let templates = depot
        .get::<Templates>("templates")
        .expect("Templates not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let policy_factory = depot
        .get::<Arc<pasion_policy::PolicyFactory>>("policy_factory")
        .expect("PolicyFactory not found in depot");

    let clock: BoxClock = Box::new(SystemClock::default());
    #[allow(clippy::disallowed_methods)]
    let mut rng: BoxRng = Box::new(ChaChaRng::from_rng(thread_rng()).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;
    let policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let user_agent: Option<String> = req.header("user-agent");

    let client_authorization: ClientAuthorization<AccessTokenRequest> =
        ClientAuthorization::extract_from_request(req).await?;

    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed(client.id))?;

    client_authorization
        .credentials
        .verify(http_client, encrypter, method, &client)
        .await
        .map_err(|err| {
            // Classify the error differently, depending on whether it's an 'internal'
            // error, or just because the client presented invalid credentials.
            if err.is_internal() {
                RouteError::ClientCredentialsVerification {
                    client_id: client.id,
                    source: err,
                }
            } else {
                RouteError::InvalidClientCredentials {
                    client_id: client.id,
                    source: err,
                }
            }
        })?;

    let form = client_authorization.form.ok_or(RouteError::BadRequest)?;

    let grant_type = form.grant_type();

    let (reply, repo) = match form {
        AccessTokenRequest::AuthorizationCode(grant) => {
            authorization_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                key_store,
                url_builder,
                site_config,
                repo,
                homeserver,
                templates,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::RefreshToken(grant) => {
            refresh_token_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                site_config,
                repo,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::ClientCredentials(grant) => {
            client_credentials_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                site_config,
                repo,
                policy,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::DeviceCode(grant) => {
            device_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                key_store,
                url_builder,
                site_config,
                repo,
                homeserver,
                user_agent,
            )
            .await?
        }
        _ => {
            return Err(RouteError::UnsupportedGrantType);
        }
    };

    repo.save().await?;

    TOKEN_REQUEST_COUNTER.add(
        1,
        &[
            KeyValue::new(GRANT_TYPE, grant_type),
            KeyValue::new(RESULT, "success"),
        ],
    );

    Ok(reply)
}

async fn authorization_code_grant(
    mut rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverConnection>,
    templates: &Templates,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let authz_grant = repo
        .oauth2_authorization_grant()
        .find_by_code(&grant.code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let now = clock.now();

    let session_id = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return Err(RouteError::InvalidGrant(authz_grant.id));
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
                let session = repo
                    .oauth2_session()
                    .lookup(session_id)
                    .await?
                    .ok_or(RouteError::NoSuchOAuthSession(session_id))?;

                repo.oauth2_session().finish(clock, session).await?;
                repo.save().await?;
            }

            return Err(RouteError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Pending => {
            warn!("Authorization grant has not been fulfilled yet");
            return Err(RouteError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Fulfilled {
            session_id,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::microseconds(10 * 60 * 1000 * 1000) {
                warn!("Code exchange took more than 10 minutes");
                return Err(RouteError::InvalidGrant(authz_grant.id));
            }

            session_id
        }
    };

    let mut session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession(session_id))?;

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
        .ok_or(RouteError::InvalidGrant(authz_grant.id))?;

    if client.id != session.client_id {
        return Err(RouteError::UnexptectedClient {
            was: client.id,
            expected: session.client_id,
        });
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return Err(RouteError::BadRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            pkce.verify(verifier)?;
        }
    }

    let Some(user_session_id) = session.user_session_id else {
        tracing::warn!("No user session associated with this OAuth2 session");
        return Err(RouteError::InvalidGrant(authz_grant.id));
    };

    let browser_session = repo
        .browser_session()
        .lookup(user_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession(user_session_id))?;

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = site_config.access_token_ttl;
    let (access_token, refresh_token) =
        generate_token_pair(&mut rng, clock, &mut repo, &session, ttl).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        Some(generate_id_token(
            &mut rng,
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
                .map_err(RouteError::ProvisionDeviceFailed)?;
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

async fn refresh_token_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &RefreshTokenGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let refresh_token = repo
        .oauth2_refresh_token()
        .find_by_token(&grant.refresh_token)
        .await?
        .ok_or(RouteError::RefreshTokenNotFound)?;

    let mut session = repo
        .oauth2_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession(refresh_token.session_id))?;

    // Let's for now record the user agent on each refresh, that should be
    // responsive enough and not too much of a burden on the database.
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    if !session.is_valid() {
        return Err(RouteError::SessionInvalid(session.id));
    }

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RouteError::ClientIDMismatch {
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
            return Err(RouteError::RefreshTokenInvalid(refresh_token.id));
        };

        let Some(next_refresh_token) = repo
            .oauth2_refresh_token()
            .lookup(next_refresh_token_id)
            .await?
        else {
            return Err(RouteError::NoSuchNextRefreshToken {
                next: next_refresh_token_id,
                previous: refresh_token.id,
            });
        };

        // Check if the next refresh token was already consumed or not
        if !next_refresh_token.is_valid() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RouteError::RefreshTokenInvalid(next_refresh_token.id));
        }

        // Check if the associated access token was already used
        let Some(access_token_id) = next_refresh_token.access_token_id else {
            // This should in theory not happen: this means an access token got cleaned up,
            // but the refresh token was still valid.
            return Err(RouteError::NoAccessTokenOnRefreshToken {
                refresh_token: next_refresh_token.id,
            });
        };

        // Load it
        let next_access_token = repo
            .oauth2_access_token()
            .lookup(access_token_id)
            .await?
            .ok_or(RouteError::NoSuchNextAccessToken {
                access_token: access_token_id,
                refresh_token: next_refresh_token_id,
            })?;

        if next_access_token.is_used() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RouteError::RefreshTokenInvalid(next_refresh_token.id));
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

async fn client_credentials_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &ClientCredentialsGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(RouteError::UnauthorizedClient(client.id));
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
        return Err(RouteError::DeniedByPolicy(res));
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

async fn device_code_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &DeviceCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverConnection>,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let grant = repo
        .oauth2_device_code_grant()
        .find_by_device_code(&grant.device_code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    // Check that the client match
    if client.id != grant.client_id {
        return Err(RouteError::ClientIDMismatch {
            expected: grant.client_id,
            actual: client.id,
        });
    }

    if grant.expires_at < clock.now() {
        return Err(RouteError::DeviceCodeExpired);
    }

    let browser_session_id = match &grant.state {
        DeviceCodeGrantState::Pending => {
            return Err(RouteError::DeviceCodePending);
        }
        DeviceCodeGrantState::Rejected { .. } => {
            return Err(RouteError::DeviceCodeRejected);
        }
        DeviceCodeGrantState::Exchanged { .. } => {
            return Err(RouteError::DeviceCodeExchanged);
        }
        DeviceCodeGrantState::Fulfilled {
            browser_session_id, ..
        } => *browser_session_id,
    };

    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession(browser_session_id))?;

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
                .map_err(RouteError::ProvisionDeviceFailed)?;
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

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
