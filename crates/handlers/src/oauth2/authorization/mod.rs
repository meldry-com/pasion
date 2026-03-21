use mas_data_model::{AuthorizationCode, BoxClock, BoxRng, Pkce, SystemClock};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_salvo_utils::{
    GenericError, InternalError, SessionInfoExt,
    cookies::CookieJar,
    sentry::SentryEventID,
};
use mas_storage::{
    BoxRepository, BoxRepositoryFactory,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::Templates;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce,
    requests::{AuthorizationRequest, GrantType, Prompt, ResponseMode},
    response_type::ResponseType,
};
use rand::{Rng, SeedableRng, distributions::Alphanumeric, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use serde::Deserialize;
use thiserror::Error;

use self::callback::CallbackDestination;
use crate::{BoundActivityTracker, PreferredLanguage, impl_from_error_for_route};

mod callback;
pub(crate) mod consent;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("could not find client")]
    ClientNotFound,

    #[error("invalid response mode")]
    InvalidResponseMode,

    #[error("invalid parameters")]
    IntoCallbackDestination(#[from] self::callback::IntoCallbackDestinationError),

    #[error("invalid redirect uri")]
    UnknownRedirectUri(#[from] mas_data_model::InvalidRedirectUriError),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(ref e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(e.to_string()));
            }
            Self::ClientNotFound
            | Self::InvalidResponseMode
            | Self::IntoCallbackDestination(_)
            | Self::UnknownRedirectUri(_) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Text::Plain(self.to_string()));
            }
        }

        // Add Sentry event ID if available
        if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
            res.headers_mut().insert(SentryEventID::name(), value);
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(self::callback::CallbackDestinationError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);

#[derive(Deserialize)]
pub(crate) struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
fn resolve_response_mode(
    response_type: &ResponseType,
    suggested_response_mode: Option<ResponseMode>,
) -> Result<ResponseMode, RouteError> {
    use ResponseMode as M;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.has_token() || response_type.has_id_token() {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(RouteError::InvalidResponseMode),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.authorization.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot).await {
        Ok((html, cookie_jar)) => {
            // Set cookies
            cookie_jar.set_cookies(res);
            res.render(html);
        }
        Err(e) => e.render(res),
    }
}

async fn handle_get(
    req: &mut Request,
    depot: &Depot,
) -> Result<(impl Scribe, CookieJar), RouteError> {
    let templates = depot
        .get::<Templates>("templates")
        .expect("Templates not found in depot");
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = depot
        .get::<BoundActivityTracker>("activity_tracker")
        .expect("BoundActivityTracker not found in depot");
    let cookie_manager = depot
        .get::<mas_salvo_utils::cookies::CookieManager>("cookie_manager")
        .expect("CookieManager not found in depot");

    let clock: BoxClock = Box::new(SystemClock::default());
    #[allow(clippy::disallowed_methods)]
    let mut rng: BoxRng = Box::new(ChaChaRng::from_rng(thread_rng()).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;

    // Extract preferred language
    let locale = PreferredLanguage::extract_from_request(req);

    // Parse form parameters
    let params: Params = req.parse_queries().map_err(|e| RouteError::Internal(Box::new(e)))?;

    // Get cookie jar
    let cookie_jar = cookie_manager.cookie_jar_from_headers(req.headers());

    // First, figure out what client it is
    let client = repo
        .oauth2_client()
        .find_by_client_id(&params.auth.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(&response_type, params.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        &response_mode,
        redirect_uri.clone(),
        params.auth.state.clone(),
    )?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();

    // One day, we will have try blocks
    let inner_result: Result<salvo::http::Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        let locale = locale.clone();
        async move {
            let maybe_session = session_info.load_active_session(&mut repo).await?;
            let prompt = params.auth.prompt.as_deref().unwrap_or_default();

            // Check if the request/request_uri/registration params are used. If so, reply
            // with the right error since we don't support them.
            if params.auth.request.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestNotSupported),
                )?);
            }

            if params.auth.request_uri.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestUriNotSupported),
                )?);
            }

            // Check if the client asked for a `token` response type, and bail out if it's
            // the case, since we don't support them
            if response_type.has_token() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnsupportedResponseType),
                )?);
            }

            // If the client asked for a `id_token` response type, we must check if it can
            // use the `implicit` grant type
            if response_type.has_id_token() && !client.grant_types.contains(&GrantType::Implicit) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnauthorizedClient),
                )?);
            }

            if params.auth.registration.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RegistrationNotSupported),
                )?);
            }

            // Fail early if prompt=none; we never let it go through
            if prompt.contains(&Prompt::None) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::LoginRequired),
                )?);
            }

            let code: Option<AuthorizationCode> = if response_type.has_code() {
                // Check if it is allowed to use this grant type
                if !client.grant_types.contains(&GrantType::AuthorizationCode) {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::UnauthorizedClient),
                    )?);
                }

                // 32 random alphanumeric characters, about 190bit of entropy
                let code: String = (&mut rng)
                    .sample_iter(&Alphanumeric)
                    .take(32)
                    .map(char::from)
                    .collect();

                let pkce = params.pkce.map(|p| Pkce {
                    challenge: p.code_challenge,
                    challenge_method: p.code_challenge_method,
                });

                Some(AuthorizationCode { code, pkce })
            } else {
                // If the request had PKCE params but no code asked, it should get back with an
                // error
                if params.pkce.is_some() {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::InvalidRequest),
                    )?);
                }

                None
            };

            let grant = repo
                .oauth2_authorization_grant()
                .add(
                    &mut rng,
                    &clock,
                    &client,
                    redirect_uri.clone(),
                    params.auth.scope,
                    code,
                    params.auth.state.clone(),
                    params.auth.nonce,
                    response_mode,
                    response_type.has_id_token(),
                    params.auth.login_hint,
                    Some(locale.to_string()),
                )
                .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let res = match maybe_session {
                None if prompt.contains(&Prompt::Create) => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    url_builder.redirect(&mas_router::Register::and_then(continue_grant))
                }

                None => {
                    // Other cases where we don't have a session, ask for a login
                    repo.save().await?;

                    url_builder.redirect(&mas_router::Login::and_then(continue_grant))
                }

                Some(user_session) => {
                    // TODO: better support for prompt=create when we have a session
                    repo.save().await?;

                    activity_tracker
                        .record_browser_session(&clock, &user_session)
                        .await;
                    url_builder.redirect(&mas_router::Consent(grant.id))
                }
            };

            Ok(res)
        }
    })
    .await;

    let response = match inner_result {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(message = &err as &dyn std::error::Error);
            callback_destination.go(
                templates,
                &locale,
                ClientError::from(ClientErrorCode::ServerError),
            )?
        }
    };

    Ok((response, cookie_jar))
}
