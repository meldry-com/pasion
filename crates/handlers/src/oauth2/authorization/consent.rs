use std::time::Duration;

use oauth2_types::requests::AuthorizationResponse;
use pasion_data_model::{AuthorizationGrantStage, Clock, MatrixUser};
use pasion_policy::Policy;
use pasion_router::PostAuthAction;
use pasion_salvo_utils::{
    GenericError, InternalError,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_storage::oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository};
use pasion_templates::{ConsentContext, PolicyViolationContext, TemplateContext};
use salvo::{prelude::*, writing::Text};
use thiserror::Error;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::{
    impl_from_error_for_route,
    oauth2::generate_id_token,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};
use crate::rest::DepotExt;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] pasion_salvo_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant {0} already used")]
    GrantNotPending(Ulid),

    #[error("Failed to load client {0}")]
    NoSuchClient(Ulid),
}

impl_from_error_for_route!(pasion_templates::TemplateError);
impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(pasion_policy::LoadError);
impl_from_error_for_route!(pasion_policy::EvaluationError);
impl_from_error_for_route!(crate::session::SessionLoadError);
impl_from_error_for_route!(crate::oauth2::IdTokenSignatureError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);
impl_from_error_for_route!(crate::rest::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(e) => InternalError::new(e).render(res),
            e @ Self::NoSuchClient(_) => InternalError::new(Box::new(e)).render(res),
            e @ Self::GrantNotFound => GenericError::new(StatusCode::NOT_FOUND, e).render(res),
            e @ Self::GrantNotPending(_) => GenericError::new(StatusCode::CONFLICT, e).render(res),
            e @ Self::Csrf(_) => GenericError::new(StatusCode::BAD_REQUEST, e).render(res),
        }
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.authorization.consent.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot, res).await {
        Ok(()) => {}
        Err(e) => e.render(res),
    }
}

async fn handle_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let grant_id: Ulid = req.param("grant_id").ok_or(RouteError::GrantNotFound)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => {
            *res = response;
            return Ok(());
        }
    };

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let Some(session) = maybe_session else {
        let login = pasion_router::Login::and_continue_grant(grant_id);
        let redirect = url_builder.redirect(&login);
        cookie_jar.write_to_response(res);
        res.render(redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::AuthorizationCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;
    if !eval_result.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = ConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_consent(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.authorization.consent.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot, res).await {
        Ok(()) => {}
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let key_store = depot.key_store()?;
    let policy_factory = depot.policy_factory()?;
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let cookie_jar = depot.cookie_jar(req)?;
    let url_builder = depot.url_builder()?;
    let grant_id: Ulid = req.param("grant_id").ok_or(RouteError::GrantNotFound)?;

    let form: ProtectedForm<()> = req
        .parse_form()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;
    cookie_jar.verify_form(&clock, form)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => {
            *res = response;
            return Ok(());
        }
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;
    let callback_destination = CallbackDestination::try_from(&grant)?;

    let Some(browser_session) = maybe_session else {
        let next = PostAuthAction::continue_grant(grant_id);
        let login = pasion_router::Login::and_then(next);
        let redirect = url_builder.redirect(&login);
        cookie_jar.write_to_response(res);
        res.render(redirect);
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let session_counts = count_user_sessions_for_limiting(&mut repo, &browser_session.user).await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::AuthorizationCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;

    if !eval_result.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
            .with_session(browser_session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    // All good, let's start the session
    let session = repo
        .oauth2_session()
        .add_from_browser_session(
            &mut rng,
            &clock,
            &client,
            &browser_session,
            grant.scope.clone(),
        )
        .await?;

    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&clock, &session, grant)
        .await?;

    let mut params = AuthorizationResponse::default();

    // Did they request an ID token?
    if grant.response_type_id_token {
        // Fetch the last authentication
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            &mut rng,
            &clock,
            &url_builder,
            &key_store,
            &client,
            Some(&grant),
            &browser_session,
            None,
            last_authentication.as_ref(),
        )?);
    }

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    let callback_response = callback_destination.go(&templates, &locale, params)?;

    *res = callback_response;
    cookie_jar.write_to_response(res);
    Ok(())
}
