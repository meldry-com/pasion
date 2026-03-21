use std::collections::HashMap;

use anyhow::Context;
use chrono::Duration;
use hyper::StatusCode;
use pasion_data_model::{Clock, MatrixUser};
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_router::CompatLoginSsoAction;
use pasion_storage::{RepositoryAccess, compat::CompatSsoLoginRepository};
use pasion_templates::{
    CompatLoginPolicyViolationContext, CompatSsoContext, ErrorContext, TemplateContext,
};
use salvo::prelude::*;
use salvo::writing::Text;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

#[derive(Serialize)]
struct AllParams<'s> {
    #[serde(flatten)]
    existing_params: HashMap<&'s str, &'s str>,

    #[serde(rename = "loginToken")]
    login_token: &'s str,
}

#[derive(Debug, Deserialize)]
pub struct Params {
    action: Option<CompatLoginSsoAction>,
}

#[handler]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    let id: Ulid = match req.param("id") {
        Some(id) => id,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Missing path parameter 'id'"));
            return;
        }
    };

    match handle_get(req, depot, id, res).await {
        Ok(()) => {}
        Err(e) => {
            e.render(res);
        }
    }
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.get",
    fields(compat_sso_login.id = %id),
    skip_all,
)]
async fn handle_get(
    req: &Request,
    depot: &Depot,
    id: Ulid,
    res: &mut Response,
) -> Result<(), InternalError> {
    let locale = crate::preferred_language(req, depot);
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let mut repo = crate::rest::get_repo_factory(depot)?
        .create()
        .await?;
    let templates = crate::rest::get_templates(depot)?;
    let url_builder = crate::rest::get_url_builder(depot)?;
    let homeserver = crate::rest::get_homeserver(depot)?;
    let policy_factory = crate::rest::get_policy_factory(depot)?;
    let mut policy = policy_factory.instantiate().await.map_err(InternalError::from_anyhow)?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(String::from);
    let cookie_jar = crate::rest::extract_cookie_jar(req, depot)?;

    let params: Params = req.parse_queries().unwrap_or(Params { action: None });

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
        SessionOrFallback::Fallback { response } => { *res = response; return Ok(()); }
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                url_builder.redirect(&pasion_router::Register::and_continue_compat_sso_login(id))
            }
            Some(CompatLoginSsoAction::Login) | None => {
                url_builder.redirect(&pasion_router::Login::and_continue_compat_sso_login(id))
            }
        };

        cookie_jar.write_to_response(res);
        res.render(url);
        return Ok(());
    };

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")
        .map_err(InternalError::from_anyhow)?;

    // Bail out if that login session is more than 30min old
    if clock.now() > login.created_at + Duration::microseconds(30 * 60 * 1000 * 1000) {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned())
            .with_language(&locale);

        let content = templates.render_error(&ctx)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    let eval_result = policy
        .evaluate_compat_login(pasion_policy::CompatLoginInput {
            user: &session.user,
            login: pasion_policy::model::CompatLogin::Sso {
                redirect_uri: login.redirect_uri.to_string(),
            },
            // We don't know if there's going to be a replacement until we received the device ID,
            // which happens too late.
            session_replaced: false,
            session_counts,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;
    if !eval_result.valid() {
        let ctx = CompatLoginPolicyViolationContext::for_violations(eval_result.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_compat_login_policy_violation(&ctx)?;

        res.status_code(StatusCode::FORBIDDEN);
        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        std::time::Duration::from_secs(1),
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

    let ctx = CompatSsoContext::new(login, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_sso_login(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}

#[handler]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    let id: Ulid = match req.param("id") {
        Some(id) => id,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Missing path parameter 'id'"));
            return;
        }
    };

    match handle_post(req, depot, id, res).await {
        Ok(()) => {}
        Err(e) => {
            e.render(res);
        }
    }
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.post",
    fields(compat_sso_login.id = %id),
    skip_all,
)]
async fn handle_post(
    req: &mut Request,
    depot: &Depot,
    id: Ulid,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let mut repo = crate::rest::get_repo_factory(depot)?
        .create()
        .await?;
    let locale = crate::preferred_language(req, depot);
    let templates = crate::rest::get_templates(depot)?;
    let url_builder = crate::rest::get_url_builder(depot)?;
    let policy_factory = crate::rest::get_policy_factory(depot)?;
    let mut policy = policy_factory.instantiate().await.map_err(InternalError::from_anyhow)?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(String::from);
    let cookie_jar = crate::rest::extract_cookie_jar(req, depot)?;

    let params: Params = req.parse_queries().unwrap_or(Params { action: None });

    let form: ProtectedForm<()> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

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
        SessionOrFallback::Fallback { response } => { *res = response; return Ok(()); }
    };

    cookie_jar.verify_form(&clock, form)?;

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                url_builder.redirect(&pasion_router::Register::and_continue_compat_sso_login(id))
            }
            Some(CompatLoginSsoAction::Login) | None => {
                url_builder.redirect(&pasion_router::Login::and_continue_compat_sso_login(id))
            }
        };

        cookie_jar.write_to_response(res);
        res.render(url);
        return Ok(());
    };

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")
        .map_err(InternalError::from_anyhow)?;

    // Bail out if that login session isn't pending, or is more than 30min old
    if !login.is_pending()
        || clock.now() > login.created_at + Duration::microseconds(30 * 60 * 1000 * 1000)
    {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned())
            .with_language(&locale);

        let content = templates.render_error(&ctx)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    let redirect_uri = {
        let mut redirect_uri = login.redirect_uri.clone();
        let existing_params = redirect_uri
            .query()
            .map(serde_urlencoded::from_str)
            .transpose()?
            .unwrap_or_default();

        let params = AllParams {
            existing_params,
            login_token: &login.login_token,
        };
        let query = serde_urlencoded::to_string(params)?;
        redirect_uri.set_query(Some(&query));
        redirect_uri
    };

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    let eval_result = policy
        .evaluate_compat_login(pasion_policy::CompatLoginInput {
            user: &session.user,
            login: pasion_policy::model::CompatLogin::Sso {
                redirect_uri: login.redirect_uri.to_string(),
            },
            session_counts,
            // We don't know if there's going to be a replacement until we received the device ID,
            // which happens too late.
            session_replaced: false,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if !eval_result.valid() {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = CompatLoginPolicyViolationContext::for_violations(eval_result.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_compat_login_policy_violation(&ctx)?;

        res.status_code(StatusCode::FORBIDDEN);
        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    // Note that if the login is not Pending,
    // this fails and aborts the transaction.
    repo.compat_sso_login()
        .fulfill(&clock, login, &session)
        .await?;

    repo.save().await?;

    cookie_jar.write_to_response(res);
    res.render(Redirect::other(redirect_uri.as_str()));
    Ok(())
}
