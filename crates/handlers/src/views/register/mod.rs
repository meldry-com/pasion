use pasion_router::{PasswordRegister, UpstreamOAuth2Authorize};
use pasion_salvo_utils::{InternalError, SessionInfoExt, cookies::CookieJar, csrf::CsrfExt as _};
use pasion_templates::{RegisterContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};

use super::shared::OptionalPostAuthAction;
use crate::rest;
use crate::rest::DepotExt;

mod cookie;
pub mod password;
pub mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let site_config = depot.site_config()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let query: OptionalPostAuthAction = req.parse_queries().unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        cookie_jar.write_to_response(res);
        res.render(reply);
        return Ok(());
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !site_config.password_registration_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&destination));
        return Ok(());
    }

    // If password-based registration is enabled and there are no upstream
    // providers, we redirect to the password registration page
    if site_config.password_registration_enabled && providers.is_empty() {
        let mut destination = PasswordRegister::default();

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&destination));
        return Ok(());
    }

    let mut ctx = RegisterContext::new(providers);
    let post_action = query
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_register(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}
