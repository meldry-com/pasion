use pasion_data::{AccountAction, PostAuthAction};
use crate::salvo_utils::{InternalError, cookies::CookieJar};
use pasion_templates::{AppContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};
use serde::Deserialize;

use crate::handlers::rest::DepotExt;
use crate::handlers::{
    rest,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize, Default)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<AccountAction>,
}

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let script_src = depot.frontend_script_src()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let cookie_jar = depot.cookie_jar(req)?;
    let Params { action } = req.parse_queries().unwrap_or_default();

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

    // TODO: keep the full path, not just the action
    let Some(session) = maybe_session else {
        cookie_jar.write_to_response(res);
        let post_action = PostAuthAction::manage_account(action);
        let query = serde_urlencoded::to_string(&post_action).unwrap_or_default();
        let path = if query.is_empty() {
            "/login".to_owned()
        } else {
            format!("/login?{query}")
        };
        res.render(salvo::writing::Redirect::other(&url_builder.relative_url(&path)));
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::new(&url_builder, &script_src).with_language(locale);
    let content = templates.render_app(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[handler]
pub async fn get_anonymous(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let script_src = depot.frontend_script_src()?;

    let ctx = AppContext::new(&url_builder, &script_src).with_language(locale);
    let content = templates.render_app(&ctx)?;

    res.render(Text::Html(content));
    Ok(())
}
