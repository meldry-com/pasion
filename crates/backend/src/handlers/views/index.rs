use crate::salvo_utils::{InternalError, cookies::CookieJar, csrf::CsrfExt};
use pasion_templates::{AppContext, AppErrorState, IndexContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};

use crate::handlers::account::DepotExt;
use crate::handlers::{
    rest,
    session::{AccountError, SessionOrFallback, load_session_or_fallback},
};

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = common::make_rng();
    let clock = common::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
    let cookie_jar = depot.cookie_jar(req)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::AccountError { cookie_jar, error } => {
            let err_state = crate::handlers::views::app::account_error_to_state(&error);
            let ctx = AppContext::new(&url_builder, &depot.frontend_script_src()?)
                .with_error(err_state)
                .with_language(locale);
            let content = templates.render_app(&ctx)?;
            cookie_jar.write_to_response(res);
            res.render(Text::Html(content));
            return Ok(());
        }
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    if let Some(session) = maybe_session.as_ref() {
        activity_tracker
            .record_browser_session(&clock, session)
            .await;
    }

    let ctx = IndexContext::new(url_builder.oidc_discovery())
        .maybe_with_session(maybe_session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_index(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}
