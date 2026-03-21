use salvo::prelude::*;
use pasion_salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_router::PostAuthAction;
use pasion_storage::user::BrowserSessionRepository;

use crate::rest;

#[handler]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), InternalError> {
    let clock = rest::make_clock();
    let mut repo = rest::get_repo_factory(depot)?.create().await?;
    let cookie_jar = rest::extract_cookie_jar(req, depot)?;
    let url_builder = rest::get_url_builder(depot)?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let form: ProtectedForm<Option<PostAuthAction>> = req.parse_form().await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    if let Some(session_id) = session_info.current_session_id() {
        let maybe_session = repo.browser_session().lookup(session_id).await?;
        if let Some(session) = maybe_session
            && session.finished_at.is_none()
        {
            activity_tracker
                .record_browser_session(&clock, &session)
                .await;

            repo.browser_session().finish(&clock, session).await?;
        }
    }

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    let destination = if let Some(action) = form {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&pasion_router::Login::default())
    };

    cookie_jar.write_to_response(res);
    res.render(destination);
    Ok(())
}
