//! Utilities for showing proposer HTML fallbacks when the user is logged out,
//! locked or deactivated

use crate::salvo_utils::{SessionInfoExt, cookies::CookieJar, csrf::CsrfExt};
use pasion_data::{
    BoxRepository, RepositoryError, oauth2::OAuth2SessionFilter, personal::PersonalSessionFilter,
};
use pasion_data::{BrowserSession, Clock, User};
use pasion_i18n::DataLocale;
use pasion_policy::model::SessionCounts;
use pasion_templates::{AccountInactiveContext, TemplateContext, Templates};
use rand::RngCore;
use salvo::{prelude::*, writing::Text};
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum SessionLoadError {
    Template(#[from] pasion_templates::TemplateError),
    Repository(#[from] RepositoryError),
}

#[allow(clippy::large_enum_variant)]
pub enum SessionOrFallback {
    MaybeSession {
        cookie_jar: CookieJar,
        maybe_session: Option<BrowserSession>,
    },
    Fallback {
        response: Response,
    },
}

/// Load a session from the cookie jar, or fall back to an HTML error page if
/// the account is locked, deactivated or logged out
pub async fn load_session_or_fallback(
    cookie_jar: CookieJar,
    clock: &impl Clock,
    rng: impl RngCore,
    templates: &Templates,
    locale: &DataLocale,
    repo: &mut BoxRepository,
) -> Result<SessionOrFallback, SessionLoadError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let Some(session_id) = session_info.current_session_id() else {
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    let Some(session) = repo.browser_session().lookup(session_id).await? else {
        // We looked up the session, but it was not found. Still update the cookie
        let session_info = session_info.mark_session_ended();
        let cookie_jar = cookie_jar.update_session_info(&session_info);
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    if session.user.deactivated_at.is_some() {
        // The account is deactivated, show the 'account deactivated' fallback
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_deactivated(&ctx)?;
        let response = {
            let mut response = Response::new();
            cookie_jar.write_to_response(&mut response);
            response.render(Text::Html(fallback));
            response
        };
        return Ok(SessionOrFallback::Fallback { response });
    }

    if session.user.locked_at.is_some() {
        // The account is locked, show the 'account locked' fallback
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_locked(&ctx)?;
        let response = {
            let mut response = Response::new();
            cookie_jar.write_to_response(&mut response);
            response.render(Text::Html(fallback));
            response
        };
        return Ok(SessionOrFallback::Fallback { response });
    }

    if session.finished_at.is_some() {
        // The session has finished, but the browser still has the cookie. This is
        // likely a 'remote' logout, triggered either by an admin or from the
        // user-management UI. In this case, we show the 'account logged out'
        // fallback.
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_logged_out(&ctx)?;
        let response = {
            let mut response = Response::new();
            cookie_jar.write_to_response(&mut response);
            response.render(Text::Html(fallback));
            response
        };
        return Ok(SessionOrFallback::Fallback { response });
    }

    Ok(SessionOrFallback::MaybeSession {
        cookie_jar,
        maybe_session: Some(session),
    })
}

/// Get a count of sessions for the given user, for the purposes of session
/// limiting.
///
/// Includes:
/// - OAuth 2 sessions
/// - Compatibility sessions
/// - Personal sessions (unless owned by a different user)
///
/// # Backstory
///
/// Originally, we were only intending to count sessions with devices in this
/// result, because those are the entries that are expensive for Palpo and
/// also would not hinder use of deviceless clients (like Element Admin, an
/// admin dashboard).
///
/// However, to do so, we would need to count only sessions including device
/// scopes. To do this efficiently, we'd need a partial index on sessions
/// including device scopes.
///
/// It turns out that this can't be done cleanly (as we need to, in Postgres,
/// match scope lists where one of the scopes matches one of 2 known prefixes),
/// at least not without somewhat uncomfortable stored functions.
///
/// So for simplicity's sake, we now count all sessions.
/// For practical use cases, it's not likely to make a noticeable difference
/// (and maybe it's good that there's an overall limit).
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let oauth2 = repo
        .oauth2_session()
        .count(OAuth2SessionFilter::new().active_only().for_user(user))
        .await? as u64;

    // Only include self-owned personal sessions, not administratively-owned ones
    let personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .active_only()
                .for_actor_user(user)
                .for_owner_user(user),
        )
        .await? as u64;

    Ok(SessionCounts {
        total: oauth2 + personal,
        oauth2,
        personal,
    })
}
