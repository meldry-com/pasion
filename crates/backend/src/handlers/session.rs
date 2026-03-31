// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Session loading helpers that render HTML fallback pages when the account
//! state prevents normal operation (deactivated, locked, or remotely logged
//! out).

use crate::salvo_utils::{SessionInfoExt, cookies::CookieJar, csrf::CsrfExt};
use pasion_data::{
    BoxRepository, BrowserSession, Clock, RepositoryError, User,
    oauth2::OAuth2SessionFilter, personal::PersonalSessionFilter,
};
use pasion_i18n::DataLocale;
use pasion_policy::model::SessionCounts;
use pasion_templates::{AccountInactiveContext, TemplateContext, Templates};
use rand::RngCore;
use salvo::{prelude::*, writing::Text};
use thiserror::Error;

/// Failures that can occur while loading a session or rendering the fallback.
#[derive(Debug, Error)]
#[error(transparent)]
pub enum SessionLoadError {
    Template(#[from] pasion_templates::TemplateError),
    Repository(#[from] RepositoryError),
}

/// Either a usable session (possibly absent) or a pre-built HTML response to
/// send back to the browser.
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

/// Attempt to resolve a browser session from cookies. When the associated
/// account is deactivated, locked, or the session has been remotely ended, an
/// HTML fallback page is returned instead.
pub async fn load_session_or_fallback(
    cookie_jar: CookieJar,
    clock: &impl Clock,
    rng: impl RngCore,
    templates: &Templates,
    locale: &DataLocale,
    repo: &mut BoxRepository,
) -> Result<SessionOrFallback, SessionLoadError> {
    let (sess_info, cookie_jar) = cookie_jar.session_info();

    // No session cookie present at all
    let Some(sid) = sess_info.current_session_id() else {
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    // Cookie references a session that no longer exists in the database
    let Some(browser_session) = repo.browser_session().lookup(sid).await? else {
        let updated_info = sess_info.mark_session_ended();
        let jar = cookie_jar.update_session_info(&updated_info);
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar: jar,
            maybe_session: None,
        });
    };

    // Account has been deactivated -- show a dedicated page
    if browser_session.user.deactivated_at.is_some() {
        let rendered = render_inactive_page(
            &browser_session.user,
            cookie_jar,
            clock,
            rng,
            locale,
            |ctx| templates.render_account_deactivated(ctx),
        )?;
        return Ok(SessionOrFallback::Fallback { response: rendered });
    }

    // Account has been locked
    if browser_session.user.locked_at.is_some() {
        let rendered = render_inactive_page(
            &browser_session.user,
            cookie_jar,
            clock,
            rng,
            locale,
            |ctx| templates.render_account_locked(ctx),
        )?;
        return Ok(SessionOrFallback::Fallback { response: rendered });
    }

    // Session was ended remotely (admin action or user-management UI)
    if browser_session.finished_at.is_some() {
        let rendered = render_inactive_page(
            &browser_session.user,
            cookie_jar,
            clock,
            rng,
            locale,
            |ctx| templates.render_account_logged_out(ctx),
        )?;
        return Ok(SessionOrFallback::Fallback { response: rendered });
    }

    Ok(SessionOrFallback::MaybeSession {
        cookie_jar,
        maybe_session: Some(browser_session),
    })
}

/// Shared helper: build a CSRF-protected HTML response for inactive-account
/// pages.
fn render_inactive_page(
    user: &User,
    cookie_jar: CookieJar,
    clock: &impl Clock,
    rng: impl RngCore,
    locale: &DataLocale,
    render_fn: impl FnOnce(
        &pasion_templates::WithLanguage<pasion_templates::WithCsrf<AccountInactiveContext>>,
    ) -> Result<String, pasion_templates::TemplateError>,
) -> Result<Response, SessionLoadError> {
    let (csrf, jar) = cookie_jar.csrf_token(clock, rng);
    let ctx = AccountInactiveContext::new(user.clone())
        .with_csrf(csrf.form_value())
        .with_language(locale.clone());
    let html_body = render_fn(&ctx)?;

    let mut resp = Response::new();
    jar.write_to_response(&mut resp);
    resp.render(Text::Html(html_body));
    Ok(resp)
}

/// Count all active sessions belonging to the given user, for use in
/// session-limit enforcement.
///
/// This tallies both OAuth 2.0 sessions and self-owned personal sessions
/// (administrative personal sessions created on behalf of the user by another
/// actor are excluded).
///
/// We intentionally count *all* sessions regardless of whether they carry
/// device scopes, because filtering by scope prefix would require a partial
/// index that is awkward to express cleanly in SQL. In practice the difference
/// is negligible, and an overall cap is arguably desirable anyway.
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let num_oauth2 = repo
        .oauth2_session()
        .count(OAuth2SessionFilter::new().active_only().for_user(user))
        .await? as u64;

    let num_personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .active_only()
                .for_actor_user(user)
                .for_owner_user(user),
        )
        .await? as u64;

    Ok(SessionCounts {
        total: num_oauth2 + num_personal,
        oauth2: num_oauth2,
        personal: num_personal,
    })
}
