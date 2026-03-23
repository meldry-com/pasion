use std::str::FromStr;

use lettre::Address;
use pasion_salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_storage::queue::{QueueJobRepositoryExt as _, SendAccountRecoveryEmailsJob};
use pasion_templates::{
    EmptyContext, FieldError, FormError, FormState, RecoveryStartContext, RecoveryStartFormField,
    TemplateContext, Templates,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};

use crate::{RequesterFingerprint, rest};

#[derive(Deserialize, Serialize)]
pub(crate) struct StartRecoveryForm {
    email: String,
}

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let site_config = rest::get_site_config(depot)?;
    let templates = rest::get_templates(depot)?;
    let url_builder = rest::get_url_builder(depot)?;
    let mut repo = rest::get_repo_factory(depot)?.create().await?;
    let cookie_jar = rest::extract_cookie_jar(req, depot)?;

    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_active_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&pasion_router::Index));
        return Ok(());
    }

    let context = RecoveryStartContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_start(&context)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(rendered));
    Ok(())
}

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let site_config = rest::get_site_config(depot)?;
    let templates = rest::get_templates(depot)?;
    let url_builder = rest::get_url_builder(depot)?;
    let limiter = rest::get_limiter(depot)?;
    let mut repo = rest::get_repo_factory(depot)?.create().await?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let cookie_jar = rest::extract_cookie_jar(req, depot)?;
    let form: ProtectedForm<StartRecoveryForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_active_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&pasion_router::Index));
        return Ok(());
    }

    let ip_address = activity_tracker.ip();

    let form = cookie_jar.verify_form(&clock, form)?;
    let mut form_state = FormState::from_form(&form);

    if Address::from_str(&form.email).is_err() {
        form_state =
            form_state.with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid);
    }

    if form_state.is_valid() {
        // Check the rate limit if we are about to process the form
        if let Err(e) = limiter.check_account_recovery(requester, &form.email) {
            tracing::warn!(error = &e as &dyn std::error::Error);
            form_state.add_error_on_form(FormError::RateLimitExceeded);
        }
    }

    if !form_state.is_valid() {
        repo.save().await?;
        let context = RecoveryStartContext::new()
            .with_form_state(form_state)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let rendered = templates.render_recovery_start(&context)?;

        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    let session = repo
        .user_recovery()
        .add_session(
            &mut rng,
            &clock,
            form.email,
            user_agent,
            ip_address,
            locale.to_string(),
        )
        .await?;

    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SendAccountRecoveryEmailsJob::new(&session),
        )
        .await?;

    repo.save().await?;

    cookie_jar.write_to_response(res);
    res.render(url_builder.redirect(&pasion_router::AccountRecoveryProgress::new(session.id)));
    Ok(())
}
