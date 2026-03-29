use pasion_salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_storage::queue::{QueueJobRepositoryExt as _, SendAccountRecoveryEmailsJob};
use pasion_templates::{EmptyContext, RecoveryProgressContext, TemplateContext, Templates};
use salvo::{prelude::*, writing::Text};
use ulid::Ulid;

use crate::rest::DepotExt;
use crate::{RequesterFingerprint, rest};

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let site_config = depot.site_config()?;
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let id: Ulid = req.param("id").unwrap_or_default();

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

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&pasion_router::AccountRecoveryStart));
        return Ok(());
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_progress(&context)?;

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
    let site_config = depot.site_config()?;
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let limiter = depot.limiter()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let cookie_jar = depot.cookie_jar(req)?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let form: ProtectedForm<()> = req
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

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&pasion_router::AccountRecoveryStart));
        return Ok(());
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    // Verify the CSRF token
    let () = cookie_jar.verify_form(&clock, form)?;

    // Check the rate limit if we are about to process the form
    if let Err(e) = limiter.check_account_recovery(requester, &recovery_session.email) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        let context = RecoveryProgressContext::new(recovery_session, true)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let rendered = templates.render_recovery_progress(&context)?;

        res.status_code(StatusCode::TOO_MANY_REQUESTS);
        cookie_jar.write_to_response(res);
        res.render(Text::Html(rendered));
        return Ok(());
    }

    // Schedule a new batch of emails
    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SendAccountRecoveryEmailsJob::new(&recovery_session),
        )
        .await?;

    repo.save().await?;

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_progress(&context)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(rendered));
    Ok(())
}
