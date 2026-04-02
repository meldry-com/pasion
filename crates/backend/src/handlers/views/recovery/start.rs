use crate::salvo_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_templates::{
    EmptyContext, FieldError, FormError, FormState, RecoveryStartContext, RecoveryStartFormField,
    TemplateContext, Templates,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};

use crate::handlers::account::DepotExt;
use crate::handlers::{
    RequesterFingerprint,
    account::service::recovery::{StartAccountRecoveryError, start_account_recovery},
    rest,
};

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
    let mut rng = common::make_rng();
    let clock = common::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let site_config = depot.site_config()?;
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let cookie_jar = depot.cookie_jar(req)?;

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
        res.render(salvo::writing::Redirect::other(&url_builder.relative_url("/")));
        return Ok(());
    }

    let context = RecoveryStartContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

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
    let mut rng = common::make_rng();
    let clock = common::make_clock();
    let locale = crate::handlers::preferred_language(req, depot);
    let site_config = depot.site_config()?;
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let limiter = depot.limiter()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = common::extract_bound_activity_tracker(req, depot);
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
    let cookie_jar = depot.cookie_jar(req)?;
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
        res.render(salvo::writing::Redirect::other(&url_builder.relative_url("/")));
        return Ok(());
    }

    let form = cookie_jar.verify_form(&clock, form)?;
    let mut form_state = FormState::from_form(&form);

    let session = match start_account_recovery(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        form.email,
        user_agent,
        activity_tracker.ip(),
        locale.to_string(),
    )
    .await
    {
        Ok(session) => session,
        Err(StartAccountRecoveryError::InvalidEmail) => {
            form_state =
                form_state.with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid);

            let context = RecoveryStartContext::new()
                .with_form_state(form_state)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);
            let rendered = templates.render_recovery_start(&context)?;

            cookie_jar.write_to_response(res);
            res.render(Text::Html(rendered));
            return Ok(());
        }
        Err(StartAccountRecoveryError::RateLimited) => {
            form_state.add_error_on_form(FormError::RateLimitExceeded);

            let context = RecoveryStartContext::new()
                .with_form_state(form_state)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);
            let rendered = templates.render_recovery_start(&context)?;

            cookie_jar.write_to_response(res);
            res.render(Text::Html(rendered));
            return Ok(());
        }
        Err(StartAccountRecoveryError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    cookie_jar.write_to_response(res);
    res.render(salvo::writing::Redirect::other(&url_builder.relative_url(
            &format!("/recover/progress/{}", session.id),
        )));
    Ok(())
}
