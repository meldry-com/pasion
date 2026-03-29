use anyhow::Context;
use pasion_router::PostAuthAction;
use pasion_salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use pasion_storage::{RepositoryAccess, user::UserEmailRepository};
use pasion_templates::{
    FieldError, RegisterStepsVerifyEmailContext, RegisterStepsVerifyEmailFormField,
    TemplateContext, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::rest::DepotExt;
use crate::{rest, views::shared::OptionalPostAuthAction};

#[derive(Serialize, Deserialize, Debug)]
pub struct CodeForm {
    code: String,
}

impl ToFormState for CodeForm {
    type Field = pasion_templates::RegisterStepsVerifyEmailFormField;
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
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        cookie_jar.write_to_response(res);
        res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
        return Ok(());
    }

    let email_authentication_id = registration
        .email_authentication_id
        .context("No email authentication started for this registration")
        .map_err(InternalError::from_anyhow)?;
    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .context("Could not find email authentication")
        .map_err(InternalError::from_anyhow)?;

    if email_authentication.completed_at.is_some() {
        // XXX: display a better error here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Email authentication already completed"
        )));
    }

    let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_verify_email(&ctx)?;

    cookie_jar.write_to_response(res);
    res.render(Text::Html(content));
    Ok(())
}

#[handler]
pub async fn post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let clock = rest::make_clock();
    let mut rng = rest::make_rng();
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let limiter = depot.limiter()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let url_builder = depot.url_builder()?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let form: ProtectedForm<CodeForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let form = cookie_jar.verify_form(&clock, form)?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        cookie_jar.write_to_response(res);
        res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
        return Ok(());
    }

    let email_authentication_id = registration
        .email_authentication_id
        .context("No email authentication started for this registration")
        .map_err(InternalError::from_anyhow)?;
    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .context("Could not find email authentication")
        .map_err(InternalError::from_anyhow)?;

    if email_authentication.completed_at.is_some() {
        // XXX: display a better error here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Email authentication already completed"
        )));
    }

    if let Err(e) = limiter.check_email_authentication_attempt(&email_authentication) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
            .with_form_state(
                form.to_form_state()
                    .with_error_on_form(pasion_templates::FormError::RateLimitExceeded),
            )
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_register_steps_verify_email(&ctx)?;

        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    }

    let Some(code) = repo
        .user_email()
        .find_authentication_code(&email_authentication, &form.code)
        .await?
    else {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx =
            RegisterStepsVerifyEmailContext::new(email_authentication)
                .with_form_state(form.to_form_state().with_error_on_field(
                    RegisterStepsVerifyEmailFormField::Code,
                    FieldError::Invalid,
                ))
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

        let content = templates.render_register_steps_verify_email(&ctx)?;

        cookie_jar.write_to_response(res);
        res.render(Text::Html(content));
        return Ok(());
    };

    repo.user_email()
        .complete_authentication_with_code(&clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    let destination = pasion_router::RegisterFinish::new(registration.id);
    cookie_jar.write_to_response(res);
    res.render(url_builder.redirect(&destination));
    Ok(())
}
