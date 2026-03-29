use anyhow::Context as _;
use pasion_router::PostAuthAction;
use pasion_salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use pasion_templates::{
    FieldError, RegisterStepsRegistrationTokenContext, RegisterStepsRegistrationTokenFormField,
    TemplateContext as _, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{rest, views::shared::OptionalPostAuthAction};
use crate::rest::DepotExt;

#[derive(Deserialize, Serialize)]
pub(crate) struct RegistrationTokenForm {
    #[serde(default)]
    token: String,
}

impl ToFormState for RegistrationTokenForm {
    type Field = pasion_templates::RegisterStepsRegistrationTokenFormField;
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
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        cookie_jar.write_to_response(res);
        res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
        return Ok(());
    }

    // If the registration already has a token, skip this step
    if registration.user_registration_token_id.is_some() {
        let destination = pasion_router::RegisterDisplayName::new(registration.id);
        cookie_jar.write_to_response(res);
        res.render(url_builder.redirect(&destination));
        return Ok(());
    }

    let ctx = RegisterStepsRegistrationTokenContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_registration_token(&ctx)?;

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
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;
    let form: ProtectedForm<RegistrationTokenForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        cookie_jar.write_to_response(res);
        res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
        return Ok(());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the token
    let token = form.token.trim();
    if token.is_empty() {
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Required,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        cookie_jar.write_to_response(res);
        res.render(Text::Html(
            templates.render_register_steps_registration_token(&ctx)?,
        ));
        return Ok(());
    }

    // Look up the token
    let Some(registration_token) = repo.user_registration_token().find_by_token(token).await?
    else {
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Invalid,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        cookie_jar.write_to_response(res);
        res.render(Text::Html(
            templates.render_register_steps_registration_token(&ctx)?,
        ));
        return Ok(());
    };

    // Check if the token is still valid
    if !registration_token.is_valid(clock.now()) {
        tracing::warn!("Registration token isn't valid (expired or already used)");
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Invalid,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        cookie_jar.write_to_response(res);
        res.render(Text::Html(
            templates.render_register_steps_registration_token(&ctx)?,
        ));
        return Ok(());
    }

    // Associate the token with the registration
    let registration = repo
        .user_registration()
        .set_registration_token(registration, &registration_token)
        .await?;

    repo.save().await?;

    // Continue to the next step
    let destination = pasion_router::RegisterFinish::new(registration.id);
    cookie_jar.write_to_response(res);
    res.render(url_builder.redirect(&destination));
    Ok(())
}
