use pasion_data::PostAuthAction;
use crate::salvo_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use pasion_templates::{
    FieldError, RegisterStepsDisplayNameContext, RegisterStepsDisplayNameFormField,
    TemplateContext as _, Templates, ToFormState,
};
use salvo::{prelude::*, writing::Text};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::handlers::rest::DepotExt;
use crate::handlers::{
    account_registration::{
        LoadRegistrationDisplayNameStepError, SetRegistrationDisplayNameError,
        load_registration_display_name_step, set_registration_display_name,
    },
    rest,
    views::shared::OptionalPostAuthAction,
};

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum FormAction {
    #[default]
    Set,
    Skip,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DisplayNameForm {
    #[serde(skip_serializing, default)]
    action: FormAction,
    #[serde(default)]
    display_name: String,
}

impl ToFormState for DisplayNameForm {
    type Field = pasion_templates::RegisterStepsDisplayNameFormField;
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
    let mut repo = depot.repo_factory()?.create().await?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    match load_registration_display_name_step(&mut repo, id).await {
        Ok(_) => {}
        Err(LoadRegistrationDisplayNameStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationDisplayNameStepError::RegistrationCompleted(registration)) => {
            let post_auth_action: Option<PostAuthAction> = registration
                .post_auth_action
                .map(serde_json::from_value)
                .transpose()?;

            cookie_jar.write_to_response(res);
            res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
            return Ok(());
        }
        Err(LoadRegistrationDisplayNameStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    }

    let ctx = RegisterStepsDisplayNameContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_display_name(&ctx)?;

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
    let locale = crate::handlers::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;
    let form: ProtectedForm<DisplayNameForm> = req
        .parse_form()
        .await
        .map_err(|e| InternalError::from_anyhow(e.into()))?;

    let step = match load_registration_display_name_step(&mut repo, id).await {
        Ok(step) => step,
        Err(LoadRegistrationDisplayNameStepError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(LoadRegistrationDisplayNameStepError::RegistrationCompleted(registration)) => {
            let post_auth_action: Option<PostAuthAction> = registration
                .post_auth_action
                .map(serde_json::from_value)
                .transpose()?;

            cookie_jar.write_to_response(res);
            res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
            return Ok(());
        }
        Err(LoadRegistrationDisplayNameStepError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    let registration = step.registration;

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let registration = match set_registration_display_name(
        repo,
        id,
        Some(form.display_name.clone()),
        matches!(form.action, FormAction::Skip),
    )
    .await
    {
        Ok(registration) => registration,
        Err(SetRegistrationDisplayNameError::InvalidDisplayName) => {
            let ctx = RegisterStepsDisplayNameContext::new()
                .with_form_state(form.to_form_state().with_error_on_field(
                    RegisterStepsDisplayNameFormField::DisplayName,
                    FieldError::Invalid,
                ))
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            cookie_jar.write_to_response(res);
            res.render(Text::Html(
                templates.render_register_steps_display_name(&ctx)?,
            ));
            return Ok(());
        }
        Err(SetRegistrationDisplayNameError::RegistrationCompleted) => {
            let post_auth_action: Option<PostAuthAction> = registration
                .post_auth_action
                .map(serde_json::from_value)
                .transpose()?;

            cookie_jar.write_to_response(res);
            res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
            return Ok(());
        }
        Err(SetRegistrationDisplayNameError::NotFound) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not find user registration"
            )));
        }
        Err(SetRegistrationDisplayNameError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    cookie_jar.write_to_response(res);
    res.render(salvo::writing::Redirect::other(&url_builder.relative_url(
        &format!("/register/steps/{}/finish", registration.id),
    )));
    Ok(())
}
