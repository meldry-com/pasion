use anyhow::Context as _;
use pasion_router::PostAuthAction;
use pasion_salvo_utils::{
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

use crate::rest::DepotExt;
use crate::{rest, views::shared::OptionalPostAuthAction};

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
    let locale = crate::preferred_language(req, depot);
    let templates = depot.templates()?;
    let url_builder = depot.url_builder()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let cookie_jar = depot.cookie_jar(req)?;
    let form: ProtectedForm<DisplayNameForm> = req
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

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let display_name = match form.action {
        FormAction::Set => {
            let display_name = form.display_name.trim();

            if display_name.is_empty() || display_name.len() > 255 {
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

            display_name.to_owned()
        }
        FormAction::Skip => {
            // If the user chose to skip, we do the same as Palpo and use the localpart as
            // default display name
            registration.username.clone()
        }
    };

    let registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    let destination = pasion_router::RegisterFinish::new(registration.id);
    cookie_jar.write_to_response(res);
    res.render(url_builder.redirect(&destination));
    Ok(())
}
