use std::sync::{Arc, LazyLock};

use chrono::Duration;
use opentelemetry::metrics::Counter;
use pasion_matrix::HomeserverConnection;
use pasion_router::PostAuthAction;
use pasion_salvo_utils::{InternalError, SessionInfoExt as _, cookies::CookieJar};
use pasion_templates::{RegisterStepsEmailInUseContext, TemplateContext as _, Templates};
use salvo::{prelude::*, writing::Text};
use ulid::Ulid;

use super::super::cookie::UserRegistrationSessions;
use crate::rest::DepotExt;
use crate::{
    METER,
    account_registration::{
        LoadRegistrationProgressError, PrepareRegistrationCompletionError, complete_registration,
        load_registration_progress, prepare_registration_completion,
    },
    rest,
    views::shared::OptionalPostAuthAction,
};

static PASSWORD_REGISTER_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.user.password_registration")
        .with_description("Number of password registrations")
        .with_unit("{registration}")
        .build()
});

#[handler]
pub async fn get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), InternalError> {
    let mut rng = rest::make_rng();
    let clock = rest::make_clock();
    let lang = crate::preferred_language(req, depot);
    let url_builder = depot.url_builder()?;
    let homeserver = depot.homeserver()?;
    let templates = depot.templates()?;
    let site_config = depot.site_config()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = rest::extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let cookie_jar = depot.cookie_jar(req)?;
    let id: Ulid = req.param("id").unwrap_or_default();
    let progress =
        load_registration_progress(&mut repo, id)
            .await
            .map_err(|error| match error {
                LoadRegistrationProgressError::NotFound => {
                    InternalError::from_anyhow(anyhow::anyhow!("User registration not found"))
                }
                LoadRegistrationProgressError::Repository(error) => {
                    InternalError::from_anyhow(error.into())
                }
            })?;
    let registration = progress.registration;

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

    // Make sure the registration session hasn't expired
    // XXX: this duration is hard-coded, could be configurable
    if clock.now() - registration.created_at > Duration::hours(1) {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Registration session has expired"
        )));
    }

    // Check that this registration belongs to this browser
    let registrations = UserRegistrationSessions::load(&cookie_jar);
    if !registrations.contains(&registration) {
        // XXX: we should have a better error screen here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Could not find the registration in the browser cookies"
        )));
    }

    // Let's perform last minute checks on the registration, especially to avoid
    // race conditions where multiple users register with the same username or email
    // address

    if repo.user().exists(&registration.username).await? {
        // XXX: this could have a better error message, but as this is unlikely to
        // happen, we're fine with a vague message for now
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is already taken"
        )));
    }

    if !homeserver
        .is_localpart_available(&registration.username)
        .await
        .map_err(InternalError::from_anyhow)?
    {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is not available"
        )));
    }

    let registration_id = registration.id;
    let post_auth_action_value = registration.post_auth_action.clone();

    let prepared = match prepare_registration_completion(
        &mut repo,
        &clock,
        progress,
        site_config.registration_token_required,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(PrepareRegistrationCompletionError::RegistrationTokenRequired) => {
            cookie_jar.write_to_response(res);
            res.render(url_builder.redirect(&pasion_router::RegisterToken::new(registration_id)));
            return Ok(());
        }
        Err(PrepareRegistrationCompletionError::EmailNotVerified) => {
            cookie_jar.write_to_response(res);
            res.render(
                url_builder.redirect(&pasion_router::RegisterVerifyEmail::new(registration_id)),
            );
            return Ok(());
        }
        Err(PrepareRegistrationCompletionError::EmailInUse(email)) => {
            let action = post_auth_action_value
                .clone()
                .map(serde_json::from_value)
                .transpose()?;

            let ctx = RegisterStepsEmailInUseContext::new(email, action).with_language(lang);

            cookie_jar.write_to_response(res);
            res.render(Text::Html(
                templates.render_register_steps_email_in_use(&ctx)?,
            ));
            return Ok(());
        }
        Err(PrepareRegistrationCompletionError::DisplayNameRequired) => {
            cookie_jar.write_to_response(res);
            res.render(
                url_builder.redirect(&pasion_router::RegisterDisplayName::new(registration_id)),
            );
            return Ok(());
        }
        Err(PrepareRegistrationCompletionError::RegistrationTokenMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not load the registration token"
            )));
        }
        Err(PrepareRegistrationCompletionError::RegistrationTokenInvalid) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Registration token used is no longer valid"
            )));
        }
        Err(PrepareRegistrationCompletionError::EmailAuthenticationMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not load the email authentication"
            )));
        }
        Err(PrepareRegistrationCompletionError::PhoneAuthenticationMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not load the phone authentication"
            )));
        }
        Err(PrepareRegistrationCompletionError::PhoneNotVerified) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Phone verification is not complete"
            )));
        }
        Err(PrepareRegistrationCompletionError::PhoneInUse) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Phone number is already in use"
            )));
        }
        Err(PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not load the upstream OAuth authorization session"
            )));
        }
        Err(PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "Could not load the upstream OAuth link"
            )));
        }
        Err(PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed) => {
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "The upstream identity was already linked to a user. Try logging in again"
            )));
        }
        Err(PrepareRegistrationCompletionError::Repository(error)) => {
            return Err(InternalError::from_anyhow(error.into()));
        }
    };

    // Consume the registration session
    let cookie_jar = registrations
        .consume_session(&prepared.registration)?
        .save(cookie_jar, &clock);

    let completed =
        complete_registration(repo, &mut rng, &clock, prepared.into_request(user_agent)).await?;

    if completed.password_authenticated {
        PASSWORD_REGISTER_COUNTER.add(1, &[]);
    }

    activity_tracker
        .record_browser_session(&clock, &completed.user_session)
        .await;

    let post_auth_action: Option<PostAuthAction> = completed
        .registration
        .post_auth_action
        .map(serde_json::from_value)
        .transpose()?;

    // Login the user with the session we just created
    let cookie_jar = cookie_jar.set_session(&completed.user_session);

    cookie_jar.write_to_response(res);
    res.render(OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder));
    Ok(())
}
