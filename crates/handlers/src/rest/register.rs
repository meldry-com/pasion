//! REST API endpoints for user registration.
//!
//! These endpoints mirror the logic in `crate::views::register` but return
//! JSON instead of rendered HTML, making them suitable for SPA / mobile
//! clients.

use std::str::FromStr;

use chrono::Duration;
use lettre::Address;
use pasion_data_model::UserRegistration;
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::SessionInfoExt;
use pasion_storage::{
    RepositoryAccess,
    queue::{
        ProvisionUserJob, QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob,
    },
    user::{UserEmailFilter, UserEmailRepository, UserFilter, UserPhoneRepository, UserRepository},
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::{
    RouteError, extract_bound_activity_tracker, extract_cookie_jar, get_homeserver, get_limiter,
    get_password_manager, get_policy_factory, get_repo_factory, get_site_config, make_clock,
    make_rng,
};
use crate::RequesterFingerprint;

// ── Shared helpers ─────────────────────────────────────────────

/// Determine the next verification step for a registration.
///
/// The registration flow supports pluggable verification steps. Each
/// verification target (email, phone, …) has its own endpoint
/// (`verify-email`, `verify-phone`, …) and its own authentication record on
/// the registration.  This function inspects which verifications have been
/// configured and returns the first one that is still pending.
///
/// **Current default flow:** `register → verify_email → display_name → finish`
fn next_step(registration: &UserRegistration, email_verified: bool) -> &'static str {
    // Email verification
    if registration.email_authentication_id.is_some() && !email_verified {
        return "verify_email";
    }

    // Future: phone / other verification steps can be added here, e.g.:
    // if registration.phone_authentication_id.is_some() && !phone_verified {
    //     return "verify_phone";
    // }

    if registration.display_name.is_none() {
        return "display_name";
    }

    "finish"
}

/// Build the list of steps that have been completed so far.
fn steps_completed(registration: &UserRegistration, email_verified: bool) -> Vec<&'static str> {
    let mut steps = Vec::new();
    steps.push("register"); // the initial registration step is always done

    if registration.email_authentication_id.is_some() && email_verified {
        steps.push("verify_email");
    }

    // Future: phone / other verification steps can be added here.

    if registration.display_name.is_some() {
        steps.push("display_name");
    }

    if registration.completed_at.is_some() {
        steps.push("finish");
    }

    steps
}

// ── POST /api/v1/auth/register ─────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterInput {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[handler]
pub async fn post_register(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegisterResponse>, RouteError> {
    let input: RegisterInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let homeserver = get_homeserver(depot)?;
    let policy_factory = get_policy_factory(depot)?;
    let limiter = get_limiter(depot)?;
    let repo_factory = get_repo_factory(depot)?;

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let ip_address = activity_tracker.ip();

    if !site_config.password_registration_enabled {
        return Ok(Json(RegisterResponse {
            status: "error",
            id: None,
            next_step: None,
            error: Some("registration_disabled".into()),
        }));
    }

    let mut repo = repo_factory.create().await?;

    // ── Validate inputs ────────────────────────────────────────
    let mut errors: Vec<String> = Vec::new();

    // Username checks
    if input.username.is_empty() {
        errors.push("username_required".into());
    } else if repo.user().exists(&input.username).await? {
        errors.push("username_exists".into());
    } else {
        match homeserver.is_localpart_available(&input.username).await {
            Ok(false) => errors.push("username_exists".into()),
            Ok(true) => {}
            Err(e) => {
                tracing::warn!(
                    error = &*e as &dyn std::error::Error,
                    "Failed to check localpart availability, skipping homeserver check"
                );
            }
        }
    }

    // Email checks (only when required by config)
    let email_str = input.email.clone().unwrap_or_default();
    let email = if site_config.password_registration_email_required {
        if email_str.is_empty() {
            errors.push("email_required".into());
            None
        } else if Address::from_str(&email_str).is_err() {
            errors.push("email_invalid".into());
            None
        } else {
            Some(email_str)
        }
    } else if !email_str.is_empty() {
        if Address::from_str(&email_str).is_err() {
            errors.push("email_invalid".into());
            None
        } else {
            Some(email_str)
        }
    } else {
        None
    };

    // Password checks
    if input.password.is_empty() {
        errors.push("password_required".into());
    }
    if input.password_confirm.is_empty() {
        errors.push("password_confirm_required".into());
    }
    if input.password != input.password_confirm {
        errors.push("password_mismatch".into());
    }

    if errors.is_empty()
        && !password_manager
            .is_password_complex_enough(&input.password)
            .map_err(|e| RouteError::Internal(e.into()))?
    {
        errors.push("password_too_weak".into());
    }

    // Policy evaluation
    if errors.is_empty() {
        let mut policy = policy_factory
            .instantiate()
            .await
            .map_err(|e| RouteError::Internal(e.into()))?;

        let result = policy
            .evaluate_register(pasion_policy::RegisterInput {
                registration_method: pasion_policy::RegistrationMethod::Password,
                username: &input.username,
                email: email.as_deref(),
                requester: pasion_policy::Requester {
                    ip_address: activity_tracker.ip(),
                    user_agent: user_agent.clone(),
                },
            })
            .await
            .map_err(|e| RouteError::Internal(e.into()))?;

        for violation in result.violations {
            let field = violation.field.as_deref().unwrap_or("form");
            errors.push(format!("policy_{field}:{}", violation.msg));
        }
    }

    // Rate limit checks
    if errors.is_empty() {
        if let Err(e) = limiter.check_registration(requester) {
            tracing::warn!(error = &e as &dyn std::error::Error);
            errors.push("rate_limited".into());
        }

        if let Some(email) = &email {
            if let Err(e) = limiter.check_email_authentication_email(requester, email) {
                tracing::warn!(error = &e as &dyn std::error::Error);
                errors.push("rate_limited".into());
            }
        }
    }

    if !errors.is_empty() {
        return Ok(Json(RegisterResponse {
            status: "error",
            id: None,
            next_step: None,
            error: Some(errors.join(", ")),
        }));
    }

    // ── Create the registration ────────────────────────────────

    let registration = repo
        .user_registration()
        .add(
            &mut rng,
            &clock,
            input.username,
            ip_address,
            user_agent,
            None, // no post_auth_action for REST API
        )
        .await?;

    // Set terms URL if configured
    let registration = if let Some(tos_uri) = &site_config.tos_uri {
        repo.user_registration()
            .set_terms_url(registration, tos_uri.clone())
            .await?
    } else {
        registration
    };

    // Set up email authentication if needed
    let (registration, email_verified) = if let Some(email) = email {
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(&mut rng, &clock, email, &registration)
            .await?;

        // Schedule email sending
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendEmailAuthenticationCodeJob::new(&user_email_authentication, "en".to_owned()),
            )
            .await?;

        let reg = repo
            .user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?;

        (reg, false)
    } else {
        (registration, true)
    };

    // NOTE: Phone number from input.phone is accepted but not verified during
    // registration.  When phone verification is needed, a similar block to the
    // email setup above should be added here using UserPhoneAuthentication +
    // the verify-phone endpoint.

    // Hash and store the password
    let password = Zeroizing::new(input.password);
    let (version, hashed_password) = password_manager
        .hash(&mut rng, password)
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    let registration = repo
        .user_registration()
        .set_password(registration, hashed_password, version)
        .await?;

    repo.save().await?;

    let step = next_step(&registration, email_verified);

    Ok(Json(RegisterResponse {
        status: "success",
        id: Some(registration.id.to_string()),
        next_step: Some(step),
        error: None,
    }))
}

// ── GET /api/v1/auth/register/:id ──────────────────────────────

#[derive(Serialize)]
pub struct RegistrationStatusResponse {
    pub id: String,
    pub username: String,
    pub email_pending: bool,
    pub steps_completed: Vec<&'static str>,
    pub next_step: &'static str,
}

#[handler]
pub async fn get_registration(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegistrationStatusResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let mut repo = repo_factory.create().await?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Check if email has been verified
    let email_verified = if let Some(email_auth_id) = registration.email_authentication_id {
        let email_auth = repo
            .user_email()
            .lookup_authentication(email_auth_id)
            .await?
            .ok_or(RouteError::NotFound)?;
        email_auth.completed_at.is_some()
    } else {
        true // no email auth means no email step needed
    };

    let email_pending = registration.email_authentication_id.is_some() && !email_verified;

    repo.cancel().await?;

    let completed = steps_completed(&registration, email_verified);
    let step = next_step(&registration, email_verified);

    Ok(Json(RegistrationStatusResponse {
        id: registration.id.to_string(),
        username: registration.username,
        email_pending,
        steps_completed: completed,
        next_step: step,
    }))
}

// ── POST /api/v1/auth/register/:id/verify-email ────────────────

#[derive(Deserialize)]
pub struct VerifyEmailInput {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyEmailResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[handler]
pub async fn post_verify_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<VerifyEmailResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: VerifyEmailInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let limiter = get_limiter(depot)?;
    let clock = make_clock();

    let mut repo = repo_factory.create().await?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(Json(VerifyEmailResponse {
            status: "error",
            next_step: None,
            error: Some("registration_already_completed".into()),
        }));
    }

    let email_authentication_id = registration.email_authentication_id.ok_or_else(|| {
        RouteError::BadRequest("no email authentication for this registration".into())
    })?;

    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if email_authentication.completed_at.is_some() {
        return Ok(Json(VerifyEmailResponse {
            status: "error",
            next_step: None,
            error: Some("email_already_verified".into()),
        }));
    }

    // Rate limit check
    if let Err(e) = limiter.check_email_authentication_attempt(&email_authentication) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        return Ok(Json(VerifyEmailResponse {
            status: "error",
            next_step: None,
            error: Some("rate_limited".into()),
        }));
    }

    // Look up the code
    let Some(code) = repo
        .user_email()
        .find_authentication_code(&email_authentication, &input.code)
        .await?
    else {
        return Ok(Json(VerifyEmailResponse {
            status: "error",
            next_step: None,
            error: Some("invalid_code".into()),
        }));
    };

    // Complete the email authentication
    repo.user_email()
        .complete_authentication_with_code(&clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(Json(VerifyEmailResponse {
        status: "success",
        next_step: Some(next_step(&registration, true)),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/verify-phone ────────────────

#[derive(Deserialize)]
pub struct VerifyPhoneInput {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyPhoneResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[handler]
pub async fn post_verify_phone(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<VerifyPhoneResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: VerifyPhoneInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let limiter = get_limiter(depot)?;
    let clock = make_clock();

    let mut repo = repo_factory.create().await?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(Json(VerifyPhoneResponse {
            status: "error",
            next_step: None,
            error: Some("registration_already_completed".into()),
        }));
    }

    let phone_authentication_id = registration.phone_authentication_id.ok_or_else(|| {
        RouteError::BadRequest("no phone authentication for this registration".into())
    })?;

    let phone_authentication = repo
        .user_phone()
        .lookup_authentication(phone_authentication_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if phone_authentication.completed_at.is_some() {
        return Ok(Json(VerifyPhoneResponse {
            status: "error",
            next_step: None,
            error: Some("phone_already_verified".into()),
        }));
    }

    // Look up the code
    let Some(code) = repo
        .user_phone()
        .find_authentication_code(&phone_authentication, &input.code)
        .await?
    else {
        return Ok(Json(VerifyPhoneResponse {
            status: "error",
            next_step: None,
            error: Some("invalid_code".into()),
        }));
    };

    // Complete the phone authentication
    repo.user_phone()
        .complete_authentication_with_code(&clock, phone_authentication, &code)
        .await?;

    repo.save().await?;

    Ok(Json(VerifyPhoneResponse {
        status: "success",
        next_step: Some(next_step(&registration, true)),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/display-name ────────────────

#[derive(Deserialize)]
pub struct DisplayNameInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
}

#[derive(Serialize)]
pub struct DisplayNameResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[handler]
pub async fn post_display_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DisplayNameResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let input: DisplayNameInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let mut repo = repo_factory.create().await?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(Json(DisplayNameResponse {
            status: "error",
            next_step: None,
            error: Some("registration_already_completed".into()),
        }));
    }

    let display_name = if input.skip.unwrap_or(false) {
        // Use the username as default display name when skipping
        registration.username.clone()
    } else {
        let display_name = input
            .display_name
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_owned();

        if display_name.is_empty() || display_name.len() > 255 {
            return Ok(Json(DisplayNameResponse {
                status: "error",
                next_step: None,
                error: Some("invalid_display_name".into()),
            }));
        }

        display_name
    };

    let _registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    Ok(Json(DisplayNameResponse {
        status: "success",
        next_step: Some("finish"),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/finish ──────────────────────

#[derive(Serialize)]
pub struct FinishRegistrationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[handler]
pub async fn post_finish(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<Json<FinishRegistrationResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = get_site_config(depot)?;
    let homeserver = get_homeserver(depot)?;
    let repo_factory = get_repo_factory(depot)?;

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let cookie_jar = extract_cookie_jar(req, depot)?;

    let mut repo = repo_factory.create().await?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if registration.completed_at.is_some() {
        return Ok(Json(FinishRegistrationResponse {
            status: "error",
            error: Some("registration_already_completed".into()),
        }));
    }

    // Check session expiry (1 hour)
    if clock.now() - registration.created_at > Duration::hours(1) {
        return Ok(Json(FinishRegistrationResponse {
            status: "error",
            error: Some("registration_expired".into()),
        }));
    }

    // Verify username is still available
    if repo.user().exists(&registration.username).await? {
        return Ok(Json(FinishRegistrationResponse {
            status: "error",
            error: Some("username_taken".into()),
        }));
    }

    match homeserver
        .is_localpart_available(&registration.username)
        .await
    {
        Ok(false) => {
            return Ok(Json(FinishRegistrationResponse {
                status: "error",
                error: Some("username_not_available".into()),
            }));
        }
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(
                error = &*e as &dyn std::error::Error,
                "Failed to check localpart availability during finish, skipping homeserver check"
            );
        }
    }

    // Check registration token if required
    let registration_token = if site_config.registration_token_required {
        if let Some(registration_token_id) = registration.user_registration_token_id {
            let registration_token = repo
                .user_registration_token()
                .lookup(registration_token_id)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Could not load the registration token",
                    )))
                })?;

            if !registration_token.is_valid(clock.now()) {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("registration_token_invalid".into()),
                }));
            }

            Some(registration_token)
        } else {
            return Ok(Json(FinishRegistrationResponse {
                status: "error",
                error: Some("registration_token_required".into()),
            }));
        }
    } else {
        None
    };

    // Check email authentication
    let email_authentication =
        if let Some(email_authentication_id) = registration.email_authentication_id {
            let email_authentication = repo
                .user_email()
                .lookup_authentication(email_authentication_id)
                .await?
                .ok_or_else(|| {
                    RouteError::Internal(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Could not load the email authentication",
                    )))
                })?;

            if email_authentication.completed_at.is_none() {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("email_not_verified".into()),
                }));
            }

            // Check that the email address is not already in use
            if repo
                .user_email()
                .count(UserEmailFilter::new().for_email(&email_authentication.email))
                .await?
                > 0
            {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("email_in_use".into()),
                }));
            }

            Some(email_authentication)
        } else {
            None
        };

    // Check display name is set
    if registration.display_name.is_none() {
        return Ok(Json(FinishRegistrationResponse {
            status: "error",
            error: Some("display_name_required".into()),
        }));
    }

    // ── Complete the registration ──────────────────────────────

    let registration = repo
        .user_registration()
        .complete(&clock, registration)
        .await?;

    // Mark registration token as used
    if let Some(registration_token) = registration_token {
        repo.user_registration_token()
            .use_token(&clock, registration_token)
            .await?;
    }

    // Create the user
    let mut user = repo
        .user()
        .add(&mut rng, &clock, registration.username.clone())
        .await?;

    // If this is the first user, automatically grant admin privileges
    let user_count = repo.user().count(UserFilter::new()).await?;
    if user_count == 1 {
        user = repo.user().set_can_request_admin(user, true).await?;
    }

    // Create a browser session to log the user in
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    // Add the email if verified
    if let Some(email_authentication) = email_authentication {
        repo.user_email()
            .add(&mut rng, &clock, &user, email_authentication.email)
            .await?;
    }

    // Set the password
    if let Some(password) = registration.password {
        let user_password = repo
            .user_password()
            .add(
                &mut rng,
                &clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
            .await?;
    }

    // Accept terms if set
    if let Some(terms_url) = registration.terms_url {
        repo.user_terms()
            .accept_terms(&mut rng, &clock, &user, terms_url)
            .await?;
    }

    // Schedule user provisioning
    let mut job = ProvisionUserJob::new(&user);
    if let Some(display_name) = registration.display_name {
        job = job.set_display_name(display_name);
    }
    repo.queue_job().schedule_job(&mut rng, &clock, job).await?;

    repo.save().await?;

    // Record the browser session activity
    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    // Set the session cookie to log the user in
    let cookie_jar = cookie_jar.set_session(&user_session);
    cookie_jar.write_to_response(res);

    Ok(Json(FinishRegistrationResponse {
        status: "success",
        error: None,
    }))
}
