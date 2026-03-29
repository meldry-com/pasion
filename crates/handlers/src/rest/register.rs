//! REST API endpoints for user registration.
//!
//! These endpoints serve as thin HTTP adapters over the business logic in
//! [`crate::account_registration`]. They parse requests, check config/policy
//! constraints, delegate to service functions, and map results to JSON
//! responses.

use std::str::FromStr;

use lettre::Address;
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::SessionInfoExt;
use pasion_storage::{
    RepositoryAccess,
    user::{UserEmailFilter, UserEmailRepository, UserPhoneRepository, UserRepository},
};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    RequesterFingerprint,
    account_registration::{
        LoadRegistrationFinishPreparationError, LoadRegistrationProgressError,
        ResendRegistrationVerificationError, ResendRegistrationVerificationStatus,
        SetRegistrationDisplayNameError, StartPasswordRegistrationRequest,
        VerifyRegistrationEmailCodeError, VerifyRegistrationPhoneCodeError, complete_registration,
        load_registration_finish_preparation, load_registration_progress, next_registration_step,
        resend_pending_registration_verification, set_registration_display_name,
        start_password_registration, verify_registration_email_code,
        verify_registration_phone_code,
    },
};

// ── POST /api/v1/auth/register ─────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_register(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegisterResponse>, RouteError> {
    let input: RegisterInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let homeserver = depot.homeserver()?;
    let policy_factory = depot.policy_factory()?;
    let limiter = depot.limiter()?;
    let repo_factory = depot.repo_factory()?;
    let notification_language = crate::notification_language(req, depot, None);

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

    // Contact check: at least one of email or phone must be provided
    let email_str = input.email.clone().unwrap_or_default();
    let phone_str = input.phone.clone().unwrap_or_default();

    if site_config.password_registration_contact_required
        && email_str.is_empty()
        && phone_str.is_empty()
    {
        errors.push("email_or_phone_required".into());
    }

    // Validate email if provided
    let email = if !email_str.is_empty() {
        if Address::from_str(&email_str).is_err() {
            errors.push("email_invalid".into());
            None
        } else if repo
            .user_email()
            .count(UserEmailFilter::new().for_email(&email_str))
            .await?
            > 0
        {
            errors.push("email_in_use".into());
            None
        } else {
            Some(email_str)
        }
    } else {
        None
    };

    // Validate phone if provided
    let phone = if !phone_str.is_empty() {
        if repo.user_phone().find_by_phone(&phone_str).await?.is_some() {
            errors.push("phone_in_use".into());
            None
        } else {
            Some(phone_str)
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
                    ..Default::default()
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

        if let Some(phone) = &phone {
            if let Err(e) = limiter.check_phone_authentication_phone(requester, phone) {
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

    let started = start_password_registration(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        StartPasswordRegistrationRequest {
            username: input.username,
            email,
            phone,
            password: Zeroizing::new(input.password),
            user_agent,
            ip_address,
            post_auth_action: None,
            terms_url: site_config.tos_uri.clone(),
            notification_language,
        },
    )
    .await
    .map_err(|error| match error {
        crate::account_registration::StartPasswordRegistrationError::Repository(error) => {
            RouteError::from(error)
        }
        crate::account_registration::StartPasswordRegistrationError::Password(error) => {
            RouteError::Internal(error.into())
        }
    })?;

    let registration = started.registration;
    let email_verified = started.email_verified;
    let phone_verified = started.phone_verified;

    let step = next_registration_step(&registration, email_verified, phone_verified);

    Ok(Json(RegisterResponse {
        status: "success",
        id: Some(registration.id.to_string()),
        next_step: Some(step),
        error: None,
    }))
}

// ── GET /api/v1/auth/register/:id ──────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RegistrationStatusResponse {
    pub id: String,
    pub username: String,
    pub email_pending: bool,
    pub phone_pending: bool,
    pub steps_completed: Vec<&'static str>,
    pub next_step: &'static str,
}

#[endpoint]
pub async fn get_registration(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RegistrationStatusResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let mut repo = repo_factory.create().await?;

    let progress =
        load_registration_progress(&mut repo, id)
            .await
            .map_err(|error| match error {
                LoadRegistrationProgressError::NotFound => RouteError::NotFound,
                LoadRegistrationProgressError::Repository(error) => RouteError::from(error),
            })?;

    let email_pending =
        progress.registration.email_authentication_id.is_some() && !progress.email_verified();
    let phone_pending =
        progress.registration.phone_authentication_id.is_some() && !progress.phone_verified();

    repo.cancel().await?;

    let completed = progress.completed_steps();
    let step = progress.next_step();

    Ok(Json(RegistrationStatusResponse {
        id: progress.registration.id.to_string(),
        username: progress.registration.username,
        email_pending,
        phone_pending,
        steps_completed: completed,
        next_step: step,
    }))
}

// ── POST /api/v1/auth/register/:id/verify-email ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyEmailResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
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

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let repo = repo_factory.create().await?;

    let progress =
        match verify_registration_email_code(repo, &limiter, &clock, id, &input.code).await {
            Ok(progress) => progress,
            Err(VerifyRegistrationEmailCodeError::NotFound)
            | Err(VerifyRegistrationEmailCodeError::EmailAuthenticationMissing) => {
                return Err(RouteError::NotFound);
            }
            Err(VerifyRegistrationEmailCodeError::NoEmailAuthentication) => {
                return Err(RouteError::BadRequest(
                    "no email authentication for this registration".into(),
                ));
            }
            Err(VerifyRegistrationEmailCodeError::RegistrationCompleted) => {
                return Ok(Json(VerifyEmailResponse {
                    status: "error",
                    next_step: None,
                    error: Some("registration_already_completed".into()),
                }));
            }
            Err(VerifyRegistrationEmailCodeError::EmailAlreadyVerified) => {
                return Ok(Json(VerifyEmailResponse {
                    status: "error",
                    next_step: None,
                    error: Some("email_already_verified".into()),
                }));
            }
            Err(VerifyRegistrationEmailCodeError::RateLimited) => {
                return Ok(Json(VerifyEmailResponse {
                    status: "error",
                    next_step: None,
                    error: Some("rate_limited".into()),
                }));
            }
            Err(VerifyRegistrationEmailCodeError::InvalidCode) => {
                return Ok(Json(VerifyEmailResponse {
                    status: "error",
                    next_step: None,
                    error: Some("invalid_code".into()),
                }));
            }
            Err(VerifyRegistrationEmailCodeError::Repository(error)) => {
                return Err(error.into());
            }
        };

    Ok(Json(VerifyEmailResponse {
        status: "success",
        next_step: Some(progress.next_step()),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/resend-verification ────────

#[derive(Serialize, ToSchema)]
pub struct ResendVerificationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Resend the next pending verification code for a registration.
///
/// Unlike the authenticated `/email-auth/:id/resend` endpoint, this one works
/// during registration when the user does not yet have a browser session.
#[endpoint]
pub async fn post_resend_verification(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendVerificationResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::notification_language(req, depot, None);

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);

    let repo = repo_factory.create().await?;

    let status = match resend_pending_registration_verification(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        id,
        notification_language,
    )
    .await
    {
        Ok(status) => status,
        Err(ResendRegistrationVerificationError::NotFound) => return Err(RouteError::NotFound),
        Err(ResendRegistrationVerificationError::RateLimited) => {
            return Ok(Json(ResendVerificationResponse {
                status: "rate_limited",
                error: None,
            }));
        }
        Err(ResendRegistrationVerificationError::Repository(error)) => {
            return Err(error.into());
        }
    };

    let (status, error) = match status {
        ResendRegistrationVerificationStatus::RegistrationCompleted => {
            ("error", Some("registration_already_completed".into()))
        }
        ResendRegistrationVerificationStatus::Resent => ("resent", None),
        ResendRegistrationVerificationStatus::AlreadyVerified => ("already_verified", None),
    };

    Ok(Json(ResendVerificationResponse { status, error }))
}

// ── POST /api/v1/auth/register/:id/verify-phone ────────────────

#[derive(Deserialize, ToSchema)]
pub struct VerifyPhoneInput {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyPhoneResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
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

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let repo = repo_factory.create().await?;

    let progress =
        match verify_registration_phone_code(repo, &limiter, &clock, id, &input.code).await {
            Ok(progress) => progress,
            Err(VerifyRegistrationPhoneCodeError::NotFound)
            | Err(VerifyRegistrationPhoneCodeError::PhoneAuthenticationMissing) => {
                return Err(RouteError::NotFound);
            }
            Err(VerifyRegistrationPhoneCodeError::NoPhoneAuthentication) => {
                return Err(RouteError::BadRequest(
                    "no phone authentication for this registration".into(),
                ));
            }
            Err(VerifyRegistrationPhoneCodeError::RegistrationCompleted) => {
                return Ok(Json(VerifyPhoneResponse {
                    status: "error",
                    next_step: None,
                    error: Some("registration_already_completed".into()),
                }));
            }
            Err(VerifyRegistrationPhoneCodeError::PhoneAlreadyVerified) => {
                return Ok(Json(VerifyPhoneResponse {
                    status: "error",
                    next_step: None,
                    error: Some("phone_already_verified".into()),
                }));
            }
            Err(VerifyRegistrationPhoneCodeError::RateLimited) => {
                return Ok(Json(VerifyPhoneResponse {
                    status: "error",
                    next_step: None,
                    error: Some("rate_limited".into()),
                }));
            }
            Err(VerifyRegistrationPhoneCodeError::InvalidCode) => {
                return Ok(Json(VerifyPhoneResponse {
                    status: "error",
                    next_step: None,
                    error: Some("invalid_code".into()),
                }));
            }
            Err(VerifyRegistrationPhoneCodeError::Repository(error)) => {
                return Err(error.into());
            }
        };

    Ok(Json(VerifyPhoneResponse {
        status: "success",
        next_step: Some(progress.next_step()),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/display-name ────────────────

#[derive(Deserialize, ToSchema)]
pub struct DisplayNameInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub skip: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct DisplayNameResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
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

    let repo_factory = depot.repo_factory()?;
    let repo = repo_factory.create().await?;

    match set_registration_display_name(repo, id, input.display_name, input.skip.unwrap_or(false))
        .await
    {
        Ok(_) => {}
        Err(SetRegistrationDisplayNameError::NotFound) => return Err(RouteError::NotFound),
        Err(SetRegistrationDisplayNameError::RegistrationCompleted) => {
            return Ok(Json(DisplayNameResponse {
                status: "error",
                next_step: None,
                error: Some("registration_already_completed".into()),
            }));
        }
        Err(SetRegistrationDisplayNameError::InvalidDisplayName) => {
            return Ok(Json(DisplayNameResponse {
                status: "error",
                next_step: None,
                error: Some("invalid_display_name".into()),
            }));
        }
        Err(SetRegistrationDisplayNameError::Repository(error)) => {
            return Err(error.into());
        }
    }

    Ok(Json(DisplayNameResponse {
        status: "success",
        next_step: Some("finish"),
        error: None,
    }))
}

// ── POST /api/v1/auth/register/:id/finish ──────────────────────

#[derive(Serialize, ToSchema)]
pub struct FinishRegistrationResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
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

    let site_config = depot.site_config()?;
    let homeserver = depot.homeserver()?;
    let repo_factory = depot.repo_factory()?;

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());
    let cookie_jar = depot.cookie_jar(req)?;

    let mut repo = repo_factory.create().await?;

    let prepared = match load_registration_finish_preparation(
        &mut repo,
        &clock,
        homeserver.as_ref(),
        id,
        None,
        crate::account_registration::HomeserverCheckMode::BestEffort,
        site_config.registration_token_required,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(LoadRegistrationFinishPreparationError::NotFound) => return Err(RouteError::NotFound),
        Err(LoadRegistrationFinishPreparationError::AlreadyCompleted(_)) => {
            return Ok(Json(FinishRegistrationResponse {
                status: "error",
                error: Some("registration_already_completed".into()),
            }));
        }
        Err(LoadRegistrationFinishPreparationError::Eligibility { source, .. }) => match source {
            crate::account_registration::CheckRegistrationFinishEligibilityError::RegistrationExpired => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("registration_expired".into()),
                }));
            }
            crate::account_registration::CheckRegistrationFinishEligibilityError::UsernameTaken => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("username_taken".into()),
                }));
            }
            crate::account_registration::CheckRegistrationFinishEligibilityError::UsernameNotAvailable => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("username_not_available".into()),
                }));
            }
            crate::account_registration::CheckRegistrationFinishEligibilityError::BrowserSessionMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Registration browser session is required",
                ))));
            }
            crate::account_registration::CheckRegistrationFinishEligibilityError::HomeserverUnavailable(_) => {
                unreachable!()
            }
            crate::account_registration::CheckRegistrationFinishEligibilityError::Repository(error) => {
                return Err(error.into());
            }
        },
        Err(LoadRegistrationFinishPreparationError::Prepare { source, .. }) => match source {
            crate::account_registration::PrepareRegistrationCompletionError::RegistrationTokenRequired => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("registration_token_required".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::RegistrationTokenInvalid => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("registration_token_invalid".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::EmailNotVerified => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("email_not_verified".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::EmailInUse(_) => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("email_in_use".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::PhoneNotVerified => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("phone_not_verified".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::PhoneInUse => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("phone_in_use".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::DisplayNameRequired => {
                return Ok(Json(FinishRegistrationResponse {
                    status: "error",
                    error: Some("display_name_required".into()),
                }));
            }
            crate::account_registration::PrepareRegistrationCompletionError::RegistrationTokenMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not load the registration token",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::EmailAuthenticationMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not load the email authentication",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::PhoneAuthenticationMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not load the phone authentication",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::UpstreamOAuthSessionMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not load the upstream OAuth authorization session",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::UpstreamOAuthLinkMissing => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Could not load the upstream OAuth link",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::UpstreamOAuthLinkAlreadyUsed => {
                return Err(RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "The upstream identity was already linked to a user",
                ))));
            }
            crate::account_registration::PrepareRegistrationCompletionError::Repository(error) => {
                return Err(error.into());
            }
        },
        Err(LoadRegistrationFinishPreparationError::Repository(error)) => {
            return Err(error.into());
        }
    };

    let completed =
        complete_registration(repo, &mut rng, &clock, prepared.into_request(user_agent)).await?;

    // Record the browser session activity
    activity_tracker
        .record_browser_session(&clock, &completed.user_session)
        .await;

    // Set the session cookie to log the user in
    let cookie_jar = cookie_jar.set_session(&completed.user_session);
    cookie_jar.write_to_response(res);

    Ok(Json(FinishRegistrationResponse {
        status: "success",
        error: None,
    }))
}
