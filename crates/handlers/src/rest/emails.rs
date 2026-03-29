use pasion_storage::{
    RepositoryAccess,
    user::{UserEmailRepository, UserRepository},
};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng, verify_password_if_needed,
};
use crate::account_contacts::{
    CompleteEmailVerificationError, RemoveUserEmailError, ResendEmailVerificationError,
    StartEmailVerificationError, complete_email_verification, remove_user_email,
    resend_email_verification_code, start_email_verification,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartEmailAuthResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<EmailAuthData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailAuthData {
    pub id: String,
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct CompleteEmailAuthResponse {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ResendEmailAuthCodeResponse {
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoveEmailResponse {
    pub status: &'static str,
}

// ── GET /api/v1/email-auth/:id ─────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailAuthStatusResponse {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[endpoint]
pub async fn get_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EmailAuthStatusResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let mut repo = repo_factory.create().await?;

    let auth = repo
        .user_email()
        .lookup_authentication(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    repo.cancel().await?;

    Ok(Json(EmailAuthStatusResponse {
        id: NodeType::UserEmailAuthentication.serialize(auth.id),
        email: auth.email,
        completed_at: auth.completed_at.map(|t| t.to_rfc3339()),
    }))
}

// ── POST /api/v1/email-auth/start ──────────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartEmailAuthInput {
    pub email: String,
    pub password: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[endpoint]
pub async fn start_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<StartEmailAuthResponse>, RouteError> {
    let input: StartEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::notification_language(req, depot, input.language.as_deref());

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    if !config.email_change_allowed {
        return Ok(Json(StartEmailAuthResponse {
            status: "DENIED",
            authentication: None,
            violations: Some(vec!["Email changes are not allowed".into()]),
        }));
    }

    // Validate email format
    if !input.email.contains('@') {
        return Ok(Json(StartEmailAuthResponse {
            status: "INVALID_EMAIL_ADDRESS",
            authentication: None,
            violations: None,
        }));
    }

    // Verify password if needed
    let mut repo = repo;
    if !verify_password_if_needed(
        &requester,
        &config,
        &password_manager,
        input.password,
        &browser_session.user,
        &mut repo,
    )
    .await?
    {
        return Ok(Json(StartEmailAuthResponse {
            status: "INCORRECT_PASSWORD",
            authentication: None,
            violations: None,
        }));
    }

    let fingerprint = requester.fingerprint();

    match start_email_verification(
        repo,
        &mut rng,
        &clock,
        &limiter,
        fingerprint,
        browser_session,
        input.email,
        notification_language,
    )
    .await
    {
        Ok(started) => Ok(Json(StartEmailAuthResponse {
            status: "STARTED",
            authentication: Some(EmailAuthData {
                id: NodeType::UserEmailAuthentication.serialize(started.authentication.id),
                email: started.authentication.email,
            }),
            violations: None,
        })),
        Err(StartEmailVerificationError::RateLimited) => Ok(Json(StartEmailAuthResponse {
            status: "RATE_LIMITED",
            authentication: None,
            violations: None,
        })),
        Err(StartEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/email-auth/:id/complete ───────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CompleteEmailAuthInput {
    pub code: String,
}

#[endpoint]
pub async fn complete_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<CompleteEmailAuthResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: CompleteEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    match complete_email_verification(
        repo,
        &limiter,
        &mut rng,
        &clock,
        ulid,
        browser_session.id,
        &browser_session.user,
        &input.code,
    )
    .await
    {
        Ok(()) => Ok(Json(CompleteEmailAuthResponse {
            status: "COMPLETED",
        })),
        Err(CompleteEmailVerificationError::NotFound) => Err(RouteError::NotFound),
        Err(CompleteEmailVerificationError::NotOwned) => Err(RouteError::Unauthorized),
        Err(CompleteEmailVerificationError::AlreadyCompleted) => {
            Ok(Json(CompleteEmailAuthResponse {
                status: "COMPLETED",
            }))
        }
        Err(CompleteEmailVerificationError::RateLimited) => Ok(Json(CompleteEmailAuthResponse {
            status: "RATE_LIMITED",
        })),
        Err(CompleteEmailVerificationError::InvalidCode) => Ok(Json(CompleteEmailAuthResponse {
            status: "INVALID_CODE",
        })),
        Err(CompleteEmailVerificationError::CodeExpired) => Ok(Json(CompleteEmailAuthResponse {
            status: "CODE_EXPIRED",
        })),
        Err(CompleteEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/email-auth/:id/resend ─────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResendEmailAuthInput {
    #[serde(default)]
    pub language: Option<String>,
}

#[endpoint]
pub async fn resend_email_auth_code(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendEmailAuthCodeResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: ResendEmailAuthInput = req
        .parse_json()
        .await
        .unwrap_or(ResendEmailAuthInput { language: None });

    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let mut rng = make_rng();
    let notification_language = crate::notification_language(req, depot, input.language.as_deref());

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    match resend_email_verification_code(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester.fingerprint(),
        ulid,
        browser_session.id,
        notification_language,
    )
    .await
    {
        Ok(()) => Ok(Json(ResendEmailAuthCodeResponse { status: "RESENT" })),
        Err(ResendEmailVerificationError::NotFound) => Err(RouteError::NotFound),
        Err(ResendEmailVerificationError::NotOwned) => Err(RouteError::Unauthorized),
        Err(ResendEmailVerificationError::AlreadyCompleted) => {
            Ok(Json(ResendEmailAuthCodeResponse {
                status: "COMPLETED",
            }))
        }
        Err(ResendEmailVerificationError::RateLimited) => Ok(Json(ResendEmailAuthCodeResponse {
            status: "RATE_LIMITED",
        })),
        Err(ResendEmailVerificationError::Repository(error)) => Err(error.into()),
    }
}

// ── DELETE /api/v1/user-emails/:id ─────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct RemoveEmailInput {
    pub password: Option<String>,
}

#[endpoint]
pub async fn remove_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RemoveEmailResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmail.extract_ulid(&id)?;

    // Body is optional for DELETE
    let input: RemoveEmailInput = req
        .parse_json()
        .await
        .unwrap_or(RemoveEmailInput { password: None });

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let email = repo
        .user_email()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(Some(email.user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(email.user_id)
        .await?
        .ok_or(RouteError::LoadFailed)?;

    if !verify_password_if_needed(
        &requester,
        &config,
        &password_manager,
        input.password,
        &user,
        &mut repo,
    )
    .await?
    {
        return Ok(Json(RemoveEmailResponse {
            status: "INCORRECT_PASSWORD",
        }));
    }

    match remove_user_email(repo, &mut rng, &clock, ulid, &user).await {
        Ok(()) => Ok(Json(RemoveEmailResponse { status: "REMOVED" })),
        Err(RemoveUserEmailError::NotFound) => Err(RouteError::NotFound),
        Err(RemoveUserEmailError::Repository(error)) => Err(error.into()),
    }
}
