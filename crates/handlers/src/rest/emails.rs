use pasion_storage::queue::{
    ProvisionUserJob, QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob,
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    NodeType, RouteError, extract_bound_activity_tracker, extract_session_info, get_limiter,
    get_password_manager, get_repo_factory, get_requester, get_site_config, make_clock, make_rng,
    verify_password_if_needed,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartEmailAuthResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<EmailAuthData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAuthData {
    pub id: String,
    pub email: String,
}

#[derive(Serialize)]
pub struct CompleteEmailAuthResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct ResendEmailAuthCodeResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveEmailResponse {
    pub status: &'static str,
}

// ── GET /api/v1/email-auth/:id ─────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAuthStatusResponse {
    pub id: String,
    pub email: String,
    pub completed_at: Option<String>,
}

#[handler]
pub async fn get_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EmailAuthStatusResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let repo_factory = get_repo_factory(depot)?;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartEmailAuthInput {
    pub email: String,
    pub password: Option<String>,
    #[serde(default = "default_language")]
    pub language: String,
}

fn default_language() -> String {
    "en".to_owned()
}

#[handler]
pub async fn start_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<StartEmailAuthResponse>, RouteError> {
    let input: StartEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let limiter = get_limiter(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

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

    // Rate limit check
    if let Err(_e) = limiter.check_email_authentication(requester.fingerprint()) {
        return Ok(Json(StartEmailAuthResponse {
            status: "RATE_LIMITED",
            authentication: None,
            violations: None,
        }));
    }

    // Verify password if needed
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

    // Create authentication session
    let auth = repo
        .user_email()
        .add_authentication_for_session(&mut rng, &clock, &input.email, browser_session)
        .await?;

    // Schedule email sending
    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SendEmailAuthenticationCodeJob::new(&auth, &input.language),
        )
        .await?;

    repo.save().await?;

    Ok(Json(StartEmailAuthResponse {
        status: "STARTED",
        authentication: Some(EmailAuthData {
            id: NodeType::UserEmailAuthentication.serialize(auth.id),
            email: auth.email,
        }),
        violations: None,
    }))
}

// ── POST /api/v1/email-auth/:id/complete ───────────────────────

#[derive(Deserialize)]
pub struct CompleteEmailAuthInput {
    pub code: String,
}

#[handler]
pub async fn complete_email_auth(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<CompleteEmailAuthResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: CompleteEmailAuthInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let limiter = get_limiter(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    let auth = repo
        .user_email()
        .lookup_authentication(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Verify ownership
    if auth.user_session_id != Some(browser_session.id) {
        return Err(RouteError::Unauthorized);
    }

    if auth.completed_at.is_some() {
        return Ok(Json(CompleteEmailAuthResponse { status: "COMPLETED" }));
    }

    // Rate limit check
    if let Err(_e) = limiter.check_email_authentication(requester.fingerprint()) {
        return Ok(Json(CompleteEmailAuthResponse { status: "RATE_LIMITED" }));
    }

    // Find and validate code
    let code = repo
        .user_email()
        .find_authentication_code(&auth, &input.code)
        .await?;

    let Some(code) = code else {
        return Ok(Json(CompleteEmailAuthResponse { status: "INVALID_CODE" }));
    };

    if code.expires_at < clock.now() {
        return Ok(Json(CompleteEmailAuthResponse { status: "CODE_EXPIRED" }));
    }

    // Complete authentication
    repo.user_email()
        .complete_authentication_with_code(&clock, auth.clone(), code)
        .await?;

    // Check if email is already in use
    let existing = repo.user_email().find(&browser_session.user, &auth.email).await?;
    if existing.is_none() {
        // Add email to user
        repo.user_email()
            .add(&mut rng, &clock, &browser_session.user, auth.email.clone())
            .await?;
    }

    repo.save().await?;

    Ok(Json(CompleteEmailAuthResponse { status: "COMPLETED" }))
}

// ── POST /api/v1/email-auth/:id/resend ─────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendEmailAuthInput {
    #[serde(default = "default_language")]
    pub language: String,
}

#[handler]
pub async fn resend_email_auth_code(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendEmailAuthCodeResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmailAuthentication.extract_ulid(&id)?;

    let input: ResendEmailAuthInput = req
        .parse_json()
        .await
        .unwrap_or(ResendEmailAuthInput { language: "en".to_owned() });

    let repo_factory = get_repo_factory(depot)?;
    let limiter = get_limiter(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    let auth = repo
        .user_email()
        .lookup_authentication(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if auth.user_session_id != Some(browser_session.id) {
        return Err(RouteError::Unauthorized);
    }

    if auth.completed_at.is_some() {
        return Ok(Json(ResendEmailAuthCodeResponse { status: "COMPLETED" }));
    }

    if let Err(_e) = limiter.check_email_authentication(requester.fingerprint()) {
        return Ok(Json(ResendEmailAuthCodeResponse { status: "RATE_LIMITED" }));
    }

    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SendEmailAuthenticationCodeJob::new(&auth, &input.language),
        )
        .await?;

    repo.save().await?;

    Ok(Json(ResendEmailAuthCodeResponse { status: "RESENT" }))
}

// ── DELETE /api/v1/user-emails/:id ─────────────────────────────

#[derive(Deserialize)]
pub struct RemoveEmailInput {
    pub password: Option<String>,
}

#[handler]
pub async fn remove_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RemoveEmailResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::UserEmail.extract_ulid(&id)?;

    // Body is optional for DELETE
    let input: RemoveEmailInput = req.parse_json().await.unwrap_or(RemoveEmailInput { password: None });

    let repo_factory = get_repo_factory(depot)?;
    let config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let email = repo
        .user_email()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(Some(email.user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let user = repo.user().lookup(email.user_id).await?.ok_or(RouteError::LoadFailed)?;

    if !verify_password_if_needed(&requester, &config, &password_manager, input.password, &user, &mut repo).await? {
        return Ok(Json(RemoveEmailResponse { status: "INCORRECT_PASSWORD" }));
    }

    repo.user_email().remove(email).await?;

    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(Json(RemoveEmailResponse { status: "REMOVED" }))
}
