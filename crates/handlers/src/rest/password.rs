use anyhow::Context as _;
use pasion_storage::queue::{QueueJobRepositoryExt as _, SendAccountRecoveryEmailsJob};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    NodeType, RouteError, extract_bound_activity_tracker, extract_session_info, get_limiter,
    get_password_manager, get_repo_factory, get_requester, get_site_config, make_clock, make_rng,
};

// ── POST /api/v1/viewer/password ───────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordInput {
    pub user_id: String,
    pub current_password: Option<String>,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct SetPasswordResponse {
    pub status: &'static str,
}

#[handler]
pub async fn set_password(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordResponse>, RouteError> {
    let input: SetPasswordInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(RouteError::Unauthorized);
    }

    if input.new_password.is_empty() {
        return Ok(Json(SetPasswordResponse {
            status: "INVALID_NEW_PASSWORD",
        }));
    }

    if !password_manager.is_enabled() {
        return Ok(Json(SetPasswordResponse {
            status: "PASSWORD_CHANGES_DISABLED",
        }));
    }

    if !password_manager
        .is_password_complex_enough(&input.new_password)
        .map_err(|e| RouteError::Internal(e.into()))?
    {
        return Ok(Json(SetPasswordResponse {
            status: "INVALID_NEW_PASSWORD",
        }));
    }

    let Some(user) = repo.user().lookup(user_id).await? else {
        return Ok(Json(SetPasswordResponse {
            status: "NOT_FOUND",
        }));
    };

    if !requester.is_admin() {
        if !config.password_change_allowed {
            return Ok(Json(SetPasswordResponse {
                status: "PASSWORD_CHANGES_DISABLED",
            }));
        }

        let Some(active_password) = repo.user_password().active(&user).await? else {
            return Ok(Json(SetPasswordResponse {
                status: "NO_CURRENT_PASSWORD",
            }));
        };

        let Some(current_password) = input.current_password else {
            return Err(RouteError::BadRequest(
                "currentPassword required for non-admins".into(),
            ));
        };

        if !password_manager
            .verify(
                active_password.version,
                Zeroizing::new(current_password),
                active_password.hashed_password,
            )
            .await
            .map_err(|e| RouteError::Internal(e.into()))?
            .is_success()
        {
            return Ok(Json(SetPasswordResponse {
                status: "WRONG_PASSWORD",
            }));
        }
    }

    let (version, hash) = password_manager
        .hash(make_rng(), Zeroizing::new(input.new_password))
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hash, None)
        .await?;

    repo.save().await?;

    Ok(Json(SetPasswordResponse { status: "ALLOWED" }))
}

// ── POST /api/v1/password-recovery/set ─────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordByRecoveryInput {
    pub ticket: String,
    pub new_password: String,
}

#[handler]
pub async fn set_password_by_recovery(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordResponse>, RouteError> {
    let input: SetPasswordByRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    if !password_manager.is_enabled() || !config.account_recovery_allowed {
        return Ok(Json(SetPasswordResponse {
            status: "PASSWORD_CHANGES_DISABLED",
        }));
    }

    if !password_manager
        .is_password_complex_enough(&input.new_password)
        .map_err(|e| RouteError::Internal(e.into()))?
    {
        return Ok(Json(SetPasswordResponse {
            status: "INVALID_NEW_PASSWORD",
        }));
    }

    let mut repo = repo_factory.create().await?;

    let Some(ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
        return Ok(Json(SetPasswordResponse {
            status: "NO_SUCH_RECOVERY_TICKET",
        }));
    };

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Unknown session")
        .map_err(|e| RouteError::Internal(e.into()))?;

    if session.consumed_at.is_some() {
        return Ok(Json(SetPasswordResponse {
            status: "RECOVERY_TICKET_ALREADY_USED",
        }));
    }

    if !ticket.active(clock.now()) {
        return Ok(Json(SetPasswordResponse {
            status: "EXPIRED_RECOVERY_TICKET",
        }));
    }

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        .context("Unknown email")
        .map_err(|e| RouteError::Internal(e.into()))?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Invalid user")
        .map_err(|e| RouteError::Internal(e.into()))?;

    if !user.is_valid() {
        return Ok(Json(SetPasswordResponse {
            status: "ACCOUNT_LOCKED",
        }));
    }

    let (version, hash) = password_manager
        .hash(make_rng(), Zeroizing::new(input.new_password))
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hash, None)
        .await?;

    repo.user_recovery()
        .consume_ticket(&clock, ticket, session)
        .await?;

    repo.save().await?;

    Ok(Json(SetPasswordResponse { status: "ALLOWED" }))
}

// ── POST /api/v1/password-recovery/resend ──────────────────────

#[derive(Deserialize)]
pub struct ResendRecoveryInput {
    pub ticket: String,
}

#[derive(Serialize)]
pub struct ResendRecoveryResponse {
    pub status: &'static str,
}

#[handler]
pub async fn resend_recovery_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendRecoveryResponse>, RouteError> {
    let input: ResendRecoveryInput = req
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
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
        return Ok(Json(ResendRecoveryResponse {
            status: "NO_SUCH_RECOVERY_TICKET",
        }));
    };

    let session = repo
        .user_recovery()
        .lookup_session(ticket.user_recovery_session_id)
        .await?
        .context("Could not load recovery session")
        .map_err(|e| RouteError::Internal(e.into()))?;

    if let Err(_e) = limiter.check_account_recovery(requester.fingerprint(), &session.email) {
        return Ok(Json(ResendRecoveryResponse {
            status: "RATE_LIMITED",
        }));
    }

    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SendAccountRecoveryEmailsJob::new(&session),
        )
        .await?;

    repo.save().await?;

    Ok(Json(ResendRecoveryResponse { status: "SENT" }))
}
