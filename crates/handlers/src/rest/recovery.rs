//! REST API endpoints for account recovery.
//!
//! These endpoints mirror the logic in `crate::views::recovery` but return
//! JSON instead of rendered HTML, making them suitable for SPA / mobile
//! clients.
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{
    RequesterFingerprint,
    account_recovery::{
        LoadAccountRecoverySessionError, ResendAccountRecoveryError, StartAccountRecoveryError,
        load_account_recovery_session, recovery_session_status, resend_account_recovery,
        start_account_recovery,
    },
};

// ── POST /api/v1/auth/recovery/start ───────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct StartRecoveryInput {
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct StartRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_recovery_start(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<StartRecoveryResponse>, RouteError> {
    let input: StartRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;
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
        .unwrap_or("")
        .to_owned();
    let ip_address = activity_tracker.ip();

    if !site_config.account_recovery_allowed {
        return Ok(Json(StartRecoveryResponse {
            status: "error",
            id: None,
            error: Some("recovery_disabled".into()),
        }));
    }

    let repo = repo_factory.create().await?;

    let session = match start_account_recovery(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester,
        input.email,
        user_agent,
        ip_address,
        notification_language,
    )
    .await
    {
        Ok(session) => session,
        Err(StartAccountRecoveryError::InvalidEmail) => {
            return Ok(Json(StartRecoveryResponse {
                status: "error",
                id: None,
                error: Some("invalid_email".into()),
            }));
        }
        Err(StartAccountRecoveryError::RateLimited) => {
            return Ok(Json(StartRecoveryResponse {
                status: "error",
                id: None,
                error: Some("rate_limited".into()),
            }));
        }
        Err(StartAccountRecoveryError::Repository(error)) => {
            return Err(error.into());
        }
    };

    Ok(Json(StartRecoveryResponse {
        status: "success",
        id: Some(session.id.to_string()),
        error: None,
    }))
}

// ── GET /api/v1/auth/recovery/:id ──────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RecoveryStatusResponse {
    pub id: String,
    pub email: String,
    pub status: &'static str,
}

#[endpoint]
pub async fn get_recovery(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RecoveryStatusResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;

    if !site_config.account_recovery_allowed {
        return Err(RouteError::BadRequest("recovery_disabled".into()));
    }

    let mut repo = repo_factory.create().await?;

    let session = match load_account_recovery_session(&mut repo, id).await {
        Ok(session) => session,
        Err(LoadAccountRecoverySessionError::NotFound) => return Err(RouteError::NotFound),
        Err(LoadAccountRecoverySessionError::Repository(error)) => return Err(error.into()),
    };
    let status = recovery_session_status(&session);

    repo.cancel().await?;

    Ok(Json(RecoveryStatusResponse {
        id: session.id.to_string(),
        email: session.email,
        status,
    }))
}

// ── POST /api/v1/auth/recovery/:id/resend ──────────────────────

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[endpoint]
pub async fn post_recovery_resend(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendRecoveryResponse>, RouteError> {
    let id: Ulid = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?
        .parse()
        .map_err(|_| RouteError::BadRequest("invalid id".into()))?;

    let site_config = depot.site_config()?;
    let repo_factory = depot.repo_factory()?;
    let limiter = depot.limiter()?;

    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);

    if !site_config.account_recovery_allowed {
        return Ok(Json(ResendRecoveryResponse {
            status: "error",
            error: Some("recovery_disabled".into()),
        }));
    }

    let repo = repo_factory.create().await?;

    match resend_account_recovery(repo, &limiter, &mut rng, &clock, requester, id).await {
        Ok(_) => {}
        Err(ResendAccountRecoveryError::NotFound) => return Err(RouteError::NotFound),
        Err(ResendAccountRecoveryError::AlreadyConsumed) => {
            return Ok(Json(ResendRecoveryResponse {
                status: "error",
                error: Some("recovery_already_consumed".into()),
            }));
        }
        Err(ResendAccountRecoveryError::RateLimited) => {
            return Ok(Json(ResendRecoveryResponse {
                status: "error",
                error: Some("rate_limited".into()),
            }));
        }
        Err(ResendAccountRecoveryError::Repository(error)) => return Err(error.into()),
    }

    Ok(Json(ResendRecoveryResponse {
        status: "success",
        error: None,
    }))
}
