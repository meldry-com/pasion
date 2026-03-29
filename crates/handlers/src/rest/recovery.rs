//! REST API endpoints for account recovery.
//!
//! These endpoints mirror the logic in `crate::views::recovery` but return
//! JSON instead of rendered HTML, making them suitable for SPA / mobile
//! clients.

use std::str::FromStr;

use lettre::Address;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng};
use crate::{RequesterFingerprint, notification_dispatch::schedule_account_recovery};

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

    // Validate email format
    if Address::from_str(&input.email).is_err() {
        return Ok(Json(StartRecoveryResponse {
            status: "error",
            id: None,
            error: Some("invalid_email".into()),
        }));
    }

    // Rate limit check
    if let Err(e) = limiter.check_account_recovery(requester, &input.email) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        return Ok(Json(StartRecoveryResponse {
            status: "error",
            id: None,
            error: Some("rate_limited".into()),
        }));
    }

    let mut repo = repo_factory.create().await?;

    // Create the recovery session
    let session = repo
        .user_recovery()
        .add_session(
            &mut rng,
            &clock,
            input.email,
            user_agent,
            ip_address,
            notification_language,
        )
        .await?;

    // Schedule recovery emails
    schedule_account_recovery(&mut repo, &mut rng, &clock, &session).await?;

    repo.save().await?;

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

    let session = repo
        .user_recovery()
        .lookup_session(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    repo.cancel().await?;

    let status = if session.consumed_at.is_some() {
        "consumed"
    } else {
        "pending"
    };

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

    let mut repo = repo_factory.create().await?;

    let session = repo
        .user_recovery()
        .lookup_session(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if session.consumed_at.is_some() {
        return Ok(Json(ResendRecoveryResponse {
            status: "error",
            error: Some("recovery_already_consumed".into()),
        }));
    }

    // Rate limit check
    if let Err(e) = limiter.check_account_recovery(requester, &session.email) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        return Ok(Json(ResendRecoveryResponse {
            status: "error",
            error: Some("rate_limited".into()),
        }));
    }

    // Schedule a new batch of recovery emails
    schedule_account_recovery(&mut repo, &mut rng, &clock, &session).await?;

    repo.save().await?;

    Ok(Json(ResendRecoveryResponse {
        status: "success",
        error: None,
    }))
}
