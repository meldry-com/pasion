use chrono::Utc;
use pasion_data::flow::{FlowSession, FlowSessionStatus};
use pasion_data::new_id;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng,
};
use crate::handlers::{
    account::service::password::{ChangePasswordError, change_password},
    account::service::recovery::{
        CompleteAccountRecoveryError, ResendAccountRecoveryByTicketError,
        complete_account_recovery, resend_account_recovery_by_ticket,
    },
    flow::{FlowExecutor, defaults::default_password_change_flow, flow_session_store_write},
};

// ── POST /api/v1/viewer/password ───────────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordInput {
    pub user_id: String,
    pub current_password: Option<String>,
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct SetPasswordResponse {
    pub status: &'static str,
    /// When the flow engine is enabled, the frontend should use this ID
    /// with the flow session API (`/api/v1/flow/session/:id`) instead of
    /// the legacy password-change endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_session_id: Option<String>,
}

#[endpoint]
pub async fn set_password(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordResponse>, RouteError> {
    let input: SetPasswordInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(RouteError::Unauthorized);
    }

    match change_password(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        user_id,
        input.current_password.map(Zeroizing::new),
        Zeroizing::new(input.new_password),
        requester.is_admin(),
        config.password_change_allowed,
    )
    .await
    {
        Ok(()) => {
            // If the flow engine is enabled, start a flow session alongside the
            // legacy password change so the frontend can choose the flow-based
            // path for any additional steps.
            let flow_session_id = if config.flow_engine_enabled {
                let mut rng = make_rng();
                let (flow_def, bindings) = default_password_change_flow(&mut *rng);
                let plan = FlowExecutor::plan(flow_def, bindings);

                let now = Utc::now();
                let session_id = new_id(now, &mut *rng);

                let session = FlowSession {
                    id: session_id,
                    flow_id: plan.flow.id,
                    current_stage_index: 0,
                    status: FlowSessionStatus::InProgress,
                    context: Value::Object(serde_json::Map::new()),
                    ip_address: None,
                    user_agent: None,
                    created_at: now,
                    updated_at: now,
                    expires_at: now + chrono::Duration::hours(1),
                    completed_at: None,
                };

                flow_session_store_write()
                    .await
                    .insert(session_id, (plan, session));

                Some(session_id.to_string())
            } else {
                None
            };

            Ok(Json(SetPasswordResponse {
                status: "ALLOWED",
                flow_session_id,
            }))
        }
        Err(ChangePasswordError::PasswordDisabled) => Ok(Json(SetPasswordResponse {
            status: "PASSWORD_CHANGES_DISABLED",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::PasswordTooWeak) => Ok(Json(SetPasswordResponse {
            status: "INVALID_NEW_PASSWORD",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::UserNotFound) => Ok(Json(SetPasswordResponse {
            status: "NOT_FOUND",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::PasswordChangesDisabled) => Ok(Json(SetPasswordResponse {
            status: "PASSWORD_CHANGES_DISABLED",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::NoCurrentPassword) => Ok(Json(SetPasswordResponse {
            status: "NO_CURRENT_PASSWORD",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::CurrentPasswordRequired) => Err(RouteError::BadRequest(
            "currentPassword required for non-admins".into(),
        )),
        Err(ChangePasswordError::WrongPassword) => Ok(Json(SetPasswordResponse {
            status: "WRONG_PASSWORD",
            flow_session_id: None,
        })),
        Err(ChangePasswordError::Password(error)) => Err(RouteError::Internal(error.into())),
        Err(ChangePasswordError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/password-recovery/set ─────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordByRecoveryInput {
    pub ticket: String,
    pub new_password: String,
}

#[endpoint]
pub async fn set_password_by_recovery(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetPasswordResponse>, RouteError> {
    let input: SetPasswordByRecoveryInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let repo = repo_factory.create().await?;

    match complete_account_recovery(
        repo,
        &mut rng,
        &clock,
        &password_manager,
        &input.ticket,
        Zeroizing::new(input.new_password),
        config.account_recovery_allowed,
    )
    .await
    {
        Ok(()) => Ok(Json(SetPasswordResponse {
            status: "ALLOWED",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::PasswordDisabled) => Ok(Json(SetPasswordResponse {
            status: "PASSWORD_CHANGES_DISABLED",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::PasswordTooWeak) => Ok(Json(SetPasswordResponse {
            status: "INVALID_NEW_PASSWORD",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::TicketNotFound) => Ok(Json(SetPasswordResponse {
            status: "NO_SUCH_RECOVERY_TICKET",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::SessionNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Could not load recovery session"),
        ))),
        Err(CompleteAccountRecoveryError::AlreadyConsumed) => Ok(Json(SetPasswordResponse {
            status: "RECOVERY_TICKET_ALREADY_USED",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::TicketExpired) => Ok(Json(SetPasswordResponse {
            status: "EXPIRED_RECOVERY_TICKET",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::EmailNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Unknown email for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::UserNotFound) => Err(RouteError::Internal(Box::new(
            std::io::Error::other("Invalid user for recovery ticket"),
        ))),
        Err(CompleteAccountRecoveryError::AccountLocked) => Ok(Json(SetPasswordResponse {
            status: "ACCOUNT_LOCKED",
            flow_session_id: None,
        })),
        Err(CompleteAccountRecoveryError::Password(error)) => {
            Err(RouteError::Internal(error.into()))
        }
        Err(CompleteAccountRecoveryError::Repository(error)) => Err(error.into()),
    }
}

// ── POST /api/v1/password-recovery/resend ──────────────────────

#[derive(Deserialize, ToSchema)]
pub struct ResendRecoveryInput {
    pub ticket: String,
}

#[derive(Serialize, ToSchema)]
pub struct ResendRecoveryResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn resend_recovery_email(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ResendRecoveryResponse>, RouteError> {
    let input: ResendRecoveryInput = req
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
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    match resend_account_recovery_by_ticket(
        repo,
        &limiter,
        &mut rng,
        &clock,
        requester.fingerprint(),
        &input.ticket,
    )
    .await
    {
        Ok(()) => Ok(Json(ResendRecoveryResponse { status: "SENT" })),
        Err(ResendAccountRecoveryByTicketError::TicketNotFound) => {
            Ok(Json(ResendRecoveryResponse {
                status: "NO_SUCH_RECOVERY_TICKET",
            }))
        }
        Err(ResendAccountRecoveryByTicketError::SessionNotFound) => Err(RouteError::Internal(
            Box::new(std::io::Error::other("Could not load recovery session")),
        )),
        Err(ResendAccountRecoveryByTicketError::AlreadyConsumed) => {
            Ok(Json(ResendRecoveryResponse {
                status: "RECOVERY_TICKET_ALREADY_USED",
            }))
        }
        Err(ResendAccountRecoveryByTicketError::RateLimited) => Ok(Json(ResendRecoveryResponse {
            status: "RATE_LIMITED",
        })),
        Err(ResendAccountRecoveryByTicketError::Repository(error)) => Err(error.into()),
    }
}
