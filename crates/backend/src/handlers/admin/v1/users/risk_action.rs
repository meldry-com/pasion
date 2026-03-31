use pasion_data::audit::AdminOperation;
use pasion_data::audit::NewAdminOperationLog;
use salvo::prelude::*;
use schemars::JsonSchema;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, User},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// # JSON payload for the `POST /api/admin/v1/users/:id/risk-action` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RiskActionRequest")]
pub struct RequestBody {
    /// The risk action to perform: "lock", "force_password_reset", or
    /// "terminate_sessions"
    action: String,

    /// The reason for the risk action
    reason: Option<String>,
}

/// Response indicating which risk action was taken
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct RiskActionResponse {
    /// The action that was performed
    action: String,

    /// The reason provided for the action
    reason: Option<String>,

    /// The user the action was performed on
    user: SingleResponse<User>,

    /// Number of sessions terminated (only for terminate_sessions action)
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions_terminated: Option<usize>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.risk_action", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<RiskActionResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    let mut sessions_terminated = None;

    let user = match params.action.as_str() {
        "lock" => repo.user().lock(&clock, user).await?,

        "force_password_reset" => {
            // Lock the user account so they must reset their password
            let user = repo.user().lock(&clock, user).await?;
            user
        }

        "terminate_sessions" => {
            use pasion_data::user::BrowserSessionFilter;

            let filter = BrowserSessionFilter::new().for_user(&user).active_only();
            let count = repo.browser_session().finish_bulk(&clock, filter).await?;
            sessions_terminated = Some(count);
            user
        }

        other => return Err(AppError::bad_request(format!("Unknown risk action: {other}"))),
    };

    // Record audit log for the risk action
    if let Some(admin_user) = &admin_user {
        let operation = match params.action.as_str() {
            "lock" | "force_password_reset" => AdminOperation::UserLocked,
            "terminate_sessions" => AdminOperation::Other("terminate_sessions".into()),
            _ => AdminOperation::Other(params.action.clone()),
        };
        repo.audit()
            .add_admin_operation(
                &mut rng,
                &clock,
                NewAdminOperationLog::new(
                    admin_user.id,
                    operation,
                    "user",
                    serde_json::json!({
                        "action": params.action,
                        "reason": params.reason,
                    }),
                )
                .with_resource_id(user.id),
            )
            .await?;
    }

    repo.save().await?;

    let user_response = SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/risk-action"),
    );

    Ok(Json(RiskActionResponse {
        action: params.action,
        reason: params.reason,
        user: user_response,
        sessions_terminated,
    }))
}
