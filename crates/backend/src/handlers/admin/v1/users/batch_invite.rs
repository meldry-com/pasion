use crate::record_error;
use chrono::Duration;
use pasion_data::audit::AdminOperation;
use pasion_data::audit::NewAdminOperationLog;
use rand::distributions::{Alphanumeric, DistString};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    response::{ErrorResponse, SingleResponse},
};
use crate::handlers::admin::CreatedJson;

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Count must be between 1 and 100")]
    InvalidCount,
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCount => StatusCode::BAD_REQUEST,
        };
        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}

/// # JSON payload for the `POST /api/admin/v1/users/batch-invite` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "BatchInviteRequest")]
pub struct RequestBody {
    /// Number of registration tokens to create (1-100)
    count: u32,

    /// Maximum number of times each token can be used. If not provided, each
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// Number of hours until each token expires. If not provided, the tokens
    /// never expire.
    expires_in_hours: Option<u64>,
}

/// Response containing the list of created registration tokens
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct BatchInviteResponse {
    /// The list of created registration tokens
    data: Vec<SingleResponse<UserRegistrationToken>>,
}


impl_endpoint_out_register!(RouteError, [
    ("400", "Bad request"),
    ("401", "Unauthorized"),
    ("404", "Not found"),
    ("409", "Conflict"),
    ("500", "Internal server error"),
]);

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.batch_invite", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<CreatedJson<BatchInviteResponse>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::rest::make_rng();
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    if params.count == 0 || params.count > 100 {
        return Err(RouteError::InvalidCount);
    }

    let expires_at = params
        .expires_in_hours
        .and_then(|h| Duration::try_hours(h as i64))
        .map(|d| clock.now() + d);

    let mut tokens = Vec::with_capacity(params.count as usize);

    for _ in 0..params.count {
        let token_string = Alphanumeric.sample_string(&mut rng, 12);

        let registration_token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &clock,
                token_string,
                params.usage_limit,
                expires_at,
            )
            .await?;

        if let Some(admin_user) = &admin_user {
            repo.audit()
                .add_admin_operation(
                    &mut rng,
                    &clock,
                    NewAdminOperationLog::new(
                        admin_user.id,
                        AdminOperation::RegistrationTokenCreated,
                        "registration_token",
                        serde_json::json!({}),
                    )
                    .with_resource_id(registration_token.id),
                )
                .await?;
        }

        let model = UserRegistrationToken::new(registration_token, clock.now());
        tokens.push(SingleResponse::new_canonical(model));
    }

    repo.save().await?;

    Ok(CreatedJson(BatchInviteResponse { data: tokens }))
}
