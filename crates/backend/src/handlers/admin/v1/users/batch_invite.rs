use chrono::Duration;
use pasion_data::audit::AdminOperation;
use pasion_data::audit::NewAdminOperationLog;
use rand::distributions::{Alphanumeric, DistString};
use salvo::prelude::*;
use schemars::JsonSchema;
use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    response::SingleResponse,
};
use crate::{AppError, CreatedJsonResult};

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
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.batch_invite", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<BatchInviteResponse> {
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
        .map_err(AppError::internal)?;

    if params.count == 0 || params.count > 100 {
        return Err(AppError::bad_request("Count must be between 1 and 100"));
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

    Ok(crate::handlers::admin::CreatedJson(BatchInviteResponse {
        data: tokens,
    }))
}
