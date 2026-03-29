use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng,
};
use crate::account_profile::{
    AccountProfileError, DeactivateAccountOutcome, SetDisplayNameOutcome,
    allow_cross_signing_reset as allow_cross_signing_reset_service,
    deactivate_current_account, set_display_name as set_display_name_service,
};

// ── POST /api/v1/viewer/display-name ───────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetDisplayNameInput {
    pub user_id: String,
    pub display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SetDisplayNameResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn set_display_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetDisplayNameResponse>, RouteError> {
    let input: SetDisplayNameInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let homeserver = depot.homeserver()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    let status = match set_display_name_service(
        repo,
        &requester,
        homeserver.as_ref(),
        user_id,
        input.display_name,
    )
    .await
    .map_err(map_account_profile_error)?
    {
        SetDisplayNameOutcome::Set => "SET",
        SetDisplayNameOutcome::Invalid => "INVALID",
    };

    Ok(Json(SetDisplayNameResponse { status }))
}

// ── POST /api/v1/viewer/cross-signing-reset ────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowCrossSigningResetInput {
    pub user_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct AllowCrossSigningResetResponse {
    pub user: Option<UserBrief>,
}

#[derive(Serialize, ToSchema)]
pub struct UserBrief {
    pub id: String,
}

#[endpoint]
pub async fn allow_cross_signing_reset(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AllowCrossSigningResetResponse>, RouteError> {
    let input: AllowCrossSigningResetInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = depot.repo_factory()?;
    let homeserver = depot.homeserver()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    let user = allow_cross_signing_reset_service(repo, &requester, homeserver.as_ref(), user_id)
        .await
        .map_err(map_account_profile_error)?;

    Ok(Json(AllowCrossSigningResetResponse {
        user: Some(UserBrief {
            id: NodeType::User.serialize(user.id),
        }),
    }))
}

// ── POST /api/v1/viewer/deactivate ─────────────────────────────

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateUserInput {
    pub hs_erase: bool,
    pub password: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DeactivateUserResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn deactivate_user(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DeactivateUserResponse>, RouteError> {
    let input: DeactivateUserInput = req
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

    let status = match deactivate_current_account(
        repo,
        &requester,
        &mut rng,
        &clock,
        &config,
        &password_manager,
        input.password,
        input.hs_erase,
    )
    .await
    .map_err(map_account_profile_error)?
    {
        DeactivateAccountOutcome::IncorrectPassword => "INCORRECT_PASSWORD",
        DeactivateAccountOutcome::Deactivated => "DEACTIVATED",
    };

    Ok(Json(DeactivateUserResponse { status }))
}

fn map_account_profile_error(error: AccountProfileError) -> RouteError {
    match error {
        AccountProfileError::NotFound => RouteError::NotFound,
        AccountProfileError::Unauthorized | AccountProfileError::BrowserSessionRequired => {
            RouteError::Unauthorized
        }
        AccountProfileError::DeactivationDisabled => {
            RouteError::BadRequest("Account deactivation is not allowed".into())
        }
        AccountProfileError::Password(error) | AccountProfileError::Homeserver(error) => {
            RouteError::Internal(error.into())
        }
        AccountProfileError::Repository(error) => RouteError::from(error),
    }
}
