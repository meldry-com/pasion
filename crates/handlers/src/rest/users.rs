use anyhow::Context as _;
use pasion_storage::queue::{DeactivateUserJob, QueueJobRepositoryExt as _};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    NodeType, RouteError, extract_bound_activity_tracker, extract_session_info, get_homeserver,
    get_password_manager, get_repo_factory, get_requester, get_site_config, make_clock, make_rng,
    verify_password_if_needed,
};

// ── POST /api/v1/viewer/display-name ───────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisplayNameInput {
    pub user_id: String,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct SetDisplayNameResponse {
    pub status: &'static str,
}

#[handler]
pub async fn set_display_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetDisplayNameResponse>, RouteError> {
    let input: SetDisplayNameInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NotFound)?;
    repo.cancel().await?;

    match &input.display_name {
        Some(name) => {
            if name.is_empty() || name.len() > 256 {
                return Ok(Json(SetDisplayNameResponse { status: "INVALID" }));
            }
            homeserver
                .set_displayname(&user.username, name)
                .await
                .map_err(|e| RouteError::Internal(e.into()))?;
        }
        None => {
            homeserver
                .unset_displayname(&user.username)
                .await
                .map_err(|e| RouteError::Internal(e.into()))?;
        }
    }

    Ok(Json(SetDisplayNameResponse { status: "SET" }))
}

// ── POST /api/v1/viewer/cross-signing-reset ────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCrossSigningResetInput {
    pub user_id: String,
}

#[derive(Serialize)]
pub struct AllowCrossSigningResetResponse {
    pub user: Option<UserBrief>,
}

#[derive(Serialize)]
pub struct UserBrief {
    pub id: String,
}

#[handler]
pub async fn allow_cross_signing_reset(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AllowCrossSigningResetResponse>, RouteError> {
    let input: AllowCrossSigningResetInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user_id = NodeType::User.extract_ulid(&input.user_id)?;

    if !requester.is_owner_or_admin(Some(user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NotFound)?;
    repo.cancel().await?;

    homeserver
        .allow_cross_signing_reset(&user.username)
        .await
        .context("Failed to allow cross-signing reset")
        .map_err(|e| RouteError::Internal(e.into()))?;

    Ok(Json(AllowCrossSigningResetResponse {
        user: Some(UserBrief {
            id: NodeType::User.serialize(user.id),
        }),
    }))
}

// ── POST /api/v1/viewer/deactivate ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateUserInput {
    pub hs_erase: bool,
    pub password: Option<String>,
}

#[derive(Serialize)]
pub struct DeactivateUserResponse {
    pub status: &'static str,
}

#[handler]
pub async fn deactivate_user(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DeactivateUserResponse>, RouteError> {
    let input: DeactivateUserInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let config = get_site_config(depot)?;
    let password_manager = get_password_manager(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let Some(browser_session) = requester.browser_session() else {
        return Err(RouteError::Unauthorized);
    };

    if !config.account_deactivation_allowed {
        return Err(RouteError::BadRequest(
            "Account deactivation is not allowed".into(),
        ));
    }

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
        return Ok(Json(DeactivateUserResponse {
            status: "INCORRECT_PASSWORD",
        }));
    }

    let user = repo
        .user()
        .deactivate(&clock, browser_session.user.clone())
        .await?;

    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            DeactivateUserJob::new(&user, input.hs_erase),
        )
        .await?;

    repo.save().await?;

    Ok(Json(DeactivateUserResponse {
        status: "DEACTIVATED",
    }))
}
