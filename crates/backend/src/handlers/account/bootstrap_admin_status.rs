use pasion_data::{
    BoxRepository, RepositoryAccess, RepositoryError, SiteConfig,
    queue::QueueJobRepositoryExt as _, user::UserFilter,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock,
};
use crate::handlers::account::service::registration::{
    ClaimBootstrapAdminError, ClaimBootstrapAdminOutcome, claim_bootstrap_admin,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct BootstrapAdminStatusResponse {
    pub has_admin: bool,
    pub token_configured: bool,
    pub setup_required: bool,
}

fn bootstrap_token_configured(config: &SiteConfig) -> bool {
    config
        .bootstrap_admin_token
        .as_deref()
        .map(str::trim)
        .is_some_and(|token| !token.is_empty())
}

async fn load_bootstrap_admin_status_from(
    config: &SiteConfig,
    repo: &mut BoxRepository,
) -> Result<BootstrapAdminStatusResponse, RepositoryError> {
    let has_admin = repo
        .user()
        .count(UserFilter::new().can_request_admin_only())
        .await?
        > 0;
    let token_configured = bootstrap_token_configured(config);

    Ok(BootstrapAdminStatusResponse {
        has_admin,
        token_configured,
        setup_required: token_configured && !has_admin,
    })
}

#[endpoint]
pub async fn get(depot: &Depot) -> Result<Json<BootstrapAdminStatusResponse>, RouteError> {
    let config = depot.site_config()?;
    let mut repo = depot.repo().await?;
    Ok(Json(
        load_bootstrap_admin_status_from(&config, &mut repo).await?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct ClaimBootstrapAdminInput {
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct ClaimBootstrapAdminResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn post_claim(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ClaimBootstrapAdminResponse>, RouteError> {
    let input: ClaimBootstrapAdminInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    let config = depot.site_config()?;
    let limiter = depot.limiter()?;
    let clock = make_clock();
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);
    let repo = depot.repo_factory()?.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;
    let user = requester
        .browser_session()
        .map(|session| &session.user)
        .ok_or(RouteError::Unauthorized)?;

    limiter
        .check_password(requester.fingerprint(), user)
        .await
        .map_err(|_| RouteError::RateLimited)?;

    let outcome = claim_bootstrap_admin(
        &mut repo,
        user.id,
        config.bootstrap_admin_token.as_deref(),
        &input.token,
    )
    .await
    .map_err(|error| match error {
        ClaimBootstrapAdminError::NotFound => RouteError::NotFound,
        ClaimBootstrapAdminError::Repository(error) => error.into(),
    })?;

    if outcome == ClaimBootstrapAdminOutcome::Claimed {
        // Mirror the new admin flag onto the homeserver.
        let mut rng = crate::handlers::account::make_rng();
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                pasion_data::queue::ProvisionUserJob::new_for_id(user.id),
            )
            .await?;
        repo.save().await?;
    }

    let status = match outcome {
        ClaimBootstrapAdminOutcome::Claimed => "claimed",
        ClaimBootstrapAdminOutcome::Unavailable => "unavailable",
        ClaimBootstrapAdminOutcome::InvalidToken => "invalid_token",
    };
    Ok(Json(ClaimBootstrapAdminResponse { status }))
}

#[cfg(test)]
mod tests {
    use super::load_bootstrap_admin_status_from;
    use crate::handlers::test_utils::{TestState, setup, test_site_config};

    #[tokio::test]
    async fn setup_required_when_token_exists_and_no_admin_exists() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool_with_site_config(
            pool,
            pasion_data::SiteConfig {
                bootstrap_admin_token: Some("bootstrap-secret".to_owned()),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut repo = state.repository().await.unwrap();
        let payload = load_bootstrap_admin_status_from(&state.site_config, &mut repo)
            .await
            .unwrap();
        repo.cancel().await.unwrap();

        assert!(!payload.has_admin);
        assert!(payload.token_configured);
        assert!(payload.setup_required);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn setup_not_required_after_first_admin_exists() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let state = TestState::from_pool_with_site_config(
            pool,
            pasion_data::SiteConfig {
                bootstrap_admin_token: Some("bootstrap-secret".to_owned()),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng.lock().unwrap();
        let user = repo
            .user()
            .add(&mut *rng, state.clock.as_ref(), "admin".to_owned())
            .await
            .unwrap();
        repo.user().set_can_request_admin(user, true).await.unwrap();
        repo.save().await.unwrap();

        let mut repo = state.repository().await.unwrap();
        let payload = load_bootstrap_admin_status_from(&state.site_config, &mut repo)
            .await
            .unwrap();
        repo.cancel().await.unwrap();

        assert!(payload.has_admin);
        assert!(payload.token_configured);
        assert!(!payload.setup_required);
    }
}
