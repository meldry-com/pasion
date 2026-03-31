// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::BoxRng;
use pasion_data::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use salvo::prelude::*;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{InconsistentPersonalSession, PersonalSession},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Revoke a personal session, invalidating its access token.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.revoke", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();

    let entry = repo
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Personal session with ID {target_id} not found"))
        })?;

    if entry.is_revoked() {
        return Err(AppError::conflict(format!(
            "Personal session with ID {target_id} is already revoked"
        )));
    }

    let revoked = repo.personal_session().revoke(&clock, entry).await?;

    // Schedule a device-sync job when the session carried device scopes
    if revoked.has_device() {
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SyncDevicesJob::new_for_id(revoked.actor_user_id),
            )
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        PersonalSession::try_from((revoked, None))?,
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use oauth2_types::scope::Scope;
    use pasion_data::{Clock, personal::session::PersonalSessionOwner};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_revoke_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Provision a user and a personal session
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{}/revoke",
            sess.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(Clock::now(&state.clock))
        );
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Provision a user and a personal session, then revoke it
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        let revoked_sess = repo
            .personal_session()
            .revoke(&state.clock, sess)
            .await
            .unwrap();

        repo.save().await.unwrap();

        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{}/revoke",
            revoked_sess.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("Personal session with ID {} is already revoked", revoked_sess.id)
        );
    }

    #[tokio::test]
    async fn test_revoke_unknown_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request =
            Request::post("/api/admin/v1/personal-sessions/01040G2081040G2081040G2081/revoke")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Personal session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
