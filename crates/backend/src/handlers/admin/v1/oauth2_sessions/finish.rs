use pasion_data::BoxRng;
use pasion_data::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{OAuth2Session, Resource},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth2_sessions.finish", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<OAuth2Session>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();

    // id already extracted above
    let session = repo
        .oauth2_session()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("OAuth 2.0 session with ID {id} not found")))?;

    // Check if the session is already finished
    if session.finished_at().is_some() {
        return Err(AppError::bad_request(format!(
            "OAuth 2.0 session with ID {id} is already finished"
        )));
    }

    // If the session has a user associated with it, schedule a job to sync devices
    if let Some(user_id) = session.user_id {
        tracing::info!(user.id = %user_id, "Scheduling device sync job for user");
        let job = SyncDevicesJob::new_for_id(user_id);
        repo.queue_job().schedule_job(&mut rng, &clock, job).await?;
    }

    // Finish the session
    let session = repo.oauth2_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        OAuth2Session::from(session),
        format!("/api/admin/v1/oauth2-sessions/{id}/finish"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::{AccessToken, Clock as _};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_finish_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Get the session ID from the token we just created
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!("/api/admin/v1/oauth2-sessions/{session_id}/finish"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The finished_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["finished_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[tokio::test]
    async fn test_finish_already_finished_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        // Create first admin token for the API call
        let admin_token = state.token_with_scope("urn:pasion:admin").await;

        // Create a second admin session that we'll finish
        let second_admin_token = state.token_with_scope("urn:pasion:admin").await;

        // Get the second session and finish it first
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&second_admin_token)
            .await
            .unwrap()
            .unwrap();

        let session = repo
            .oauth2_session()
            .lookup(session_id)
            .await
            .unwrap()
            .unwrap();

        // Finish the session first
        let session = repo
            .oauth2_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/oauth2-sessions/{}/finish",
            session.id
        ))
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "OAuth 2.0 session with ID {} is already finished",
                session.id
            )
        );
    }

    #[tokio::test]
    async fn test_finish_unknown_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request =
            Request::post("/api/admin/v1/oauth2-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "OAuth 2.0 session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
