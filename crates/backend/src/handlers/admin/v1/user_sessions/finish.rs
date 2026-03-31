use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserSession},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_sessions.finish", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserSession>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;

    // id already extracted above
    let session = repo
        .browser_session()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User session with ID {id} not found")))?;

    // Check if the session is already finished
    if session.finished_at.is_some() {
        return Err(AppError::bad_request(format!(
            "User session with ID {id} is already finished"
        )));
    }

    // Finish the session
    let session = repo.browser_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserSession::from(session),
        format!("/api/admin/v1/user-sessions/{id}/finish"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::Clock as _;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_finish_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a user and a user session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!("/api/admin/v1/user-sessions/{}/finish", session.id))
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
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a user and a user session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();

        // Finish the session first
        let session = repo
            .browser_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!("/api/admin/v1/user-sessions/{}/finish", session.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("User session with ID {} is already finished", session.id)
        );
    }

    #[tokio::test]
    async fn test_finish_unknown_session() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request =
            Request::post("/api/admin/v1/user-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
