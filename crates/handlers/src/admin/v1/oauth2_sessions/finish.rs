use pasion_data_model::BoxRng;
use pasion_salvo_utils::record_error;
use pasion_storage::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::{OAuth2Session, Resource},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("OAuth 2.0 session with ID {0} not found")]
    NotFound(Ulid),

    #[error("OAuth 2.0 session with ID {0} is already finished")]
    AlreadyFinished(Ulid),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyFinished(_) => StatusCode::BAD_REQUEST,
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

#[handler]
#[tracing::instrument(name = "handler.admin.v1.oauth2_sessions.finish", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<OAuth2Session>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::rest::make_rng();

    // id already extracted above
    let session = repo
        .oauth2_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the session is already finished
    if session.finished_at().is_some() {
        return Err(RouteError::AlreadyFinished(id));
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
    use pasion_data_model::{AccessToken, Clock as _};

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_finish_session() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

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
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        // Create first admin token for the API call
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        // Create a second admin session that we'll finish
        let second_admin_token = state.token_with_scope("urn:mas:admin").await;

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
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

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
