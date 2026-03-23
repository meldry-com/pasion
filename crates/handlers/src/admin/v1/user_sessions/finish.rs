use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::{Resource, UserSession},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User session with ID {0} not found")]
    NotFound(Ulid),

    #[error("User session with ID {0} is already finished")]
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
#[tracing::instrument(name = "handler.admin.v1.user_sessions.finish", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<UserSession>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;

    // id already extracted above
    let session = repo
        .browser_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the session is already finished
    if session.finished_at.is_some() {
        return Err(RouteError::AlreadyFinished(id));
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
    use pasion_data_model::Clock as _;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_finish_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
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

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_finish_already_finished_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
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

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_finish_unknown_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

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
