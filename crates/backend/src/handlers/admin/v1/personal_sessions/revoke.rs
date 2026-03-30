use pasion_data_model::BoxRng;
use crate::record_error;
use pasion_storage::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::{InconsistentPersonalSession, PersonalSession},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Personal session with ID {0} not found")]
    NotFound(Ulid),

    #[error("Personal session with ID {0} is already revoked")]
    AlreadyRevoked(Ulid),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);
impl_from_error_for_route!(InconsistentPersonalSession);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyRevoked(_) => StatusCode::CONFLICT,
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
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.revoke", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<PersonalSession>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let session_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();

    // session_id already extracted above
    let session = repo
        .personal_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NotFound(session_id))?;

    if session.is_revoked() {
        return Err(RouteError::AlreadyRevoked(session_id));
    }

    let session = repo.personal_session().revoke(&clock, session).await?;

    if session.has_device() {
        // If the session has a device, then we are now
        // deleting a device and should schedule a device sync to clean up.
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SyncDevicesJob::new_for_id(session.actor_user_id),
            )
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        PersonalSession::try_from((session, None))?,
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use oauth2_types::scope::Scope;
    use pasion_data_model::{Clock, personal::session::PersonalSessionOwner};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_revoke_session() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
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
            personal_session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The revoked_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(Clock::now(&state.clock))
        );
    }

    #[tokio::test]
    async fn test_revoke_already_revoked_session() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
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

        // Revoke the session first
        let session = repo
            .personal_session()
            .revoke(&state.clock, personal_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{}/revoke",
            session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("Personal session with ID {} is already revoked", session.id)
        );
    }

    #[tokio::test]
    async fn test_revoke_unknown_session() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
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
