use salvo::prelude::*;
use salvo::http::StatusCode;
use pasion_salvo_utils::record_error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::UserSession,
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User session ID {0} not found")]
    NotFound(Ulid),
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
#[tracing::instrument(name = "handler.admin.v1.user_sessions.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot) -> Result<Json<SingleResponse<UserSession>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let session = repo
        .browser_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    Ok(Json(SingleResponse::new_canonical(UserSession::from(
        session,
    ))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_get(pool: PgPool) {
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

        let session_id = session.id;
        let request = Request::get(format!("/api/admin/v1/user-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-session",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "finished_at": null,
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null
            },
            "links": {
              "self": "/api/admin/v1/user-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "###);
    }
}
