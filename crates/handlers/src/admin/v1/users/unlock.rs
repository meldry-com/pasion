use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::{Resource, User},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User ID {0} not found")]
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
#[tracing::instrument(name = "handler.admin.v1.users.unlock", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    // id already extracted above
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let user = repo.user().unlock(user).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/unlock"),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_data_model::Clock;
    use pasion_matrix::{HomeserverConnection, ProvisionRequest};
    use pasion_storage::{RepositoryAccess, user::UserRepository};

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_unlock_user() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Also provision the user on the homeserver, because this endpoint will try to
        // reactivate it
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();

        let request = Request::post(format!("/api/admin/v1/users/{}/unlock", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn test_unlock_deactivated_user() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Provision the user on the homeserver
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();
        // but then deactivate it
        state
            .homeserver_connection
            .delete_user(&user.username, true)
            .await
            .unwrap();

        // The user should be deactivated on the homeserver
        let mx_user = state
            .homeserver_connection
            .query_user(&user.username)
            .await
            .unwrap();
        assert!(mx_user.deactivated);

        let request = Request::post(format!("/api/admin/v1/users/{}/unlock", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );
        // The user should remain deactivated
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::json!(state.clock.now())
        );
        let mx_user = state
            .homeserver_connection
            .query_user(&user.username)
            .await
            .unwrap();
        assert!(mx_user.deactivated);
    }

    #[tokio::test]
    async fn test_lock_unknown_user() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/unlock")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }
}
