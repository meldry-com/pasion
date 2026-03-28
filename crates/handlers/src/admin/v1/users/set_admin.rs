use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
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

/// # JSON payload for the `POST /api/admin/v1/users/:id/set-admin` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UserSetAdminRequest")]
pub struct RequestBody {
    /// Whether the user can request admin privileges.
    admin: bool,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.users.set_admin", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // id already extracted above
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let user = repo
        .user()
        .set_can_request_admin(user, params.admin)
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/set-admin"),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_storage::{RepositoryAccess, user::UserRepository};

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_change_can_request_admin() {
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
        repo.save().await.unwrap();

        let request = Request::post(format!("/api/admin/v1/users/{}/set-admin", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "admin": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["admin"], true);

        // Look at the state from the repository
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert!(user.can_request_admin);
        repo.save().await.unwrap();

        // Flip it back
        let request = Request::post(format!("/api/admin/v1/users/{}/set-admin", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "admin": false,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["admin"], false);

        // Look at the state from the repository
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert!(!user.can_request_admin);
        repo.save().await.unwrap();
    }
}
