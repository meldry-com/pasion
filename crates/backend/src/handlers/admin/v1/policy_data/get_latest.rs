use crate::record_error;
use salvo::{http::StatusCode, prelude::*};

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::PolicyData,
        response::{ErrorResponse, SingleResponse},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("No policy data found")]
    NotFound,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
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
#[tracing::instrument(name = "handler.admin.v1.policy_data.get_latest", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<PolicyData>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;

    let policy_data = repo
        .policy_data()
        .get()
        .await?
        .ok_or(RouteError::NotFound)?;

    Ok(Json(SingleResponse::new_canonical(policy_data.into())))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get_latest() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        repo.policy_data()
            .set(
                &mut rng,
                &state.clock,
                serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/policy-data/latest")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "policy-data",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "data": {
                "hello": "world"
              }
            },
            "links": {
              "self": "/api/admin/v1/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_no_latest() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::get("/api/admin/v1/policy-data/latest")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "No policy data found"
            }
          ]
        }
        "###);
    }
}
