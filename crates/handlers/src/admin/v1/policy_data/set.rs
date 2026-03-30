use std::sync::Arc;

use pasion_data_model::BoxRng;
use pasion_policy::PolicyFactory;
use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::PolicyData,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
    rest::DepotExt,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Failed to instanciate policy with the provided data")]
    InvalidPolicyData(#[from] pasion_policy::LoadError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::rest::RouteError);
impl_from_error_for_route!(crate::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            RouteError::InvalidPolicyData(_) => StatusCode::BAD_REQUEST,
            RouteError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

fn data_example() -> serde_json::Value {
    serde_json::json!({
        "hello": "world",
        "foo": 42,
        "bar": true
    })
}

/// # JSON payload for the `POST /api/admin/v1/policy-data`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "SetPolicyDataRequest")]
pub struct SetPolicyDataRequest {
    #[schemars(example = data_example())]
    pub data: serde_json::Value,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.policy_data.set", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<(StatusCode, Json<SingleResponse<PolicyData>>), RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let mut rng = crate::rest::make_rng();
    let policy_factory = depot.policy_factory()?;
    let request: SetPolicyDataRequest = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let policy_data = repo
        .policy_data()
        .set(&mut rng, &clock, request.data)
        .await?;

    // Swap the policy data. This will fail if the policy data is invalid
    policy_factory.set_dynamic_data(policy_data.clone()).await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(policy_data.into())),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/policy-data")
            .bearer(&token)
            .json(serde_json::json!({
                "data": {
                    "hello": "world"
                }
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
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
}
