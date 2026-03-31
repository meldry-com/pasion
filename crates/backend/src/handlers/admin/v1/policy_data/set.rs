// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::PolicyData,
        response::SingleResponse,
        CreatedJson,
    },
    rest::DepotExt,
};
use crate::{AppError, CreatedJsonResult};

fn data_example() -> serde_json::Value {
    serde_json::json!({
        "hello": "world",
        "foo": 42,
        "bar": true
    })
}

/// Request body for creating a new policy data record.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "SetPolicyDataRequest")]
pub struct SetPolicyDataRequest {
    #[schemars(example = data_example())]
    pub data: serde_json::Value,
}

/// Store a new policy data snapshot, replacing the active policy in memory.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_data.set", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<PolicyData>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let mut rng = crate::handlers::rest::make_rng();
    let factory = depot.policy_factory()?;

    let body: SetPolicyDataRequest = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    let record = repo
        .policy_data()
        .set(&mut rng, &clock, body.data)
        .await?;

    // Validate by attempting to load the new data into the policy engine.
    // Rolls back on failure since we haven't called save() yet.
    factory
        .set_dynamic_data(record.clone())
        .await
        .map_err(|err| {
            AppError::with_source(
                salvo::http::StatusCode::BAD_REQUEST,
                "Provided data could not be loaded as a valid policy",
                Box::new(err),
                false,
            )
        })?;

    repo.save().await?;

    Ok(CreatedJson(SingleResponse::new_canonical(record.into())))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
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
