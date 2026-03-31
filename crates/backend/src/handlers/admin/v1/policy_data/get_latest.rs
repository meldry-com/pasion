// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::PolicyData,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Retrieve the most recent policy data record.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_data.get_latest", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<PolicyData>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;

    let entry = repo
        .policy_data()
        .get()
        .await?
        .ok_or_else(|| AppError::not_found("No policy data found"))?;

    Ok(Json(SingleResponse::new_canonical(entry.into())))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get_latest() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
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
        let pool = pasion_data::test_utils::setup_test_pool().await;
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
