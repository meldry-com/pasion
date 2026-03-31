// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use crate::handlers::{admin::call_context::extract_call_context, common::DepotExt};
use crate::salvo_utils::InternalError;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Serialize;

/// Payload returned by the version endpoint.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct Version {
    /// Semver string of the running application
    pub version: &'static str,
}

/// Return the application version.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.version", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> Result<Json<Version>, InternalError> {
    let _ctx = extract_call_context(req, depot).await?;
    let pasion_data::AppVersion(ver) = depot.app_version()?;

    Ok(Json(Version { version: ver }))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_add_user() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::get("/api/admin/v1/version").bearer(&token).empty();

        let response = state.request(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "version": "v0.0.0-test"
        }
        "#);
    }
}
