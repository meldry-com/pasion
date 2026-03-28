use pasion_data_model::AppVersion;
use pasion_salvo_utils::InternalError;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Serialize;

use crate::admin::call_context::extract_call_context;

#[derive(Serialize, JsonSchema)]
pub struct Version {
    /// The semver version of the app
    pub version: &'static str,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.version", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> Result<Json<Version>, InternalError> {
    let _call_context = extract_call_context(req, depot).await?;
    let pasion_data_model::AppVersion(version) = crate::rest::get_app_version(depot)?;

    Ok(Json(Version { version }))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_add_user() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

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
