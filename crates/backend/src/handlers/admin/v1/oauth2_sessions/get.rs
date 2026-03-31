// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::OAuth2Session,
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth2_session.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<OAuth2Session>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let session = repo
        .oauth2_session()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("OAuth 2.0 session ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(OAuth2Session::from(
        session,
    ))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_data::AccessToken;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // state.token_with_scope did create a session, so we can get it here
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!("/api/admin/v1/oauth2-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "oauth2-session");
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "oauth2-session",
            "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "finished_at": null,
              "user_id": null,
              "user_session_id": null,
              "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "scope": "urn:pasion:admin",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null,
              "human_name": null
            },
            "links": {
              "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
            }
          },
          "links": {
            "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let session_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/oauth2-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
