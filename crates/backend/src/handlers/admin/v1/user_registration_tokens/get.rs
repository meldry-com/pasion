// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UserRegistrationToken,
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Fetch a single registration token by its ULID.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;

    let entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Registration token with ID {target_id} not found"
            ))
        })?;

    Ok(Json(SingleResponse::new_canonical(
        UserRegistrationToken::new(entry, clock.now()),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let mut repo = state.repository().await.unwrap();
        let reg_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_123".to_owned(),
                Some(5),
                None,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_get_nonexistent_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let missing_id = Ulid::from_string("00000000000000000000000000").unwrap();
        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{missing_id}"
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Registration token with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }
}
