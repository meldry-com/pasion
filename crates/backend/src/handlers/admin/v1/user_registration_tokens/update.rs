// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::{DateTime, Utc};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Treat any value that is present (including explicit `null`) as `Some`.
fn nullable_field<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// Payload for `PUT /api/admin/v1/user-registration-tokens/{id}`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "EditUserRegistrationTokenRequest")]
pub struct RequestBody {
    /// Updated expiration timestamp, or `null` to clear it
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "nullable_field"
    )]
    #[expect(clippy::option_option)]
    expires_at: Option<Option<DateTime<Utc>>>,

    /// Updated usage cap, or `null` to remove the limit
    #[expect(clippy::option_option)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "nullable_field"
    )]
    usage_limit: Option<Option<u32>>,
}

/// Apply partial updates to a registration token's mutable fields.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.update", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let target_id = extract_ulid_param(req)?;
    let body: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    let mut entry = repo
        .user_registration_token()
        .lookup(target_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Registration token with ID {target_id} not found"
            ))
        })?;

    // Patch expiry when the field was explicitly supplied
    if let Some(new_expiry) = body.expires_at {
        entry = repo
            .user_registration_token()
            .set_expiry(entry, new_expiry)
            .await?;
    }

    // Patch usage limit when the field was explicitly supplied
    if let Some(new_limit) = body.usage_limit {
        entry = repo
            .user_registration_token()
            .set_usage_limit(entry, new_limit)
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(entry, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{target_id}"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::Clock as _;
    use serde_json::json;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_update_expiry() {
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
                "test_update_expiry".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Set an expiry date
        let new_expiry = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": new_expiry
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
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

        // Clear the expiry
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "usage_limit": null,
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
    async fn test_update_usage_limit() {
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
                "test_update_limit".to_owned(),
                Some(5),
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Increase the limit
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": 10
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "usage_limit": 10,
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

        // Remove the limit entirely
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "usage_limit": null,
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
    async fn test_update_multiple_fields() {
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
                "test_update_multiple".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let new_expiry = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": new_expiry,
            "usage_limit": 20
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_multiple",
              "valid": true,
              "usage_limit": 20,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
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
    async fn test_update_no_fields() {
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
                "test_update_none".to_owned(),
                Some(5),
                Some(state.clock.now() + Duration::days(30)),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Empty body -- nothing changes
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            reg_token.id
        ))
        .bearer(&token)
        .json(json!({}));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_none",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
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
    async fn test_update_unknown_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request =
            Request::put("/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081")
                .bearer(&token)
                .json(json!({
                    "usage_limit": 5
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["errors"][0]["title"],
            "Registration token with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
