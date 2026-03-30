use crate::record_error;
use chrono::{DateTime, Utc};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    params::extract_ulid_param,
    response::{ErrorResponse, SingleResponse},
};

// Any value that is present is considered Some value, including null.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// # JSON payload for the `PUT /api/admin/v1/user-registration-tokens/{id}` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "EditUserRegistrationTokenRequest")]
pub struct RequestBody {
    /// New expiration date for the token, or null to remove expiration
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_some"
    )]
    #[expect(clippy::option_option)]
    expires_at: Option<Option<DateTime<Utc>>>,

    /// New usage limit for the token, or null to remove the limit
    #[expect(clippy::option_option)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_some"
    )]
    usage_limit: Option<Option<u32>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Registration token with ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

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

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.update", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<UserRegistrationToken>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let request: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // id already extracted above

    // Get the token
    let mut token = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Update expiration if present in the request
    if let Some(expires_at) = request.expires_at {
        token = repo
            .user_registration_token()
            .set_expiry(token, expires_at)
            .await?;
    }

    // Update usage limit if present in the request
    if let Some(usage_limit) = request.usage_limit {
        token = repo
            .user_registration_token()
            .set_usage_limit(token, usage_limit)
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(token, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{id}"),
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

        // Create a token without expiry
        let registration_token = repo
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

        // Update with an expiry date
        let future_date = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": future_date
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify expiry was updated
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

        // Now remove the expiry
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify expiry was removed
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

        // Create a token with usage limit
        let registration_token = repo
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

        // Update the usage limit
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": 10
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify usage limit was updated
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

        // Now remove the usage limit
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify usage limit was removed
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

        // Create a token
        let registration_token = repo
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

        // Update both fields
        let future_date = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": future_date,
            "usage_limit": 20
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Both fields were updated
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

        // Create a token
        let registration_token = repo
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

        // Send empty update
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({}));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // It shouldn't have updated the token
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

        // Try to update a non-existent token
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
