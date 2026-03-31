use std::sync::Arc;

use anyhow::Context;
use chrono::Duration;
use oauth2_types::scope::Scope;
use pasion_data::{BoxRng, TokenType};
use pasion_matrix::HomeserverConnection;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::{InconsistentPersonalSession, PersonalSession},
        response::SingleResponse,
        v1::personal_sessions::personal_session_owner_from_caller,
    },
    rest::DepotExt,
};
use crate::{AppError, CreatedJsonResult};

/// # JSON payload for the `POST /api/admin/v1/personal-sessions` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "CreatePersonalSessionRequest")]
pub struct RequestBody {
    /// The user this session will act on behalf of
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    actor_user_id: Ulid,

    /// Human-readable name for the session
    human_name: String,

    /// `OAuth2` scopes for this session
    scope: String,

    /// Token expiry time in seconds.
    /// If not set, the token won't expire.
    expires_in: Option<u32>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<PersonalSession>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        session,
        ..
    } = call_context;
    let mut rng = crate::handlers::rest::make_rng();
    let homeserver = depot.homeserver()?;
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;
    let owner = personal_session_owner_from_caller(&session);

    let actor_user = repo
        .user()
        .lookup(params.actor_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    if !actor_user.is_valid_actor() {
        return Err(AppError::gone("User is not active"));
    }

    let scope: Scope = params
        .scope
        .parse()
        .map_err(|_| AppError::bad_request("Invalid scope"))?;

    // Create the personal session
    let session = repo
        .personal_session()
        .add(
            &mut rng,
            &clock,
            owner,
            &actor_user,
            params.human_name,
            scope,
        )
        .await?;

    // Create the initial token for the session
    let access_token_string = TokenType::PersonalAccessToken.generate(&mut rng);
    let access_token = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_string,
            params
                .expires_in
                .map(|exp_in| Duration::seconds(i64::from(exp_in))),
        )
        .await?;

    // If the session has a device, we should add those to the homeserver now
    if session.has_device() {
        // Lock the user sync to make sure we don't get into a race condition
        repo.user().acquire_lock_for_sync(&actor_user).await?;

        for scope in &*session.scope {
            let s = scope.as_str();
            let device_id = s
                .strip_prefix("urn:matrix:client:device:")
                .or_else(|| s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"));
            if let Some(device_id) = device_id {
                // NOTE: We haven't relinquished the repo at this point,
                // so we are holding a transaction across the homeserver
                // operation.
                // This is suboptimal, but simpler.
                // Given this is an administrative endpoint, this is a tolerable
                // compromise for now.
                homeserver
                    .upsert_device(&actor_user.username, device_id, None)
                    .await
                    .context("Failed to provision device")
                    .map_err(|error| {
                        AppError::internal(std::io::Error::other(error.to_string()))
                    })?;
            }
        }
    }

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(
            PersonalSession::try_from((session, Some(access_token)))?
                .with_token(access_token_string),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::Value;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create_personal_session_with_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request_body = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "openid urn:pasion:admin",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": null,
              "owner_client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test Session",
              "scope": "openid urn:pasion:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-16T15:40:00Z",
              "access_token": "mpt_FM44zJN5qePGMLvvMXC4Ds1A3lCWc6_bJ9Wj1"
            },
            "links": {
              "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_create_personal_session_invalid_user() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request_body = serde_json::json!({
            "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "scope": "openid",
            "human_name": "Test Session",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_personal_session_invalid_scope() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request_body = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "invalid\nscope",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
