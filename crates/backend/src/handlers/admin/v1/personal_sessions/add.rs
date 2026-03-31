// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

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

/// Request body accepted by `POST /api/admin/v1/personal-sessions`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "CreatePersonalSessionRequest")]
pub struct RequestBody {
    /// The user this session acts on behalf of
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    actor_user_id: Ulid,

    /// A human-friendly label for the session
    human_name: String,

    /// Space-separated OAuth2 scopes
    scope: String,

    /// How long (in seconds) before the access token expires.
    /// Omit for a non-expiring token.
    expires_in: Option<u32>,
}

/// Create a new personal session and its initial access token.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        session: caller_session,
        ..
    } = ctx;
    let mut rng = crate::handlers::rest::make_rng();
    let homeserver = depot.homeserver()?;
    let body: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;
    let owner = personal_session_owner_from_caller(&caller_session);

    // Look up the target user
    let target_user = repo
        .user()
        .lookup(body.actor_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("Specified user does not exist"))?;

    if !target_user.is_valid_actor() {
        return Err(AppError::gone("Target user account is not active"));
    }

    let parsed_scope: Scope = body
        .scope
        .parse()
        .map_err(|_| AppError::bad_request("Provided scope string is malformed"))?;

    // Persist the personal session
    let new_session = repo
        .personal_session()
        .add(
            &mut rng,
            &clock,
            owner,
            &target_user,
            body.human_name,
            parsed_scope,
        )
        .await?;

    // Issue the initial access token
    let raw_token = TokenType::PersonalAccessToken.generate(&mut rng);
    let token_record = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &new_session,
            &raw_token,
            body.expires_in
                .map(|secs| Duration::seconds(i64::from(secs))),
        )
        .await?;

    // Provision any matrix devices declared through scope entries
    if new_session.has_device() {
        repo.user().acquire_lock_for_sync(&target_user).await?;

        for scope_token in &*new_session.scope {
            let raw = scope_token.as_str();
            let device = raw
                .strip_prefix("urn:matrix:client:device:")
                .or_else(|| raw.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"));
            if let Some(device_id) = device {
                homeserver
                    .upsert_device(&target_user.username, device_id, None)
                    .await
                    .context("Device provisioning failed")
                    .map_err(|e| AppError::internal(std::io::Error::other(e.to_string())))?;
            }
        }
    }

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(
            PersonalSession::try_from((new_session, Some(token_record)))?
                .with_token(raw_token),
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

        // Provision a user first
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let payload = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "openid urn:pasion:admin",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&payload);

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

        let payload = serde_json::json!({
            "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "scope": "openid",
            "human_name": "Test Session",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&payload);

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_personal_session_invalid_scope() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Provision a user first
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let payload = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "invalid\nscope",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&payload);

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
