// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::Duration;
use pasion_data::{BoxRng, TokenType};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::error;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{InconsistentPersonalSession, PersonalSession},
    params::extract_ulid_param,
    response::SingleResponse,
    v1::personal_sessions::personal_session_owner_from_caller,
};
use crate::{AppError, CreatedJsonResult};

/// Optional payload for the regenerate endpoint.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RegeneratePersonalSessionRequest")]
pub struct RequestBody {
    /// Lifetime of the new token in seconds; omit for a non-expiring token.
    expires_in: Option<u32>,
}

/// Rotate the access token for an existing personal session.
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
    let target_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();
    let body: RequestBody = req
        .parse_json()
        .await
        .unwrap_or(RequestBody { expires_in: None });

    let entry = repo
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| AppError::not_found("Requested session does not exist"))?;

    if !entry.is_valid() {
        return Err(AppError::unprocessable_entity("Session not valid"));
    }

    // Only the session owner may regenerate the token
    let caller_owner = personal_session_owner_from_caller(&caller_session);
    if entry.owner != caller_owner {
        return Err(AppError::forbidden("Session does not belong to you"));
    }

    // Revoke the currently-active token
    let previous_token = repo
        .personal_access_token()
        .find_active_for_session(&entry)
        .await?;
    let Some(prev) = previous_token else {
        error!("session appears valid but has no active access token");
        return Err(AppError::unprocessable_entity("Session not valid"));
    };

    repo.personal_access_token()
        .revoke(&clock, prev)
        .await?;

    // Mint the replacement token
    let new_token_str = TokenType::PersonalAccessToken.generate(&mut rng);
    let new_token_record = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &entry,
            &new_token_str,
            body.expires_in
                .map(|secs| Duration::seconds(i64::from(secs))),
        )
        .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(
            PersonalSession::try_from((entry, Some(new_token_record)))?
                .with_token(new_token_str),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_regenerate_personal_session() {
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

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(json!({
                "actor_user_id": user.id,
                "human_name": "SuperDuperAdminCLITool Token",
                "scope": "openid urn:pasion:admin",
                "expires_in": 3600
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let created_body: Value = response.json();

        let sess_id = created_body["data"]["id"].as_str().unwrap();

        state.clock.advance(Duration::minutes(3));

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{sess_id}/regenerate"
        ))
        .bearer(&token)
        .json(json!({
            "expires_in": 86400
        }));

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
              "human_name": "SuperDuperAdminCLITool Token",
              "scope": "openid urn:pasion:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-17T14:43:00Z",
              "access_token": "mpt_6cq7FqNSYoosbXl3bbpfh9yNy9NzuR_0vOV2O"
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
}
