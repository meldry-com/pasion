// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{InconsistentPersonalSession, PersonalSession},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Retrieve a single personal session by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let target_id = extract_ulid_param(req)?;

    let entry = repo
        .personal_session()
        .lookup(target_id)
        .await?
        .ok_or_else(|| AppError::not_found("No personal session matches the given ID"))?;

    let active_token = if entry.is_revoked() {
        None
    } else {
        repo.personal_access_token()
            .find_active_for_session(&entry)
            .await?
    };

    Ok(Json(SingleResponse::new_canonical(
        PersonalSession::try_from((entry, active_token))?,
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data::personal::session::PersonalSessionOwner;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(&mut rng, &state.clock, &personal_session, "mpt_hiss", None)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/api/admin/v1/personal-sessions/{}",
            personal_session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["id"], personal_session.id.to_string());
        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "owner_client_id": null,
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test session",
              "scope": "openid",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": null
            },
            "links": {
              "self": "/api/admin/v1/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/api/admin/v1/personal-sessions/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
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

        let missing_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/personal-sessions/{missing_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
