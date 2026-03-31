// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UserEmail,
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

/// Retrieve a single user email record by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserEmail>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let email_id = extract_ulid_param(req)?;

    let entry = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User email ID {email_id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(UserEmail::from(entry))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a user and an email
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let pasion_data::UserEmail { id, .. } = repo
            .user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!("/api/admin/v1/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user-email");
        insta::assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-email",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "email": "alice@example.com"
            },
            "links": {
              "self": "/api/admin/v1/user-emails/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-emails/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let email_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/user-emails/{email_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
