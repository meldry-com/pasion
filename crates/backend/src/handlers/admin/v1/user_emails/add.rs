// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr as _;

use pasion_data::BoxRng;
use pasion_data::{
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UserEmail,
    response::SingleResponse,
};
use crate::{AppError, CreatedJsonResult};

/// JSON body accepted by `POST /api/admin/v1/user-emails`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserEmailRequest")]
pub struct RequestBody {
    /// Identifier of the user who should own this email.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    user_id: Ulid,

    /// The email address to attach.
    #[schemars(email)]
    email: String,
}

/// Add a new email address to an existing user account.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<UserEmail>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let mut rng = crate::handlers::rest::make_rng();
    let body: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    // Resolve the target user
    let owner = repo
        .user()
        .lookup(body.user_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {} not found", body.user_id)))?;

    // Ensure the provided address is syntactically valid
    if let Err(source) = lettre::Address::from_str(&body.email) {
        return Err(AppError::with_source(
            StatusCode::BAD_REQUEST,
            format!("Email {:?} is not valid", body.email),
            Box::new(source),
            false,
        ));
    }

    // Reject duplicates
    let existing = repo
        .user_email()
        .count(UserEmailFilter::new().for_email(&body.email))
        .await?;

    if existing > 0 {
        return Err(AppError::conflict(format!(
            "User email {:?} already in use",
            body.email
        )));
    }

    // Persist the new email
    let entry = repo
        .user_email()
        .add(&mut rng, &clock, &owner, body.email)
        .await?;

    // Enqueue a provisioning job so downstream systems pick up the change
    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new_for_id(owner.id))
        .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(SingleResponse::new_canonical(
        entry.into(),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    #[tokio::test]
    async fn test_create() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a user
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-email",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "email": "alice@example.com"
            },
            "links": {
              "self": "/api/admin/v1/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": Ulid::nil(),
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_email_already_exists() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User email \"alice@example.com\" already in use"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_invalid_email() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "invalid-email",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Email \"invalid-email\" is not valid"
            },
            {
              "title": "Missing domain or user"
            }
          ]
        }
        "###);
    }
}
