// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::BoxRng;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UpstreamOAuthLink},
    response::SingleResponse,
};
use crate::{AppError, CreatedJsonResult};

/// JSON body accepted by `POST /api/admin/v1/upstream-oauth-links`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUpstreamOauthLinkRequest")]
pub struct RequestBody {
    /// Identifier of the user to associate with this link.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    user_id: Ulid,

    /// Identifier of the upstream OAuth provider.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    provider_id: Ulid,

    /// The subject (sub) claim identifying the user at the provider.
    subject: String,

    /// Optional human-readable label for this account.
    human_account_name: Option<String>,
}

/// Create a new upstream OAuth link or associate an existing unlinked one.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.post", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<UpstreamOAuthLink>> {
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

    // Resolve the upstream provider
    let provider = repo
        .upstream_oauth_provider()
        .lookup(body.provider_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Upstream OAuth 2.0 Provider ID {} not found",
                body.provider_id
            ))
        })?;

    // Check whether a link with this subject already exists for the provider
    let existing_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &body.subject)
        .await?;

    if let Some(mut entry) = existing_link {
        // If already associated to a user, reject as conflict
        if entry.user_id.is_some() {
            return Err(AppError::conflict(format!(
                "Upstream Oauth 2.0 Provider ID {} with subject {} is already linked to a user",
                entry.provider_id, entry.subject
            )));
        }

        // Otherwise, associate the orphaned link to the requested user
        repo.upstream_oauth_link()
            .associate_to_user(&entry, &owner)
            .await?;
        entry.user_id = Some(owner.id);

        repo.save().await?;

        return Ok(crate::handlers::admin::CreatedJson(
            SingleResponse::new_canonical(entry.into()),
        ));
    }

    // No existing link -- create a brand-new one
    let mut entry = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &clock,
            &provider,
            body.subject,
            body.human_account_name,
        )
        .await?;

    repo.upstream_oauth_link()
        .associate_to_user(&entry, &owner)
        .await?;
    entry.user_id = Some(owner.id);

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleResponse::new_canonical(entry.into()),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use ulid::Ulid;

    use super::super::test_utils;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_create() {
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

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_association() {
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

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        // Existing unfinished link
        repo.upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG09NMZYX8MFYH578R9",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_link_already_exists() {
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

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": bob.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream Oauth 2.0 Provider ID 01FSHN9AG09NMZYX8MFYH578R9 with subject subject1 is already linked to a user"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": Ulid::nil(),
                "provider_id": provider.id,
                "subject": "subject1"
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
    async fn test_provider_not_found() {
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

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": Ulid::nil(),
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream OAuth 2.0 Provider ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }
}
