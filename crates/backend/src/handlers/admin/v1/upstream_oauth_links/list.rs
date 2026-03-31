// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::{Page, upstream_oauth2::UpstreamOAuthLinkFilter};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UpstreamOAuthLink},
    params::{IncludeCount, extract_pagination},
    response::PaginatedResponse,
};
use crate::{AppError, JsonResult};

/// Query-string filters for the upstream OAuth link list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UpstreamOAuthLinkFilter")]
pub struct FilterParams {
    /// Narrow results to links belonging to this user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Narrow results to links from this provider
    #[serde(rename = "filter[provider]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    provider: Option<Ulid>,

    /// Narrow results to links matching this subject claim
    #[serde(rename = "filter[subject]")]
    subject: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(uid) = self.user {
            write!(f, "{delimiter}filter[user]={uid}")?;
            delimiter = '&';
        }

        if let Some(pid) = self.provider {
            write!(f, "{delimiter}filter[provider]={pid}")?;
            delimiter = '&';
        }

        if let Some(sub) = &self.subject {
            write!(f, "{delimiter}filter[subject]={sub}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List upstream OAuth links with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<UpstreamOAuthLink>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UpstreamOAuthLink::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let mut filter = UpstreamOAuthLinkFilter::default();

    // Optionally scope to a particular user
    let resolved_user = match params.user {
        Some(uid) => {
            let u = repo
                .user()
                .lookup(uid)
                .await?
                .ok_or_else(|| AppError::not_found(format!("User ID {uid} not found")))?;
            Some(u)
        }
        None => None,
    };

    filter = match &resolved_user {
        Some(u) => filter.for_user(u),
        None => filter,
    };

    // Optionally scope to a particular provider
    let resolved_provider = match params.provider {
        Some(pid) => {
            let p = repo
                .upstream_oauth_provider()
                .lookup(pid)
                .await?
                .ok_or_else(|| AppError::not_found(format!("Provider ID {pid} not found")))?;
            Some(p)
        }
        None => None,
    };

    filter = match &resolved_provider {
        Some(p) => filter.for_provider(p),
        None => filter,
    };

    // Optionally match by subject claim
    filter = match &params.subject {
        Some(sub) => filter.for_subject(sub),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_link()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthLink::from);
            let total = repo.upstream_oauth_link().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_link()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthLink::from);
            PaginatedResponse::for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.upstream_oauth_link().count(filter).await?;
            PaginatedResponse::for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use super::super::test_utils;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_list() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision users and providers
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
        let provider1 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("acme"),
            )
            .await
            .unwrap();
        let provider2 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("example"),
            )
            .await
            .unwrap();

        // Create some links
        let link1 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject1".to_owned(),
                Some("alice@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link1, &alice)
            .await
            .unwrap();
        let link2 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider2,
                "subject2".to_owned(),
                Some("alice@example".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link2, &alice)
            .await
            .unwrap();
        let link3 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject3".to_owned(),
                Some("bob@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link3, &bob)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?page[last]=10"
          }
        }
        "#);

        // Filter by user ID
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

        // Filter by provider
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[provider]={}",
            provider1.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[last]=10"
          }
        }
        "#);

        // Filter by subject
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[subject]={}",
            "subject1"
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/upstream-oauth-links?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/upstream-oauth-links?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?count=only&filter[provider]={}",
            provider1.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&count=only"
          }
        }
        "#);
    }
}
