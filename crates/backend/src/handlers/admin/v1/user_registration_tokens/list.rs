// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::{Page, user::UserRegistrationTokenFilter};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    params::{IncludeCount, extract_pagination},
    response::PaginatedResponse,
};
use crate::JsonResult;

/// Query-string filters for the registration-token list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "RegistrationTokenFilter")]
pub struct FilterParams {
    /// Whether the token has been redeemed at least once
    #[serde(rename = "filter[used]")]
    used: Option<bool>,

    /// Whether the token is currently revoked
    #[serde(rename = "filter[revoked]")]
    revoked: Option<bool>,

    /// Whether the token has passed its expiry timestamp
    #[serde(rename = "filter[expired]")]
    expired: Option<bool>,

    /// Whether the token is still usable (not expired, not revoked,
    /// and has not exhausted its usage limit)
    #[serde(rename = "filter[valid]")]
    valid: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delim = '?';

        if let Some(val) = self.used {
            write!(f, "{delim}filter[used]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.revoked {
            write!(f, "{delim}filter[revoked]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.expired {
            write!(f, "{delim}filter[expired]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.valid {
            write!(f, "{delim}filter[valid]={val}")?;
            delim = '&';
        }

        let _ = delim;
        Ok(())
    }
}

/// List registration tokens with optional filtering and cursor-based pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.registration_tokens.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<UserRegistrationToken>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UserRegistrationToken::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let now = clock.now();
    let mut filter = UserRegistrationTokenFilter::new(now);

    if let Some(val) = params.used {
        filter = filter.with_been_used(val);
    }
    if let Some(val) = params.revoked {
        filter = filter.with_revoked(val);
    }
    if let Some(val) = params.expired {
        filter = filter.with_expired(val);
    }
    if let Some(val) = params.valid {
        filter = filter.with_valid(val);
    }

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|t| UserRegistrationToken::new(t, now));
            let total = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|t| UserRegistrationToken::new(t, now));
            PaginatedResponse::for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::Clock as _;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// Provision a set of tokens covering all relevant combinations of
    /// used / revoked / expired status so that filter tests can work
    /// against a known data set.
    async fn seed_tokens(ts: &mut TestState) {
        let mut repo = ts.repository().await.unwrap();

        // 1 -- never used, not revoked, not expired
        repo.user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_unused".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();

        // 2 -- used once, not revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_used".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .use_token(&ts.clock, tok)
            .await
            .unwrap();

        // 3 -- never used, revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&ts.clock, tok)
            .await
            .unwrap();

        // 4 -- used once, then revoked
        let tok = repo
            .user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_used_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        let tok = repo
            .user_registration_token()
            .use_token(&ts.clock, tok)
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&ts.clock, tok)
            .await
            .unwrap();

        // 5 -- already expired
        let past = ts.clock.now() - Duration::try_days(1).unwrap();
        repo.user_registration_token()
            .add(
                &mut ts.rng(),
                &ts.clock,
                "token_expired".to_owned(),
                Some(5),
                Some(past),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();
    }

    #[tokio::test]
    async fn test_list_all_tokens() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        let request = Request::get("/api/admin/v1/user-registration-tokens")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_used() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // used=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[last]=10"
          }
        }
        "#);

        // used=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_revoked() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // revoked=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[last]=10"
          }
        }
        "#);

        // revoked=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_expired() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // expired=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[last]=10"
          }
        }
        "#);

        // expired=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 4
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_filter_by_valid() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // valid=true
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[last]=10"
          }
        }
        "#);

        // valid=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_combined_filters() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // used AND revoked
        let request = Request::get(
            "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true",
        )
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[last]=10"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_pagination() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // First page of 2
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[first]=2")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2"
          }
        }
        "#);

        // Second page
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=2"
          }
        }
        "#);

        // Last item via page[last]=1
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[last]=1")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=1",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "prev": "/api/admin/v1/user-registration-tokens?page[before]=01FSHN9AG0S3ZJD8CXQ7F11KXN&page[last]=1"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=invalid")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert!(
            body["errors"][0]["title"]
                .as_str()
                .unwrap()
                .contains("Invalid filter parameters")
        );
    }

    #[tokio::test]
    async fn test_count_parameter() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:pasion:admin").await;
        seed_tokens(&mut state).await;

        // count=false -- no meta.count in the response
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?count=false&page[last]=10"
          }
        }
        "#);

        // count=only -- just the total
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=only")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=only"
          }
        }
        "#);

        // count=false combined with a filter
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=false&filter[valid]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[last]=10"
          }
        }
        "#);

        // count=only combined with a filter
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=only&filter[revoked]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&count=only"
          }
        }
        "#);
    }
}
