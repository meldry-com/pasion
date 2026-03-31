// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr as _;

use chrono::{DateTime, Utc};
use oauth2_types::scope::{Scope, ScopeToken};
use pasion_data::personal::PersonalSessionFilter;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{InconsistentPersonalSession, PersonalSession, Resource},
    params::{IncludeCount, extract_pagination},
    response::PaginatedResponse,
};
use crate::{AppError, JsonResult};

/// Whether a personal session is currently active or has been revoked.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum PersonalSessionStatus {
    Active,
    Revoked,
}

impl std::fmt::Display for PersonalSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Revoked => f.write_str("revoked"),
        }
    }
}

/// Query-string parameters that control filtering on the list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "PersonalSessionFilter")]
pub struct FilterParams {
    /// Narrow results to sessions owned by this user
    #[serde(rename = "filter[owner_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_user: Option<Ulid>,

    /// Narrow results to sessions owned by this OAuth2 client
    #[serde(rename = "filter[owner_client]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_client: Option<Ulid>,

    /// Narrow results to sessions where the acting user matches
    #[serde(rename = "filter[actor_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    actor_user: Option<Ulid>,

    /// Only return sessions whose scope contains every listed token
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Restrict by lifecycle status
    #[serde(rename = "filter[status]")]
    status: Option<PersonalSessionStatus>,

    /// Upper bound on the access-token expiry timestamp
    #[serde(rename = "filter[expires_before]")]
    expires_before: Option<DateTime<Utc>>,

    /// Lower bound on the access-token expiry timestamp
    #[serde(rename = "filter[expires_after]")]
    expires_after: Option<DateTime<Utc>>,

    /// Whether the access token carries an expiry at all
    #[serde(rename = "filter[expires]")]
    expires: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delim = '?';

        if let Some(val) = self.owner_user {
            write!(f, "{delim}filter[owner_user]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.owner_client {
            write!(f, "{delim}filter[owner_client]={val}")?;
            delim = '&';
        }
        if let Some(val) = self.actor_user {
            write!(f, "{delim}filter[actor_user]={val}")?;
            delim = '&';
        }
        for tok in &self.scope {
            write!(f, "{delim}filter[scope]={tok}")?;
            delim = '&';
        }
        if let Some(val) = self.status {
            write!(f, "{delim}filter[status]={val}")?;
            delim = '&';
        }
        if let Some(ts) = self.expires_before {
            write!(
                f,
                "{delim}filter[expires_before]={}",
                ts.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            delim = '&';
        }
        if let Some(ts) = self.expires_after {
            write!(
                f,
                "{delim}filter[expires_after]={}",
                ts.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            delim = '&';
        }
        if let Some(val) = self.expires {
            write!(f, "{delim}filter[expires]={val}")?;
            delim = '&';
        }

        let _ = delim;
        Ok(())
    }
}

/// List personal sessions, with optional filtering and cursor-based pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<PersonalSession>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = PersonalSession::PATH);
    let base_url = include_count.add_to_base(&base_url);

    let mut filter = PersonalSessionFilter::new();

    // Resolve and apply the owner-user filter
    let resolved_owner = if let Some(uid) = params.owner_user {
        let u = repo
            .user()
            .lookup(uid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User {uid} does not exist")))?;
        Some(u)
    } else {
        None
    };

    filter = match &resolved_owner {
        Some(u) => filter.for_owner_user(u),
        None => filter,
    };

    // Resolve and apply the owner-client filter
    let resolved_client = if let Some(cid) = params.owner_client {
        let c = repo
            .oauth2_client()
            .lookup(cid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Client {cid} does not exist")))?;
        Some(c)
    } else {
        None
    };

    filter = match &resolved_client {
        Some(c) => filter.for_owner_oauth2_client(c),
        None => filter,
    };

    // Resolve and apply the actor-user filter
    let resolved_actor = if let Some(uid) = params.actor_user {
        let u = repo
            .user()
            .lookup(uid)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User {uid} does not exist")))?;
        Some(u)
    } else {
        None
    };

    filter = match &resolved_actor {
        Some(u) => filter.for_actor_user(u),
        None => filter,
    };

    // Parse and apply scope tokens
    let requested_scope: Scope = params
        .scope
        .into_iter()
        .map(|raw| {
            ScopeToken::from_str(&raw)
                .map_err(|_| AppError::bad_request(format!("Scope token {raw:?} is not valid")))
        })
        .collect::<Result<_, _>>()?;

    if !requested_scope.is_empty() {
        filter = filter.with_scope(&requested_scope);
    }

    // Apply status filter
    filter = match params.status {
        Some(PersonalSessionStatus::Active) => filter.active_only(),
        Some(PersonalSessionStatus::Revoked) => filter.finished_only(),
        None => filter,
    };

    // Apply expiry-window filters
    if let Some(after) = params.expires_after {
        filter = filter.with_expires_after(after);
    }
    if let Some(before) = params.expires_before {
        filter = filter.with_expires_before(before);
    }
    if let Some(has_expiry) = params.expires {
        filter = filter.with_expires(has_expiry);
    }

    let result = match include_count {
        IncludeCount::True => {
            let page = repo.personal_session().list(filter, pagination).await?;
            let total = repo.personal_session().count(filter).await?;
            PaginatedResponse::for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                Some(total),
                &base_url,
            )
        }
        IncludeCount::False => {
            let page = repo.personal_session().list(filter, pagination).await?;
            PaginatedResponse::for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                None,
                &base_url,
            )
        }
        IncludeCount::Only => {
            let total = repo.personal_session().count(filter).await?;
            PaginatedResponse::for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use oauth2_types::scope::{OPENID, Scope};
    use pasion_data::personal::session::PersonalSessionOwner;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_list() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        // Provision a user and several personal sessions for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let sess_a = repo
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
            .add(
                &mut rng,
                &state.clock,
                &sess_a,
                "mpt_hiss",
                Some(Duration::days(42)),
            )
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let sess_b = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Another test session".to_owned(),
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(
                &mut rng,
                &state.clock,
                &sess_b,
                "mpt_scratch",
                Some(Duration::days(21)),
            )
            .await
            .unwrap();
        repo.personal_session()
            .revoke(&state.clock, sess_b)
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let sess_c = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Another test session".to_owned(),
                Scope::from_iter([OPENID, "urn:pasion:admin".parse().unwrap()]),
            )
            .await
            .unwrap();
        repo.personal_access_token()
            .add(
                &mut rng,
                &state.clock,
                &sess_c,
                "mpt_meow",
                Some(Duration::days(14)),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let token = state.token_with_scope("urn:pasion:admin").await;
        let request = Request::get("/api/admin/v1/personal-sessions")
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
              "type": "personal-session",
              "id": "01FSHN9AG0YQYAR04VCYTHJ8SK",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "revoked_at": null,
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Test session",
                "scope": "openid",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": "2022-02-27T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/personal-sessions/01FSHN9AG0YQYAR04VCYTHJ8SK"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0YQYAR04VCYTHJ8SK"
                }
              }
            },
            {
              "type": "personal-session",
              "id": "01FSM7P1G0VBGAMK9D9QMGQ5MY",
              "attributes": {
                "created_at": "2022-01-17T14:40:00Z",
                "revoked_at": "2022-01-17T14:40:00Z",
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Another test session",
                "scope": "openid",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": null
              },
              "links": {
                "self": "/api/admin/v1/personal-sessions/01FSM7P1G0VBGAMK9D9QMGQ5MY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSM7P1G0VBGAMK9D9QMGQ5MY"
                }
              }
            },
            {
              "type": "personal-session",
              "id": "01FSPT2RG08Y11Y5BM4VZ4CN8K",
              "attributes": {
                "created_at": "2022-01-18T14:40:00Z",
                "revoked_at": null,
                "owner_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "owner_client_id": null,
                "actor_user_id": "01FSHN9AG09FE39KETP6F390F8",
                "human_name": "Another test session",
                "scope": "openid urn:pasion:admin",
                "last_active_at": null,
                "last_active_ip": null,
                "expires_at": "2022-02-01T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/personal-sessions/01FSPT2RG08Y11Y5BM4VZ4CN8K"
              },
              "meta": {
                "page": {
                  "cursor": "01FSPT2RG08Y11Y5BM4VZ4CN8K"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/personal-sessions?page[first]=10",
            "first": "/api/admin/v1/personal-sessions?page[first]=10",
            "last": "/api/admin/v1/personal-sessions?page[last]=10"
          }
        }
        "#);

        // Validate individual filters against expected ID sets
        let cases: &[(&str, &[&str])] = &[
            (
                "filter[expires_before]=2022-02-15T00:00:00Z",
                &["01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            (
                "filter[expires_after]=2022-02-15T00:00:00Z",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK"],
            ),
            (
                "filter[status]=active",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK", "01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            ("filter[status]=revoked", &["01FSM7P1G0VBGAMK9D9QMGQ5MY"]),
            (
                "filter[expires]=true",
                &["01FSHN9AG0YQYAR04VCYTHJ8SK", "01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
            ("filter[expires]=false", &["01FSM7P1G0VBGAMK9D9QMGQ5MY"]),
            (
                "filter[scope]=urn:pasion:admin",
                &["01FSPT2RG08Y11Y5BM4VZ4CN8K"],
            ),
        ];

        for (qs, want_ids) in cases {
            let request = Request::get(format!("/api/admin/v1/personal-sessions?{qs}"))
                .bearer(&token)
                .empty();
            let response = state.request(request).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            let got: BTreeSet<&str> = body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str().unwrap())
                .collect();
            let want: BTreeSet<&str> = want_ids.iter().copied().collect();

            assert_eq!(
                got, want,
                "filter {qs} returned unexpected results"
            );
        }
    }
}
