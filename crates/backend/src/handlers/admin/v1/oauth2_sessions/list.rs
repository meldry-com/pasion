// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use oauth2_types::scope::{Scope, ScopeToken};
use pasion_data::{Page, oauth2::OAuth2SessionFilter};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{OAuth2Session, Resource},
    params::{IncludeCount, extract_pagination},
    response::PaginatedResponse,
};
use crate::{AppError, JsonResult};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuth2SessionStatus {
    Active,
    Finished,
}

impl std::fmt::Display for OAuth2SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Finished => write!(f, "finished"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuth2ClientKind {
    Dynamic,
    Static,
}

impl std::fmt::Display for OAuth2ClientKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dynamic => write!(f, "dynamic"),
            Self::Static => write!(f, "static"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "OAuth2SessionFilter")]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items for the given client
    #[serde(rename = "filter[client]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    client: Option<Ulid>,

    /// Retrieve the items only for a specific client kind
    #[serde(rename = "filter[client-kind]")]
    client_kind: Option<OAuth2ClientKind>,

    /// Retrieve the items started from the given browser session
    #[serde(rename = "filter[user-session]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user_session: Option<Ulid>,

    /// Retrieve the items with the given scope
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all sessions, including finished ones.
    ///
    /// * `active`: Only retrieve active sessions
    ///
    /// * `finished`: Only retrieve finished sessions
    #[serde(rename = "filter[status]")]
    status: Option<OAuth2SessionStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(client) = self.client {
            write!(f, "{sep}filter[client]={client}")?;
            sep = '&';
        }

        if let Some(client_kind) = self.client_kind {
            write!(f, "{sep}filter[client-kind]={client_kind}")?;
            sep = '&';
        }

        if let Some(user_session) = self.user_session {
            write!(f, "{sep}filter[user-session]={user_session}")?;
            sep = '&';
        }

        for scope in &self.scope {
            write!(f, "{sep}filter[scope]={scope}")?;
            sep = '&';
        }

        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.oauth2_sessions.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<OAuth2Session>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = OAuth2Session::PATH);
    let base = include_count.add_to_base(&base);
    let filter = OAuth2SessionFilter::default();

    // Load the user from the filter
    let user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("User ID {user_id} not found")))?;

        Some(user)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let client = if let Some(client_id) = params.client {
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("Client ID {client_id} not found")))?;

        Some(client)
    } else {
        None
    };

    let filter = match &client {
        Some(client) => filter.for_client(client),
        None => filter,
    };

    let filter = match params.client_kind {
        Some(OAuth2ClientKind::Dynamic) => filter.only_dynamic_clients(),
        Some(OAuth2ClientKind::Static) => filter.only_static_clients(),
        None => filter,
    };

    let user_session = if let Some(user_session_id) = params.user_session {
        let user_session = repo
            .browser_session()
            .lookup(user_session_id)
            .await?
            .ok_or_else(|| {
                AppError::not_found(format!("User session ID {user_session_id} not found"))
            })?;

        Some(user_session)
    } else {
        None
    };

    let filter = match &user_session {
        Some(user_session) => filter.for_browser_session(user_session),
        None => filter,
    };

    let scope: Scope = params
        .scope
        .into_iter()
        .map(|s| {
            ScopeToken::from_str(&s).map_err(|_| {
                AppError::bad_request(format!("Invalid scope {s:?} in filter parameters"))
            })
        })
        .collect::<Result<_, _>>()?;

    let filter = if scope.is_empty() {
        filter
    } else {
        filter.with_scope(&scope)
    };

    let filter = match params.status {
        Some(OAuth2SessionStatus::Active) => filter.active_only(),
        Some(OAuth2SessionStatus::Finished) => filter.finished_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .oauth2_session()
                .list(filter, pagination)
                .await?
                .map(OAuth2Session::from);
            let count = repo.oauth2_session().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .oauth2_session()
                .list(filter, pagination)
                .await?
                .map(OAuth2Session::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.oauth2_session().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_oauth2_simple_session_list() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // We already have a session because of the token above
        let request = Request::get("/api/admin/v1/oauth2-sessions")
            .bearer(&token)
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
              "type": "oauth2-session",
              "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "finished_at": null,
                "user_id": null,
                "user_session_id": null,
                "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
                "scope": "urn:pasion:admin",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?page[first]=10",
            "first": "/api/admin/v1/oauth2-sessions?page[first]=10",
            "last": "/api/admin/v1/oauth2-sessions?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/oauth2-sessions?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "oauth2-session",
              "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "finished_at": null,
                "user_id": null,
                "user_session_id": null,
                "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
                "scope": "urn:pasion:admin",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?count=false&page[first]=10",
            "first": "/api/admin/v1/oauth2-sessions?count=false&page[first]=10",
            "last": "/api/admin/v1/oauth2-sessions?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/oauth2-sessions?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?count=only"
          }
        }
        "#);
    }
}
