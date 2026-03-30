use std::str::FromStr as _;

use crate::record_error;
use chrono::{DateTime, Utc};
use oauth2_types::scope::{Scope, ScopeToken};
use pasion_data::personal::PersonalSessionFilter;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{InconsistentPersonalSession, PersonalSession, Resource},
    params::{IncludeCount, extract_pagination},
    response::{ErrorResponse, PaginatedResponse},
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum PersonalSessionStatus {
    Active,
    Revoked,
}

impl std::fmt::Display for PersonalSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "PersonalSessionFilter")]
pub struct FilterParams {
    /// Filter by owner user ID
    #[serde(rename = "filter[owner_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_user: Option<Ulid>,

    /// Filter by owner `OAuth2` client ID
    #[serde(rename = "filter[owner_client]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    owner_client: Option<Ulid>,

    /// Filter by actor user ID
    #[serde(rename = "filter[actor_user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    actor_user: Option<Ulid>,

    /// Retrieve the items with the given scope
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Filter by session status
    #[serde(rename = "filter[status]")]
    status: Option<PersonalSessionStatus>,

    /// Filter by access token expiry date
    #[serde(rename = "filter[expires_before]")]
    expires_before: Option<DateTime<Utc>>,

    /// Filter by access token expiry date
    #[serde(rename = "filter[expires_after]")]
    expires_after: Option<DateTime<Utc>>,

    /// Filter by whether the access token has an expiry time
    #[serde(rename = "filter[expires]")]
    expires: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(owner_user) = self.owner_user {
            write!(f, "{sep}filter[owner_user]={owner_user}")?;
            sep = '&';
        }
        if let Some(owner_client) = self.owner_client {
            write!(f, "{sep}filter[owner_client]={owner_client}")?;
            sep = '&';
        }
        if let Some(actor_user) = self.actor_user {
            write!(f, "{sep}filter[actor_user]={actor_user}")?;
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
        if let Some(expires_before) = self.expires_before {
            write!(
                f,
                "{sep}filter[expires_before]={}",
                expires_before.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            sep = '&';
        }
        if let Some(expires_after) = self.expires_after {
            write!(
                f,
                "{sep}filter[expires_after]={}",
                expires_after.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            sep = '&';
        }
        if let Some(expires) = self.expires {
            write!(f, "{sep}filter[expires]={expires}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),

    #[error("Client ID {0} not found")]
    ClientNotFound(Ulid),

    #[error("Invalid scope {0:?} in filter parameters")]
    InvalidScope(String),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::PaginationRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);
impl_from_error_for_route!(InconsistentPersonalSession);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound(_) | Self::ClientNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidScope(_) => StatusCode::BAD_REQUEST,
        };
        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}


impl_endpoint_out_register!(RouteError, [
    ("400", "Bad request"),
    ("401", "Unauthorized"),
    ("404", "Not found"),
    ("409", "Conflict"),
    ("500", "Internal server error"),
]);

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PaginatedResponse<PersonalSession>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = PersonalSession::PATH);
    let base = include_count.add_to_base(&base);

    let filter = PersonalSessionFilter::new();

    let owner_user = if let Some(owner_user_id) = params.owner_user {
        let owner_user = repo
            .user()
            .lookup(owner_user_id)
            .await?
            .ok_or(RouteError::UserNotFound(owner_user_id))?;
        Some(owner_user)
    } else {
        None
    };

    let filter = match &owner_user {
        Some(user) => filter.for_owner_user(user),
        None => filter,
    };

    let owner_client = if let Some(owner_client_id) = params.owner_client {
        let owner_client = repo
            .oauth2_client()
            .lookup(owner_client_id)
            .await?
            .ok_or(RouteError::ClientNotFound(owner_client_id))?;
        Some(owner_client)
    } else {
        None
    };

    let filter = match &owner_client {
        Some(client) => filter.for_owner_oauth2_client(client),
        None => filter,
    };

    let actor_user = if let Some(actor_user_id) = params.actor_user {
        let user = repo
            .user()
            .lookup(actor_user_id)
            .await?
            .ok_or(RouteError::UserNotFound(actor_user_id))?;
        Some(user)
    } else {
        None
    };

    let filter = match &actor_user {
        Some(user) => filter.for_actor_user(user),
        None => filter,
    };

    let scope: Scope = params
        .scope
        .into_iter()
        .map(|s| ScopeToken::from_str(&s).map_err(|_| RouteError::InvalidScope(s)))
        .collect::<Result<_, _>>()?;

    let filter = if scope.is_empty() {
        filter
    } else {
        filter.with_scope(&scope)
    };

    let filter = match params.status {
        Some(PersonalSessionStatus::Active) => filter.active_only(),
        Some(PersonalSessionStatus::Revoked) => filter.finished_only(),
        None => filter,
    };

    let filter = if let Some(expires_after) = params.expires_after {
        filter.with_expires_after(expires_after)
    } else {
        filter
    };

    let filter = if let Some(expires_before) = params.expires_before {
        filter.with_expires_before(expires_before)
    } else {
        filter
    };

    let filter = if let Some(expires) = params.expires {
        filter.with_expires(expires)
    } else {
        filter
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.personal_session().list(filter, pagination).await?;
            let count = repo.personal_session().count(filter).await?;
            PaginatedResponse::for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                Some(count),
                &base,
            )
        }
        IncludeCount::False => {
            let page = repo.personal_session().list(filter, pagination).await?;
            PaginatedResponse::for_page(
                page.try_map(PersonalSession::try_from)?,
                pagination,
                None,
                &base,
            )
        }
        IncludeCount::Only => {
            let count = repo.personal_session().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
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
            .add(
                &mut rng,
                &state.clock,
                &personal_session,
                "mpt_hiss",
                Some(Duration::days(42)),
            )
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let personal_session = repo
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
                &personal_session,
                "mpt_scratch",
                Some(Duration::days(21)),
            )
            .await
            .unwrap();
        repo.personal_session()
            .revoke(&state.clock, personal_session)
            .await
            .unwrap();

        state.clock.advance(Duration::days(1));

        let personal_session = repo
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
                &personal_session,
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

        // Map of filters to their expected set of returned ULIDs
        let filters_and_expected: &[(&str, &[&str])] = &[
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

        for (filter, expected_ids) in filters_and_expected {
            let request = Request::get(format!("/api/admin/v1/personal-sessions?{filter}"))
                .bearer(&token)
                .empty();
            let response = state.request(request).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            let found: BTreeSet<&str> = body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].as_str().unwrap())
                .collect();
            let expected: BTreeSet<&str> = expected_ids.iter().copied().collect();

            assert_eq!(
                found, expected,
                "filter {filter} did not produce expected results"
            );
        }
    }
}
