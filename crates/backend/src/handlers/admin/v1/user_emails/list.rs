use crate::record_error;
use pasion_data::{Page, user::UserEmailFilter};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserEmail},
    params::{IncludeCount, extract_pagination},
    response::{ErrorResponse, PaginatedResponse},
};

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UserEmailFilter")]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the user email with the given email address
    #[serde(rename = "filter[email]")]
    email: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(email) = &self.email {
            write!(f, "{sep}filter[email]={email}")?;
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
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::PaginationRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound(_) => StatusCode::NOT_FOUND,
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

#[handler]
#[tracing::instrument(name = "handler.admin.v1.user_emails.list", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PaginatedResponse<UserEmail>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = UserEmail::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserEmailFilter::default();

    // Load the user from the filter
    let user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UserNotFound(user_id))?;

        Some(user)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let filter = match &params.email {
        Some(email) => filter.for_email(email),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            let count = repo.user_email().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user_email().count(filter).await?;
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
    async fn test_list() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision two users, two emails
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

        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.user_email()
            .add(&mut rng, &state.clock, &bob, "bob@example.com".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/user-emails")
            .bearer(&token)
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            },
            {
              "type": "user-email",
              "id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "email": "bob@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG0KEPHYQQXW9XPTX6Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0KEPHYQQXW9XPTX6Z"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?page[first]=10",
            "first": "/api/admin/v1/user-emails?page[first]=10",
            "last": "/api/admin/v1/user-emails?page[last]=10"
          }
        }
        "#);

        // Filter by user
        let request = Request::get(format!(
            "/api/admin/v1/user-emails?filter[user]={}",
            alice.id
        ))
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

        // Filter by email
        let request = Request::get("/api/admin/v1/user-emails?filter[email]=alice@example.com")
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
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[first]=10",
            "first": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[first]=10",
            "last": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/user-emails?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            },
            {
              "type": "user-email",
              "id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "email": "bob@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG0KEPHYQQXW9XPTX6Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0KEPHYQQXW9XPTX6Z"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?count=false&page[first]=10",
            "first": "/api/admin/v1/user-emails?count=false&page[first]=10",
            "last": "/api/admin/v1/user-emails?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/user-emails?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/user-emails?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/api/admin/v1/user-emails?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09NMZYX8MFYH578R9"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get(format!(
            "/api/admin/v1/user-emails?count=only&filter[user]={}",
            alice.id
        ))
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
            "self": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=only"
          }
        }
        "#);
    }
}
