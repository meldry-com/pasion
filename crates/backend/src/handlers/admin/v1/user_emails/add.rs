use std::str::FromStr as _;

use crate::record_error;
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
    response::{ErrorResponse, SingleResponse},
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User email {0:?} already in use")]
    EmailAlreadyInUse(String),

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::EmailAlreadyInUse(_) => StatusCode::CONFLICT,
            Self::EmailNotValid { .. } => StatusCode::BAD_REQUEST,
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

/// # JSON payload for the `POST /api/admin/v1/user-emails`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserEmailRequest")]
pub struct RequestBody {
    /// The ID of the user to which the email should be added.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    user_id: Ulid,

    /// The email address of the user to add.
    #[schemars(email)]
    email: String,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.user_emails.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<(StatusCode, Json<SingleResponse<UserEmail>>), RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let mut rng = crate::handlers::rest::make_rng();
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // Find the user
    let user = repo
        .user()
        .lookup(params.user_id)
        .await?
        .ok_or(RouteError::UserNotFound(params.user_id))?;

    // Validate the email
    if let Err(source) = lettre::Address::from_str(&params.email) {
        return Err(RouteError::EmailNotValid {
            email: params.email,
            source,
        });
    }

    // Check if the email already exists
    let count = repo
        .user_email()
        .count(UserEmailFilter::new().for_email(&params.email))
        .await?;

    if count > 0 {
        return Err(RouteError::EmailAlreadyInUse(params.email));
    }

    // Add the email to the user
    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, params.email)
        .await?;

    // Schedule a job to update the user
    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new_for_id(user.id))
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(user_email.into())),
    ))
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
