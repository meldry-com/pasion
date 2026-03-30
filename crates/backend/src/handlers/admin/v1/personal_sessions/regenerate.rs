use chrono::Duration;
use pasion_data_model::{BoxRng, TokenType};
use crate::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::error;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::{InconsistentPersonalSession, PersonalSession},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
        v1::personal_sessions::personal_session_owner_from_caller,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User not found")]
    UserNotFound,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session not valid")]
    SessionNotValid,

    #[error("Session does not belong to you")]
    SessionNotYours,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);
impl_from_error_for_route!(InconsistentPersonalSession);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound | Self::SessionNotFound => StatusCode::NOT_FOUND,
            Self::SessionNotValid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::SessionNotYours => StatusCode::FORBIDDEN,
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

/// # JSON payload for the `POST /api/admin/v1/personal-sessions/{id}/regenerate` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RegeneratePersonalSessionRequest")]
pub struct RequestBody {
    /// Token expiry time in seconds.
    /// If not set, the token won't expire.
    expires_in: Option<u32>,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<(StatusCode, Json<SingleResponse<PersonalSession>>), RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        session: caller_session,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();
    let params: RequestBody = req
        .parse_json()
        .await
        .unwrap_or(RequestBody { expires_in: None });

    let session_id = id;

    let session = repo
        .personal_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    if !session.is_valid() {
        // We don't revive revoked sessions through regeneration
        return Err(RouteError::SessionNotValid);
    }

    // If the owner is not the current caller, then currently we reject the
    // regeneration.
    let caller = personal_session_owner_from_caller(&caller_session);
    if session.owner != caller {
        return Err(RouteError::SessionNotYours);
    }

    // Revoke the existing active token for the session.
    let old_token_opt = repo
        .personal_access_token()
        .find_active_for_session(&session)
        .await?;
    let Some(old_token) = old_token_opt else {
        // This shouldn't happen
        error!("session is supposedly valid but had no access token");
        return Err(RouteError::SessionNotValid);
    };

    repo.personal_access_token()
        .revoke(&clock, old_token)
        .await?;

    // Create the regenerated token for the session
    let access_token_string = TokenType::PersonalAccessToken.generate(&mut rng);
    let access_token = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_string,
            params
                .expires_in
                .map(|exp_in| Duration::seconds(i64::from(exp_in))),
        )
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(
            PersonalSession::try_from((session, Some(access_token)))?
                .with_token(access_token_string),
        )),
    ))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_regenerate_personal_session() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(json!({
                "actor_user_id": user.id,
                "human_name": "SuperDuperAdminCLITool Token",
                "scope": "openid urn:pasion:admin",
                "expires_in": 3600
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let created: Value = response.json();

        let session_id = created["data"]["id"].as_str().unwrap();

        state.clock.advance(Duration::minutes(3));

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{session_id}/regenerate"
        ))
        .bearer(&token)
        .json(json!({
            "expires_in": 86400
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": null,
              "owner_client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "SuperDuperAdminCLITool Token",
              "scope": "openid urn:pasion:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-17T14:43:00Z",
              "access_token": "mpt_6cq7FqNSYoosbXl3bbpfh9yNy9NzuR_0vOV2O"
            },
            "links": {
              "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }
}
