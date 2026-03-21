use salvo::prelude::*;
use salvo::http::StatusCode;
use pasion_salvo_utils::record_error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::extract_call_context,
        model::{Resource, UserRegistrationToken},
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Registration token with ID {0} not found")]
    NotFound(Ulid),

    #[error("Registration token with ID {0} is already revoked")]
    AlreadyRevoked(Ulid),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyRevoked(_) => StatusCode::BAD_REQUEST,
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
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.revoke", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot) -> Result<Json<SingleResponse<UserRegistrationToken>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::admin::call_context::CallContext { mut repo, clock, .. } = call_context;
    let id = extract_ulid_param(req)?;

    // id already extracted above
    let token = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the token is already revoked
    if token.revoked_at.is_some() {
        return Err(RouteError::AlreadyRevoked(id));
    }

    // Revoke the token
    let token = repo.user_registration_token().revoke(&clock, token).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(token, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{id}/revoke"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data_model::Clock as _;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_revoke_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_456".to_owned(),
                Some(5),
                None,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/api/admin/v1/user-registration-tokens/{}/revoke",
            registration_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The revoked_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_revoke_already_revoked_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_789".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        // Revoke the token first
        let registration_token = repo
            .user_registration_token()
            .revoke(&state.clock, registration_token)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/user-registration-tokens/{}/revoke",
            registration_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "Registration token with ID {} is already revoked",
                registration_token.id
            )
        );
    }

    #[sqlx::test(migrator = "pasion_storage_pg::MIGRATOR")]
    async fn test_revoke_unknown_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post(
            "/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081/revoke",
        )
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Registration token with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
