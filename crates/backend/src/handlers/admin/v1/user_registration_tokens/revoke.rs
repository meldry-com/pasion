use salvo::prelude::*;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::{Resource, UserRegistrationToken},
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.revoke", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserRegistrationToken>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let id = extract_ulid_param(req)?;

    // id already extracted above
    let token = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("Registration token with ID {id} not found")))?;

    // Check if the token is already revoked
    if token.revoked_at.is_some() {
        return Err(AppError::bad_request(format!(
            "Registration token with ID {id} is already revoked"
        )));
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
    use pasion_data::Clock as _;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_revoke_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

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

    #[tokio::test]
    async fn test_revoke_already_revoked_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

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

    #[tokio::test]
    async fn test_revoke_unknown_token() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

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
