use pasion_data::{BoxRng, audit::AdminOperation};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::handlers::{
    admin::{
        call_context::extract_call_context, params::extract_ulid_param,
    },
    passwords::PasswordManager,
    rest::DepotExt,
};
use crate::{AppError, AppResult};

/// # JSON payload for the `POST /api/admin/v1/users/:id/set-password` endpoint
#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "SetUserPasswordRequest")]
pub struct RequestBody {
    /// The password to set for the user
    #[schemars(example = &"hunter2")]
    password: String,

    /// Skip the password complexity check
    skip_password_check: Option<bool>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.set_password", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();
    let password_manager = depot.password_manager()?;
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    if !password_manager.is_enabled() {
        return Err(AppError::forbidden("Password auth is disabled"));
    }

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    let skip_password_check = params.skip_password_check.unwrap_or(false);
    tracing::info!(skip_password_check, "skip_password_check");
    if !skip_password_check
        && !password_manager
            .is_password_complex_enough(&params.password)
            .unwrap_or(false)
    {
        return Err(AppError::bad_request("Password is too weak"));
    }

    let password = Zeroizing::new(params.password);
    let (version, hashed_password) = password_manager
        .hash(&mut rng, password)
        .await
        .map_err(|error| {
            AppError::with_source(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password hashing failed",
                Box::new(std::io::Error::other(error.to_string())),
                true,
            )
        })?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    crate::handlers::admin_audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserPasswordSet,
        "user",
        Some(user.id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_data::{RepositoryAccess, user::UserPasswordRepository};
    use zeroize::Zeroizing;

    use crate::handlers::{
        passwords::{PasswordManager, PasswordVerificationResult},
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
    };

    #[tokio::test]
    async fn test_set_password() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        // Double-check that the user doesn't have a password
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());

        repo.save().await.unwrap();

        let user_id = user.id;

        // Set the password through the API
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new(String::from("this is a good enough password"));
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Success(()));
    }

    #[tokio::test]
    async fn test_weak_password() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let user_id = user.id;

        // Set a weak password through the API
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Check that the user still has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());
        repo.save().await.unwrap();

        // Now try with the skip_password_check flag
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
                "skip_password_check": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new("password".to_owned());
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Success(()));
    }

    #[tokio::test]
    async fn test_unknown_user() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Set the password through the API
        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/set-password")
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[tokio::test]
    async fn test_disabled() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        state.password_manager = PasswordManager::disabled();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/set-password")
            .bearer(&token)
            .json(serde_json::json!({
                "password": "hunter2",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Password auth is disabled");
    }
}
