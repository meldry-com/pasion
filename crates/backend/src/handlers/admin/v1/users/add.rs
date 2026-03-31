use pasion_data::BoxRng;
use pasion_matrix::ProvisionRequest;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::warn;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::User,
        response::SingleResponse,
    },
    rest::DepotExt,
};
use crate::util::username_valid;
use crate::{AppError, CreatedJsonResult};

/// # JSON payload for the `POST /api/admin/v1/users` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRequest")]
pub struct RequestBody {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is available.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in Pasion to craft special
    /// tokens (like with admin access) for them
    #[serde(default)]
    skip_homeserver_check: bool,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.add", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = call_context;
    let mut rng = crate::handlers::rest::make_rng();
    let homeserver = depot.homeserver()?;
    let params: RequestBody = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    if repo.user().exists(&params.username).await? {
        return Err(AppError::conflict("User already exists"));
    }

    // Do some basic check on the username
    if !username_valid(&params.username) {
        return Err(AppError::bad_request("Username is not valid"));
    }

    // Ask the homeserver if the username is available
    let homeserver_available = homeserver
        .is_localpart_available(&params.username)
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    if !homeserver_available {
        if !params.skip_homeserver_check {
            return Err(AppError::conflict("Username is reserved by the homeserver"));
        }

        // If we skipped the check, we still want to shout about it
        warn!("Skipped homeserver check for username {}", params.username);
    }

    let user = repo.user().add(&mut rng, &clock, params.username).await?;

    homeserver
        .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
        .await
        .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(SingleResponse::new_canonical(
        User::from(user),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_data::{RepositoryAccess, user::UserRepository};
    use pasion_matrix::HomeserverConnection;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_add_user() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.username, "alice");

        // Check that the user was created on the homeserver
        let result = state.homeserver_connection.query_user("alice").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_user_invalid_username() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "this is invalid",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Username is not valid");
    }

    #[tokio::test]
    async fn test_add_user_exists() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "User already exists");
    }

    #[tokio::test]
    async fn test_add_user_reserved() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        // Reserve a username on the homeserver and try to add it
        state.homeserver_connection.reserve_localpart("bob").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "bob",
            }));

        let response = state.request(request).await;

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Username is reserved by the homeserver"
        );

        // But we can force it with the skip_homeserver_check flag
        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "bob",
                "skip_homeserver_check": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "bob");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.username, "bob");
    }
}
