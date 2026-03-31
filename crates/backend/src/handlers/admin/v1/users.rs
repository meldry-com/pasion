// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::Duration;
use pasion_data::BoxRng;
use pasion_data::Page;
use pasion_data::audit::{AdminOperation, NewAdminOperationLog};
use pasion_data::user::UserFilter;
use pasion_matrix::ProvisionRequest;
use rand::distributions::{Alphanumeric, DistString};
use salvo::http::StatusCode;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::AppError;
use crate::AppResult;
use crate::CreatedJsonResult;
use crate::JsonResult;
use crate::handlers::{
    admin::call_context::extract_call_context,
    admin::model::Resource,
    admin::model::User,
    admin::model::UserRegistrationToken,
    admin::params::IncludeCount,
    admin::params::extract_pagination,
    admin::params::extract_ulid_param,
    admin::response::PaginatedResponse,
    admin::response::SingleResponse,
    passwords::PasswordManager,
    common::DepotExt,
};
use crate::util::username_valid;

/// # JSON payload for the `POST /api/admin/v1/users` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRequest")]
pub struct AddRequest {
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
pub async fn add_user(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let homeserver = depot.homeserver()?;
    let params: AddRequest = req
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

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UserCreated,
        "user",
        Some(user.id),
        serde_json::json!({ "username": user.username }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(SingleResponse::new_canonical(
        User::from(user),
    )))
}

/// # JSON payload for the `POST /api/admin/v1/users/batch-invite` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "BatchInviteRequest")]
pub struct BatchInviteRequest {
    /// Number of registration tokens to create (1-100)
    count: u32,

    /// Maximum number of times each token can be used. If not provided, each
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// Number of hours until each token expires. If not provided, the tokens
    /// never expire.
    expires_in_hours: Option<u64>,
}

/// Response containing the list of created registration tokens
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct BatchInviteResponse {
    /// The list of created registration tokens
    data: Vec<SingleResponse<UserRegistrationToken>>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.batch_invite", skip_all)]
pub async fn batch_invite(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<BatchInviteResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let mut rng = crate::handlers::account::make_rng();
    let params: BatchInviteRequest = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    if params.count == 0 || params.count > 100 {
        return Err(AppError::bad_request("Count must be between 1 and 100"));
    }

    let expires_at = params
        .expires_in_hours
        .and_then(|h| Duration::try_hours(h as i64))
        .map(|d| clock.now() + d);

    let mut tokens = Vec::with_capacity(params.count as usize);

    for _ in 0..params.count {
        let token_string = Alphanumeric.sample_string(&mut rng, 12);

        let registration_token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &clock,
                token_string,
                params.usage_limit,
                expires_at,
            )
            .await?;

        if let Some(admin_user) = &admin_user {
            repo.audit()
                .add_admin_operation(
                    &mut rng,
                    &clock,
                    NewAdminOperationLog::new(
                        admin_user.id,
                        AdminOperation::RegistrationTokenCreated,
                        "registration_token",
                        serde_json::json!({}),
                    )
                    .with_resource_id(registration_token.id),
                )
                .await?;
        }

        let model = UserRegistrationToken::new(registration_token, clock.now());
        tokens.push(SingleResponse::new_canonical(model));
    }

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(BatchInviteResponse {
        data: tokens,
    }))
}

#[derive(Deserialize, JsonSchema)]
pub struct UsernamePathParam {
    /// The username (localpart) of the user to get
    username: String,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.by_username", skip_all)]
pub async fn get_by_username(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let username: String = req
        .param::<String>("username")
        .ok_or_else(|| AppError::not_found(r#"User with username "unknown" not found"#))?;

    let self_path = format!("/api/admin/v1/users/by-username/{username}");
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User with username {username:?} not found")))?;

    Ok(Json(SingleResponse::new(User::from(user), self_path)))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.get", skip_all)]
pub async fn get_user(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    Active,
    Locked,
    Deactivated,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Deactivated => write!(f, "deactivated"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UserFilter")]
pub struct FilterParams {
    /// Retrieve users with (or without) the `admin` flag set
    #[serde(rename = "filter[admin]")]
    admin: Option<bool>,

    /// Retrieve users with (or without) the `legacy_guest` flag set
    #[serde(rename = "filter[legacy-guest]")]
    legacy_guest: Option<bool>,

    /// Retrieve users where the username matches contains the given string
    ///
    /// Note that this doesn't change the ordering of the result, which are
    /// still ordered by ID.
    #[serde(rename = "filter[search]")]
    search: Option<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all users, including locked ones.
    ///
    /// * `active`: Only retrieve active users
    ///
    /// * `locked`: Only retrieve locked users (includes deactivated users)
    ///
    /// * `deactivated`: Only retrieve deactivated users
    #[serde(rename = "filter[status]")]
    status: Option<UserStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(admin) = self.admin {
            write!(f, "{sep}filter[admin]={admin}")?;
            sep = '&';
        }
        if let Some(legacy_guest) = self.legacy_guest {
            write!(f, "{sep}filter[legacy-guest]={legacy_guest}")?;
            sep = '&';
        }
        if let Some(search) = &self.search {
            write!(f, "{sep}filter[search]={search}")?;
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
#[tracing::instrument(name = "handler.admin.v1.users.list", skip_all)]
pub async fn list_users(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = User::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserFilter::default();

    let filter = match params.admin {
        Some(true) => filter.can_request_admin_only(),
        Some(false) => filter.cannot_request_admin_only(),
        None => filter,
    };

    let filter = match params.legacy_guest {
        Some(true) => filter.guest_only(),
        Some(false) => filter.non_guest_only(),
        None => filter,
    };

    let filter = match params.search.as_deref() {
        Some(search) => filter.matching_search(search),
        None => filter,
    };

    let filter = match params.status {
        Some(UserStatus::Active) => filter.active_only(),
        Some(UserStatus::Locked) => filter.locked_only(),
        Some(UserStatus::Deactivated) => filter.deactivated_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

/// # JSON payload for the `POST /api/admin/v1/users/:id/risk-action` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RiskActionRequest")]
pub struct RiskActionRequest {
    /// The risk action to perform: "lock", "force_password_reset", or
    /// "terminate_sessions"
    action: String,

    /// The reason for the risk action
    reason: Option<String>,
}

/// Response indicating which risk action was taken
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct RiskActionResponse {
    /// The action that was performed
    action: String,

    /// The reason provided for the action
    reason: Option<String>,

    /// The user the action was performed on
    user: SingleResponse<User>,

    /// Number of sessions terminated (only for terminate_sessions action)
    #[serde(skip_serializing_if = "Option::is_none")]
    sessions_terminated: Option<usize>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.risk_action", skip_all)]
pub async fn risk_action(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<RiskActionResponse> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let params: RiskActionRequest = req
        .parse_json()
        .await
        .map_err(AppError::internal)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    let mut sessions_terminated = None;

    let user = match params.action.as_str() {
        "lock" => repo.user().lock(&clock, user).await?,

        "force_password_reset" => {
            // Lock the user account so they must reset their password
            let user = repo.user().lock(&clock, user).await?;
            user
        }

        "terminate_sessions" => {
            use pasion_data::user::BrowserSessionFilter;

            let filter = BrowserSessionFilter::new().for_user(&user).active_only();
            let count = repo.browser_session().finish_bulk(&clock, filter).await?;
            sessions_terminated = Some(count);
            user
        }

        other => return Err(AppError::bad_request(format!("Unknown risk action: {other}"))),
    };

    // Record audit log for the risk action
    if let Some(admin_user) = &admin_user {
        let operation = match params.action.as_str() {
            "lock" | "force_password_reset" => AdminOperation::UserLocked,
            "terminate_sessions" => AdminOperation::Other("terminate_sessions".into()),
            _ => AdminOperation::Other(params.action.clone()),
        };
        repo.audit()
            .add_admin_operation(
                &mut rng,
                &clock,
                NewAdminOperationLog::new(
                    admin_user.id,
                    operation,
                    "user",
                    serde_json::json!({
                        "action": params.action,
                        "reason": params.reason,
                    }),
                )
                .with_resource_id(user.id),
            )
            .await?;
    }

    repo.save().await?;

    let user_response = SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/risk-action"),
    );

    Ok(Json(RiskActionResponse {
        action: params.action,
        reason: params.reason,
        user: user_response,
        sessions_terminated,
    }))
}

/// # JSON payload for the `POST /api/admin/v1/users/:id/set-password` endpoint
#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "SetUserPasswordRequest")]
pub struct SetPasswordRequest {
    /// The password to set for the user
    #[schemars(example = &"hunter2")]
    password: String,

    /// Skip the password complexity check
    skip_password_check: Option<bool>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.set_password", skip_all)]
pub async fn set_password(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let password_manager = depot.password_manager()?;
    let params: SetPasswordRequest = req
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

    crate::handlers::admin::audit_helper::record_admin_operation(
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    preferred_locale: Option<Option<String>>,
    admin: Option<bool>,
    locked: Option<bool>,
    deactivated: Option<bool>,
    hs_erase: Option<bool>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.update", skip_all)]
pub async fn update_user(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let homeserver = depot.homeserver()?;
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let patch = pasion_data::AdminUserPatch {
        display_name: body.display_name,
        avatar_url: body.avatar_url,
        preferred_locale: body.preferred_locale,
        can_request_admin: body.admin,
        locked: body.locked,
        deactivated: body.deactivated,
    };

    let user = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        homeserver.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        body.hs_erase.unwrap_or(true),
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::not_found(format!("User ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            AppError::bad_request(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            AppError::bad_request(format!("Unexpected user email lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            AppError::bad_request(format!(
                "Unexpected upstream oauth link lookup failure for {id}"
            ))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            AppError::bad_request(format!("Provider ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            AppError::bad_request("Invalid display name")
        }
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            AppError::bad_request(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            AppError::conflict(format!("User email {email:?} already in use"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => AppError::conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::Homeserver(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::Request;
    use hyper::StatusCode;
    use pasion_data::RepositoryAccess;
    use pasion_data::user::{UserPasswordRepository, UserRepository};
    use pasion_matrix::HomeserverConnection;
    use pasion_matrix::ProvisionRequest;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use ulid::Ulid;
    use zeroize::Zeroizing;
    
    use crate::handlers::{
        passwords::PasswordManager,
        passwords::PasswordVerificationResult,
        test_utils::RequestBuilderExt,
        test_utils::ResponseExt,
        test_utils::TestState,
        test_utils::setup,
        test_utils::unique_test_nonce,
    };

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

    #[tokio::test]
    async fn test_list_users() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision two users
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Test default behavior (count=true)
        let request = Request::get("/api/admin/v1/users").bearer(&token).empty();
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
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?page[first]=10",
            "first": "/api/admin/v1/users?page[first]=10",
            "last": "/api/admin/v1/users?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/users?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?count=false&page[first]=10",
            "first": "/api/admin/v1/users?count=false&page[first]=10",
            "last": "/api/admin/v1/users?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/users?count=only")
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
            "self": "/api/admin/v1/users?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get("/api/admin/v1/users?count=false&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "first": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "last": "/api/admin/v1/users?filter[search]=alice&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get("/api/admin/v1/users?count=only&filter[search]=alice")
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
            "self": "/api/admin/v1/users?filter[search]=alice&count=only"
          }
        }
        "#);
    }

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
        assert_eq!(res, PasswordVerificationResult::Matched(()));
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
        assert_eq!(res, PasswordVerificationResult::Matched(()));
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

    #[tokio::test]
    async fn test_patch_user_profile_and_state() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.clone())
            .await
            .unwrap();
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "displayName": "Alice Admin",
                "preferredLocale": "zh-CN",
                "admin": true,
                "locked": true
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["display_name"], "Alice Admin");
        assert_eq!(body["data"]["attributes"]["preferred_locale"], "zh-CN");
        assert_eq!(body["data"]["attributes"]["admin"], true);
        assert!(body["data"]["attributes"]["locked_at"].is_string());

        let user = state
            .homeserver_connection
            .query_user(&username)
            .await
            .unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice Admin"));
    }

    #[tokio::test]
    async fn test_patch_user_reactivate() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();
        state
            .homeserver_connection
            .delete_user(&user.username, true)
            .await
            .unwrap();

        let request = Request::patch(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "deactivated": false
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::Value::Null
        );

        let matrix_user = state
            .homeserver_connection
            .query_user(&user.username)
            .await
            .unwrap();
        assert!(!matrix_user.deactivated);
    }
}
