//! REST API endpoints for authentication flows (login, logout, providers).
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. Session cookies are set/cleared as side effects.

use std::sync::LazyLock;

use opentelemetry::{Key, KeyValue, metrics::Counter};
use pasion_data_model::Clock;
use pasion_matrix::HomeserverConnection;
use pasion_salvo_utils::SessionInfoExt;
use pasion_storage::{
    RepositoryAccess,
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository} };
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{DepotExt, 
    NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    make_clock, make_rng };
use crate::{METER, RequesterFingerprint, passwords::PasswordVerificationResult};

// ── Metrics ────────────────────────────────────────────────────

static PASSWORD_LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.rest.password_login_attempt")
        .with_description("Number of REST API password login attempts")
        .with_unit("{attempt}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

// ── Request / Response types ───────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String }

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<ViewerInfo> }

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ViewerInfo {
    pub id: String,
    pub username: String,
    pub mxid: String,
    pub display_name: Option<String> }

#[derive(Serialize, ToSchema)]
pub struct LogoutResponse {
    pub status: &'static str }

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersResponse {
    pub providers: Vec<ProviderInfo>,
    pub password_login_enabled: bool,
    pub password_registration_enabled: bool }

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    pub id: String,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub authorize_url: String }

// ── Helper: look up user by email or username ──────────────────

async fn get_user_by_email_or_by_username<R: RepositoryAccess>(
    site_config: &pasion_data_model::SiteConfig,
    repo: &mut R,
    username_or_email: &str,
) -> Result<Option<pasion_data_model::User>, R::Error> {
    if site_config.login_with_email_allowed && username_or_email.contains('@') {
        let maybe_user_email = repo.user_email().find_by_email(username_or_email).await?;

        if let Some(user_email) = maybe_user_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            if user.is_some() {
                return Ok(user);
            }
        }
    }

    let user = repo.user().find_by_username(username_or_email).await?;

    Ok(user)
}

// ── POST /api/v1/auth/login ────────────────────────────────────

/// Authenticate a user with username and password, returning viewer info and
/// setting a session cookie on success.
#[endpoint]
pub async fn login(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let password_manager = depot.password_manager()?;
    let site_config = depot.site_config()?;
    let limiter = depot.limiter()?;
    let homeserver = depot.homeserver()?;
    let mut repo = depot.repo_factory()?.create().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let cookie_jar = depot.cookie_jar(req)?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());

    let input: LoginRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    // Check if password login is enabled
    if !site_config.password_login_enabled {
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("password_login_disabled"),
            viewer: None }));
        return Ok(());
    }

    // Validate fields
    if input.username.is_empty() || input.password.is_empty() {
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_credentials"),
            viewer: None }));
        return Ok(());
    }

    // Extract the localpart of the MXID, fallback to the bare username
    let username = homeserver
        .localpart(&input.username)
        .unwrap_or(&input.username);

    // Look up the user
    let Some(user) = get_user_by_email_or_by_username(&site_config, &mut repo, username).await?
    else {
        tracing::warn!(username, "REST login: user not found");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_credentials"),
            viewer: None }));
        return Ok(());
    };

    // Check rate limit
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "REST login: rate limited"
        );
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.status_code(StatusCode::TOO_MANY_REQUESTS);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("rate_limited"),
            viewer: None }));
        return Ok(());
    }

    // Fetch password
    let Some(user_password) = repo.user_password().active(&user).await? else {
        // No password for this user — show generic "invalid credentials"
        tracing::warn!(username, "REST login: no password for user");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("invalid_credentials"),
            viewer: None }));
        return Ok(());
    };

    let password = Zeroizing::new(input.password);

    // Verify the password, and upgrade it on-the-fly if needed
    let user_password = match password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
    {
        Ok(PasswordVerificationResult::Success(Some((version, new_password_hash)))) => {
            // Save the upgraded password
            repo.user_password()
                .add(
                    &mut rng,
                    &clock,
                    &user,
                    version,
                    new_password_hash,
                    Some(&user_password),
                )
                .await?
        }
        Ok(PasswordVerificationResult::Success(None)) => user_password,
        Ok(PasswordVerificationResult::Failure) => {
            tracing::warn!(username, "REST login: password mismatch");
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "mismatch")]);
            res.render(Json(LoginResponse {
                status: "error",
                error: Some("invalid_credentials"),
                viewer: None }));
            return Ok(());
        }
        Err(err) => return Err(RouteError::Internal(err.into())) };

    // Check deactivated
    if user.deactivated_at.is_some() {
        tracing::warn!(username, "REST login: user deactivated");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("account_deactivated"),
            viewer: None }));
        return Ok(());
    }

    // Check locked
    if user.locked_at.is_some() {
        tracing::warn!(username, "REST login: user locked");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        res.render(Json(LoginResponse {
            status: "error",
            error: Some("account_locked"),
            viewer: None }));
        return Ok(());
    }

    debug_assert!(user.is_valid());

    // Start a new browser session
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    // Mark it as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
        .await?;

    repo.save().await?;

    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    // Set session cookie
    let cookie_jar = cookie_jar.set_session(&user_session);

    // Fetch Matrix display name for the response
    let display_name = match homeserver.query_user(&user.username).await {
        Ok(info) => info.displayname,
        Err(_) => None };

    cookie_jar.write_to_response(res);
    res.render(Json(LoginResponse {
        status: "success",
        error: None,
        viewer: Some(ViewerInfo {
            id: NodeType::User.serialize(user.id),
            username: user.username.clone(),
            mxid: homeserver.mxid(&user.username),
            display_name }) }));
    Ok(())
}

// ── POST /api/v1/auth/logout ───────────────────────────────────

/// End the current browser session and clear the session cookie.
#[endpoint]
pub async fn logout(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let mut repo = depot.repo_factory()?.create().await?;
    let cookie_jar = depot.cookie_jar(req)?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);

    let (session_info, cookie_jar) = cookie_jar.session_info();

    if let Some(session_id) = session_info.current_session_id() {
        let maybe_session = repo.browser_session().lookup(session_id).await?;
        if let Some(session) = maybe_session
            && session.finished_at.is_none()
        {
            activity_tracker
                .record_browser_session(&clock, &session)
                .await;

            repo.browser_session().finish(&clock, session).await?;
        }
    }

    repo.save().await?;

    // Clear the session cookie
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    cookie_jar.write_to_response(res);
    res.render(Json(LogoutResponse { status: "success" }));
    Ok(())
}

// ── GET /api/v1/auth/providers ─────────────────────────────────

/// List all enabled upstream OAuth providers and site configuration flags
/// relevant to the login/registration UI.
#[endpoint]
pub async fn providers(depot: &Depot) -> Result<Json<ProvidersResponse>, RouteError> {
    let site_config = depot.site_config()?;
    let mut repo = depot.repo_factory()?.create().await?;

    let upstream_providers = repo.upstream_oauth_provider().all_enabled().await?;

    let provider_list: Vec<ProviderInfo> = upstream_providers
        .into_iter()
        .map(|p| {
            let authorize_url = format!("/upstream/authorize/{}", p.id);
            ProviderInfo {
                id: p.id.to_string(),
                human_name: p.human_name,
                brand_name: p.brand_name,
                authorize_url }
        })
        .collect();

    repo.cancel().await?;

    Ok(Json(ProvidersResponse {
        providers: provider_list,
        password_login_enabled: site_config.password_login_enabled,
        password_registration_enabled: site_config.password_registration_enabled }))
}
