//! REST API endpoints for OAuth2 consent and device-code flows.
//!
//! These endpoints are consumed by the Dioxus SPA frontend and return JSON
//! responses. They replace the server-rendered HTML consent pages.

use std::time::Duration;

use oauth2_types::requests::AuthorizationResponse;
use pasion_data_model::{AuthorizationGrantStage, Clock, MatrixUser};
use pasion_matrix::HomeserverConnection;
use pasion_policy::Policy;
use pasion_salvo_utils::SessionInfoExt;
use pasion_storage::{
    RepositoryAccess,
    oauth2::{
        OAuth2AuthorizationGrantRepository, OAuth2ClientRepository,
        OAuth2DeviceCodeGrantRepository, OAuth2SessionRepository,
    },
    user::BrowserSessionRepository,
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{
    RouteError, extract_bound_activity_tracker, extract_session_info, get_homeserver,
    get_key_store, get_policy_factory, get_repo_factory, get_url_builder, make_clock, make_rng,
};
use crate::{
    oauth2::{authorization::callback::CallbackDestination, generate_id_token},
    session::count_user_sessions_for_limiting,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub id: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub mxid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentGetResponse {
    pub grant_id: String,
    pub client: ClientInfo,
    pub scope: String,
    pub user: UserInfo,
    pub policy_violation: bool,
}

#[derive(Deserialize)]
pub struct ConsentPostRequest {
    pub action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentPostResponse {
    pub status: &'static str,
    pub redirect_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLinkResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceLinkQuery {
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceConsentPostRequest {
    pub action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceConsentPostResponse {
    pub status: &'static str,
}

// ── Helpers ────────────────────────────────────────────────────

/// Fetch the user's Matrix display name with a 1-second timeout.
async fn fetch_display_name(
    homeserver: &dyn HomeserverConnection,
    localpart: &str,
) -> Option<String> {
    match tokio::time::timeout(Duration::from_secs(1), homeserver.query_user(localpart)).await {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    }
}

fn client_info(client: &pasion_data_model::Client) -> ClientInfo {
    ClientInfo {
        id: client.id.to_string(),
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        client_uri: client.client_uri.as_ref().map(|u| u.to_string()),
        logo_uri: client.logo_uri.as_ref().map(|u| u.to_string()),
    }
}

// ── GET /api/v1/oauth2/consent/:grant_id ───────────────────────

/// Return the data needed to render a consent page for an OAuth2 authorization
/// grant.
#[handler]
#[tracing::instrument(name = "handlers.rest.consent.oauth2_get", skip_all)]
pub async fn oauth2_consent_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let homeserver = get_homeserver(depot)?;
    let policy_factory = get_policy_factory(depot)?;
    let mut repo = get_repo_factory(depot)?.create().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("grant_id")
        .ok_or_else(|| RouteError::BadRequest("missing grant_id".into()))?;

    // Load the browser session from the cookie
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({
            "status": "error",
            "error": "not_authenticated"
        })));
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // Look up the grant
    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::BadRequest("grant is not pending".into()));
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Evaluate the policy
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    repo.save().await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::AuthorizationCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let policy_violation = !eval_result.valid();

    let localpart = &session.user.username;
    let display_name = fetch_display_name(homeserver.as_ref(), localpart).await;

    res.render(Json(ConsentGetResponse {
        grant_id: grant.id.to_string(),
        client: client_info(&client),
        scope: grant.scope.to_string(),
        user: UserInfo {
            mxid: homeserver.mxid(localpart),
            display_name,
        },
        policy_violation,
    }));
    Ok(())
}

// ── POST /api/v1/oauth2/consent/:grant_id ──────────────────────

/// Accept the OAuth2 authorization consent: create an OAuth2 session, fulfill
/// the grant, and return the callback redirect URL.
#[handler]
#[tracing::instrument(name = "handlers.rest.consent.oauth2_post", skip_all)]
pub async fn oauth2_consent_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let mut rng = make_rng();
    let clock = make_clock();
    let key_store = get_key_store(depot)?;
    let url_builder = get_url_builder(depot)?;
    let policy_factory = get_policy_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let mut repo = get_repo_factory(depot)?.create().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("grant_id")
        .ok_or_else(|| RouteError::BadRequest("missing grant_id".into()))?;

    let input: ConsentPostRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    if input.action != "consent" {
        return Err(RouteError::BadRequest("invalid action".into()));
    }

    // Load the browser session from the cookie
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let Some(browser_session) = maybe_session else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({
            "status": "error",
            "error": "not_authenticated"
        })));
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;

    // Look up the grant
    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let callback_destination = CallbackDestination::try_from(&grant)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::BadRequest("grant is not pending".into()));
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Evaluate the policy
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let session_counts =
        count_user_sessions_for_limiting(&mut repo, &browser_session.user).await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::AuthorizationCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    if !eval_result.valid() {
        return Err(RouteError::BadRequest("policy_violation".into()));
    }

    // Create the OAuth2 session
    let session = repo
        .oauth2_session()
        .add_from_browser_session(
            &mut rng,
            &clock,
            &client,
            &browser_session,
            grant.scope.clone(),
        )
        .await?;

    // Fulfill the grant
    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&clock, &session, grant)
        .await?;

    // Build the authorization response parameters
    let mut params = AuthorizationResponse::default();

    // Generate ID token if requested
    if grant.response_type_id_token {
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            &mut rng,
            &clock,
            &url_builder,
            &key_store,
            &client,
            Some(&grant),
            &browser_session,
            None,
            last_authentication.as_ref(),
        ).map_err(|e| RouteError::Internal(Box::new(e)))?);
    }

    // Include auth code if present
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    // Build the redirect URL as a string
    let redirect_info = callback_destination
        .redirect_url(&params)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    res.render(Json(ConsentPostResponse {
        status: "success",
        redirect_url: redirect_info.url,
    }));
    Ok(())
}

// ── GET /api/v1/device-link ────────────────────────────────────

/// Validate a device user code and return the grant ID if valid.
#[handler]
#[tracing::instrument(name = "handlers.rest.consent.device_link_get", skip_all)]
pub async fn device_link_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let mut repo = get_repo_factory(depot)?.create().await?;

    let query: DeviceLinkQuery = req.parse_queries().unwrap_or(DeviceLinkQuery { code: None });

    let Some(code) = query.code else {
        res.render(Json(DeviceLinkResponse {
            status: "invalid",
            grant_id: None,
        }));
        return Ok(());
    };

    let code = code.to_uppercase();
    let grant = repo
        .oauth2_device_code_grant()
        .find_by_user_code(&code)
        .await?
        .filter(|grant| grant.is_pending())
        .filter(|grant| grant.expires_at > clock.now());

    repo.cancel().await?;

    if let Some(grant) = grant {
        res.render(Json(DeviceLinkResponse {
            status: "valid",
            grant_id: Some(grant.id.to_string()),
        }));
    } else {
        res.render(Json(DeviceLinkResponse {
            status: "invalid",
            grant_id: None,
        }));
    }
    Ok(())
}

// ── GET /api/v1/device-consent/:id ─────────────────────────────

/// Return the data needed to render a consent page for a device code grant.
#[handler]
#[tracing::instrument(name = "handlers.rest.consent.device_consent_get", skip_all)]
pub async fn device_consent_get(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let homeserver = get_homeserver(depot)?;
    let policy_factory = get_policy_factory(depot)?;
    let mut repo = get_repo_factory(depot)?.create().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing id".into()))?;

    // Load the browser session from the cookie
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({
            "status": "error",
            "error": "not_authenticated"
        })));
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // Look up the device code grant
    let grant = repo
        .oauth2_device_code_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if grant.expires_at < clock.now() {
        return Err(RouteError::BadRequest("grant is expired".into()));
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Evaluate the policy
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    repo.save().await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::DeviceCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let policy_violation = !eval_result.valid();

    let localpart = &session.user.username;
    let display_name = fetch_display_name(homeserver.as_ref(), localpart).await;

    res.render(Json(ConsentGetResponse {
        grant_id: grant.id.to_string(),
        client: client_info(&client),
        scope: grant.scope.to_string(),
        user: UserInfo {
            mxid: homeserver.mxid(localpart),
            display_name,
        },
        policy_violation,
    }));
    Ok(())
}

// ── POST /api/v1/device-consent/:id ────────────────────────────

/// Accept or reject a device code grant.
#[handler]
#[tracing::instrument(name = "handlers.rest.consent.device_consent_post", skip_all)]
pub async fn device_consent_post(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let clock = make_clock();
    let policy_factory = get_policy_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let mut repo = get_repo_factory(depot)?.create().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let user_agent: Option<String> = req.header("user-agent");
    let session_info = extract_session_info(req, depot);
    let grant_id: Ulid = req
        .param("id")
        .ok_or_else(|| RouteError::BadRequest("missing id".into()))?;

    let input: DeviceConsentPostRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let action = match input.action.as_str() {
        "consent" => DeviceAction::Consent,
        "reject" => DeviceAction::Reject,
        _ => return Err(RouteError::BadRequest("invalid action".into())),
    };

    // Load the browser session from the cookie
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(serde_json::json!({
            "status": "error",
            "error": "not_authenticated"
        })));
        return Ok(());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // Look up the device code grant
    let grant = repo
        .oauth2_device_code_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    if grant.expires_at < clock.now() {
        return Err(RouteError::BadRequest("grant is expired".into()));
    }

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    // Evaluate the policy
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    let eval_result = policy
        .evaluate_authorization_grant(pasion_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: pasion_policy::GrantType::DeviceCode,
            requester: pasion_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    if !eval_result.valid() {
        return Err(RouteError::BadRequest("policy_violation".into()));
    }

    // Fulfill or reject the grant
    let result_status = if grant.is_pending() {
        match action {
            DeviceAction::Consent => {
                repo.oauth2_device_code_grant()
                    .fulfill(&clock, grant, &session)
                    .await?;
                "fulfilled"
            }
            DeviceAction::Reject => {
                repo.oauth2_device_code_grant()
                    .reject(&clock, grant, &session)
                    .await?;
                "rejected"
            }
        }
    } else {
        // Grant was already processed (e.g. double-submit), return current
        // state rather than erroring.
        tracing::warn!(
            oauth2_device_code.id = %grant_id,
            browser_session.id = %session.id,
            user.id = %session.user.id,
            "Grant is not pending",
        );
        if grant.is_fulfilled() {
            "fulfilled"
        } else if grant.is_rejected() {
            "rejected"
        } else {
            "fulfilled"
        }
    };

    repo.save().await?;

    res.render(Json(DeviceConsentPostResponse {
        status: result_status,
    }));
    Ok(())
}

enum DeviceAction {
    Consent,
    Reject,
}
