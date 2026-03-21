use pasion_storage::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker, extract_session_info,
    get_homeserver, get_repo_factory, get_requester, make_clock, make_rng, parse_user_agent,
};

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize)]
#[serde(tag = "__typename")]
pub enum SessionDetailResponse {
    BrowserSession(BrowserSessionDetail),
    Oauth2Session(Oauth2SessionDetail),
    CompatSession(CompatSessionDetail),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSessionDetail {
    pub id: String,
    pub display_name: Option<String>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
    pub last_authentication: Option<AuthenticationData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    pub id: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2SessionDetail {
    pub id: String,
    pub scope: Option<String>,
    pub display_name: Option<String>,
    pub client: Option<Oauth2ClientBrief>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2ClientBrief {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatSessionDetail {
    pub id: String,
    pub device_id: Option<String>,
    pub display_name: Option<String>,
    pub user_agent: Option<UserAgentInfo>,
    pub last_active_ip: Option<String>,
    pub last_active_at: Option<String>,
    pub created_at: Option<String>,
    pub sso_login: Option<SsoLoginData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoLoginData {
    pub id: String,
    pub redirect_uri: String,
}

// ── GET /api/v1/sessions/:id ───────────────────────────────────

#[handler]
pub async fn get_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionDetailResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let (node_type, ulid) = NodeType::deserialize(&id)?;

    let response = match node_type {
        NodeType::BrowserSession => {
            let session = repo
                .browser_session()
                .lookup(ulid)
                .await?
                .ok_or(RouteError::NotFound)?;

            if !requester.is_owner_or_admin(Some(session.user.id)) {
                return Err(RouteError::Unauthorized);
            }

            let last_auth = repo.browser_session().get_last_authentication(&session).await?;

            SessionDetailResponse::BrowserSession(BrowserSessionDetail {
                id: NodeType::BrowserSession.serialize(session.id),
                display_name: None,
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
                last_authentication: last_auth.map(|a| AuthenticationData {
                    id: NodeType::Authentication.serialize(a.id),
                    created_at: a.created_at.to_rfc3339(),
                }),
            })
        }
        NodeType::OAuth2Session => {
            let session = repo
                .oauth2_session()
                .lookup(ulid)
                .await?
                .ok_or(RouteError::NotFound)?;

            if !requester.is_owner_or_admin(session.user_id) {
                return Err(RouteError::Unauthorized);
            }

            let client = repo.oauth2_client().lookup(session.client_id).await?;

            SessionDetailResponse::Oauth2Session(Oauth2SessionDetail {
                id: NodeType::OAuth2Session.serialize(session.id),
                scope: Some(session.scope.to_string()),
                display_name: None,
                client: client.map(|c| Oauth2ClientBrief {
                    id: NodeType::OAuth2Client.serialize(c.id),
                    client_id: c.client_id.to_string(),
                    client_name: c.client_name.clone(),
                    client_uri: c.client_uri.as_ref().map(|u| u.to_string()),
                    logo_uri: c.logo_uri.as_ref().map(|u| u.to_string()),
                }),
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
            })
        }
        NodeType::CompatSession => {
            let session = repo
                .compat_session()
                .lookup(ulid)
                .await?
                .ok_or(RouteError::NotFound)?;

            if !requester.is_owner_or_admin(Some(session.user_id)) {
                return Err(RouteError::Unauthorized);
            }

            let sso_login = repo.compat_sso_login().find_for_session(&session).await?.map(|l| SsoLoginData {
                id: NodeType::CompatSsoLogin.serialize(l.id),
                redirect_uri: l.redirect_uri.to_string(),
            });

            SessionDetailResponse::CompatSession(CompatSessionDetail {
                id: NodeType::CompatSession.serialize(session.id),
                device_id: session.device.as_ref().map(|d| d.to_string()),
                display_name: None,
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
                sso_login,
            })
        }
        _ => return Err(RouteError::BadRequest("not a session id".into())),
    };

    repo.cancel().await?;

    Ok(Json(response))
}

// ── DELETE /api/v1/browser-sessions/:id ────────────────────────

#[derive(Serialize)]
pub struct EndSessionResponse {
    pub status: &'static str,
}

#[handler]
pub async fn end_browser_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::BrowserSession.extract_ulid(&id)?;

    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let session = repo
        .browser_session()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(Some(session.user.id)) {
        return Err(RouteError::Unauthorized);
    }

    repo.browser_session().finish(&clock, session).await?;
    repo.save().await?;

    Ok(Json(EndSessionResponse { status: "ENDED" }))
}

// ── DELETE /api/v1/oauth2-sessions/:id ─────────────────────────

#[handler]
pub async fn end_oauth2_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Session.extract_ulid(&id)?;

    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let session = repo
        .oauth2_session()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(RouteError::Unauthorized);
    }

    if let Some(user_id) = session.user_id {
        let user = repo.user().lookup(user_id).await?;
        if let Some(user) = user {
            repo.queue_job()
                .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
                .await?;
        }
    }

    repo.oauth2_session().finish(&clock, session).await?;
    repo.save().await?;

    Ok(Json(EndSessionResponse { status: "ENDED" }))
}

// ── DELETE /api/v1/compat-sessions/:id ─────────────────────────

#[handler]
pub async fn end_compat_session(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<EndSessionResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::CompatSession.extract_ulid(&id)?;

    let repo_factory = get_repo_factory(depot)?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let session = repo
        .compat_session()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(Some(session.user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let user = repo.user().lookup(session.user_id).await?;
    if let Some(user) = user {
        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;
    }

    repo.compat_session().finish(&clock, session).await?;
    repo.save().await?;

    Ok(Json(EndSessionResponse { status: "ENDED" }))
}

// ── PUT /api/v1/oauth2-sessions/:id/name ───────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSessionNameInput {
    pub human_name: Option<String>,
}

#[derive(Serialize)]
pub struct SetSessionNameResponse {
    pub status: &'static str,
}

#[handler]
pub async fn set_oauth2_session_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetSessionNameResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Session.extract_ulid(&id)?;

    let input: SetSessionNameInput = req
        .parse_json::<SetSessionNameInput>()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let session = repo
        .oauth2_session()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(session.user_id) {
        return Err(RouteError::Unauthorized);
    }

    let session = repo
        .oauth2_session()
        .set_human_name(session, input.human_name.clone())
        .await?;

    // Update device display name on homeserver for each device in scope
    if let Some(name) = &input.human_name {
        for token in session.scope.iter() {
            if let Some(device_id) = token.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:") {
                let _ = homeserver
                    .update_device_display_name(&session.user_id.map(|_| "").unwrap_or(""), device_id, name)
                    .await;
            }
        }
    }

    repo.save().await?;

    Ok(Json(SetSessionNameResponse { status: "UPDATED" }))
}

// ── PUT /api/v1/compat-sessions/:id/name ───────────────────────

#[handler]
pub async fn set_compat_session_name(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SetSessionNameResponse>, RouteError> {
    let id = req.param::<String>("id").ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::CompatSession.extract_ulid(&id)?;

    let input: SetSessionNameInput = req
        .parse_json::<SetSessionNameInput>()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let repo_factory = get_repo_factory(depot)?;
    let homeserver = get_homeserver(depot)?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let session = repo
        .compat_session()
        .lookup(ulid)
        .await?
        .ok_or(RouteError::NotFound)?;

    if !requester.is_owner_or_admin(Some(session.user_id)) {
        return Err(RouteError::Unauthorized);
    }

    let session = repo
        .compat_session()
        .set_human_name(session, input.human_name.clone())
        .await?;

    // Update device display name on homeserver
    if let (Some(name), Some(device)) = (&input.human_name, &session.device) {
        let user = repo.user().lookup(session.user_id).await?;
        if let Some(user) = user {
            let _ = homeserver
                .update_device_display_name(&user.username, &device.to_string(), name)
                .await;
        }
    }

    repo.save().await?;

    Ok(Json(SetSessionNameResponse { status: "UPDATED" }))
}
