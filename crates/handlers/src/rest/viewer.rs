use pasion_data_model::SiteConfig;
use pasion_matrix::HomeserverConnection;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;

use super::{
    DepotExt, NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker,
    extract_session_info, get_requester, make_clock, parse_user_agent,
};
use crate::account_connections::load_linked_accounts;

// ── Response types ─────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ViewerResponse {
    viewer: ViewerData,
    viewer_session: ViewerSessionData,
    site_config: SiteConfigData,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
enum ViewerData {
    User(ViewerUser),
    Anonymous(AnonymousData),
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ViewerUser {
    id: String,
    has_password: bool,
    matrix: Option<MatrixUserData>,
    emails: Option<EmailListData>,
    linked_accounts: Option<Vec<LinkedAccountData>>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct LinkedAccountData {
    id: String,
    provider_id: String,
    provider_name: Option<String>,
    provider_brand: Option<String>,
    subject: String,
    human_account_name: Option<String>,
    created_at: String,
}

#[derive(Serialize, ToSchema)]
struct AnonymousData {
    id: String,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "__typename")]
enum ViewerSessionData {
    BrowserSession(BrowserSessionData),
    Anonymous(AnonymousData),
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct BrowserSessionData {
    id: String,
    user: Option<ViewerUser>,
    user_agent: Option<UserAgentInfo>,
    last_active_ip: Option<String>,
    last_active_at: Option<String>,
    created_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct MatrixUserData {
    mxid: String,
    display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct SiteConfigData {
    id: Option<String>,
    email_change_allowed: bool,
    password_login_enabled: bool,
    account_deactivation_allowed: bool,
    display_name_change_allowed: bool,
    password_registration_enabled: bool,
    minimum_password_complexity: u8,
    imprint: Option<String>,
    tos_uri: Option<String>,
    policy_uri: Option<String>,
    plan_management_iframe_uri: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct EmailListData {
    total_count: i64,
    edges: Vec<EmailEdgeData>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct EmailEdgeData {
    cursor: String,
    node: EmailData,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct EmailData {
    id: String,
    email: String,
    confirmed_at: Option<String>,
}

fn site_config_data(config: &SiteConfig) -> SiteConfigData {
    SiteConfigData {
        id: Some("site_config".to_owned()),
        email_change_allowed: config.email_change_allowed,
        password_login_enabled: config.password_login_enabled,
        account_deactivation_allowed: config.account_deactivation_allowed,
        display_name_change_allowed: config.displayname_change_allowed,
        password_registration_enabled: config.password_registration_enabled,
        minimum_password_complexity: config.minimum_password_complexity,
        imprint: config.imprint.clone(),
        tos_uri: config.tos_uri.as_ref().map(|u| u.to_string()),
        policy_uri: config.policy_uri.as_ref().map(|u| u.to_string()),
        plan_management_iframe_uri: config.plan_management_iframe_uri.clone(),
    }
}

// ── GET /api/v1/viewer ─────────────────────────────────────────

/// Returns the current viewer (user or anonymous), viewer session, and site
/// config in a single response.
#[endpoint]
pub async fn get_viewer(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ViewerResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let homeserver = depot.homeserver()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let (viewer, viewer_session) = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => {
            let user = &session.user;

            // Fetch matrix info
            let matrix = match homeserver.query_user(&user.username).await {
                Ok(info) => Some(MatrixUserData {
                    mxid: homeserver.mxid(&user.username),
                    display_name: info.displayname,
                }),
                Err(_) => Some(MatrixUserData {
                    mxid: homeserver.mxid(&user.username),
                    display_name: None,
                }),
            };

            // Fetch emails
            let emails_list = repo.user_email().all(&user).await?;
            let email_edges: Vec<EmailEdgeData> = emails_list
                .into_iter()
                .map(|e| EmailEdgeData {
                    cursor: NodeType::UserEmail.serialize(e.id),
                    node: EmailData {
                        id: NodeType::UserEmail.serialize(e.id),
                        email: e.email,
                        confirmed_at: Some(e.created_at.to_rfc3339()),
                    },
                })
                .collect();
            let total = email_edges.len() as i64;

            // Check password
            let has_password = repo.user_password().active(user).await?.is_some();

            // Fetch linked upstream OAuth accounts
            let linked_accounts: Vec<LinkedAccountData> =
                load_linked_accounts(&mut repo, user, 100)
                    .await?
                    .into_iter()
                    .map(|link| LinkedAccountData {
                        id: link.id.to_string(),
                        provider_id: link.provider_id.to_string(),
                        provider_name: link.provider_name,
                        provider_brand: link.provider_brand,
                        subject: link.subject,
                        human_account_name: link.human_account_name,
                        created_at: link.created_at.to_rfc3339(),
                    })
                    .collect();

            let viewer_user = ViewerUser {
                id: NodeType::User.serialize(user.id),
                has_password,
                matrix,
                emails: Some(EmailListData {
                    total_count: total,
                    edges: email_edges,
                }),
                linked_accounts: Some(linked_accounts),
            };

            let browser_session_data = BrowserSessionData {
                id: NodeType::BrowserSession.serialize(session.id),
                user: None, // avoid duplication, user is in viewer
                user_agent: session.user_agent.as_deref().map(parse_user_agent),
                last_active_ip: session.last_active_ip.map(|ip| ip.to_string()),
                last_active_at: session.last_active_at.map(|t| t.to_rfc3339()),
                created_at: Some(session.created_at.to_rfc3339()),
            };

            (
                ViewerData::User(viewer_user),
                ViewerSessionData::BrowserSession(browser_session_data),
            )
        }
        _ => (
            ViewerData::Anonymous(AnonymousData {
                id: "anonymous".to_owned(),
            }),
            ViewerSessionData::Anonymous(AnonymousData {
                id: "anonymous".to_owned(),
            }),
        ),
    };

    repo.cancel().await?;

    Ok(Json(ViewerResponse {
        viewer,
        viewer_session,
        site_config: site_config_data(&config),
    }))
}
