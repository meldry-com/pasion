use pasion_data_model::SiteConfig;
use pasion_storage::RepositoryAccess;
use pasion_storage::account::AccountSecuritySummary;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;

use super::{
    DepotExt, NodeType, RouteError, UserAgentInfo, extract_bound_activity_tracker,
    extract_session_info, get_requester, make_clock, parse_user_agent,
};
use crate::account_connections::load_linked_accounts;
use crate::account_profile::{AccountProfileError, load_viewer_profile};

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

            // Load viewer profile from service
            let profile = load_viewer_profile(&mut repo, homeserver.as_ref(), user)
                .await
                .map_err(map_account_profile_error)?;

            let matrix = Some(MatrixUserData {
                mxid: profile.mxid,
                display_name: profile.matrix_display_name,
            });

            let email_edges: Vec<EmailEdgeData> = profile
                .emails
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

            let has_password = profile.has_password;

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

fn map_account_profile_error(error: AccountProfileError) -> RouteError {
    match error {
        AccountProfileError::NotFound => RouteError::NotFound,
        AccountProfileError::Unauthorized | AccountProfileError::BrowserSessionRequired => {
            RouteError::Unauthorized
        }
        AccountProfileError::DeactivationDisabled => {
            RouteError::BadRequest("Account deactivation is not allowed".into())
        }
        AccountProfileError::Password(error) | AccountProfileError::Homeserver(error) => {
            RouteError::Internal(error.into())
        }
        AccountProfileError::Repository(error) => RouteError::from(error),
    }
}

// ── Response type for security summary ────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct SecuritySummaryResponse {
    has_password: bool,
    active_sessions_count: usize,
    linked_providers_count: usize,
    verified_emails_count: usize,
    verified_phones_count: usize,
}

// ── GET /api/v1/viewer/security ───────────────────────────────

/// Returns a lightweight security summary for the current user, including
/// password status, active session count, linked provider count, and
/// verified email/phone counts.
#[endpoint]
pub async fn get_security_summary(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SecuritySummaryResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => return Err(RouteError::Unauthorized),
    };

    let summary = repo.account().security_summary(user.id).await?;

    repo.cancel().await?;

    Ok(Json(SecuritySummaryResponse {
        has_password: summary.has_password,
        active_sessions_count: summary.active_sessions_count,
        linked_providers_count: summary.linked_providers_count,
        verified_emails_count: summary.verified_emails_count,
        verified_phones_count: summary.verified_phones_count,
    }))
}

// ── Response types for workflow inbox ────────────────────────

/// A single pending workflow item in the inbox.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInboxItem {
    pub session_id: String,
    pub flow_slug: String,
    pub flow_title: String,
    pub current_stage: String,
    pub started_at: String,
}

/// Response for `GET /api/v1/viewer/workflow-inbox`.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInboxResponse {
    pub pending: Vec<WorkflowInboxItem>,
    pub total: usize,
}

// ── GET /api/v1/viewer/workflow-inbox ────────────────────────

/// Returns the list of pending flow sessions for the current user.
///
/// Flow sessions are currently in-memory and do not have a user-id
/// association, so this endpoint always returns an empty list. Once
/// persistent flow sessions with user ownership are implemented, this
/// will return actual pending items.
#[endpoint]
pub async fn get_workflow_inbox(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<WorkflowInboxResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    // Require an authenticated user.
    match &requester.entity {
        super::RequestingEntity::BrowserSession(_) => {}
        _ => return Err(RouteError::Unauthorized),
    };

    repo.cancel().await?;

    // Placeholder: flow sessions are in-memory and not user-associated yet.
    let pending: Vec<WorkflowInboxItem> = Vec::new();
    let total = pending.len();

    Ok(Json(WorkflowInboxResponse { pending, total }))
}

// ── Response types for viewer overview ─────────────────────

/// Summary of the user for the overview dashboard.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ViewerUserSummary {
    pub id: String,
    pub has_password: bool,
}

/// Security summary data exposed in the overview.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummaryData {
    pub has_password: bool,
    pub active_sessions_count: usize,
    pub linked_providers_count: usize,
    pub verified_emails_count: usize,
    pub verified_phones_count: usize,
}

/// Summary of contact points for the overview.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactsSummary {
    pub total: usize,
    pub verified: usize,
}

/// Summary of identity bindings for the overview.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentitiesSummary {
    pub total: usize,
}

/// Summary of pending workflows for the overview.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowsSummary {
    pub pending_count: usize,
}

/// Unified overview response combining security, contacts, identities, and
/// workflow summaries into a single payload for the account dashboard.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ViewerOverviewResponse {
    pub user: ViewerUserSummary,
    pub security: SecuritySummaryData,
    pub contacts: ContactsSummary,
    pub identities: IdentitiesSummary,
    pub workflows: WorkflowsSummary,
}

impl From<&AccountSecuritySummary> for SecuritySummaryData {
    fn from(s: &AccountSecuritySummary) -> Self {
        Self {
            has_password: s.has_password,
            active_sessions_count: s.active_sessions_count,
            linked_providers_count: s.linked_providers_count,
            verified_emails_count: s.verified_emails_count,
            verified_phones_count: s.verified_phones_count,
        }
    }
}

// ── GET /api/v1/viewer/overview ────────────────────────────

/// Returns a unified account overview for the dashboard, combining the
/// security summary, contact-point counts, identity-binding counts, and
/// pending workflow counts into a single response.
#[endpoint]
pub async fn get_viewer_overview(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ViewerOverviewResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = match &requester.entity {
        super::RequestingEntity::BrowserSession(session) => &session.user,
        _ => return Err(RouteError::Unauthorized),
    };

    let user_id = user.id;

    // Fetch all three aggregates from the account repository.
    let security = repo.account().security_summary(user_id).await?;
    let contacts = repo.account().list_contact_points(user_id).await?;
    let identities = repo.account().list_identity_bindings(user_id).await?;

    repo.cancel().await?;

    let verified_contacts = contacts.iter().filter(|c| c.verified).count();

    // Workflow sessions are in-memory and not user-associated yet, so
    // pending count is always zero for now.
    let pending_workflow_count: usize = 0;

    Ok(Json(ViewerOverviewResponse {
        user: ViewerUserSummary {
            id: NodeType::User.serialize(user_id),
            has_password: security.has_password,
        },
        security: SecuritySummaryData::from(&security),
        contacts: ContactsSummary {
            total: contacts.len(),
            verified: verified_contacts,
        },
        identities: IdentitiesSummary {
            total: identities.len(),
        },
        workflows: WorkflowsSummary {
            pending_count: pending_workflow_count,
        },
    }))
}
