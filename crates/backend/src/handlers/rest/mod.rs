//! REST API endpoints for the account-management frontend.
//!
//! These endpoints are consumed by the SPA (single-page application) that lets
//! users manage their sessions, emails, passwords, and profile. All responses
//! use JSON and authentication is via browser session cookies or OAuth 2.0
//! bearer tokens.
//!
//! # Sub-modules
//!
//! - [`emails`] — Email verification and management
//! - [`sessions`] — List / terminate browser, OAuth 2.0, and compat sessions
//! - [`viewer`] — Current-user ("viewer") profile information
//! - [`site_config`] — Public site configuration
//! - [`password`] — Password change and recovery
//! - [`users`] — Display name, cross-signing reset, account deactivation
//! - [`oauth2_clients`] — OAuth 2.0 client details
//!
//! # API classification
//!
//! ## User Portal API
//!
//! Endpoints consumed by the account-management dashboard. Authenticated via
//! browser session cookies.
//!
//! ```text
//! GET  /api/v1/viewer                           -> user profile
//! GET  /api/v1/viewer/overview                   -> dashboard overview
//! GET  /api/v1/viewer/security                   -> security summary
//! GET  /api/v1/viewer/workflow-inbox              -> pending workflows
//! GET  /api/v1/viewer/notification-preferences    -> notification prefs
//! POST /api/v1/auth/register                     -> registration
//! POST /api/v1/auth/recovery/start               -> recovery
//! GET  /api/v1/email-auth/*                      -> email verification
//! GET  /api/v1/linked-accounts                   -> identity bindings
//! GET  /api/v1/sessions/*                        -> session management
//! ```
//!
//! ## Workflow API
//!
//! Multi-step challenge/response flows (login, registration, consent).
//!
//! ```text
//! POST /api/v1/flow/:slug/start                  -> start flow
//! GET  /api/v1/flow/session/:id                  -> get challenge
//! POST /api/v1/flow/session/:id/respond           -> submit response
//! ```
//!
//! ## OAuth2 Protocol API
//!
//! Standards-track OAuth 2.0 / OpenID Connect endpoints and supporting
//! resources.
//!
//! ```text
//! GET  /api/v1/oauth2/consent/*                  -> consent
//! GET  /api/v1/device-link                       -> device code
//! GET  /api/v1/site-config                       -> public config
//! ```

#![allow(clippy::module_name_repetitions)]

use std::{net::IpAddr, ops::Deref, sync::Arc};

use crate::handlers::{
    BoundActivityTracker, Limiter, RequesterFingerprint,
    passwords::PasswordManager,
};
use chrono::{DateTime, Utc};
use pasion_data_model::{
    BoxClock, BoxRng, BrowserSession, Clock, Session, SiteConfig, SystemClock, User,
};
use pasion_matrix::HomeserverConnection;
use pasion_policy::PolicyFactory;
use pasion_data_model::UrlBuilder;
use crate::salvo_utils::{SessionInfo, SessionInfoExt, cookies::CookieJar};
use pasion_storage::{BoxRepository, BoxRepositoryFactory, RepositoryError};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub mod auth;
pub mod consent;
pub mod emails;
pub mod flow;
pub mod linked_accounts;
pub mod notification_prefs;
pub mod oauth2_clients;
pub mod openapi;
pub mod password;
pub mod recovery;
pub mod register;
pub mod sessions;
pub mod site_config;
pub mod upstream_oauth2;
pub mod users;
pub mod viewer;

// ── Requester / Auth ───────────────────────────────────────────

/// The authenticated entity making a REST API request, together with
/// connection metadata (IP address, user-agent).
pub struct Requester {
    /// Who is making the request (anonymous, browser session, or OAuth 2.0
    /// session).
    pub entity: RequestingEntity,
    /// Client IP address (after trusted-proxy unwrapping).
    pub ip_address: Option<IpAddr>,
    /// Raw `User-Agent` header value.
    pub user_agent: Option<String>,
}

impl Requester {
    pub fn fingerprint(&self) -> RequesterFingerprint {
        if let Some(ip) = self.ip_address {
            RequesterFingerprint::new(ip)
        } else {
            RequesterFingerprint::EMPTY
        }
    }
}

impl Deref for Requester {
    type Target = RequestingEntity;

    fn deref(&self) -> &Self::Target {
        &self.entity
    }
}

/// Describes who is making a request to the REST API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RequestingEntity {
    /// No authenticated session (public/anonymous access).
    #[default]
    Anonymous,
    /// A logged-in user via a browser session cookie.
    BrowserSession(Box<BrowserSession>),
    /// An OAuth 2.0 client acting on behalf of (optionally) a user.
    OAuth2Session(Box<(Session, Option<User>)>),
}

impl RequestingEntity {
    pub fn browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            _ => None,
        }
    }

    pub fn user(&self) -> Option<&User> {
        match self {
            Self::BrowserSession(session) => Some(&session.user),
            Self::OAuth2Session(tuple) => tuple.1.as_ref(),
            Self::Anonymous => None,
        }
    }

    pub fn oauth2_session(&self) -> Option<&Session> {
        match self {
            Self::OAuth2Session(tuple) => Some(&tuple.0),
            _ => None,
        }
    }

    pub fn is_owner_or_admin(&self, owner_id: Option<Ulid>) -> bool {
        if self.is_admin() {
            return true;
        }
        let Some(owner_id) = owner_id else {
            return false;
        };
        let Some(user) = self.user() else {
            return false;
        };
        user.id == owner_id
    }

    pub fn is_admin(&self) -> bool {
        match self {
            Self::OAuth2Session(tuple) => crate::handlers::admin::has_admin_scope(&tuple.0.scope),
            _ => false,
        }
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

impl From<BrowserSession> for RequestingEntity {
    fn from(session: BrowserSession) -> Self {
        Self::BrowserSession(Box::new(session))
    }
}

impl<T> From<Option<T>> for RequestingEntity
where
    T: Into<RequestingEntity>,
{
    fn from(session: Option<T>) -> Self {
        session.map(Into::into).unwrap_or_default()
    }
}

// ── Error type ─────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Loading of some database objects failed")]
    LoadFailed,

    #[error("Invalid access token")]
    InvalidToken,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl_from_error_for_route!(self::RouteError: RepositoryError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(_) | Self::LoadFailed => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({"error": "internal_error"})));
            }
            Self::InvalidToken => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(serde_json::json!({"error": "invalid_token"})));
            }
            Self::Unauthorized => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(serde_json::json!({"error": "unauthorized"})));
            }
            Self::NotFound => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({"error": "not_found"})));
            }
            Self::BadRequest(msg) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({"error": msg})));
            }
        }
    }
}

impl salvo::oapi::EndpointOutRegister for RouteError {
    fn register(
        _components: &mut salvo::oapi::Components,
        _operation: &mut salvo::oapi::Operation,
    ) {
        // Register common error responses in the OpenAPI spec
        use salvo::oapi::*;

        let error_schema = Object::new()
            .property("error", Object::new().schema_type(BasicType::String))
            .required("error");

        for (status, desc) in [
            ("400", "Bad request"),
            ("401", "Invalid or missing access token"),
            ("403", "Unauthorized"),
            ("404", "Resource not found"),
            ("500", "Internal server error"),
        ] {
            let response = Response::new(desc)
                .add_content("application/json", Content::new(error_schema.clone()));
            _operation
                .responses
                .insert(status, salvo::oapi::RefOr::Type(response));
        }
    }
}

// ── Depot helpers ──────────────────────────────────────────────

/// Extension trait for [`Depot`] that provides typed access to shared state
/// injected by the server setup.
pub trait DepotExt {
    fn repo_factory(&self) -> Result<&BoxRepositoryFactory, RouteError>;
    fn site_config(&self) -> Result<SiteConfig, RouteError>;
    fn homeserver(&self) -> Result<Arc<dyn HomeserverConnection>, RouteError>;
    fn policy_factory(&self) -> Result<Arc<PolicyFactory>, RouteError>;
    fn password_manager(&self) -> Result<PasswordManager, RouteError>;
    fn url_builder(&self) -> Result<UrlBuilder, RouteError>;
    fn limiter(&self) -> Result<Limiter, RouteError>;
    fn templates(&self) -> Result<pasion_templates::Templates, RouteError>;
    fn frontend_script_src(&self) -> Result<String, RouteError>;
    fn translator(&self) -> Result<Arc<pasion_i18n::Translator>, RouteError>;
    fn cookie_manager(&self) -> Result<crate::handlers::CookieManager, RouteError>;
    fn metadata_cache(&self) -> Result<crate::handlers::MetadataCache, RouteError>;
    fn http_client(&self) -> Result<reqwest::Client, RouteError>;
    fn encrypter(&self) -> Result<pasion_keystore::Encrypter, RouteError>;
    fn key_store(&self) -> Result<pasion_keystore::Keystore, RouteError>;
    fn app_version(&self) -> Result<pasion_data_model::AppVersion, RouteError>;
    fn cookie_jar(&self, req: &Request) -> Result<CookieJar, RouteError>;
}

fn depot_get<T: Send + Sync + Clone + 'static>(depot: &Depot, key: &str) -> Result<T, RouteError> {
    depot.get::<T>(key).cloned().map_err(|_| {
        RouteError::Internal(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{key} not found in depot"),
        )))
    })
}

impl DepotExt for Depot {
    fn repo_factory(&self) -> Result<&BoxRepositoryFactory, RouteError> {
        self.get::<BoxRepositoryFactory>("box_repository_factory")
            .map_err(|_| {
                RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "box_repository_factory not found in depot",
                )))
            })
    }

    fn site_config(&self) -> Result<SiteConfig, RouteError> {
        depot_get(self, "site_config")
    }

    fn homeserver(&self) -> Result<Arc<dyn HomeserverConnection>, RouteError> {
        depot_get(self, "homeserver_connection")
    }

    fn policy_factory(&self) -> Result<Arc<PolicyFactory>, RouteError> {
        depot_get(self, "policy_factory")
    }

    fn password_manager(&self) -> Result<PasswordManager, RouteError> {
        depot_get(self, "password_manager")
    }

    fn url_builder(&self) -> Result<UrlBuilder, RouteError> {
        depot_get(self, "url_builder")
    }

    fn limiter(&self) -> Result<Limiter, RouteError> {
        depot_get(self, "limiter")
    }

    fn templates(&self) -> Result<pasion_templates::Templates, RouteError> {
        depot_get(self, "templates")
    }

    fn frontend_script_src(&self) -> Result<String, RouteError> {
        depot_get(self, "frontend_script_src")
    }

    fn translator(&self) -> Result<Arc<pasion_i18n::Translator>, RouteError> {
        depot_get(self, "translator")
    }

    fn cookie_manager(&self) -> Result<crate::handlers::CookieManager, RouteError> {
        depot_get(self, "cookie_manager")
    }

    fn metadata_cache(&self) -> Result<crate::handlers::MetadataCache, RouteError> {
        depot_get(self, "metadata_cache")
    }

    fn http_client(&self) -> Result<reqwest::Client, RouteError> {
        depot_get(self, "http_client")
    }

    fn encrypter(&self) -> Result<pasion_keystore::Encrypter, RouteError> {
        depot_get(self, "encrypter")
    }

    fn key_store(&self) -> Result<pasion_keystore::Keystore, RouteError> {
        depot_get(self, "keystore")
    }

    fn app_version(&self) -> Result<pasion_data_model::AppVersion, RouteError> {
        depot_get(self, "app_version")
    }

    fn cookie_jar(&self, req: &Request) -> Result<CookieJar, RouteError> {
        let cm = self.cookie_manager()?;
        Ok(cm.cookie_jar_from_headers(req.headers()))
    }
}

pub fn make_clock() -> BoxClock {
    Box::new(SystemClock::default())
}

pub fn make_rng() -> BoxRng {
    #[allow(clippy::disallowed_methods)]
    let rng = thread_rng();
    let rng = ChaChaRng::from_rng(rng).expect("Failed to seed rng");
    Box::new(rng)
}

// ── Helper: extract requester from session cookie ──────────────

pub async fn get_requester(
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    mut repo: BoxRepository,
    session_info: &SessionInfo,
) -> Result<(Requester, BoxRepository), RouteError> {
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session.as_ref() {
        activity_tracker
            .record_browser_session(clock, session)
            .await;
    }

    let entity = RequestingEntity::from(maybe_session);

    let requester = Requester {
        entity,
        ip_address: activity_tracker.ip(),
        user_agent: None,
    };

    Ok((requester, repo))
}

// ── Helper: verify password if needed ──────────────────────────

pub async fn verify_password_if_needed(
    requester: &Requester,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    user: &User,
    repo: &mut BoxRepository,
) -> Result<bool, RouteError> {
    crate::handlers::account_password::verify_password_if_needed(
        requester.is_admin(),
        config.password_login_enabled,
        password_manager,
        password,
        user,
        repo,
    )
    .await
    .map_err(|error| RouteError::Internal(Box::new(error)))
}

// ── Node ID helpers ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Authentication,
    BrowserSession,
    OAuth2Client,
    OAuth2Session,
    UpstreamOAuth2Provider,
    UpstreamOAuth2Link,
    User,
    UserEmail,
    UserEmailAuthentication,
    UserRecoveryTicket,
}

impl NodeType {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::BrowserSession => "browser_session",
            Self::OAuth2Client => "oauth2_client",
            Self::OAuth2Session => "oauth2_session",
            Self::UpstreamOAuth2Provider => "upstream_oauth2_provider",
            Self::UpstreamOAuth2Link => "upstream_oauth2_link",
            Self::User => "user",
            Self::UserEmail => "user_email",
            Self::UserEmailAuthentication => "user_email_authentication",
            Self::UserRecoveryTicket => "user_recovery_ticket",
        }
    }

    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "authentication" => Some(Self::Authentication),
            "browser_session" => Some(Self::BrowserSession),
            "oauth2_client" => Some(Self::OAuth2Client),
            "oauth2_session" => Some(Self::OAuth2Session),
            "upstream_oauth2_provider" => Some(Self::UpstreamOAuth2Provider),
            "upstream_oauth2_link" => Some(Self::UpstreamOAuth2Link),
            "user" => Some(Self::User),
            "user_email" => Some(Self::UserEmail),
            "user_email_authentication" => Some(Self::UserEmailAuthentication),
            "user_recovery_ticket" => Some(Self::UserRecoveryTicket),
            _ => None,
        }
    }

    pub fn serialize(self, id: Ulid) -> String {
        format!("{}:{}", self.prefix(), id)
    }

    pub fn deserialize(s: &str) -> Result<(Self, Ulid), RouteError> {
        let (prefix, id) = s
            .split_once(':')
            .ok_or_else(|| RouteError::BadRequest("invalid id format".into()))?;
        let node_type = Self::from_prefix(prefix)
            .ok_or_else(|| RouteError::BadRequest("unknown id prefix".into()))?;
        let ulid: Ulid = id
            .parse()
            .map_err(|_| RouteError::BadRequest("invalid ulid".into()))?;
        Ok((node_type, ulid))
    }

    pub fn extract_ulid(self, id: &str) -> Result<Ulid, RouteError> {
        let (node_type, ulid) = Self::deserialize(id)?;
        if node_type == self {
            Ok(ulid)
        } else {
            Err(RouteError::BadRequest(format!(
                "expected {} id, got {}",
                self.prefix(),
                node_type.prefix()
            )))
        }
    }
}

// ── User-agent parsing helper ──────────────────────────────────

#[derive(Serialize, Clone, salvo::oapi::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserAgentInfo {
    pub name: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub device_type: &'static str,
}

pub fn parse_user_agent(ua: &str) -> UserAgentInfo {
    let parsed = woothee::parser::Parser::new().parse(ua);
    let (name, os, category) = match parsed {
        Some(result) => (
            if result.name != "UNKNOWN" {
                Some(result.name.to_owned())
            } else {
                None
            },
            if result.os != "UNKNOWN" {
                Some(result.os.to_owned())
            } else {
                None
            },
            result.category,
        ),
        None => (None, None, "UNKNOWN"),
    };

    let device_type = match category {
        "pc" => "PC",
        "smartphone" | "mobilephone" => "MOBILE",
        _ => "UNKNOWN",
    };

    UserAgentInfo {
        name,
        model: None,
        os,
        device_type,
    }
}

// ── Pagination helpers ─────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams {
    pub first: Option<i64>,
    pub after: Option<String>,
    pub last: Option<i64>,
    pub before: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub has_next_page: bool,
    pub has_previous_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[derive(Serialize)]
pub struct Edge<T: Serialize> {
    pub cursor: String,
    pub node: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection<T: Serialize> {
    pub total_count: i64,
    pub edges: Vec<Edge<T>>,
    pub page_info: PageInfo,
}

// ── Date filter ────────────────────────────────────────────────

#[derive(Deserialize, Default, Clone, Copy)]
pub struct DateFilter {
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
}

// ── Activity tracker extraction ────────────────────────────────

pub fn extract_bound_activity_tracker(req: &Request, depot: &Depot) -> BoundActivityTracker {
    let activity_tracker = depot
        .get::<crate::handlers::ActivityTracker>("activity_tracker")
        .expect("ActivityTracker not found in depot")
        .clone();

    let trusted_proxies = depot
        .get::<Vec<ipnetwork::IpNetwork>>("trusted_proxies")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let ip = infer_client_ip(req, trusted_proxies);
    activity_tracker.bind(ip)
}

fn infer_client_ip(req: &Request, trusted_proxies: &[ipnetwork::IpNetwork]) -> Option<IpAddr> {
    // Get IPs from the X-Forwarded-For header
    let peers_from_header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.trim().parse().ok()))
        .into_iter()
        .flatten();

    let peer_list: Vec<IpAddr> = peers_from_header
        .map(|ip: IpAddr| ip.to_canonical())
        .collect();

    let fallback = peer_list.first().copied();

    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}

// ── Cookie jar extraction helper ───────────────────────────────

pub fn extract_session_info(req: &Request, depot: &Depot) -> SessionInfo {
    let Ok(cookie_jar) = CookieJar::extract_from_request(req, depot) else {
        return SessionInfo::default();
    };
    let (session_info, _) = cookie_jar.session_info();
    session_info
}
