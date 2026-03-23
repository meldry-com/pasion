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

#![allow(clippy::module_name_repetitions)]

use std::{net::IpAddr, ops::Deref, sync::Arc};

use chrono::{DateTime, Utc};
use pasion_data_model::{
    BoxClock, BoxRng, BrowserSession, Clock, Session, SiteConfig, SystemClock, User,
};
use pasion_matrix::HomeserverConnection;
use pasion_policy::PolicyFactory;
use pasion_router::UrlBuilder;
use pasion_salvo_utils::{SessionInfo, SessionInfoExt, cookies::CookieJar};
use pasion_storage::{BoxRepository, BoxRepositoryFactory, RepositoryError};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    BoundActivityTracker, Limiter, RequesterFingerprint, impl_from_error_for_route,
    passwords::PasswordManager,
};

pub mod emails;
pub mod oauth2_clients;
pub mod password;
pub mod sessions;
pub mod site_config;
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
            Self::OAuth2Session(tuple) => tuple.0.scope.contains("urn:mas:admin"),
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

// ── Depot helpers ──────────────────────────────────────────────

fn depot_get<T: Send + Sync + Clone + 'static>(depot: &Depot, key: &str) -> Result<T, RouteError> {
    depot.get::<T>(key).cloned().map_err(|_| {
        RouteError::Internal(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{key} not found in depot"),
        )))
    })
}

pub fn get_repo_factory(depot: &Depot) -> Result<&BoxRepositoryFactory, RouteError> {
    depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .map_err(|_| {
            RouteError::Internal(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "box_repository_factory not found in depot",
            )))
        })
}

pub fn get_site_config(depot: &Depot) -> Result<SiteConfig, RouteError> {
    depot_get(depot, "site_config")
}

pub fn get_homeserver(depot: &Depot) -> Result<Arc<dyn HomeserverConnection>, RouteError> {
    depot_get(depot, "homeserver_connection")
}

pub fn get_policy_factory(depot: &Depot) -> Result<Arc<PolicyFactory>, RouteError> {
    depot_get(depot, "policy_factory")
}

pub fn get_password_manager(depot: &Depot) -> Result<PasswordManager, RouteError> {
    depot_get(depot, "password_manager")
}

pub fn get_url_builder(depot: &Depot) -> Result<UrlBuilder, RouteError> {
    depot_get(depot, "url_builder")
}

pub fn get_limiter(depot: &Depot) -> Result<Limiter, RouteError> {
    depot_get(depot, "limiter")
}

pub fn get_templates(depot: &Depot) -> Result<pasion_templates::Templates, RouteError> {
    depot_get(depot, "templates")
}

pub fn get_translator(depot: &Depot) -> Result<Arc<pasion_i18n::Translator>, RouteError> {
    depot_get(depot, "translator")
}

pub fn get_cookie_manager(depot: &Depot) -> Result<crate::CookieManager, RouteError> {
    depot_get(depot, "cookie_manager")
}

pub fn get_metadata_cache(depot: &Depot) -> Result<crate::MetadataCache, RouteError> {
    depot_get(depot, "metadata_cache")
}

pub fn get_http_client(depot: &Depot) -> Result<reqwest::Client, RouteError> {
    depot_get(depot, "http_client")
}

pub fn get_encrypter(depot: &Depot) -> Result<pasion_keystore::Encrypter, RouteError> {
    depot_get(depot, "encrypter")
}

pub fn get_key_store(depot: &Depot) -> Result<pasion_keystore::Keystore, RouteError> {
    depot_get(depot, "key_store")
}

pub fn get_app_version(depot: &Depot) -> Result<pasion_data_model::AppVersion, RouteError> {
    depot_get(depot, "app_version")
}

pub fn extract_cookie_jar(req: &Request, depot: &Depot) -> Result<CookieJar, RouteError> {
    let cookie_manager = get_cookie_manager(depot)?;
    Ok(cookie_manager.cookie_jar_from_headers(req.headers()))
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
    if requester.is_admin() {
        return Ok(true);
    }

    if !config.password_login_enabled {
        return Ok(true);
    }

    let user_password = repo
        .user_password()
        .active(user)
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    let Some(user_password) = user_password else {
        return Ok(true);
    };

    let Some(password) = password else {
        return Ok(false);
    };

    let password = Zeroizing::new(password);

    let res = password_manager
        .verify(
            user_password.version,
            password,
            user_password.hashed_password,
        )
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    Ok(res.is_success())
}

// ── Node ID helpers ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Authentication,
    BrowserSession,
    CompatSession,
    CompatSsoLogin,
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
            Self::CompatSession => "compat_session",
            Self::CompatSsoLogin => "compat_sso_login",
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
            "compat_session" => Some(Self::CompatSession),
            "compat_sso_login" => Some(Self::CompatSsoLogin),
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

#[derive(Serialize, Clone)]
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
        .get::<crate::ActivityTracker>("activity_tracker")
        .cloned()
        .unwrap_or_else(|| crate::ActivityTracker::new(100));

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

pub fn extract_session_info(depot: &Depot) -> SessionInfo {
    let cookie_jar = depot
        .get::<CookieJar>("cookie_jar")
        .cloned()
        .unwrap_or_default();
    let (session_info, _) = cookie_jar.session_info();
    session_info
}
