#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    time::Duration,
};

use crate::listener::{ConnectionInfo, unix_or_tcp::UnixOrTcpListener};
use anyhow::Context;
use headers::{CacheControl, HeaderMapExt as _, UserAgent};
use http::{
    Method, StatusCode, Version,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
};
use listenfd::ListenFd;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::trace::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, NETWORK_PROTOCOL_NAME,
    NETWORK_PROTOCOL_VERSION, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use pasion_config::{HttpBindConfig, HttpResource, HttpTlsConfig, UnixOrTcp};
use pasion_templates::Templates;
use rustls::ServerConfig;
use salvo::{
    cors::{Any, Cors},
    prelude::*,
    serve_static::StaticDir,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::app_state::{AppState, inject_app_state};

/// Scan the Dioxus build output directory for the hashed frontend JS entry
/// point. Returns a URL path like `/assets/pasion-frontend-dxh<hash>.js`.
pub fn discover_frontend_script(assets_root: &camino::Utf8Path) -> Option<String> {
    let assets_dir = assets_root.join("assets");
    let dir = std::fs::read_dir(&assets_dir).ok()?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("pasion-frontend-") && name.ends_with(".js") {
            return Some(format!("/assets/{name}"));
        }
    }
    // Fallback: check for non-hashed name
    if assets_dir.join("pasion-frontend.js").exists() {
        return Some("/assets/pasion-frontend.js".into());
    }
    None
}

#[inline]
fn otel_http_method(method: &Method) -> &'static str {
    match method {
        &Method::OPTIONS => "OPTIONS",
        &Method::GET => "GET",
        &Method::POST => "POST",
        &Method::PUT => "PUT",
        &Method::DELETE => "DELETE",
        &Method::HEAD => "HEAD",
        &Method::TRACE => "TRACE",
        &Method::CONNECT => "CONNECT",
        &Method::PATCH => "PATCH",
        _other => "_OTHER",
    }
}

#[inline]
fn otel_net_protocol_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _other => "_OTHER",
    }
}

fn otel_url_scheme(req: &Request) -> &'static str {
    // Check if connection info indicates TLS
    req.extensions()
        .get::<ConnectionInfo>()
        .map_or("http", |conn_info| {
            if conn_info.get_tls_ref().is_some() {
                "https"
            } else {
                "http"
            }
        })
}

/// Middleware for logging responses
#[handler]
pub async fn log_response_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let user_agent: Option<UserAgent> = req.headers().typed_get();
    let user_agent_str = user_agent.as_ref().map_or("-", |u| u.as_str());
    let method = otel_http_method(req.method());
    let path = req.uri().path().to_owned();
    let version = otel_net_protocol_version(req.version());

    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    match status_code.as_u16() {
        100..=399 => tracing::info!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        400..=499 => tracing::warn!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        500..=599 => tracing::error!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?}",
        ),
        _ => { /* This shouldn't happen */ }
    }
}

/// Middleware for OpenTelemetry tracing
#[handler]
pub async fn tracing_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let method = otel_http_method(req.method());
    let path = req.uri().path().to_owned();
    let version = otel_net_protocol_version(req.version());
    let scheme = otel_url_scheme(req);

    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(String::from);

    let query = req.uri().query().map(String::from);

    let span = tracing::info_span!(
        "http.server.request",
        "otel.kind" = "server",
        "otel.name" = format!("{method} {path}"),
        "otel.status_code" = tracing::field::Empty,
        { NETWORK_PROTOCOL_NAME } = "http",
        { NETWORK_PROTOCOL_VERSION } = version,
        { HTTP_REQUEST_METHOD } = method,
        { HTTP_ROUTE } = %path,
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { URL_PATH } = %path,
        { URL_QUERY } = tracing::field::Empty,
        { URL_SCHEME } = scheme,
        { USER_AGENT_ORIGINAL } = tracing::field::Empty,
    );

    if let Some(ref q) = query {
        span.record(URL_QUERY, q.as_str());
    }

    if let Some(ref ua) = user_agent {
        span.record(USER_AGENT_ORIGINAL, ua.as_str());
    }

    // Extract the parent span context from the request headers
    if !span.is_disabled() {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            let extractor = HeaderExtractor(req.headers());
            let context = opentelemetry::Context::new();
            propagator.extract_with_context(&context, &extractor)
        });

        if let Err(err) = span.set_parent(parent_context) {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to set parent context on span"
            );
        }
    }

    let _guard = span.enter();
    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    span.record(HTTP_RESPONSE_STATUS_CODE, status_code.as_u16());
    span.record("otel.status_code", "OK");
}

/// Middleware for Sentry integration
#[handler]
pub async fn sentry_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let path = req.uri().path().to_string();
    let method = otel_http_method(req.method());

    sentry::configure_scope(|scope| {
        scope.set_transaction(Some(&format!("{method} {path}")));
    });

    ctrl.call_next(req, depot, res).await;
}

/// Cache control middleware for static files
#[handler]
pub async fn cache_control_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    let cache_control = if status_code == StatusCode::NOT_FOUND {
        // Cache 404s for 5 minutes
        CacheControl::new()
            .with_public()
            .with_max_age(Duration::from_secs(5 * 60))
    } else {
        // Cache assets for 1 year
        CacheControl::new()
            .with_public()
            .with_max_age(Duration::from_secs(365 * 24 * 60 * 60))
            .with_immutable()
    };
    res.headers_mut().typed_insert(cache_control);
}

/// A Salvo handler that injects [`AppState`] into the depot for every request.
#[derive(Clone)]
struct InjectAppState(AppState);

#[salvo::async_trait]
impl Handler for InjectAppState {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.insert("app_state", self.0.clone());
        ctrl.call_next(req, depot, res).await;
    }
}

fn public_oidc_browser_cors() -> impl Handler {
    Cors::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([ACCEPT, AUTHORIZATION, CONTENT_TYPE])
        .into_handler()
}

#[handler]
async fn oidc_preflight_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub fn build_router(
    state: AppState,
    resources: &[HttpResource],
    prefix: Option<&str>,
    _name: Option<&str>,
) -> Router {
    let templates = state.templates.clone();

    // Create the base router with the AppState in depot
    let mut router = Router::new();

    // Add state injection middleware at the top level
    router = router.hoop(InjectAppState(state));

    // Build sub-routers for each resource
    use crate::handlers::{health, oauth2::discovery, oauth2::webfinger};

    for resource in resources {
        router = match resource {
            pasion_config::HttpResource::Health => {
                router.push(Router::with_path("/health").get(health::get))
            }
            pasion_config::HttpResource::Prometheus => {
                router.push(Router::with_path("/metrics").get(crate::telemetry::prometheus_handler))
            }
            pasion_config::HttpResource::Discovery => router
                .push(
                    Router::with_path("/.well-known/openid-configuration")
                        .hoop(public_oidc_browser_cors())
                        .get(discovery::get),
                )
                .push(
                    Router::with_path("/.well-known/webfinger")
                        .hoop(public_oidc_browser_cors())
                        .get(webfinger::get),
                ),
            pasion_config::HttpResource::Human => build_human_router(router, templates.clone()),
            pasion_config::HttpResource::RestApi {
                playground: _,
                undocumented_oauth2_access: _,
            } => build_rest_api_router(router),
            pasion_config::HttpResource::Assets { path } => router.push(
                Router::with_path("/assets/{**path}")
                    .hoop(cache_control_middleware)
                    .get(
                        StaticDir::new([path.join("assets")])
                            .include_dot_files(false)
                            .auto_list(false),
                    ),
            ),
            pasion_config::HttpResource::OAuth => build_oauth_router(router),
            pasion_config::HttpResource::Compat => {
                // Compat layer removed — pass through
                router
            }
            pasion_config::HttpResource::AdminApi => build_admin_router(router),
            pasion_config::HttpResource::ConnectionInfo => {
                router.push(Router::with_path("/connection-info").get(connection_info_handler))
            }
        }
    }

    // Apply prefix if specified
    let prefix = format!("{}/", prefix.unwrap_or_default().trim_end_matches('/'));
    if !prefix.is_empty() && prefix != "/" {
        let prefixed_router = Router::with_path(&prefix);
        router = prefixed_router.push(router);
    }

    // Add middleware layers
    router
        .hoop(inject_app_state)
        .hoop(log_response_middleware)
        .hoop(tracing_middleware)
        .hoop(sentry_middleware)
}

fn build_human_router(router: Router, _templates: Templates) -> Router {
    use crate::handlers::{oauth2::authorization, spa, upstream_oauth2};

    router
        // ── OAuth2 protocol endpoints (server-side redirects) ──
        .push(Router::with_path("/authorize").get(authorization::get))
        // ── Upstream OAuth2 (server-side redirect & callback) ──
        .push(
            Router::with_path("/upstream/authorize/{provider_id}")
                .get(upstream_oauth2::authorize::get),
        )
        .push(
            Router::with_path("/upstream/callback/{provider_id}")
                .get(upstream_oauth2::callback::handler)
                .post(upstream_oauth2::callback::handler),
        )
        .push(Router::with_path("/upstream/link/{link_id}").get(spa::get))
        .push(
            Router::with_path("/upstream/backchannel-logout/{provider_id}")
                .post(upstream_oauth2::backchannel_logout::post),
        )
        // ── Well-known redirect ──
        .push(
            Router::with_path("/.well-known/change-password").get(change_password_redirect_handler),
        )
        // ── SPA shell ──
        .push(Router::with_path("/").get(spa::get))
        .push(Router::with_path("/login").get(spa::get))
        .push(Router::with_path("/register").get(spa::get))
        .push(Router::with_path("/register/{**rest}").get(spa::get))
        .push(Router::with_path("/recover").get(spa::get))
        .push(Router::with_path("/recover/{**rest}").get(spa::get))
        .push(Router::with_path("/consent/{**rest}").get(spa::get))
        .push(Router::with_path("/link").get(spa::get))
        .push(Router::with_path("/device/{**rest}").get(spa::get))
        .push(Router::with_path("/account").get(account_redirect_handler))
        .push(Router::with_path("/account/").get(spa::get))
        .push(Router::with_path("/account/{*rest}").get(spa::get))
}

fn build_oauth_router(router: Router) -> Router {
    use crate::handlers::oauth2::{
        device, introspection, keys, registration, revoke, token, userinfo,
    };

    let cors = || public_oidc_browser_cors();

    router
        .push(
            Router::with_path("/oauth2/keys.json")
                .hoop(cors())
                .get(keys::get),
        )
        .push(
            Router::with_path("/oauth2/userinfo")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .get(userinfo::get)
                .post(userinfo::get),
        )
        .push(
            Router::with_path("/oauth2/introspect")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(introspection::post),
        )
        .push(
            Router::with_path("/oauth2/revoke")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(revoke::post),
        )
        .push(
            Router::with_path("/oauth2/token")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(token::post),
        )
        .push(
            Router::with_path("/oauth2/registration")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(registration::post),
        )
        .push(
            Router::with_path("/oauth2/device")
                .hoop(cors())
                .options(oidc_preflight_handler)
                .post(device::authorize::post),
        )
}

fn build_rest_api_router(router: Router) -> Router {
    use crate::handlers::rest::*;

    let api_router = Router::with_path("/api/v1")
            // Viewer
            .push(
                Router::with_path("viewer")
                    .get(viewer::get_viewer)
                    .push(Router::with_path("overview").get(viewer::get_viewer_overview))
                    .push(Router::with_path("security").get(viewer::get_security_summary))
                    .push(Router::with_path("password").post(password::set_password))
                    .push(Router::with_path("profile").patch(users::patch_profile))
                    .push(
                        Router::with_path("cross-signing-reset")
                            .post(users::allow_cross_signing_reset),
                    )
                    .push(Router::with_path("deactivate").post(users::deactivate_user))
                    .push(
                        Router::with_path("preferences")
                            .get(notification_prefs::get_notification_preferences)
                            .patch(notification_prefs::patch_notification_preferences),
                    )
                    .push(Router::with_path("workflow-inbox").get(viewer::get_workflow_inbox)),
            )
            // Site config
            .push(Router::with_path("site-config").get(site_config::get))
            // Sessions
            .push(Router::with_path("sessions/{id}").get(sessions::get_session))
            .push(Router::with_path("browser-sessions/{id}").delete(sessions::end_browser_session))
            .push(
                Router::with_path("oauth2-sessions/{id}")
                    .delete(sessions::end_oauth2_session)
                    .push(Router::with_path("name").put(sessions::set_oauth2_session_name)),
            )
            // OAuth2 clients
            .push(Router::with_path("oauth2-clients/{id}").get(oauth2_clients::get_client))
            // Password recovery
            .push(
                Router::with_path("password-recovery")
                    .push(Router::with_path("set").post(password::set_password_by_recovery))
                    .push(Router::with_path("resend").post(password::resend_recovery_email)),
            )
            // Email authentication
            .push(
                Router::with_path("email-auth")
                    .push(Router::with_path("start").post(emails::start_email_auth))
                    .push(
                        Router::with_path("{id}")
                            .get(emails::get_email_auth)
                            .push(Router::with_path("complete").post(emails::complete_email_auth))
                            .push(Router::with_path("resend").post(emails::resend_email_auth_code)),
                    ),
            )
            // User emails
            .push(Router::with_path("user-emails/{id}").delete(emails::remove_email))
            // Auth (login, logout, providers, registration, recovery)
            .push(
                Router::with_path("auth")
                    .push(Router::with_path("login").post(auth::login))
                    .push(Router::with_path("logout").post(auth::logout))
                    .push(Router::with_path("providers").get(auth::providers))
                    // Registration
                    .push(
                        Router::with_path("register")
                            .post(register::post_register)
                            .push(
                                Router::with_path("{id}")
                                    .get(register::get_registration)
                                    .push(
                                        Router::with_path("verify-email")
                                            .post(register::post_verify_email),
                                    )
                                    .push(
                                        Router::with_path("verify-phone")
                                            .post(register::post_verify_phone),
                                    )
                                    .push(
                                        Router::with_path("resend-verification")
                                            .post(register::post_resend_verification),
                                    )
                                    .push(
                                        Router::with_path("display-name")
                                            .post(register::post_display_name),
                                    )
                                    .push(Router::with_path("finish").post(register::post_finish)),
                            ),
                    )
                    // Account recovery
                    .push(
                        Router::with_path("recovery")
                            .push(Router::with_path("start").post(recovery::post_recovery_start))
                            .push(Router::with_path("{id}").get(recovery::get_recovery).push(
                                Router::with_path("resend").post(recovery::post_recovery_resend),
                            )),
                    ),
            )
            // OAuth2 consent
            .push(
                Router::with_path("oauth2/consent/{grant_id}")
                    .get(consent::oauth2_consent_get)
                    .post(consent::oauth2_consent_post),
            )
            // Device code link & consent
            .push(Router::with_path("device-link").get(consent::device_link_get))
            .push(
                Router::with_path("device-consent/{id}")
                    .get(consent::device_consent_get)
                    .post(consent::device_consent_post),
            )
            // Linked accounts
            .push(
                Router::with_path("linked-accounts")
                    .get(linked_accounts::list_linked_accounts)
                    .push(Router::with_path("{id}").delete(linked_accounts::unlink_account)),
            )
            // Upstream OAuth2 link
            .push(
                Router::with_path("upstream-oauth2/link/{id}")
                    .get(upstream_oauth2::get_link)
                    .post(upstream_oauth2::post_link),
            )
            // Flow engine
            .push(
                Router::with_path("flow")
                    .push(Router::with_path("{slug}/start").post(flow::start_flow))
                    .push(
                        Router::with_path("session/{id}")
                            .get(flow::get_flow_session)
                            .push(Router::with_path("respond").post(flow::respond_flow)),
                    ),
            );
    let docs_router = openapi::build_openapi_router(&api_router);

    router.push(api_router).push(docs_router)
}

fn build_admin_router(router: Router) -> Router {
    use crate::handlers::admin;
    use crate::handlers::admin::v1::*;

    router.push(
        Router::with_path("/api/admin/v1")
            // Documentation
            .push(Router::with_path("doc").get(admin::swagger))
            .push(Router::with_path("doc/callback").get(admin::swagger_callback))
            // Version
            .push(Router::with_path("version").get(version::handler))
            // Site config
            .push(Router::with_path("site-config").get(site_config::handler))
            // Operational health
            .push(Router::with_path("connector-health").get(connector_health::handler))
            .push(Router::with_path("notification-channels").get(notification_channels::handler))
            // Notification templates
            .push(
                Router::with_path("notification-templates")
                    .get(notification_templates::list_handler)
                    .push(
                        Router::with_path("publish").post(notification_templates::publish_handler),
                    ),
            )
            // Audit feed
            .push(Router::with_path("audit-feed").get(audit_feed::handler))
            // Users
            .push(
                Router::with_path("users")
                    .get(users::list::handler)
                    .post(users::add::handler)
                    .push(
                        Router::with_path("by-username/{username}")
                            .get(users::by_username::handler),
                    )
                    .push(Router::with_path("batch-invite").post(users::batch_invite::handler))
                    .push(
                        Router::with_path("{id}")
                            .get(users::get::handler)
                            .patch(users::update::handler)
                            .push(
                                Router::with_path("set-password")
                                    .post(users::set_password::handler),
                            )
                            .push(
                                Router::with_path("risk-action").post(users::risk_action::handler),
                            ),
                    ),
            )
            // User emails
            .push(
                Router::with_path("user-emails")
                    .get(user_emails::list::handler)
                    .post(user_emails::add::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(user_emails::get::handler)
                            .patch(user_emails::update::handler)
                            .delete(user_emails::delete::handler),
                    ),
            )
            // User sessions
            .push(
                Router::with_path("user-sessions")
                    .get(user_sessions::list::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(user_sessions::get::handler)
                            .push(Router::with_path("finish").post(user_sessions::finish::handler)),
                    ),
            )
            // OAuth2 sessions
            .push(
                Router::with_path("oauth2-sessions")
                    .get(oauth2_sessions::list::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(oauth2_sessions::get::handler)
                            .push(
                                Router::with_path("finish").post(oauth2_sessions::finish::handler),
                            ),
                    ),
            )
            // Personal sessions
            .push(
                Router::with_path("personal-sessions")
                    .get(personal_sessions::list::handler)
                    .post(personal_sessions::add::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(personal_sessions::get::handler)
                            .push(
                                Router::with_path("regenerate")
                                    .post(personal_sessions::regenerate::handler),
                            )
                            .push(
                                Router::with_path("revoke")
                                    .post(personal_sessions::revoke::handler),
                            ),
                    ),
            )
            // User registration tokens
            .push(
                Router::with_path("user-registration-tokens")
                    .get(user_registration_tokens::list::handler)
                    .post(user_registration_tokens::add::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(user_registration_tokens::get::handler)
                            .put(user_registration_tokens::update::handler)
                            .push(
                                Router::with_path("revoke")
                                    .post(user_registration_tokens::revoke::handler),
                            )
                            .push(
                                Router::with_path("unrevoke")
                                    .post(user_registration_tokens::unrevoke::handler),
                            ),
                    ),
            )
            // Upstream OAuth providers
            .push(
                Router::with_path("upstream-oauth-providers")
                    .get(upstream_oauth_providers::list::handler)
                    .push(Router::with_path("{id}").get(upstream_oauth_providers::get::handler)),
            )
            // Upstream OAuth links
            .push(
                Router::with_path("upstream-oauth-links")
                    .get(upstream_oauth_links::list::handler)
                    .post(upstream_oauth_links::add::handler)
                    .push(
                        Router::with_path("{id}")
                            .get(upstream_oauth_links::get::handler)
                            .patch(upstream_oauth_links::update::handler)
                            .delete(upstream_oauth_links::delete::handler),
                    ),
            )
            // Policy data
            .push(
                Router::with_path("policy-data")
                    .push(Router::with_path("latest").get(policy_data::get_latest::handler))
                    .push(Router::with_path("{id}").get(policy_data::get::handler))
                    .put(policy_data::set::handler),
            ),
    )
}

#[handler]
async fn account_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    if let Some(url_builder) = url_builder {
        Redirect::found(url_builder.relative_url("/account/"))
    } else {
        Redirect::found("/account/")
    }
}

#[handler]
async fn change_password_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    if let Some(url_builder) = url_builder {
        Redirect::found(
            url_builder
                .absolute_url("/account/password/change")
                .to_string(),
        )
    } else {
        Redirect::found("/account/password/change")
    }
}

#[handler]
async fn connection_info_handler(req: &Request) -> String {
    if let Some(conn_info) = req.extensions().get::<ConnectionInfo>() {
        format!("{conn_info:?}")
    } else {
        "No connection info available".to_string()
    }
}

pub fn build_tls_server_config(config: &HttpTlsConfig) -> Result<ServerConfig, anyhow::Error> {
    let (key, chain) = config.load()?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("failed to build TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

fn bind_description(bind: &HttpBindConfig) -> String {
    match bind {
        HttpBindConfig::Listen { host, port } => match host {
            Some(host) => format!("TCP listener {host}:{port}"),
            None => format!("TCP listener [::]:{port} or 0.0.0.0:{port}"),
        },
        HttpBindConfig::Address { address } => format!("TCP listener {address}"),
        HttpBindConfig::Unix { socket } => format!("UNIX socket {socket}"),
        HttpBindConfig::FileDescriptor {
            fd,
            kind: UnixOrTcp::Tcp,
        } => format!("TCP listener on file descriptor {fd}"),
        HttpBindConfig::FileDescriptor {
            fd,
            kind: UnixOrTcp::Unix,
        } => format!("UNIX listener on file descriptor {fd}"),
    }
}

pub fn build_listeners(
    fd_manager: &mut ListenFd,
    configs: &[HttpBindConfig],
) -> Result<Vec<UnixOrTcpListener>, anyhow::Error> {
    let mut listeners = Vec::with_capacity(configs.len());

    for bind in configs {
        let bind_description = bind_description(bind);
        let listener = match bind {
            HttpBindConfig::Listen { host, port } => {
                let addrs = match host.as_deref() {
                    Some(host) => (host, *port)
                        .to_socket_addrs()
                        .with_context(|| {
                            format!("could not parse listener host for {bind_description}")
                        })?
                        .collect(),

                    None => vec![
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), *port),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port),
                    ],
                };

                let listener = TcpListener::bind(&addrs[..])
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            HttpBindConfig::Address { address } => {
                let addr: SocketAddr = address
                    .parse()
                    .with_context(|| format!("could not parse listener address {address}"))?;
                let listener = TcpListener::bind(addr)
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(unix)]
            HttpBindConfig::Unix { socket } => {
                let listener = UnixListener::bind(socket)
                    .with_context(|| format!("could not bind {bind_description}"))?;
                listener.try_into()?
            }

            #[cfg(not(unix))]
            HttpBindConfig::Unix { .. } => {
                anyhow::bail!("UNIX domain sockets are not supported on this platform");
            }

            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Tcp,
            } => {
                let listener = fd_manager
                    .take_tcp_listener(*fd)?
                    .with_context(|| format!("no listener found for {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(unix)]
            HttpBindConfig::FileDescriptor {
                fd,
                kind: UnixOrTcp::Unix,
            } => {
                let listener = fd_manager
                    .take_unix_listener(*fd)?
                    .with_context(|| format!("no listener found for {bind_description}"))?;
                listener.set_nonblocking(true)?;
                listener.try_into()?
            }

            #[cfg(not(unix))]
            HttpBindConfig::FileDescriptor {
                kind: UnixOrTcp::Unix,
                ..
            } => {
                anyhow::bail!(
                    "UNIX domain socket file descriptors are not supported on this platform"
                );
            }
        };

        listeners.push(listener);
    }

    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::build_listeners;
    use pasion_config::HttpBindConfig;

    #[test]
    fn bind_error_mentions_requested_address() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut fd_manager = listenfd::ListenFd::from_env();

        let error = match build_listeners(
            &mut fd_manager,
            &[HttpBindConfig::Address {
                address: format!("127.0.0.1:{port}"),
            }],
        ) {
            Ok(_) => panic!("expected listener bind to fail"),
            Err(error) => error,
        };

        let message = format!("{error:#}");
        assert!(message.contains(&format!("127.0.0.1:{port}")), "{message}");
    }
}
