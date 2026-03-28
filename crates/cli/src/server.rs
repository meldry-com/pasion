#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    time::Duration,
};

use anyhow::Context;
use headers::{CacheControl, HeaderMapExt as _, UserAgent};
use http::{Method, StatusCode, Version, header::USER_AGENT};
use listenfd::ListenFd;
use opentelemetry_http::HeaderExtractor;
use opentelemetry_semantic_conventions::trace::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE, NETWORK_PROTOCOL_NAME,
    NETWORK_PROTOCOL_VERSION, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};
use pasion_config::{HttpBindConfig, HttpResource, HttpTlsConfig, UnixOrTcp};
use pasion_context::LogContext;
use pasion_listener::{ConnectionInfo, unix_or_tcp::UnixOrTcpListener};
use pasion_router::Route;
use pasion_templates::Templates;
use rustls::ServerConfig;
use salvo::{prelude::*, serve_static::StaticDir};
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

    let Some(stats) = LogContext::maybe_with(LogContext::stats) else {
        tracing::error!("Missing log context for request, this is a bug!");
        return;
    };

    let status_code = res.status_code.unwrap_or(StatusCode::OK);
    match status_code.as_u16() {
        100..=399 => tracing::info!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?} [{stats}]",
        ),
        400..=499 => tracing::warn!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?} [{stats}]",
        ),
        500..=599 => tracing::error!(
            name: "http.server.response",
            "\"{method} {path} HTTP/{version}\" {status_code} {user_agent_str:?} [{stats}]",
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

/// Middleware for LogContext
#[handler]
pub async fn log_context_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let method = otel_http_method(req.method());
    let ctx = LogContext::new(method);
    pasion_context::CURRENT_LOG_CONTEXT
        .scope(ctx, ctrl.call_next(req, depot, res))
        .await;
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
    for resource in resources {
        router = match resource {
            pasion_config::HttpResource::Health => router.push(
                Router::with_path(pasion_router::Healthcheck::route())
                    .get(pasion_handlers::health::get),
            ),
            pasion_config::HttpResource::Prometheus => {
                router.push(Router::with_path("/metrics").get(crate::telemetry::prometheus_handler))
            }
            pasion_config::HttpResource::Discovery => router
                .push(
                    Router::with_path(pasion_router::OidcConfiguration::route())
                        .get(pasion_handlers::oauth2::discovery::get),
                )
                .push(
                    Router::with_path(pasion_router::Webfinger::route())
                        .get(pasion_handlers::oauth2::webfinger::get),
                ),
            pasion_config::HttpResource::Human => build_human_router(router, templates.clone()),
            pasion_config::HttpResource::RestApi {
                playground: _,
                undocumented_oauth2_access: _,
            } => build_rest_api_router(router),
            pasion_config::HttpResource::Assets { path } => router
                .push(
                    Router::with_path(&format!(
                        "{}/{{**path}}",
                        pasion_router::StaticAsset::route()
                    ))
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
        .hoop(log_context_middleware)
        .hoop(sentry_middleware)
}

fn build_human_router(router: Router, _templates: Templates) -> Router {
    router
        // ── OAuth2 protocol endpoints (server-side redirects, MUST stay) ──
        .push(
            Router::with_path(pasion_router::OAuth2AuthorizationEndpoint::route())
                .get(pasion_handlers::oauth2::authorization::get),
        )
        // ── Upstream OAuth2 (server-side redirect & callback) ──
        .push(
            Router::with_path(pasion_router::UpstreamOAuth2Authorize::route())
                .get(pasion_handlers::upstream_oauth2::authorize::get),
        )
        .push(
            Router::with_path(pasion_router::UpstreamOAuth2Callback::route())
                .get(pasion_handlers::upstream_oauth2::callback::handler)
                .post(pasion_handlers::upstream_oauth2::callback::handler),
        )
        // Upstream link page is now served by the SPA frontend
        .push(
            Router::with_path(pasion_router::UpstreamOAuth2Link::route())
                .get(pasion_handlers::spa::get),
        )
        .push(
            Router::with_path(pasion_router::UpstreamOAuth2BackchannelLogout::route())
                .post(pasion_handlers::upstream_oauth2::backchannel_logout::post),
        )
        // ── Well-known redirect ──
        .push(
            Router::with_path(pasion_router::ChangePasswordDiscovery::route())
                .get(change_password_redirect_handler),
        )
        // ── SPA shell: all user-facing pages are rendered by the Dioxus frontend ──
        // In production these serve the SPA HTML shell; the client-side router
        // handles the actual page rendering.
        .push(Router::with_path(pasion_router::Index::route()).get(pasion_handlers::spa::get))
        .push(Router::with_path("/login").get(pasion_handlers::spa::get))
        .push(Router::with_path("/register").get(pasion_handlers::spa::get))
        .push(Router::with_path("/register/{**rest}").get(pasion_handlers::spa::get))
        .push(Router::with_path("/recover").get(pasion_handlers::spa::get))
        .push(Router::with_path("/recover/{**rest}").get(pasion_handlers::spa::get))
        .push(Router::with_path("/consent/{**rest}").get(pasion_handlers::spa::get))
        .push(Router::with_path("/link").get(pasion_handlers::spa::get))
        .push(Router::with_path("/device/{**rest}").get(pasion_handlers::spa::get))
        .push(Router::with_path("/account").get(account_redirect_handler))
        .push(Router::with_path(pasion_router::Account::route()).get(pasion_handlers::spa::get))
        .push(
            Router::with_path(pasion_router::AccountWildcard::route())
                .get(pasion_handlers::spa::get),
        )
}

fn build_oauth_router(router: Router) -> Router {
    router
        .push(
            Router::with_path(pasion_router::OAuth2Keys::route())
                .get(pasion_handlers::oauth2::keys::get),
        )
        .push(
            Router::with_path(pasion_router::OidcUserinfo::route())
                .get(pasion_handlers::oauth2::userinfo::get)
                .post(pasion_handlers::oauth2::userinfo::get),
        )
        .push(
            Router::with_path(pasion_router::OAuth2Introspection::route())
                .post(pasion_handlers::oauth2::introspection::post),
        )
        .push(
            Router::with_path(pasion_router::OAuth2Revocation::route())
                .post(pasion_handlers::oauth2::revoke::post),
        )
        .push(
            Router::with_path(pasion_router::OAuth2TokenEndpoint::route())
                .post(pasion_handlers::oauth2::token::post),
        )
        .push(
            Router::with_path(pasion_router::OAuth2RegistrationEndpoint::route())
                .post(pasion_handlers::oauth2::registration::post),
        )
        .push(
            Router::with_path(pasion_router::OAuth2DeviceAuthorizationEndpoint::route())
                .post(pasion_handlers::oauth2::device::authorize::post),
        )
}

fn build_rest_api_router(router: Router) -> Router {
    router
        // Viewer (combined viewer + session + site config)
        .push(Router::with_path("/api/v1/viewer").get(pasion_handlers::rest::viewer::get_viewer))
        // Site config
        .push(Router::with_path("/api/v1/site-config").get(pasion_handlers::rest::site_config::get))
        // Sessions
        .push(
            Router::with_path("/api/v1/sessions/{id}")
                .get(pasion_handlers::rest::sessions::get_session),
        )
        .push(
            Router::with_path("/api/v1/browser-sessions/{id}")
                .delete(pasion_handlers::rest::sessions::end_browser_session),
        )
        .push(
            Router::with_path("/api/v1/oauth2-sessions/{id}")
                .delete(pasion_handlers::rest::sessions::end_oauth2_session),
        )
        .push(
            Router::with_path("/api/v1/oauth2-sessions/{id}/name")
                .put(pasion_handlers::rest::sessions::set_oauth2_session_name),
        )
        // OAuth2 clients
        .push(
            Router::with_path("/api/v1/oauth2-clients/{id}")
                .get(pasion_handlers::rest::oauth2_clients::get_client),
        )
        // Password
        .push(
            Router::with_path("/api/v1/viewer/password")
                .post(pasion_handlers::rest::password::set_password),
        )
        .push(
            Router::with_path("/api/v1/password-recovery/set")
                .post(pasion_handlers::rest::password::set_password_by_recovery),
        )
        .push(
            Router::with_path("/api/v1/password-recovery/resend")
                .post(pasion_handlers::rest::password::resend_recovery_email),
        )
        // Users (display name, cross-signing, deactivation)
        .push(
            Router::with_path("/api/v1/viewer/display-name")
                .post(pasion_handlers::rest::users::set_display_name),
        )
        .push(
            Router::with_path("/api/v1/viewer/cross-signing-reset")
                .post(pasion_handlers::rest::users::allow_cross_signing_reset),
        )
        .push(
            Router::with_path("/api/v1/viewer/deactivate")
                .post(pasion_handlers::rest::users::deactivate_user),
        )
        // Email authentication
        .push(
            Router::with_path("/api/v1/email-auth/start")
                .post(pasion_handlers::rest::emails::start_email_auth),
        )
        .push(
            Router::with_path("/api/v1/email-auth/{id}")
                .get(pasion_handlers::rest::emails::get_email_auth),
        )
        .push(
            Router::with_path("/api/v1/email-auth/{id}/complete")
                .post(pasion_handlers::rest::emails::complete_email_auth),
        )
        .push(
            Router::with_path("/api/v1/email-auth/{id}/resend")
                .post(pasion_handlers::rest::emails::resend_email_auth_code),
        )
        // User emails
        .push(
            Router::with_path("/api/v1/user-emails/{id}")
                .delete(pasion_handlers::rest::emails::remove_email),
        )
        // Registration
        .push(
            Router::with_path("/api/v1/auth/register")
                .post(pasion_handlers::rest::register::post_register),
        )
        .push(
            Router::with_path("/api/v1/auth/register/{id}")
                .get(pasion_handlers::rest::register::get_registration),
        )
        .push(
            Router::with_path("/api/v1/auth/register/{id}/verify-email")
                .post(pasion_handlers::rest::register::post_verify_email),
        )
        .push(
            Router::with_path("/api/v1/auth/register/{id}/verify-phone")
                .post(pasion_handlers::rest::register::post_verify_phone),
        )
        .push(
            Router::with_path("/api/v1/auth/register/{id}/display-name")
                .post(pasion_handlers::rest::register::post_display_name),
        )
        .push(
            Router::with_path("/api/v1/auth/register/{id}/finish")
                .post(pasion_handlers::rest::register::post_finish),
        )
        // Account recovery
        .push(
            Router::with_path("/api/v1/auth/recovery/start")
                .post(pasion_handlers::rest::recovery::post_recovery_start),
        )
        .push(
            Router::with_path("/api/v1/auth/recovery/{id}")
                .get(pasion_handlers::rest::recovery::get_recovery),
        )
        .push(
            Router::with_path("/api/v1/auth/recovery/{id}/resend")
                .post(pasion_handlers::rest::recovery::post_recovery_resend),
        )
        // Auth (login, logout, providers)
        .push(Router::with_path("/api/v1/auth/login").post(pasion_handlers::rest::auth::login))
        .push(Router::with_path("/api/v1/auth/logout").post(pasion_handlers::rest::auth::logout))
        .push(
            Router::with_path("/api/v1/auth/providers").get(pasion_handlers::rest::auth::providers),
        )
        // OAuth2 consent (SPA)
        .push(
            Router::with_path("/api/v1/oauth2/consent/{grant_id}")
                .get(pasion_handlers::rest::consent::oauth2_consent_get)
                .post(pasion_handlers::rest::consent::oauth2_consent_post),
        )
        // Device code link & consent (SPA)
        .push(
            Router::with_path("/api/v1/device-link")
                .get(pasion_handlers::rest::consent::device_link_get),
        )
        .push(
            Router::with_path("/api/v1/device-consent/{id}")
                .get(pasion_handlers::rest::consent::device_consent_get)
                .post(pasion_handlers::rest::consent::device_consent_post),
        )
        // Linked accounts (view/unlink upstream OAuth providers)
        .push(
            Router::with_path("/api/v1/linked-accounts")
                .get(pasion_handlers::rest::linked_accounts::list_linked_accounts),
        )
        .push(
            Router::with_path("/api/v1/linked-accounts/{id}")
                .delete(pasion_handlers::rest::linked_accounts::unlink_account),
        )
        // Upstream OAuth2 link (SPA)
        .push(
            Router::with_path("/api/v1/upstream-oauth2/link/{id}")
                .get(pasion_handlers::rest::upstream_oauth2::get_link)
                .post(pasion_handlers::rest::upstream_oauth2::post_link),
        )
}

fn build_admin_router(router: Router) -> Router {
    // Admin API routes - these would need OpenAPI integration
    // For now, we'll set up the basic structure
    router.push(
        Router::with_path("/api/admin/v1/{**path}")
            .get(admin_api_placeholder)
            .post(admin_api_placeholder)
            .put(admin_api_placeholder)
            .delete(admin_api_placeholder),
    )
}

#[handler]
async fn account_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    if let Some(url_builder) = url_builder {
        let prefix = url_builder.prefix().unwrap_or_default();
        let route = pasion_router::Account::route();
        Redirect::found(format!("{prefix}{route}"))
    } else {
        Redirect::found(pasion_router::Account::route())
    }
}

#[handler]
async fn change_password_redirect_handler(depot: &Depot) -> impl Writer + use<> {
    use crate::app_state::DepotExt;

    let url_builder = depot.get_url_builder().cloned();
    if let Some(url_builder) = url_builder {
        Redirect::found(
            url_builder
                .absolute_url_for(&pasion_router::AccountPasswordChange)
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

#[handler]
async fn admin_api_placeholder() -> impl Writer {
    StatusError::not_implemented().brief("Admin API not yet migrated")
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
