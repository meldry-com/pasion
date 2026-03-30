use std::sync::{Arc, Mutex, RwLock};

use chrono::Duration;
use cookie_store::{CookieStore, RawCookie};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use headers::{Authorization, ContentType, HeaderMapExt, HeaderName, HeaderValue};
use hyper::{
    Request, Response, StatusCode,
    header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
};
use oauth2_types::{registration::ClientRegistrationResponse, requests::AccessTokenResponse};
use pasion_config::RateLimitingConfig;
use pasion_data_model::{AppVersion, BoxClock, BoxRng, SiteConfig, clock::MockClock};
use pasion_i18n::Translator;
use pasion_keystore::{Encrypter, JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use pasion_matrix::{HomeserverConnection, MockHomeserverConnection};
use pasion_messaging::{MailTransport, Mailer, NotificationCenter};
use pasion_policy::{InstantiateError, Policy, PolicyFactory};
use pasion_router::{Route, SimpleRoute, UrlBuilder};
use pasion_salvo_utils::cookies::{CookieJar, CookieManager};
use pasion_storage::{BoxRepository, BoxRepositoryFactory, RepositoryError, RepositoryFactory};
use pasion_storage_pg::PgRepositoryFactory;
use pasion_tasks::QueueWorker;
use pasion_templates::{SiteConfigExt, Templates};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use salvo::{prelude::*, test::TestClient, test::ResponseExt as SalvoResponseExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio_util::{
    sync::{CancellationToken, DropGuard},
    task::TaskTracker,
};
use url::Url;

use crate::handlers::{
    ActivityTracker, BoundActivityTracker, Limiter, RequesterFingerprint,
    passwords::{Hasher, PasswordManager},
    upstream_oauth2::cache::MetadataCache,
};

/// Setup rustcrypto and tracing for tests.
#[allow(unused_must_use)]
pub(crate) fn setup() {
    rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();
}

pub(crate) async fn policy_factory(
    server_name: &str,
    data: serde_json::Value,
) -> Result<Arc<PolicyFactory>, anyhow::Error> {
    let workspace_root = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let file = tokio::fs::File::open(workspace_root.join("policies").join("policy.wasm")).await?;

    let entrypoints = pasion_policy::Entrypoints {
        register: "register/violation".to_owned(),
        client_registration: "client_registration/violation".to_owned(),
        authorization_grant: "authorization_grant/violation".to_owned(),

        email: "email/violation".to_owned(),
    };

    let data = pasion_policy::Data::new(server_name.to_owned(), None).with_rest(data);

    let policy_factory = PolicyFactory::load(file, data, entrypoints).await?;
    let policy_factory = Arc::new(policy_factory);
    Ok(policy_factory)
}

#[derive(Clone)]
pub(crate) struct TestState {
    pub repository_factory: PgRepositoryFactory,
    pub templates: Templates,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub metadata_cache: MetadataCache,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_connection: Arc<MockHomeserverConnection>,
    pub policy_factory: Arc<PolicyFactory>,
    pub password_manager: PasswordManager,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub limiter: Limiter,
    pub clock: Arc<MockClock>,
    pub rng: Arc<Mutex<ChaChaRng>>,
    pub http_client: reqwest::Client,
    pub task_tracker: TaskTracker,
    queue_worker: Arc<tokio::sync::Mutex<QueueWorker>>,

    #[allow(dead_code)] // It is used, as it will cancel the CancellationToken when dropped
    cancellation_drop_guard: Arc<DropGuard>,
}

fn workspace_root() -> camino::Utf8PathBuf {
    camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize_utf8()
        .unwrap()
}

pub fn test_site_config() -> SiteConfig {
    SiteConfig {
        access_token_ttl: Duration::try_minutes(5).unwrap(),
        server_name: "example.com".to_owned(),
        policy_uri: Some("https://example.com/policy".parse().unwrap()),
        tos_uri: Some("https://example.com/tos".parse().unwrap()),
        imprint: None,
        password_login_enabled: true,
        password_registration_enabled: true,
        registration_token_required: false,
        email_change_allowed: true,
        displayname_change_allowed: true,
        password_change_allowed: true,
        password_registration_contact_required: true,
        account_recovery_allowed: true,
        account_deactivation_allowed: true,
        captcha: None,
        minimum_password_complexity: 1,
        session_expiration: None,
        login_with_email_allowed: true,
        plan_management_iframe_uri: None,
        session_limit: None,
        flow_engine_enabled: false,
    }
}

/// Salvo handler that injects TestState components into the Depot.
#[derive(Clone)]
struct InjectTestState(TestState);

#[salvo::async_trait]
impl Handler for InjectTestState {
    async fn handle(
        &self,
        req: &mut salvo::Request,
        depot: &mut Depot,
        res: &mut salvo::Response,
        ctrl: &mut FlowCtrl,
    ) {
        let state = &self.0;
        depot.insert(
            "box_repository_factory",
            state.repository_factory.clone().boxed(),
        );
        depot.insert("templates", state.templates.clone());
        depot.insert("translator", state.templates.translator());
        depot.insert("keystore", state.key_store.clone());
        depot.insert("encrypter", state.encrypter.clone());
        depot.insert("url_builder", state.url_builder.clone());
        depot.insert("http_client", state.http_client.clone());
        depot.insert("password_manager", state.password_manager.clone());
        depot.insert("cookie_manager", state.cookie_manager.clone());
        depot.insert("metadata_cache", state.metadata_cache.clone());
        depot.insert("site_config", state.site_config.clone());
        depot.insert("limiter", state.limiter.clone());
        depot.insert("policy_factory", state.policy_factory.clone());
        depot.insert(
            "homeserver_connection",
            Arc::clone(&state.homeserver_connection) as Arc<dyn HomeserverConnection>,
        );
        depot.insert("app_version", AppVersion("v0.0.0-test"));
        depot.insert("activity_tracker", state.activity_tracker.clone());
        depot.insert("trusted_proxies", Vec::<ipnetwork::IpNetwork>::new());
        ctrl.call_next(req, depot, res).await;
    }
}

impl TestState {
    /// Create a new test state from the given database pool
    pub async fn from_pool(pool: DieselPool<AsyncPgConnection>) -> Result<Self, anyhow::Error> {
        Self::from_pool_with_site_config(pool, test_site_config()).await
    }

    /// Create a new test state from the given database pool and site config
    pub async fn from_pool_with_site_config(
        pool: DieselPool<AsyncPgConnection>,
        site_config: SiteConfig,
    ) -> Result<Self, anyhow::Error> {
        let workspace_root = workspace_root();

        let task_tracker = TaskTracker::new();
        let shutdown_token = CancellationToken::new();

        let url_builder = UrlBuilder::new("https://example.com/".parse()?, None, None);

        let templates = Templates::load(
            workspace_root.join("templates"),
            url_builder.clone(),
            workspace_root.join("translations"),
            site_config.templates_branding(),
            site_config.templates_features(),
            // Strict mode in testing
            true,
        )
        .await?;

        let http_client = pasion_http::reqwest_client();

        // TODO: add more test keys to the store
        let rsa =
            PrivateKey::load_pem(include_str!("../../keystore/tests/keys/rsa.pkcs1.pem")).unwrap();
        let rsa = JsonWebKey::new(rsa).with_kid("test-rsa");

        let jwks = JsonWebKeySet::new(vec![rsa]);
        let key_store = Keystore::new(jwks);

        let encrypter = Encrypter::new(&[0x42; 32]);
        let cookie_manager = CookieManager::derive_from(url_builder.http_base(), &[0x42; 32]);

        let metadata_cache = MetadataCache::new();

        let password_manager = if site_config.password_login_enabled {
            PasswordManager::new(
                site_config.minimum_password_complexity,
                [(1, Hasher::argon2id(None, false))],
            )?
        } else {
            PasswordManager::disabled()
        };

        let policy_factory =
            policy_factory(&site_config.server_name, serde_json::json!({})).await?;

        let homeserver_connection =
            Arc::new(MockHomeserverConnection::new(&site_config.server_name));

        let clock = Arc::new(MockClock::default());
        let rng = Arc::new(Mutex::new(ChaChaRng::seed_from_u64(42)));

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            std::time::Duration::from_secs(60),
            &task_tracker,
            shutdown_token.child_token(),
        );

        let mailer = Mailer::new(
            templates.clone(),
            MailTransport::blackhole(),
            "hello@example.com".parse().unwrap(),
            "hello@example.com".parse().unwrap(),
        );
        let notifications = NotificationCenter::email_only(mailer);
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for handler tests");

        let queue_worker = pasion_tasks::init(
            PgRepositoryFactory::new(pool.clone()),
            database_url,
            Arc::clone(&clock),
            &notifications,
            homeserver_connection.clone(),
            url_builder.clone(),
            &site_config,
            shutdown_token.child_token(),
        )
        .await
        .unwrap();

        let queue_worker = Arc::new(tokio::sync::Mutex::new(queue_worker));

        Ok(Self {
            repository_factory: PgRepositoryFactory::new(pool),
            templates,
            key_store,
            cookie_manager,
            metadata_cache,
            encrypter,
            url_builder,
            homeserver_connection,
            policy_factory,
            password_manager,
            site_config,
            activity_tracker,
            limiter,
            clock,
            rng,
            http_client,
            task_tracker,
            queue_worker,
            cancellation_drop_guard: Arc::new(shutdown_token.drop_guard()),
        })
    }

    /// Run all the available jobs in the queue.
    ///
    /// Panics if it fails to run the jobs (but not on job failures!)
    pub async fn run_jobs_in_queue(&self) {
        let mut queue = self.queue_worker.lock().await;
        queue.process_all_jobs_in_tests().await.unwrap();
    }

    /// Reset the test utils to a fresh state, with the same configuration.
    pub async fn reset(self) -> Self {
        let site_config = self.site_config.clone();
        let pool = self.repository_factory.pool().clone();
        let task_tracker = self.task_tracker.clone();

        // This should trigger the cancellation drop guard
        drop(self);

        // Wait for tasks to complete
        task_tracker.close();
        task_tracker.wait().await;

        Self::from_pool_with_site_config(pool, site_config)
            .await
            .unwrap()
    }

    /// Build a Salvo router with all test routes and state injection.
    fn build_test_router(&self) -> Router {
        Router::new()
            .hoop(InjectTestState(self.clone()))
            // Health
            .push(Router::with_path(pasion_router::Healthcheck::route()).get(crate::handlers::health::get))
            // OAuth2 discovery
            .push(
                Router::with_path(pasion_router::OidcConfiguration::route())
                    .get(crate::handlers::oauth2::discovery::get),
            )
            .push(
                Router::with_path(pasion_router::Webfinger::route())
                    .get(crate::handlers::oauth2::webfinger::get),
            )
            // OAuth2 endpoints
            .push(
                Router::with_path(pasion_router::OAuth2Keys::route()).get(crate::handlers::oauth2::keys::get),
            )
            .push(
                Router::with_path(pasion_router::OidcUserinfo::route())
                    .get(crate::handlers::oauth2::userinfo::get)
                    .post(crate::handlers::oauth2::userinfo::get),
            )
            .push(
                Router::with_path(pasion_router::OAuth2Introspection::route())
                    .post(crate::handlers::oauth2::introspection::post),
            )
            .push(
                Router::with_path(pasion_router::OAuth2Revocation::route())
                    .post(crate::handlers::oauth2::revoke::post),
            )
            .push(
                Router::with_path(pasion_router::OAuth2TokenEndpoint::route())
                    .post(crate::handlers::oauth2::token::post),
            )
            .push(
                Router::with_path(pasion_router::OAuth2RegistrationEndpoint::route())
                    .post(crate::handlers::oauth2::registration::post),
            )
            .push(
                Router::with_path(pasion_router::OAuth2DeviceAuthorizationEndpoint::route())
                    .post(crate::handlers::oauth2::device::authorize::post),
            )
            // REST API
            .push(Router::with_path("/api/v1/viewer").get(crate::handlers::rest::viewer::get_viewer))
            .push(Router::with_path("/api/v1/site-config").get(crate::handlers::rest::site_config::get))
            .push(
                Router::with_path("/api/v1/sessions/<id>").get(crate::handlers::rest::sessions::get_session),
            )
            .push(
                Router::with_path("/api/v1/browser-sessions/<id>")
                    .delete(crate::handlers::rest::sessions::end_browser_session),
            )
            .push(
                Router::with_path("/api/v1/oauth2-sessions/<id>")
                    .delete(crate::handlers::rest::sessions::end_oauth2_session),
            )
            .push(
                Router::with_path("/api/v1/oauth2-sessions/<id>/name")
                    .put(crate::handlers::rest::sessions::set_oauth2_session_name),
            )
            .push(
                Router::with_path("/api/v1/oauth2-clients/<id>")
                    .get(crate::handlers::rest::oauth2_clients::get_client),
            )
            .push(
                Router::with_path("/api/v1/viewer/password")
                    .post(crate::handlers::rest::password::set_password),
            )
            .push(
                Router::with_path("/api/v1/password-recovery/set")
                    .post(crate::handlers::rest::password::set_password_by_recovery),
            )
            .push(
                Router::with_path("/api/v1/password-recovery/resend")
                    .post(crate::handlers::rest::password::resend_recovery_email),
            )
            .push(
                Router::with_path("/api/v1/viewer/display-name")
                    .post(crate::handlers::rest::users::set_display_name),
            )
            .push(
                Router::with_path("/api/v1/viewer/cross-signing-reset")
                    .post(crate::handlers::rest::users::allow_cross_signing_reset),
            )
            .push(
                Router::with_path("/api/v1/viewer/deactivate")
                    .post(crate::handlers::rest::users::deactivate_user),
            )
            .push(
                Router::with_path("/api/v1/email-auth/start")
                    .post(crate::handlers::rest::emails::start_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/<id>")
                    .get(crate::handlers::rest::emails::get_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/<id>/complete")
                    .post(crate::handlers::rest::emails::complete_email_auth),
            )
            .push(
                Router::with_path("/api/v1/email-auth/<id>/resend")
                    .post(crate::handlers::rest::emails::resend_email_auth_code),
            )
            .push(
                Router::with_path("/api/v1/user-emails/<id>")
                    .delete(crate::handlers::rest::emails::remove_email),
            )
            // OAuth2 authorization
            .push(
                Router::with_path(pasion_router::OAuth2AuthorizationEndpoint::route())
                    .get(crate::handlers::oauth2::authorization::get),
            )
            // Upstream OAuth2
            .push(
                Router::with_path(pasion_router::UpstreamOAuth2Authorize::route())
                    .get(crate::handlers::upstream_oauth2::authorize::get),
            )
            .push(
                Router::with_path(pasion_router::UpstreamOAuth2Callback::route())
                    .get(crate::handlers::upstream_oauth2::callback::handler)
                    .post(crate::handlers::upstream_oauth2::callback::handler),
            )
            .push(
                Router::with_path(pasion_router::UpstreamOAuth2BackchannelLogout::route())
                    .post(crate::handlers::upstream_oauth2::backchannel_logout::post),
            )
            // Admin API
            .push(
                Router::with_path("/api/admin/v1")
                    .push(Router::with_path("version").get(crate::handlers::admin::v1::version::handler))
                    .push(Router::with_path("site-config").get(crate::handlers::admin::v1::site_config::handler))
                    .push(Router::with_path("connector-health").get(crate::handlers::admin::v1::connector_health::handler))
                    .push(Router::with_path("notification-channels").get(crate::handlers::admin::v1::notification_channels::handler))
                    .push(
                        Router::with_path("notification-templates")
                            .get(crate::handlers::admin::v1::notification_templates::list_handler)
                            .push(
                                Router::with_path("publish")
                                    .post(crate::handlers::admin::v1::notification_templates::publish_handler),
                            ),
                    )
                    .push(Router::with_path("audit-feed").get(crate::handlers::admin::v1::audit_feed::handler))
                    .push(
                        Router::with_path("users")
                            .get(crate::handlers::admin::v1::users::list::handler)
                            .post(crate::handlers::admin::v1::users::add::handler)
                            .push(
                                Router::with_path("by-username/<username>")
                                    .get(crate::handlers::admin::v1::users::by_username::handler),
                            )
                            .push(
                                Router::with_path("batch-invite")
                                    .post(crate::handlers::admin::v1::users::batch_invite::handler),
                            )
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::users::get::handler)
                                    .push(
                                        Router::with_path("set-password")
                                            .post(crate::handlers::admin::v1::users::set_password::handler),
                                    )
                                    .push(Router::with_path("set-admin").post(crate::handlers::admin::v1::users::set_admin::handler))
                                    .push(Router::with_path("deactivate").post(crate::handlers::admin::v1::users::deactivate::handler))
                                    .push(Router::with_path("reactivate").post(crate::handlers::admin::v1::users::reactivate::handler))
                                    .push(Router::with_path("lock").post(crate::handlers::admin::v1::users::lock::handler))
                                    .push(Router::with_path("unlock").post(crate::handlers::admin::v1::users::unlock::handler))
                                    .push(Router::with_path("risk-action").post(crate::handlers::admin::v1::users::risk_action::handler)),
                            ),
                    )
                    .push(
                        Router::with_path("user-emails")
                            .get(crate::handlers::admin::v1::user_emails::list::handler)
                            .post(crate::handlers::admin::v1::user_emails::add::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::user_emails::get::handler)
                                    .delete(crate::handlers::admin::v1::user_emails::delete::handler),
                            ),
                    )
                    .push(
                        Router::with_path("user-sessions")
                            .get(crate::handlers::admin::v1::user_sessions::list::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::user_sessions::get::handler)
                                    .push(Router::with_path("finish").post(crate::handlers::admin::v1::user_sessions::finish::handler)),
                            ),
                    )
                    .push(
                        Router::with_path("oauth2-sessions")
                            .get(crate::handlers::admin::v1::oauth2_sessions::list::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::oauth2_sessions::get::handler)
                                    .push(
                                        Router::with_path("finish").post(crate::handlers::admin::v1::oauth2_sessions::finish::handler),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("personal-sessions")
                            .get(crate::handlers::admin::v1::personal_sessions::list::handler)
                            .post(crate::handlers::admin::v1::personal_sessions::add::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::personal_sessions::get::handler)
                                    .push(
                                        Router::with_path("regenerate")
                                            .post(crate::handlers::admin::v1::personal_sessions::regenerate::handler),
                                    )
                                    .push(
                                        Router::with_path("revoke")
                                            .post(crate::handlers::admin::v1::personal_sessions::revoke::handler),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("user-registration-tokens")
                            .get(crate::handlers::admin::v1::user_registration_tokens::list::handler)
                            .post(crate::handlers::admin::v1::user_registration_tokens::add::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::user_registration_tokens::get::handler)
                                    .put(crate::handlers::admin::v1::user_registration_tokens::update::handler)
                                    .push(
                                        Router::with_path("revoke")
                                            .post(crate::handlers::admin::v1::user_registration_tokens::revoke::handler),
                                    )
                                    .push(
                                        Router::with_path("unrevoke")
                                            .post(crate::handlers::admin::v1::user_registration_tokens::unrevoke::handler),
                                    ),
                            ),
                    )
                    .push(
                        Router::with_path("upstream-oauth-providers")
                            .get(crate::handlers::admin::v1::upstream_oauth_providers::list::handler)
                            .push(Router::with_path("<id>").get(crate::handlers::admin::v1::upstream_oauth_providers::get::handler)),
                    )
                    .push(
                        Router::with_path("upstream-oauth-links")
                            .get(crate::handlers::admin::v1::upstream_oauth_links::list::handler)
                            .post(crate::handlers::admin::v1::upstream_oauth_links::add::handler)
                            .push(
                                Router::with_path("<id>")
                                    .get(crate::handlers::admin::v1::upstream_oauth_links::get::handler)
                                    .delete(crate::handlers::admin::v1::upstream_oauth_links::delete::handler),
                            ),
                    )
                    .push(
                        Router::with_path("policy-data")
                            .push(Router::with_path("latest").get(crate::handlers::admin::v1::policy_data::get_latest::handler))
                            .push(Router::with_path("<id>").get(crate::handlers::admin::v1::policy_data::get::handler))
                            .put(crate::handlers::admin::v1::policy_data::set::handler),
                    ),
            )
    }

    pub async fn request(&self, request: Request<String>) -> Response<String> {
        let router = self.build_test_router();
        let service = salvo::Service::new(router);

        let (parts, body) = request.into_parts();
        let uri = parts.uri;
        let url = format!(
            "https://example.com{}",
            uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
        );

        let mut test_req = match parts.method {
            hyper::Method::GET => TestClient::get(&url),
            hyper::Method::POST => TestClient::post(&url),
            hyper::Method::PUT => TestClient::put(&url),
            hyper::Method::DELETE => TestClient::delete(&url),
            hyper::Method::PATCH => TestClient::patch(&url),
            hyper::Method::HEAD => TestClient::head(&url),
            hyper::Method::OPTIONS => TestClient::options(&url),
            other => panic!("Unsupported HTTP method: {other}"),
        };

        for (name, value) in &parts.headers {
            test_req = test_req.add_header(name, value, true);
        }

        if !body.is_empty() {
            test_req = test_req.bytes(body.into_bytes());
        }

        let mut salvo_res = test_req.send(&service).await;
        let status = salvo_res.status_code.unwrap_or(StatusCode::OK);
        let response_headers = salvo_res.headers().clone();
        let body_str = salvo_res.take_string().await.unwrap_or_default();

        let mut builder = Response::builder().status(status);
        *builder.headers_mut().unwrap() = response_headers;
        builder.body(body_str).unwrap()
    }

    /// Get a token with the given scope
    pub async fn token_with_scope(&mut self, scope: &str) -> String {
        // Provision a client
        let request = Request::post(pasion_router::OAuth2RegistrationEndpoint::PATH).json(
            serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["client_credentials"],
            }),
        );
        let response = self.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;
        let client_secret = response.client_secret.expect("to have a client secret");

        // Make the client admin
        let state = {
            let mut state = self.clone();
            state.policy_factory = policy_factory(
                "example.com",
                serde_json::json!({
                    "admin_clients": [client_id],
                }),
            )
            .await
            .unwrap();
            state
        };

        // Ask for a token with the admin scope
        let request =
            Request::post(pasion_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let AccessTokenResponse { access_token, .. } = response.json();

        access_token
    }

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        self.repository_factory.create().await
    }

    /// Returns a new random number generator.
    ///
    /// # Panics
    ///
    /// Panics if the RNG is already locked.
    pub fn rng(&self) -> ChaChaRng {
        let mut parent_rng = self.rng.try_lock().expect("Failed to lock RNG");
        ChaChaRng::from_rng(&mut *parent_rng).unwrap()
    }

    /// Do a call to the userinfo endpoint to check if the given token is valid.
    /// Returns true if the token is valid.
    ///
    /// # Panics
    ///
    /// Panics if the response status code is not 200 or 401.
    pub async fn is_access_token_valid(&self, token: &str) -> bool {
        let request = Request::get(pasion_router::OidcUserinfo::PATH)
            .bearer(token)
            .empty();

        let response = self.request(request).await;

        match response.status() {
            StatusCode::OK => true,
            StatusCode::UNAUTHORIZED => false,
            _ => panic!("Unexpected status code: {}", response.status()),
        }
    }

    /// Get an empty cookie jar
    pub fn cookie_jar(&self) -> CookieJar {
        self.cookie_manager.cookie_jar()
    }
}

pub(crate) trait RequestBuilderExt {
    /// Builds the request with the given JSON value as body.
    fn json<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Builds the request with the given form value as body.
    fn form<T: Serialize>(self, body: T) -> hyper::Request<String>;

    /// Sets the request Authorization header to the given bearer token.
    fn bearer(self, token: &str) -> Self;

    /// Sets the request Authorization header to the given basic auth
    /// credentials.
    fn basic_auth(self, username: &str, password: &str) -> Self;

    /// Builds the request with an empty body.
    fn empty(self) -> hyper::Request<String>;
}

impl RequestBuilderExt for hyper::http::request::Builder {
    fn json<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::json());

        self.body(serde_json::to_string(&body).unwrap()).unwrap()
    }

    fn form<T: Serialize>(mut self, body: T) -> hyper::Request<String> {
        self.headers_mut()
            .unwrap()
            .typed_insert(ContentType::form_url_encoded());

        self.body(serde_urlencoded::to_string(&body).unwrap())
            .unwrap()
    }

    fn bearer(mut self, token: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::bearer(token).unwrap());
        self
    }

    fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.headers_mut()
            .unwrap()
            .typed_insert(Authorization::basic(username, password));
        self
    }

    fn empty(self) -> hyper::Request<String> {
        self.body(String::new()).unwrap()
    }
}

pub(crate) trait ResponseExt {
    /// Asserts that the response has the given status code.
    ///
    /// # Panics
    ///
    /// Panics if the response has a different status code.
    fn assert_status(&self, status: StatusCode);

    /// Asserts that the response has the given header value.
    ///
    /// # Panics
    ///
    /// Panics if the response does not have the given header or if the header
    /// value does not match.
    fn assert_header_value(&self, header: HeaderName, value: &str);

    /// Get the response body as JSON.
    ///
    /// # Panics
    ///
    /// Panics if the response is missing the `Content-Type: application/json`,
    /// or if the body is not valid JSON.
    fn json<T: DeserializeOwned>(&self) -> T;
}

impl ResponseExt for Response<String> {
    #[track_caller]
    fn assert_status(&self, status: StatusCode) {
        assert_eq!(
            self.status(),
            status,
            "HTTP status code mismatch: got {}, expected {}. Body: {}",
            self.status(),
            status,
            self.body()
        );
    }

    #[track_caller]
    fn assert_header_value(&self, header: HeaderName, value: &str) {
        let actual_value = self
            .headers()
            .get(&header)
            .unwrap_or_else(|| panic!("Missing header {header}"));

        assert_eq!(
            actual_value,
            value,
            "Header mismatch: got {:?}, expected {:?}",
            self.headers().get(header),
            value
        );
    }

    #[track_caller]
    fn json<T: DeserializeOwned>(&self) -> T {
        self.assert_header_value(CONTENT_TYPE, "application/json");
        serde_json::from_str(self.body()).expect("JSON deserialization failed")
    }
}

/// A helper for storing and retrieving cookies in tests.
#[derive(Clone, Debug, Default)]
pub struct CookieHelper {
    store: Arc<RwLock<CookieStore>>,
}

impl CookieHelper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject the cookies from the store into the request.
    pub fn with_cookies<B>(&self, mut request: Request<B>) -> Request<B> {
        let url = Url::options()
            .base_url(Some(&"https://example.com/".parse().unwrap()))
            .parse(&request.uri().to_string())
            .expect("Failed to parse URL");

        let store = self.store.read().unwrap();
        let value = store
            .get_request_values(&url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");

        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&value).expect("Invalid cookie value"),
        );
        request
    }

    /// Save the cookies from the response into the store.
    pub fn save_cookies<B>(&self, response: &Response<B>) {
        let url = "https://example.com/".parse().unwrap();
        let mut store = self.store.write().unwrap();
        store.store_response_cookies(
            response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .map(|set_cookie| {
                    RawCookie::parse(
                        set_cookie
                            .to_str()
                            .expect("Invalid set-cookie header")
                            .to_owned(),
                    )
                    .expect("Invalid set-cookie header")
                }),
            &url,
        );
    }

    /// Import cookies from a CookieJar into the store.
    pub fn import(&self, cookie_jar: CookieJar) {
        let url = "https://example.com/".parse().unwrap();
        let mut store = self.store.write().unwrap();
        store.store_response_cookies(
            cookie_jar
                .pending_cookies()
                .iter()
                .map(|c| RawCookie::parse(c.to_string()).expect("Invalid cookie from CookieJar")),
            &url,
        );
    }
}
