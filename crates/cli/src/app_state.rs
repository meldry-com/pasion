use std::{net::IpAddr, sync::Arc};

use ipnetwork::IpNetwork;
use pasion_context::LogContext;
use pasion_data_model::{AppVersion, BoxClock, BoxRng, SiteConfig, SystemClock};
use pasion_handlers::{
    ActivityTracker, BoundActivityTracker, CookieManager, Limiter,
    MetadataCache, RequesterFingerprint, passwords::PasswordManager,
};
use pasion_i18n::Translator;
use pasion_keystore::{Encrypter, Keystore};
use pasion_matrix::HomeserverConnection;
use pasion_policy::{Policy, PolicyFactory};
use pasion_router::UrlBuilder;
use pasion_storage::{BoxRepository, BoxRepositoryFactory, RepositoryFactory};
use pasion_storage_pg::PgRepositoryFactory;
use pasion_templates::Templates;
use opentelemetry::KeyValue;
use rand::SeedableRng;
use salvo::prelude::*;
use sqlx::PgPool;
use tracing::Instrument;

use crate::{VERSION, telemetry::METER};

#[derive(Clone)]
pub struct AppState {
    pub repository_factory: PgRepositoryFactory,
    pub templates: Templates,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_connection: Arc<dyn HomeserverConnection>,
    pub policy_factory: Arc<PolicyFactory>,
    pub http_client: reqwest::Client,
    pub password_manager: PasswordManager,
    pub metadata_cache: MetadataCache,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub trusted_proxies: Vec<IpNetwork>,
    pub limiter: Limiter,
}

impl AppState {
    /// Init the metrics for the app state.
    pub fn init_metrics(&mut self) {
        let pool = self.repository_factory.pool();
        METER
            .i64_observable_up_down_counter("db.connections.usage")
            .with_description("The number of connections that are currently in `state` described by the state attribute.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
                let used = pool.size() - idle;
                instrument.observe(i64::from(idle), &[KeyValue::new("state", "idle")]);
                instrument.observe(i64::from(used), &[KeyValue::new("state", "used")]);
            })
            .build();

        let pool = self.repository_factory.pool();
        METER
            .i64_observable_up_down_counter("db.connections.max")
            .with_description("The maximum number of open connections allowed.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let max_conn = pool.options().get_max_connections();
                instrument.observe(i64::from(max_conn), &[]);
            })
            .build();
    }

    /// Init the metadata cache in the background
    pub fn init_metadata_cache(&self) {
        let factory = self.repository_factory.clone();
        let metadata_cache = self.metadata_cache.clone();
        let http_client = self.http_client.clone();

        tokio::spawn(
            LogContext::new("metadata-cache-warmup")
                .run(async move || {
                    let mut repo = match factory.create().await {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::error!(
                                error = &e as &dyn std::error::Error,
                                "Failed to acquire a database connection"
                            );
                            return;
                        }
                    };

                    if let Err(e) = metadata_cache
                        .warm_up_and_run(
                            &http_client,
                            std::time::Duration::from_secs(60 * 15),
                            &mut repo,
                        )
                        .await
                    {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            "Failed to warm up the metadata cache"
                        );
                    }
                })
                .instrument(tracing::info_span!("metadata_cache.background_warmup")),
        );
    }
}

/// Middleware to inject AppState components into Depot
#[handler]
pub async fn inject_app_state(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // The AppState should already be in depot from the router setup
    let state: AppState = match depot.get::<AppState>("app_state").cloned() {
        Some(state) => state,
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain("AppState not found in depot"));
            ctrl.skip_rest();
            return;
        }
    };

    // Inject all components into depot with their type names as keys
    depot.insert("pg_pool", state.repository_factory.pool());
    depot.insert("box_repository_factory", state.repository_factory.clone().boxed());
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
    depot.insert("homeserver_connection", Arc::clone(&state.homeserver_connection));
    depot.insert("app_version", AppVersion(VERSION));
    depot.insert("activity_tracker", state.activity_tracker.clone());
    depot.insert("trusted_proxies", state.trusted_proxies.clone());

    ctrl.call_next(req, depot, res).await;
}

/// Helper trait to extract components from Depot
pub trait DepotExt {
    fn get_pg_pool(&self) -> Option<&PgPool>;
    fn get_box_repository_factory(&self) -> Option<&BoxRepositoryFactory>;
    fn get_templates(&self) -> Option<&Templates>;
    fn get_translator(&self) -> Option<&Arc<Translator>>;
    fn get_keystore(&self) -> Option<&Keystore>;
    fn get_encrypter(&self) -> Option<&Encrypter>;
    fn get_url_builder(&self) -> Option<&UrlBuilder>;
    fn get_http_client(&self) -> Option<&reqwest::Client>;
    fn get_password_manager(&self) -> Option<&PasswordManager>;
    fn get_cookie_manager(&self) -> Option<&CookieManager>;
    fn get_metadata_cache(&self) -> Option<&MetadataCache>;
    fn get_site_config(&self) -> Option<&SiteConfig>;
    fn get_limiter(&self) -> Option<&Limiter>;
    fn get_policy_factory(&self) -> Option<&Arc<PolicyFactory>>;
    fn get_homeserver_connection(&self) -> Option<&Arc<dyn HomeserverConnection>>;
    fn get_app_version(&self) -> Option<&AppVersion>;
    fn get_activity_tracker(&self) -> Option<&ActivityTracker>;
    fn get_trusted_proxies(&self) -> Option<&Vec<IpNetwork>>;
}

impl DepotExt for Depot {
    fn get_pg_pool(&self) -> Option<&PgPool> {
        self.get::<PgPool>("pg_pool")
    }

    fn get_box_repository_factory(&self) -> Option<&BoxRepositoryFactory> {
        self.get::<BoxRepositoryFactory>("box_repository_factory")
    }

    fn get_templates(&self) -> Option<&Templates> {
        self.get::<Templates>("templates")
    }

    fn get_translator(&self) -> Option<&Arc<Translator>> {
        self.get::<Arc<Translator>>("translator")
    }

    fn get_keystore(&self) -> Option<&Keystore> {
        self.get::<Keystore>("keystore")
    }

    fn get_encrypter(&self) -> Option<&Encrypter> {
        self.get::<Encrypter>("encrypter")
    }

    fn get_url_builder(&self) -> Option<&UrlBuilder> {
        self.get::<UrlBuilder>("url_builder")
    }

    fn get_http_client(&self) -> Option<&reqwest::Client> {
        self.get::<reqwest::Client>("http_client")
    }

    fn get_password_manager(&self) -> Option<&PasswordManager> {
        self.get::<PasswordManager>("password_manager")
    }

    fn get_cookie_manager(&self) -> Option<&CookieManager> {
        self.get::<CookieManager>("cookie_manager")
    }

    fn get_metadata_cache(&self) -> Option<&MetadataCache> {
        self.get::<MetadataCache>("metadata_cache")
    }

    fn get_site_config(&self) -> Option<&SiteConfig> {
        self.get::<SiteConfig>("site_config")
    }

    fn get_limiter(&self) -> Option<&Limiter> {
        self.get::<Limiter>("limiter")
    }

    fn get_policy_factory(&self) -> Option<&Arc<PolicyFactory>> {
        self.get::<Arc<PolicyFactory>>("policy_factory")
    }

    fn get_homeserver_connection(&self) -> Option<&Arc<dyn HomeserverConnection>> {
        self.get::<Arc<dyn HomeserverConnection>>("homeserver_connection")
    }

    fn get_app_version(&self) -> Option<&AppVersion> {
        self.get::<AppVersion>("app_version")
    }

    fn get_activity_tracker(&self) -> Option<&ActivityTracker> {
        self.get::<ActivityTracker>("activity_tracker")
    }

    fn get_trusted_proxies(&self) -> Option<&Vec<IpNetwork>> {
        self.get::<Vec<IpNetwork>>("trusted_proxies")
    }
}

/// Extract BoxClock from request
pub fn extract_clock() -> BoxClock {
    let clock = SystemClock::default();
    Box::new(clock)
}

/// Extract BoxRng from request
pub fn extract_rng() -> BoxRng {
    // This rng is used to source the local rng
    #[allow(clippy::disallowed_methods)]
    let rng = rand::thread_rng();

    let rng = rand_chacha::ChaChaRng::from_rng(rng).expect("Failed to seed RNG");
    Box::new(rng)
}

/// Extract Policy from depot
pub async fn extract_policy(depot: &Depot) -> Result<Policy, pasion_policy::InstantiateError> {
    let policy_factory = depot
        .get_policy_factory()
        .ok_or_else(|| {
            pasion_policy::InstantiateError::Instantiate(anyhow::anyhow!("PolicyFactory not found in depot").into())
        })?;
    policy_factory.instantiate().await
}

/// Extract BoxRepository from depot
pub async fn extract_repository(depot: &Depot) -> Result<BoxRepository, pasion_storage::RepositoryError> {
    let app_state = depot
        .get::<AppState>("app_state")
        .ok_or_else(|| pasion_storage::RepositoryError::from(anyhow::anyhow!("AppState not found in depot")))?;
    app_state.repository_factory.create().await
}

fn infer_client_ip(
    req: &Request,
    trusted_proxies: &[IpNetwork],
) -> Option<IpAddr> {
    let connection_info = req.extensions().get::<pasion_listener::ConnectionInfo>();

    let peer = if let Some(info) = connection_info {
        // We can always trust the proxy protocol to give us the correct IP address
        if let Some(proxy) = info.get_proxy_ref()
            && let Some(source) = proxy.source()
        {
            return Some(source.ip());
        }

        info.get_peer_addr().map(|addr| addr.ip())
    } else {
        None
    };

    // Get the list of IPs from the X-Forwarded-For header
    let peers_from_header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.trim().parse().ok()))
        .into_iter()
        .flatten();

    // This constructs a list of IP addresses that might be the client's IP address.
    // Each intermediate proxy is supposed to add the client's IP address to front
    // of the list. We are effectively adding the IP we got from the socket to the
    // front of the list.
    // We also call `to_canonical` so that IPv6-mapped IPv4 addresses
    // (::ffff:A.B.C.D) are converted to IPv4.
    let peer_list: Vec<IpAddr> = peer
        .into_iter()
        .chain(peers_from_header)
        .map(|ip| ip.to_canonical())
        .collect();

    // We'll fallback to the first IP in the list if all the IPs we got are trusted
    let fallback = peer_list.first().copied();

    // Now we go through the list, and the IP of the client is the first IP that is
    // not in the list of trusted proxies, starting from the back.
    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}

/// Extract BoundActivityTracker from request and depot
pub fn extract_bound_activity_tracker(req: &Request, depot: &Depot) -> BoundActivityTracker {
    let activity_tracker = depot
        .get_activity_tracker()
        .cloned()
        .unwrap_or_else(|| ActivityTracker::new(100));

    let trusted_proxies = depot
        .get_trusted_proxies()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let ip = infer_client_ip(req, trusted_proxies);
    tracing::debug!(ip = ?ip, "Inferred client IP address");
    activity_tracker.bind(ip)
}

/// Extract RequesterFingerprint from request and depot
pub fn extract_requester_fingerprint(req: &Request, depot: &Depot) -> RequesterFingerprint {
    let trusted_proxies = depot
        .get_trusted_proxies()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let ip = infer_client_ip(req, trusted_proxies);

    if let Some(ip) = ip {
        RequesterFingerprint::new(ip)
    } else {
        // If we can't infer the IP address, we'll just use an empty fingerprint and
        // warn about it
        tracing::warn!(
            "Could not infer client IP address for an operation which rate-limits based on IP addresses"
        );
        RequesterFingerprint::EMPTY
    }
}
