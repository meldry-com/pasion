//! Embed Pasion without installing signals, tracing, or a network listener.
use std::{sync::Arc, time::Duration};

use anyhow::Context;
use figment::Figment;
use pasion_config::{
    AppConfig, ClientsConfig, ConfigurationSection, ConfigurationSectionExt, HttpResource,
    UpstreamOAuth2Config,
};
use pasion_data::{PgRepositoryFactory, SystemClock, UrlBuilder};
use salvo::Router;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::info;

use crate::{
    app_state::AppState,
    handlers::{ActivityTracker, CookieManager, Limiter, MetadataCache},
    services::email_webhook::EmailWebhookService,
    util::{
        database_url_from_config, diesel_pool_from_config, homeserver_connection_from_config,
        load_policy_factory_dynamic_data_continuously, notification_center_from_config,
        password_manager_from_config, policy_factory_from_config, site_config_from_config,
        templates_from_config, test_mailer_in_background_with_shutdown,
    },
};

/// The same migration, configuration-sync and worker switches as the CLI.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerOptions {
    pub no_migrate: bool,
    pub no_worker: bool,
    pub no_sync: bool,
}

/// One Pasion instance per process (storage and version use global state).
/// The host owns its runtime, logging, listener and signal handlers.
pub struct PasionServer {
    state: AppState,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

impl PasionServer {
    /// Initialize state, migrations, config sync and background workers.
    /// No ports are opened. Dropping the server cancels its background tasks.
    pub async fn initialize(figment: &Figment, options: ServerOptions) -> anyhow::Result<Self> {
        Self::initialize_with_runtime(
            figment,
            options,
            CancellationToken::new(),
            TaskTracker::new(),
        )
        .await
    }

    /// Use the CLI's (or another host's) lifecycle tokens and task tracker.
    pub async fn initialize_with_runtime(
        figment: &Figment,
        options: ServerOptions,
        shutdown: CancellationToken,
        tasks: TaskTracker,
    ) -> anyhow::Result<Self> {
        super::VERSION.get_or_init(|| env!("CARGO_PKG_VERSION"));
        let guard = shutdown.clone().drop_guard();
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        // Connect to the database
        info!("Connecting to the database");
        let db_url = database_url_from_config(&config.database)?;
        let pool = diesel_pool_from_config(&config.database).await?;

        if options.no_migrate {
            if pasion_data::has_pending_migrations(&db_url).await? {
                // Refuse to start if there are pending migrations
                return Err(anyhow::anyhow!(
                    "The server is running with `--no-migrate` but there are pending migrations. Please run them first with `pasion database migrate`, or omit the `--no-migrate` flag to apply them automatically on startup."
                ));
            }
        } else {
            info!("Running pending database migrations");
            pasion_data::migrate(&pool, &db_url)
                .await
                .context("could not run migrations")?;
        }

        let encrypter = config.secrets.encrypter().await?;

        if options.no_sync {
            info!("Skipping configuration sync");
        } else {
            // Sync the configuration with the database
            let conn = pool
                .get()
                .await
                .context("could not get connection from pool")?;
            let clients_config =
                ClientsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
            let upstream_oauth2_config = UpstreamOAuth2Config::extract_or_default(figment)
                .map_err(anyhow::Error::from_boxed)?;

            crate::sync::config_sync(
                upstream_oauth2_config,
                clients_config,
                conn,
                &encrypter,
                &SystemClock::default(),
                false,
                false,
            )
            .await
            .context("could not sync the configuration with the database")?;
        }

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let cookie_manager = CookieManager::derive_from(
            config.http.public_base.clone(),
            &config.secrets.encryption().await?,
        );

        // Load and compile the WASM policies (and fallback to the default
        // embedded one)
        info!("Loading and compiling the policy module");
        let policy_factory =
            policy_factory_from_config(&config.policy, &config.matrix, &config.experimental)
                .await?;
        let policy_factory = Arc::new(policy_factory);

        load_policy_factory_dynamic_data_continuously(
            &policy_factory,
            PgRepositoryFactory::new(pool.clone()).boxed(),
            shutdown.clone(),
            &tasks,
        )
        .await?;

        let url_builder = UrlBuilder::new(
            config.http.public_base.clone(),
            config.http.issuer.clone(),
            None,
        );

        // Load the site configuration
        let site_config = site_config_from_config(
            &config.branding,
            &config.matrix,
            &config.experimental,
            &config.passwords,
            &config.account,
            &config.captcha,
            &config.sms,
        )?;

        // Load and compile the templates
        let templates = templates_from_config(
            &config.templates,
            &site_config,
            &url_builder,
            // Don't use strict mode in production yet
            false,
        )
        .await?;

        let http_client = crate::reqwest_client();

        let connector_registry =
            homeserver_connection_from_config(&config.matrix, http_client.clone()).await?;
        let matrix_shared_secret = config.matrix.secret().await?;

        if !options.no_worker {
            let notifications = notification_center_from_config(
                &config.email,
                &config.sms,
                &templates,
                &config.experimental,
            )?;

            if let Some(mailer) = notifications.email() {
                test_mailer_in_background_with_shutdown(
                    mailer,
                    Duration::from_secs(30),
                    shutdown.clone(),
                    &tasks,
                );
            }
            info!("Starting task worker");
            let database_url = database_url_from_config(&config.database)?;
            pasion_tasks::init_and_run(
                PgRepositoryFactory::new(pool.clone()),
                database_url,
                SystemClock::default(),
                &notifications,
                connector_registry
                    .primary_homeserver()
                    .context("matrix connector registry has no primary provider")?,
                url_builder.clone(),
                &site_config,
                shutdown.clone(),
                &tasks,
            )
            .await?;
        }

        let listeners_config = config.http.listeners.clone();

        // Discover the hashed frontend script path from the Dioxus build output
        let frontend_script_src = listeners_config
            .iter()
            .flat_map(|l| &l.resources)
            .find_map(|r| {
                if let HttpResource::Assets { path } = r {
                    crate::server::discover_frontend_script(path)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "/assets/pasion-frontend.js".into());
        let frontend_script_src = url_builder.relative_url(&frontend_script_src);
        info!(frontend_script_src, "Discovered frontend script path");

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // The upstream OIDC metadata cache
        let metadata_cache = MetadataCache::new();

        // Initialize the activity tracker
        // Activity is flushed every minute
        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            Duration::from_mins(1),
            &tasks,
            shutdown.clone(),
        );

        let trusted_proxies = config.http.trusted_proxies.clone();

        // Build a rate limiter.
        // This should not raise an error here as the config should already have
        // been validated.
        let limiter = Limiter::new(&config.rate_limiting)
            .context("rate-limiting configuration is not valid")?;

        // Initialize the storage backend
        crate::storage::init(&config.storage).context("failed to initialize storage backend")?;

        let email_webhook_service =
            EmailWebhookService::from_email_config(&config.email, http_client.clone())
                .context("invalid email webhook configuration")?;

        // Explicitly the config to properly zeroize secret keys
        drop(config);

        limiter.start();

        let state = {
            let mut s = AppState {
                repository_factory: PgRepositoryFactory::new(pool),
                templates,
                key_store,
                cookie_manager,
                encrypter,
                url_builder,
                connector_registry,
                policy_factory,
                http_client,
                password_manager,
                metadata_cache,
                site_config,
                matrix_shared_secret,
                activity_tracker,
                trusted_proxies,
                limiter,
                frontend_script_src,
                email_webhook_service,
            };
            s.init_metrics();
            s.init_metadata_cache_with_shutdown(shutdown.clone(), tasks.clone());
            s
        };

        guard.disarm();
        Ok(Self {
            state,
            shutdown,
            tasks,
        })
    }

    /// Shared state, for hosts that support template/activity reloads.
    #[must_use]
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Build routes scoped to this prefix, including all middleware.
    #[must_use]
    pub fn router(&self, resources: &[HttpResource], prefix: Option<&str>) -> Router {
        crate::server::build_router(self.state.clone(), resources, prefix, None)
    }

    /// Cancel workers and wait for tracked tasks to finish.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}

impl Drop for PasionServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
