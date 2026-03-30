use std::{process::ExitCode, time::Duration};

use clap::Parser;
use figment::Figment;
use pasion_config::{AppConfig, ConfigurationSection};
use pasion_data_model::SystemClock;
use pasion_data_model::UrlBuilder;
use pasion_storage_pg::PgRepositoryFactory;
use tracing::{info, info_span};

use pasion_backend::{
    lifecycle::LifecycleManager,
    util::{
        database_url_from_config, diesel_pool_from_config, homeserver_connection_from_config,
        notification_center_from_config, site_config_from_config, templates_from_config,
        test_mailer_in_background,
    },
};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let shutdown = LifecycleManager::new()?;
        let span = info_span!("cli.worker.init").entered();
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        // Connect to the database
        info!("Connecting to the database");
        let pool = diesel_pool_from_config(&config.database).await?;

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
        )?;

        // Load and compile the templates
        let templates = templates_from_config(
            &config.templates,
            &site_config,
            &url_builder,
            // Don't use strict mode on task workers for now
            false,
        )
        .await?;

        let notifications =
            notification_center_from_config(&config.email, &config.sms, &templates)?;
        if let Some(mailer) = notifications.email() {
            test_mailer_in_background(mailer, Duration::from_secs(30));
        }

        let http_client = pasion_http::reqwest_client();
        let (conn, _registry) = homeserver_connection_from_config(&config.matrix, http_client).await?;

        let database_url = database_url_from_config(&config.database)?;

        drop(config);

        info!("Starting task scheduler");
        pasion_tasks::init_and_run(
            PgRepositoryFactory::new(pool.clone()),
            database_url,
            SystemClock::default(),
            &notifications,
            conn,
            url_builder,
            &site_config,
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker(),
        )
        .await?;

        span.exit();

        let exit_code = shutdown.run().await;

        Ok(exit_code)
    }
}
