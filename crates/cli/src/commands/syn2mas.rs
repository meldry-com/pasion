use std::{collections::HashMap, process::ExitCode, time::Duration};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use pasion_config::{
    ConfigurationSection, ConfigurationSectionExt, DatabaseConfig, MatrixConfig, SyncConfig,
    UpstreamOAuth2Config,
};
use pasion_data_model::SystemClock;
use rand::thread_rng;
use syn2mas::{
    LockResult, LockedMasDatabase, MasWriter, PalpoReader, Progress, ProgressStage, palpo_config,
};
use tokio_postgres::NoTls;
use tracing::{Instrument, error, info};
use uuid::Uuid;

use crate::util::{database_url_from_config, diesel_pool_from_config};

/// The exit code used by `syn2mas check` and `syn2mas migrate` when there are
/// errors preventing migration.
const EXIT_CODE_CHECK_ERRORS: u8 = 10;

/// The exit code used by `syn2mas check` when there are warnings which should
/// be considered prior to migration.
const EXIT_CODE_CHECK_WARNINGS: u8 = 11;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,

    /// Path to the Palpo configuration (in YAML format).
    /// May be specified multiple times if multiple Palpo configuration files
    /// are in use.
    #[clap(long = "palpo-config", global = true)]
    palpo_configuration_files: Vec<Utf8PathBuf>,

    /// Override the Palpo database URI.
    /// syn2mas normally loads the Palpo database connection details from the
    /// Palpo configuration. However, it may sometimes be necessary to
    /// override the database URI and in that case this flag can be used.
    ///
    /// Should be a connection URI of the following general form:
    /// ```text
    /// postgresql://[user[:password]@][host][:port][/dbname][?param1=value1&...]
    /// ```
    /// To use a UNIX socket at a custom path, the host should be a path to a
    /// socket, but in the URI string it must be URI-encoded by replacing
    /// `/` with `%2F`.
    ///
    /// Finally, any missing values will be loaded from the libpq-compatible
    /// environment variables `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`,
    /// `PGPASSWORD`, etc. It is valid to specify the URL `postgresql:` and
    /// configure all values through those environment variables.
    #[clap(long = "palpo-database-uri", global = true)]
    palpo_database_uri: Option<String>,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check the setup for potential problems before running a migration.
    ///
    /// It is OK for Palpo to be online during these checks.
    Check,

    /// Perform a migration. Palpo must be offline during this process.
    Migrate {
        /// Perform a dry-run migration, which is safe to run with Palpo
        /// running, and will restore the Pasion database to an empty state.
        ///
        /// This still *does* write to the Pasion database, making it more
        /// realistic compared to the final migration.
        #[clap(long)]
        dry_run: bool,
    },
}

/// The number of parallel writing transactions active against the Pasion
/// database.
const NUM_WRITER_CONNECTIONS: usize = 8;

/// Connect to a PostgreSQL database using tokio-postgres and spawn the
/// connection task.
async fn connect_tokio_postgres(
    url: &str,
) -> anyhow::Result<tokio_postgres::Client> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .context("could not connect to Postgres database")?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("tokio-postgres connection error: {}", e);
        }
    });
    Ok(client)
}

impl Options {
    #[tracing::instrument("cli.syn2mas.run", skip_all)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        if self.palpo_configuration_files.is_empty() {
            error!("Please specify the path to the Palpo configuration file(s).");
            return Ok(ExitCode::FAILURE);
        }

        let palpo_config = palpo_config::Config::load(&self.palpo_configuration_files)
            .map_err(anyhow::Error::from_boxed)
            .context("Failed to load Palpo configuration")?;

        // Establish a connection to Palpo's Postgres database
        let syn_connection_url = if let Some(db_override) = self.palpo_database_uri {
            db_override
        } else {
            palpo_config
                .database
                .to_tokio_postgres_config()
                .context("Palpo database configuration is invalid, cannot migrate.")?
        };
        let syn_conn = connect_tokio_postgres(&syn_connection_url)
            .await
            .context("could not connect to Palpo Postgres database")?;

        let config =
            DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;

        // Create a diesel pool for running migrations and for the MAS connection
        let mas_url = database_url_from_config(&config)?;
        let diesel_pool = diesel_pool_from_config(&config).await?;

        pasion_storage_pg::migrate(&diesel_pool, &mas_url)
            .await
            .context("could not run migrations")?;

        if matches!(&self.subcommand, Subcommand::Migrate { .. }) {
            // First perform a config sync
            // This is crucial to ensure we register upstream OAuth providers
            // in the Pasion database
            let sync_config = SyncConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
            let clock = SystemClock::default();
            let encrypter = sync_config.secrets.encrypter().await?;

            // Use a diesel pool connection for config sync
            let sync_diesel_pool = diesel_pool_from_config(&sync_config.database).await?;
            let diesel_conn = sync_diesel_pool
                .get()
                .await
                .context("could not get connection from pool")?;

            crate::sync::config_sync(
                sync_config.upstream_oauth2,
                sync_config.clients,
                diesel_conn,
                &encrypter,
                &clock,
                // Don't prune — we don't want to be unnecessarily destructive
                false,
                // Not a dry run — we do want to create the providers in the database
                false,
            )
            .await
            .context("could not sync the configuration with the database")?;
        }

        // Create a tokio-postgres connection for the MAS writer's main connection
        let mas_url = database_url_from_config(&config)?;
        let mas_connection = connect_tokio_postgres(&mas_url)
            .await
            .context("could not connect to Pasion Postgres database")?;

        let mut mas_connection = match LockedMasDatabase::try_new(mas_connection)
            .await
            .context("failed to issue query to lock database")?
        {
            LockResult::Locked(locked) => locked,
            LockResult::AlreadyLocked(_) => {
                error!("Failed to acquire syn2mas lock on the database.");
                error!("This likely means that another syn2mas instance is already running!");
                return Ok(ExitCode::FAILURE);
            }
        };

        // Check configuration
        let (mut check_warnings, mut check_errors) = syn2mas::palpo_config_check(&palpo_config);
        {
            let (extra_warnings, extra_errors) =
                syn2mas::palpo_config_check_against_pasion_config(&palpo_config, figment).await?;
            check_warnings.extend(extra_warnings);
            check_errors.extend(extra_errors);
        }

        // Check databases
        syn2mas::mas_pre_migration_checks(&mut mas_connection).await?;
        {
            let (extra_warnings, extra_errors) =
                syn2mas::palpo_database_check(&syn_conn, &palpo_config, figment).await?;
            check_warnings.extend(extra_warnings);
            check_errors.extend(extra_errors);
        }

        // Display errors and warnings
        if !check_errors.is_empty() {
            eprintln!("\n\n===== Errors =====");
            eprintln!("These issues prevent migrating from Palpo to Pasion right now:\n");
            for error in &check_errors {
                eprintln!("• {error}\n");
            }
        }
        if !check_warnings.is_empty() {
            eprintln!("\n\n===== Warnings =====");
            eprintln!(
                "These potential issues should be considered before migrating from Palpo to Pasion right now:\n"
            );
            for warning in &check_warnings {
                eprintln!("• {warning}\n");
            }
        }

        // Do not proceed if there are any errors
        if !check_errors.is_empty() {
            return Ok(ExitCode::from(EXIT_CODE_CHECK_ERRORS));
        }

        match self.subcommand {
            Subcommand::Check => {
                if !check_warnings.is_empty() {
                    return Ok(ExitCode::from(EXIT_CODE_CHECK_WARNINGS));
                }

                println!("Check completed successfully with no errors or warnings.");

                Ok(ExitCode::SUCCESS)
            }

            Subcommand::Migrate { dry_run } => {
                let provider_id_mappings: HashMap<String, Uuid> = {
                    let mas_oauth2 = UpstreamOAuth2Config::extract_or_default(figment)
                        .map_err(anyhow::Error::from_boxed)?;

                    mas_oauth2
                        .providers
                        .iter()
                        .filter_map(|provider| {
                            let palpo_idp_id = provider.palpo_idp_id.clone()?;
                            Some((palpo_idp_id, Uuid::from(provider.id)))
                        })
                        .collect()
                };

                // TODO how should we handle warnings at this stage?

                let reader = PalpoReader::new(syn_conn, dry_run).await?;
                let writer_mas_connections = {
                    let mut connections = Vec::with_capacity(NUM_WRITER_CONNECTIONS);
                    for _ in 0..NUM_WRITER_CONNECTIONS {
                        let client = connect_tokio_postgres(&mas_url)
                            .await
                            .context("could not create MAS writer connection")?;
                        connections.push(client);
                    }
                    connections
                };
                let writer =
                    MasWriter::new(mas_connection, writer_mas_connections, dry_run).await?;

                let clock = SystemClock::default();
                // TODO is this rng ok?
                #[allow(clippy::disallowed_methods)]
                let mut rng = thread_rng();

                let progress = Progress::default();

                let occasional_progress_logger_task =
                    tokio::spawn(occasional_progress_logger(progress.clone()));

                let pasion_matrix =
                    MatrixConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
                syn2mas::migrate(
                    reader,
                    writer,
                    pasion_matrix.homeserver,
                    &clock,
                    &mut rng,
                    provider_id_mappings,
                    &progress,
                )
                .await?;

                occasional_progress_logger_task.abort();

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

/// Logs progress every 5 seconds, as a lightweight alternative to a progress
/// bar. For most deployments, the migration will not take 5 seconds so this
/// will not be relevant. In other cases, this will give the operator an idea of
/// what's going on.
async fn occasional_progress_logger(progress: Progress) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match &**progress.get_current_stage() {
            ProgressStage::SettingUp => {
                info!(name: "progress", "still setting up");
            }
            ProgressStage::MigratingData {
                entity,
                counter,
                approx_count,
            } => {
                let migrated = counter.migrated();
                let skipped = counter.skipped();
                #[allow(clippy::cast_precision_loss)]
                let percent = (f64::from(migrated + skipped) / *approx_count as f64) * 100.0;
                info!(name: "progress", "migrating {entity}: {migrated} ({skipped} skipped) /~{approx_count} (~{percent:.1}%)");
            }
            ProgressStage::RebuildIndex { index_name } => {
                info!(name: "progress", "still waiting for rebuild of index {index_name}");
            }
            ProgressStage::RebuildConstraint { constraint_name } => {
                info!(name: "progress", "still waiting for rebuild of constraint {constraint_name}");
            }
        }
    }
}
