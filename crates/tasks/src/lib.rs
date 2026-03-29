//! Background task queue and worker for the Pasion authentication service.
//!
//! This crate implements an asynchronous job queue backed by PostgreSQL. Tasks
//! are enqueued during HTTP request handling and processed by a background
//! worker. Task types include:
//!
//! - **Notification delivery** — sending verification codes, password-reset
//!   links, and other outbound messages.
//! - **Homeserver provisioning** — creating / deactivating Matrix users via the
//!   homeserver admin API
//! - **Session cleanup** — expiring old sessions and tokens
//! - **Account recovery** — processing recovery ticket workflows
//!
//! # Entry points
//!
//! - [`init`] — Register all task handlers and return a [`QueueWorker`] (does
//!   **not** start processing).
//! - [`init_and_run`] — Same as [`init`], but immediately spawns the worker
//!   onto the provided [`TaskTracker`].

use std::sync::{Arc, LazyLock};

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use new_queue::QueueRunnerError;
use opentelemetry::metrics::Meter;
use pasion_data_model::{Clock, SiteConfig};
use pasion_matrix::HomeserverConnection;
use pasion_messaging::NotificationCenter;
use pasion_router::UrlBuilder;
use pasion_storage::{BoxRepository, RepositoryError, RepositoryFactory};
use pasion_storage_pg::PgRepositoryFactory;
use rand::SeedableRng;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub use crate::new_queue::QueueWorker;

mod cleanup;
mod email;
mod matrix;
mod new_queue;
mod recovery;
mod sessions;
mod sms;
mod user;

static METER: LazyLock<Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});

#[derive(Clone)]
struct State {
    repository_factory: PgRepositoryFactory,
    /// Database URL used for tokio-postgres LISTEN/NOTIFY
    database_url: String,
    notifications: NotificationCenter,
    clock: Arc<dyn Clock>,
    homeserver: Arc<dyn HomeserverConnection>,
    url_builder: UrlBuilder,
    site_config: SiteConfig,
}

impl State {
    pub fn new(
        repository_factory: PgRepositoryFactory,
        database_url: String,
        clock: impl Clock + 'static,
        notifications: NotificationCenter,
        homeserver: impl HomeserverConnection + 'static,
        url_builder: UrlBuilder,
        site_config: SiteConfig,
    ) -> Self {
        Self {
            repository_factory,
            database_url,
            notifications,
            clock: Arc::new(clock),
            homeserver: Arc::new(homeserver),
            url_builder,
            site_config,
        }
    }

    pub fn pool(&self) -> &DieselPool<AsyncPgConnection> {
        self.repository_factory.pool()
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn clock(&self) -> &dyn Clock {
        &self.clock
    }

    pub fn notifications(&self) -> &NotificationCenter {
        &self.notifications
    }

    // This is fine for now, we may move that to a trait at some point.
    #[allow(clippy::unused_self, clippy::disallowed_methods)]
    pub fn rng(&self) -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_rng(rand::thread_rng()).expect("failed to seed rng")
    }

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        self.repository_factory.create().await
    }

    pub fn matrix_connection(&self) -> &dyn HomeserverConnection {
        self.homeserver.as_ref()
    }

    pub fn url_builder(&self) -> &UrlBuilder {
        &self.url_builder
    }

    pub fn site_config(&self) -> &SiteConfig {
        &self.site_config
    }
}

/// Initialise the worker, without running it.
///
/// This is mostly useful for tests.
///
/// # Errors
///
/// This function can fail if the database connection fails.
pub async fn init(
    repository_factory: PgRepositoryFactory,
    database_url: String,
    clock: impl Clock + 'static,
    notifications: &NotificationCenter,
    homeserver: impl HomeserverConnection + 'static,
    url_builder: UrlBuilder,
    site_config: &SiteConfig,
    cancellation_token: CancellationToken,
) -> Result<QueueWorker, QueueRunnerError> {
    let state = State::new(
        repository_factory,
        database_url,
        clock,
        notifications.clone(),
        homeserver,
        url_builder,
        site_config.clone(),
    );
    let mut worker = QueueWorker::new(state, cancellation_token).await?;

    worker
        .register_handler::<pasion_storage::queue::CleanupRevokedOAuthAccessTokensJob>()
        .register_handler::<pasion_storage::queue::CleanupExpiredOAuthAccessTokensJob>()
        .register_handler::<pasion_storage::queue::CleanupRevokedOAuthRefreshTokensJob>()
        .register_handler::<pasion_storage::queue::CleanupConsumedOAuthRefreshTokensJob>()
        .register_handler::<pasion_storage::queue::CleanupUserRegistrationsJob>()
        .register_handler::<pasion_storage::queue::CleanupFinishedOAuth2SessionsJob>()
        .register_handler::<pasion_storage::queue::CleanupFinishedUserSessionsJob>()
        .register_handler::<pasion_storage::queue::CleanupOAuthAuthorizationGrantsJob>()
        .register_handler::<pasion_storage::queue::CleanupOAuthDeviceCodeGrantsJob>()
        .register_handler::<pasion_storage::queue::CleanupUserRecoverySessionsJob>()
        .register_handler::<pasion_storage::queue::CleanupUserEmailAuthenticationsJob>()
        .register_handler::<pasion_storage::queue::CleanupUpstreamOAuthSessionsJob>()
        .register_handler::<pasion_storage::queue::CleanupUpstreamOAuthLinksJob>()
        .register_handler::<pasion_storage::queue::CleanupQueueJobsJob>()
        .register_handler::<pasion_storage::queue::DeactivateUserJob>()
        .register_handler::<pasion_storage::queue::DeleteDeviceJob>()
        .register_handler::<pasion_storage::queue::ProvisionDeviceJob>()
        .register_handler::<pasion_storage::queue::ProvisionUserJob>()
        .register_handler::<pasion_storage::queue::ReactivateUserJob>()
        .register_handler::<pasion_storage::queue::SendAccountRecoveryEmailsJob>()
        .register_handler::<pasion_storage::queue::SendEmailAuthenticationCodeJob>()
        .register_handler::<pasion_storage::queue::SendSmsAuthenticationCodeJob>()
        .register_handler::<pasion_storage::queue::SyncDevicesJob>()
        .register_handler::<pasion_storage::queue::VerifyEmailJob>()
        .register_handler::<pasion_storage::queue::ExpireInactiveSessionsJob>()
        .register_handler::<pasion_storage::queue::ExpireInactiveOAuthSessionsJob>()
        .register_handler::<pasion_storage::queue::ExpireInactiveUserSessionsJob>()
        .register_handler::<pasion_storage::queue::PruneStalePolicyDataJob>()
        .register_handler::<pasion_storage::queue::CleanupInactiveOAuth2SessionIpsJob>()
        .register_handler::<pasion_storage::queue::CleanupInactiveUserSessionIpsJob>()
        .register_deprecated_queue("cleanup-expired-tokens")
        .register_deprecated_queue("cleanup-finished-compat-sessions")
        .register_deprecated_queue("expire-inactive-compat-sessions")
        .register_deprecated_queue("cleanup-inactive-compat-session-ips")
        // Recurring jobs are spread across the hour at ~5 minute intervals
        // to avoid clustering and distribute database load evenly.
        .add_schedule(
            "cleanup-revoked-oauth-access-tokens",
            // Run this job every hour at minute 0
            "0 0 * * * *".parse()?,
            pasion_storage::queue::CleanupRevokedOAuthAccessTokensJob,
        )
        .add_schedule(
            "cleanup-revoked-oauth-refresh-tokens",
            // Run this job every hour at minute 5
            "0 5 * * * *".parse()?,
            pasion_storage::queue::CleanupRevokedOAuthRefreshTokensJob,
        )
        .add_schedule(
            "cleanup-consumed-oauth-refresh-tokens",
            // Run this job every hour at minute 5 (safe to parallelize with revoked)
            "0 5 * * * *".parse()?,
            pasion_storage::queue::CleanupConsumedOAuthRefreshTokensJob,
        )
        .add_schedule(
            "cleanup-finished-oauth2-sessions",
            // Run this job every hour at minute 15
            "0 15 * * * *".parse()?,
            pasion_storage::queue::CleanupFinishedOAuth2SessionsJob,
        )
        .add_schedule(
            "cleanup-finished-user-sessions",
            // Run this job every hour at minute 20
            "0 20 * * * *".parse()?,
            pasion_storage::queue::CleanupFinishedUserSessionsJob,
        )
        .add_schedule(
            "cleanup-inactive-oauth2-session-ips",
            // Run this job every hour at minute 25
            "0 25 * * * *".parse()?,
            pasion_storage::queue::CleanupInactiveOAuth2SessionIpsJob,
        )
        .add_schedule(
            "cleanup-inactive-user-session-ips",
            // Run this job every hour at minute 25
            "0 25 * * * *".parse()?,
            pasion_storage::queue::CleanupInactiveUserSessionIpsJob,
        )
        .add_schedule(
            "cleanup-oauth-authorization-grants",
            // Run this job every hour at minute 30
            "0 30 * * * *".parse()?,
            pasion_storage::queue::CleanupOAuthAuthorizationGrantsJob,
        )
        .add_schedule(
            "cleanup-oauth-device-code-grants",
            // Run this job every hour at minute 35
            "0 35 * * * *".parse()?,
            pasion_storage::queue::CleanupOAuthDeviceCodeGrantsJob,
        )
        .add_schedule(
            "cleanup-upstream-oauth-sessions",
            // Run this job every hour at minute 40 (independent, safe to parallelize)
            "0 40 * * * *".parse()?,
            pasion_storage::queue::CleanupUpstreamOAuthSessionsJob,
        )
        .add_schedule(
            "cleanup-upstream-oauth-links",
            // Run this job every hour at minute 40
            "0 40 * * * *".parse()?,
            pasion_storage::queue::CleanupUpstreamOAuthLinksJob,
        )
        // User cleanup jobs (minutes 45, 50)
        .add_schedule(
            "cleanup-user-registrations",
            // Run this job every hour at minute 45
            "0 45 * * * *".parse()?,
            pasion_storage::queue::CleanupUserRegistrationsJob,
        )
        .add_schedule(
            "cleanup-user-recovery-sessions",
            // Run this job every hour at minute 50
            "0 50 * * * *".parse()?,
            pasion_storage::queue::CleanupUserRecoverySessionsJob,
        )
        .add_schedule(
            "cleanup-user-email-authentications",
            // Run this job every hour at minute 50
            "0 50 * * * *".parse()?,
            pasion_storage::queue::CleanupUserEmailAuthenticationsJob,
        )
        .add_schedule(
            "cleanup-queue-jobs",
            // Run this job every hour at minute 55
            "0 55 * * * *".parse()?,
            pasion_storage::queue::CleanupQueueJobsJob,
        )
        .add_schedule(
            "cleanup-expired-oauth-access-tokens",
            // Run this job every 4 hours at minute 5
            "0 5 */4 * * *".parse()?,
            pasion_storage::queue::CleanupExpiredOAuthAccessTokensJob,
        )
        .add_schedule(
            "expire-inactive-sessions",
            // Run this job every 15 minutes at second 30
            "30 */15 * * * *".parse()?,
            pasion_storage::queue::ExpireInactiveSessionsJob,
        )
        .add_schedule(
            "prune-stale-policy-data",
            // Run once a day at 2:00 AM
            "0 0 2 * * *".parse()?,
            pasion_storage::queue::PruneStalePolicyDataJob,
        );

    Ok(worker)
}

/// Initialise the worker and run it.
///
/// # Errors
///
/// This function can fail if the database connection fails.
#[expect(clippy::too_many_arguments, reason = "this is fine")]
pub async fn init_and_run(
    repository_factory: PgRepositoryFactory,
    database_url: String,
    clock: impl Clock + 'static,
    notifications: &NotificationCenter,
    homeserver: impl HomeserverConnection + 'static,
    url_builder: UrlBuilder,
    site_config: &SiteConfig,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), QueueRunnerError> {
    let worker = init(
        repository_factory,
        database_url,
        clock,
        notifications,
        homeserver,
        url_builder,
        site_config,
        cancellation_token,
    )
    .await?;

    task_tracker.spawn(worker.run());

    Ok(())
}
