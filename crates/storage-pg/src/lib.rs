//! An implementation of the storage traits for a PostgreSQL database
//!
//! This backend uses [`diesel`] with [`diesel_async`] for all database access.

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]

use ::tracing::{info, warn};
use diesel::sql_types::{BigInt, Bool};
use diesel_async::{AsyncPgConnection, RunQueryDsl, pooled_connection::deadpool::Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

/// PostgreSQL account aggregate repositories.
pub mod account;
/// PostgreSQL app session repositories.
pub mod app_session;
/// PostgreSQL audit log repositories.
mod audit;
/// PostgreSQL notification persistence repositories.
pub mod notification;
/// PostgreSQL OAuth 2.0 repositories.
pub mod oauth2;
/// PostgreSQL personal access repositories.
pub mod personal;
/// PostgreSQL queue repositories.
pub mod queue;
/// Diesel schema definitions generated from the database
pub mod schema;
/// PostgreSQL upstream OAuth 2.0 repositories.
pub mod upstream_oauth2;
/// PostgreSQL user repositories.
pub mod user;
/// PostgreSQL workflow engine repositories.
pub mod workflow;

// Define `lower()` as a SQL function for Diesel (Diesel doesn't ship one).
diesel::define_sql_function! {
    /// SQL `lower()` function for case-insensitive text comparisons
    fn lower(x: diesel::sql_types::Text) -> diesel::sql_types::Text;
}

mod errors;
pub(crate) mod policy_data;
pub(crate) mod repository;
pub(crate) mod telemetry;
#[cfg(test)]
pub(crate) mod test_utils;
pub(crate) mod tracing;

pub(crate) use self::errors::DatabaseInconsistencyError;
pub use self::{
    errors::DatabaseError,
    repository::{PgRepository, PgRepositoryFactory},
};

/// Embedded Diesel migrations.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("diesel_migrations");

/// Run the migrations on the given connection pool.
///
/// The `database_url` is needed to establish a separate synchronous connection
/// for running diesel migrations (which require a synchronous
/// `MigrationHarness`).
///
/// This function acquires a PostgreSQL advisory lock to ensure that only one
/// migrator is running at a time.
///
/// For databases previously managed by sqlx, this will detect the
/// `_sqlx_migrations` table and stamp the diesel migration table accordingly.
///
/// # Errors
///
/// Returns an error if the migration fails.
#[::tracing::instrument(name = "db.migrate", skip_all, err)]
pub async fn migrate(
    pool: &Pool<AsyncPgConnection>,
    database_url: &str,
) -> Result<(), anyhow::Error> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("could not get connection from pool: {e}"))?;

    // Get the current database name for the advisory lock
    let db_name: String = diesel::sql_query("SELECT current_database()::text AS name")
        .get_result::<DbName>(&mut *conn)
        .await
        .map_err(|e| anyhow::anyhow!("could not get current database name: {e}"))?
        .name;

    let lock_id = generate_lock_id(&db_name);

    // Try to acquire the advisory lock, retrying with backoff
    let mut backoff = std::time::Duration::from_millis(250);
    loop {
        let result: AdvisoryLockResult =
            diesel::sql_query("SELECT pg_try_advisory_lock($1) AS acquired")
                .bind::<BigInt, _>(lock_id)
                .get_result(&mut *conn)
                .await
                .map_err(|e| anyhow::anyhow!("could not acquire advisory lock: {e}"))?;

        if result.acquired {
            break;
        }

        warn!(
            "Another process is already running migrations on the database, waiting {duration}s and trying again…",
            duration = backoff.as_secs_f32()
        );
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(5));
    }

    // Bridge: if coming from sqlx-managed database, stamp diesel migrations
    bridge_from_sqlx(&mut *conn).await?;

    // Run pending migrations using diesel_migrations.
    // MigrationHarness requires a synchronous connection, so we establish
    // a separate blocking connection via AsyncConnectionWrapper.
    let url = database_url.to_owned();
    let migration_result = tokio::task::spawn_blocking(move || {
        use diesel::Connection;
        let mut wrapper = diesel_async::async_connection_wrapper::AsyncConnectionWrapper::<
            AsyncPgConnection,
        >::establish(&url)
        .map_err(|e| anyhow::anyhow!("could not establish migration connection: {e}"))?;
        let applied = wrapper
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("could not run migrations: {e}"))?;
        // Convert MigrationVersion (which borrows wrapper) to owned strings
        let versions: Vec<String> = applied.iter().map(|v| v.to_string()).collect();
        Ok::<_, anyhow::Error>(versions)
    })
    .await
    .map_err(|e| anyhow::anyhow!("migration task panicked: {e}"))??;

    for version in &migration_result {
        info!("Applied migration: {version}");
    }

    // Release the advisory lock
    let _ = diesel::sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(lock_id)
        .execute(&mut *conn)
        .await;

    Ok(())
}

/// Check if there are pending migrations.
///
/// # Errors
///
/// Returns an error if there is a problem checking the migration state.
pub async fn has_pending_migrations(database_url: &str) -> Result<bool, anyhow::Error> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || {
        use diesel::Connection;
        let mut wrapper = diesel_async::async_connection_wrapper::AsyncConnectionWrapper::<
            AsyncPgConnection,
        >::establish(&url)
        .map_err(|e| anyhow::anyhow!("could not establish connection: {e}"))?;
        let pending = wrapper
            .pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("could not check pending migrations: {e}"))?;
        Ok::<_, anyhow::Error>(!pending.is_empty())
    })
    .await
    .map_err(|e| anyhow::anyhow!("migration check task panicked: {e}"))?
}

/// Bridge from sqlx-managed migrations to diesel-managed migrations.
///
/// If `_sqlx_migrations` exists but `__diesel_schema_migrations` does not,
/// creates the diesel table and stamps the initial migration as applied.
async fn bridge_from_sqlx(conn: &mut AsyncPgConnection) -> Result<(), anyhow::Error> {
    // Check if _sqlx_migrations table exists
    let has_sqlx: HasTable = diesel::sql_query(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = '_sqlx_migrations'
        ) AS exists",
    )
    .get_result(conn)
    .await
    .map_err(|e| anyhow::anyhow!("could not check for _sqlx_migrations table: {e}"))?;

    if !has_sqlx.exists {
        return Ok(());
    }

    // Check if __diesel_schema_migrations already exists
    let has_diesel: HasTable = diesel::sql_query(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = '__diesel_schema_migrations'
        ) AS exists",
    )
    .get_result(conn)
    .await
    .map_err(|e| anyhow::anyhow!("could not check for __diesel_schema_migrations table: {e}"))?;

    if has_diesel.exists {
        // Already bridged or fresh diesel install
        return Ok(());
    }

    info!("Detected sqlx-managed database, bridging to diesel migrations");

    // Create the diesel schema migrations table and stamp initial migration
    diesel::sql_query(
        "CREATE TABLE __diesel_schema_migrations (
            version VARCHAR(50) NOT NULL PRIMARY KEY,
            run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(conn)
    .await
    .map_err(|e| anyhow::anyhow!("could not create __diesel_schema_migrations table: {e}"))?;

    // Stamp the initial consolidated migration as already applied
    diesel::sql_query(
        "INSERT INTO __diesel_schema_migrations (version, run_on) VALUES ('00000000000000', NOW())",
    )
    .execute(conn)
    .await
    .map_err(|e| anyhow::anyhow!("could not stamp initial migration: {e}"))?;

    info!("Successfully bridged from sqlx to diesel migrations");

    Ok(())
}

// Copied from the sqlx source code, so that we generate the same lock ID
// for backward compatibility with existing advisory locks.
fn generate_lock_id(database_name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    0x3d32_ad9e * i64::from(CRC_IEEE.checksum(database_name.as_bytes()))
}

/// Helper struct for advisory lock queries
#[derive(diesel::QueryableByName)]
struct AdvisoryLockResult {
    #[diesel(sql_type = Bool)]
    acquired: bool,
}

/// Helper struct for database name query
#[derive(diesel::QueryableByName)]
struct DbName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

/// Helper struct for table existence check
#[derive(diesel::QueryableByName)]
struct HasTable {
    #[diesel(sql_type = Bool)]
    exists: bool,
}
