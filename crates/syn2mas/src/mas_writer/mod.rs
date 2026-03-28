//! # Pasion Writer
//!
//! This module is responsible for writing new records to Pasion' database.

use std::{
    fmt::Display,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use chrono::{DateTime, Utc};
use futures_util::{FutureExt, future::BoxFuture};
use thiserror::Error;
use thiserror_ext::{Construct, ContextInto};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_postgres::Client;
use tokio_postgres::types::ToSql;
use tracing::{Instrument, error, info, warn};
use uuid::{NonNilUuid, Uuid};

use self::{
    constraint_pausing::{ConstraintDescription, IndexDescription},
    locking::LockedMasDatabase,
};
use crate::Progress;

pub mod checks;
pub mod locking;

mod constraint_pausing;

#[derive(Debug, Error, Construct, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}")]
    Database {
        #[source]
        source: tokio_postgres::Error,
        context: String,
    },

    #[error("writer connection pool shut down due to error")]
    #[expect(clippy::enum_variant_names)]
    WriterConnectionPoolError,

    #[error("inconsistent database: {0}")]
    Inconsistent(String),

    #[error("bug in syn2mas: write buffers not finished")]
    WriteBuffersNotFinished,

    #[error("{0}")]
    Multiple(MultipleErrors),
}

#[derive(Debug)]
pub struct MultipleErrors {
    errors: Vec<Error>,
}

impl Display for MultipleErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multiple errors")?;
        for error in &self.errors {
            write!(f, "\n- {error}")?;
        }
        Ok(())
    }
}

impl From<Vec<Error>> for MultipleErrors {
    fn from(value: Vec<Error>) -> Self {
        MultipleErrors { errors: value }
    }
}

struct WriterConnectionPool {
    /// How many connections are in circulation
    num_connections: usize,

    /// A receiver handle to get a writer connection
    /// The writer connection will be mid-transaction!
    connection_rx: Receiver<Result<Client, Error>>,

    /// A sender handle to return a writer connection to the pool
    /// The connection should still be mid-transaction!
    connection_tx: Sender<Result<Client, Error>>,
}

impl WriterConnectionPool {
    pub fn new(connections: Vec<Client>) -> Self {
        let num_connections = connections.len();
        let (connection_tx, connection_rx) = mpsc::channel(num_connections);
        for connection in connections {
            connection_tx
                .try_send(Ok(connection))
                .expect("there should be room for this connection");
        }

        WriterConnectionPool {
            num_connections,
            connection_rx,
            connection_tx,
        }
    }

    pub async fn spawn_with_connection<F>(&mut self, task: F) -> Result<(), Error>
    where
        F: for<'conn> FnOnce(&'conn Client) -> BoxFuture<'conn, Result<(), Error>>
            + Send
            + 'static,
    {
        match self.connection_rx.recv().await {
            Some(Ok(connection)) => {
                let connection_tx = self.connection_tx.clone();
                tokio::task::spawn(
                    async move {
                        let to_return = match task(&connection).await {
                            Ok(()) => Ok(connection),
                            Err(error) => {
                                error!("error in writer: {error}");
                                Err(error)
                            }
                        };
                        // This should always succeed in sending unless we're already shutting
                        // down for some other reason.
                        let _: Result<_, _> = connection_tx.send(to_return).await;
                    }
                    .instrument(tracing::debug_span!("spawn_with_connection")),
                );

                Ok(())
            }
            Some(Err(error)) => {
                // This should always succeed in sending unless we're already shutting
                // down for some other reason.
                let _: Result<_, _> = self.connection_tx.send(Err(error)).await;

                Err(Error::WriterConnectionPoolError)
            }
            None => {
                unreachable!("we still hold a reference to the sender, so this shouldn't happen")
            }
        }
    }

    /// Finishes writing to the database, committing all changes.
    ///
    /// # Errors
    ///
    /// - If any errors were returned to the pool.
    /// - If committing the changes failed.
    ///
    /// # Panics
    ///
    /// - If connections were not returned to the pool. (This indicates a
    ///   serious bug.)
    pub async fn finish(self) -> Result<(), Vec<Error>> {
        let mut errors = Vec::new();

        let Self {
            num_connections,
            mut connection_rx,
            connection_tx,
        } = self;
        // Drop the sender handle so we gracefully allow the receiver to close
        drop(connection_tx);

        let mut finished_connections = 0;

        while let Some(connection_or_error) = connection_rx.recv().await {
            finished_connections += 1;

            match connection_or_error {
                Ok(connection) => {
                    if let Err(err) = connection.execute("COMMIT", &[]).await {
                        errors.push(err.into_database("commit writer transaction"));
                    }
                }
                Err(error) => {
                    errors.push(error);
                }
            }
        }
        assert_eq!(
            finished_connections, num_connections,
            "syn2mas had a bug: connections went missing {finished_connections} != {num_connections}"
        );

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Small utility to make sure `finish()` is called on all write buffers
/// before committing to the database.
#[derive(Default)]
struct FinishChecker {
    counter: Arc<AtomicU32>,
}

struct FinishCheckerHandle {
    counter: Arc<AtomicU32>,
}

impl FinishChecker {
    /// Acquire a new handle, for a task that should declare when it has
    /// finished.
    pub fn handle(&self) -> FinishCheckerHandle {
        self.counter.fetch_add(1, Ordering::SeqCst);
        FinishCheckerHandle {
            counter: Arc::clone(&self.counter),
        }
    }

    /// Check that all handles have been declared as finished.
    pub fn check_all_finished(self) -> Result<(), Error> {
        if self.counter.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(Error::WriteBuffersNotFinished)
        }
    }
}

impl FinishCheckerHandle {
    /// Declare that the task this handle represents has been finished.
    pub fn declare_finished(self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct MasWriter {
    conn: LockedMasDatabase,
    writer_pool: WriterConnectionPool,
    dry_run: bool,

    indices_to_restore: Vec<IndexDescription>,
    constraints_to_restore: Vec<ConstraintDescription>,

    write_buffer_finish_checker: FinishChecker,
}

pub trait WriteBatch: Send + Sync + Sized + 'static {
    fn write_batch(
        conn: &Client,
        batch: Vec<Self>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

pub struct MasNewUser {
    pub user_id: NonNilUuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
    /// Whether the user was a Palpo guest.
    /// Although Pasion doesn't support guest access, it's still useful to track
    /// for the future.
    pub is_guest: bool,
}

impl WriteBatch for MasNewUser {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        // `UNNEST` is a fast way to do bulk inserts, as it lets us send multiple rows
        // in one statement without having to change the statement
        // SQL thus altering the query plan.
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut usernames: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut locked_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut deactivated_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut can_request_admins: Vec<bool> = Vec::with_capacity(batch.len());
        let mut is_guests: Vec<bool> = Vec::with_capacity(batch.len());
        for MasNewUser {
            user_id,
            username,
            created_at,
            locked_at,
            deactivated_at,
            can_request_admin,
            is_guest,
        } in batch
        {
            user_ids.push(user_id.get());
            usernames.push(username);
            created_ats.push(created_at);
            locked_ats.push(locked_at);
            deactivated_ats.push(deactivated_at);
            can_request_admins.push(can_request_admin);
            is_guests.push(is_guest);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__users (
              user_id, username,
              created_at, locked_at,
              deactivated_at,
              can_request_admin, is_guest)
            SELECT * FROM UNNEST(
              $1::UUID[], $2::TEXT[],
              $3::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[],
              $5::TIMESTAMP WITH TIME ZONE[],
              $6::BOOL[], $7::BOOL[])
            "#,
            &[
                &user_ids as &(dyn ToSql + Sync),
                &usernames,
                &created_ats,
                &locked_ats,
                &deactivated_ats,
                &can_request_admins,
                &is_guests,
            ],
        )
        .await
        .into_database("writing users to Pasion")?;

        Ok(())
    }
}

pub struct MasNewUserPassword {
    pub user_password_id: Uuid,
    pub user_id: NonNilUuid,
    pub hashed_password: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUserPassword {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_password_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut hashed_passwords: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut versions: Vec<i32> = Vec::with_capacity(batch.len());
        for MasNewUserPassword {
            user_password_id,
            user_id,
            hashed_password,
            created_at,
        } in batch
        {
            user_password_ids.push(user_password_id);
            user_ids.push(user_id.get());
            hashed_passwords.push(hashed_password);
            created_ats.push(created_at);
            versions.push(MIGRATED_PASSWORD_VERSION.into());
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__user_passwords
            (user_password_id, user_id, hashed_password, created_at, version)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[], $5::INTEGER[])
            "#,
            &[
                &user_password_ids as &(dyn ToSql + Sync),
                &user_ids,
                &hashed_passwords,
                &created_ats,
                &versions,
            ],
        )
        .await
        .into_database("writing users to Pasion")?;

        Ok(())
    }
}

pub struct MasNewEmailThreepid {
    pub user_email_id: Uuid,
    pub user_id: NonNilUuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewEmailThreepid {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_email_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut emails: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewEmailThreepid {
            user_email_id,
            user_id,
            email,
            created_at,
        } in batch
        {
            user_email_ids.push(user_email_id);
            user_ids.push(user_id.get());
            emails.push(email);
            created_ats.push(created_at);
        }

        // `confirmed_at` is going to get removed in a future Pasion release,
        // so just populate with `created_at`
        conn.execute(
            r#"
            INSERT INTO syn2mas__user_emails
            (user_email_id, user_id, email, created_at, confirmed_at)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[])
            "#,
            &[
                &user_email_ids as &(dyn ToSql + Sync),
                &user_ids,
                &emails,
                &created_ats,
            ],
        )
        .await
        .into_database("writing emails to Pasion")?;

        Ok(())
    }
}

pub struct MasNewUnsupportedThreepid {
    pub user_id: NonNilUuid,
    pub medium: String,
    pub address: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUnsupportedThreepid {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut mediums: Vec<String> = Vec::with_capacity(batch.len());
        let mut addresses: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewUnsupportedThreepid {
            user_id,
            medium,
            address,
            created_at,
        } in batch
        {
            user_ids.push(user_id.get());
            mediums.push(medium);
            addresses.push(address);
            created_ats.push(created_at);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__user_unsupported_third_party_ids
            (user_id, medium, address, created_at)
            SELECT * FROM UNNEST($1::UUID[], $2::TEXT[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[])
            "#,
            &[
                &user_ids as &(dyn ToSql + Sync),
                &mediums,
                &addresses,
                &created_ats,
            ],
        )
        .await
        .into_database("writing unsupported threepids to Pasion")?;

        Ok(())
    }
}

pub struct MasNewUpstreamOauthLink {
    pub link_id: Uuid,
    pub user_id: NonNilUuid,
    pub upstream_provider_id: Uuid,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUpstreamOauthLink {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut link_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut upstream_provider_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut subjects: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewUpstreamOauthLink {
            link_id,
            user_id,
            upstream_provider_id,
            subject,
            created_at,
        } in batch
        {
            link_ids.push(link_id);
            user_ids.push(user_id.get());
            upstream_provider_ids.push(upstream_provider_id);
            subjects.push(subject);
            created_ats.push(created_at);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__upstream_oauth_links
            (upstream_oauth_link_id, user_id, upstream_oauth_provider_id, subject, created_at)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::UUID[], $4::TEXT[], $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &[
                &link_ids as &(dyn ToSql + Sync),
                &user_ids,
                &upstream_provider_ids,
                &subjects,
                &created_ats,
            ],
        )
        .await
        .into_database("writing unsupported threepids to Pasion")?;

        Ok(())
    }
}

pub struct MasNewCompatSession {
    pub session_id: Uuid,
    pub user_id: NonNilUuid,
    pub device_id: Option<String>,
    pub human_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_palpo_admin: bool,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl WriteBatch for MasNewCompatSession {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut device_ids: Vec<Option<String>> = Vec::with_capacity(batch.len());
        let mut human_names: Vec<Option<String>> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut is_palpo_admins: Vec<bool> = Vec::with_capacity(batch.len());
        let mut last_active_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut last_active_ips: Vec<Option<IpAddr>> = Vec::with_capacity(batch.len());
        let mut user_agents: Vec<Option<String>> = Vec::with_capacity(batch.len());

        for MasNewCompatSession {
            session_id,
            user_id,
            device_id,
            human_name,
            created_at,
            is_palpo_admin,
            last_active_at,
            last_active_ip,
            user_agent,
        } in batch
        {
            session_ids.push(session_id);
            user_ids.push(user_id.get());
            device_ids.push(device_id);
            human_names.push(human_name);
            created_ats.push(created_at);
            is_palpo_admins.push(is_palpo_admin);
            last_active_ats.push(last_active_at);
            last_active_ips.push(last_active_ip);
            user_agents.push(user_agent);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__compat_sessions (
              compat_session_id, user_id,
              device_id, human_name,
              created_at, is_palpo_admin,
              last_active_at, last_active_ip,
              user_agent)
            SELECT * FROM UNNEST(
              $1::UUID[], $2::UUID[],
              $3::TEXT[], $4::TEXT[],
              $5::TIMESTAMP WITH TIME ZONE[], $6::BOOLEAN[],
              $7::TIMESTAMP WITH TIME ZONE[], $8::INET[],
              $9::TEXT[])
            "#,
            &[
                &session_ids as &(dyn ToSql + Sync),
                &user_ids,
                &device_ids,
                &human_names,
                &created_ats,
                &is_palpo_admins,
                &last_active_ats,
                &last_active_ips,
                &user_agents,
            ],
        )
        .await
        .into_database("writing compat sessions to Pasion")?;

        Ok(())
    }
}

pub struct MasNewCompatAccessToken {
    pub token_id: Uuid,
    pub session_id: Uuid,
    pub access_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl WriteBatch for MasNewCompatAccessToken {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut access_tokens: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut expires_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());

        for MasNewCompatAccessToken {
            token_id,
            session_id,
            access_token,
            created_at,
            expires_at,
        } in batch
        {
            token_ids.push(token_id);
            session_ids.push(session_id);
            access_tokens.push(access_token);
            created_ats.push(created_at);
            expires_ats.push(expires_at);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__compat_access_tokens (
              compat_access_token_id,
              compat_session_id,
              access_token,
              created_at,
              expires_at)
            SELECT * FROM UNNEST(
              $1::UUID[],
              $2::UUID[],
              $3::TEXT[],
              $4::TIMESTAMP WITH TIME ZONE[],
              $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &[
                &token_ids as &(dyn ToSql + Sync),
                &session_ids,
                &access_tokens,
                &created_ats,
                &expires_ats,
            ],
        )
        .await
        .into_database("writing compat access tokens to Pasion")?;

        Ok(())
    }
}

pub struct MasNewCompatRefreshToken {
    pub refresh_token_id: Uuid,
    pub session_id: Uuid,
    pub access_token_id: Uuid,
    pub refresh_token: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewCompatRefreshToken {
    async fn write_batch(conn: &Client, batch: Vec<Self>) -> Result<(), Error> {
        let mut refresh_token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut access_token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut refresh_tokens: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewCompatRefreshToken {
            refresh_token_id,
            session_id,
            access_token_id,
            refresh_token,
            created_at,
        } in batch
        {
            refresh_token_ids.push(refresh_token_id);
            session_ids.push(session_id);
            access_token_ids.push(access_token_id);
            refresh_tokens.push(refresh_token);
            created_ats.push(created_at);
        }

        conn.execute(
            r#"
            INSERT INTO syn2mas__compat_refresh_tokens (
              compat_refresh_token_id,
              compat_session_id,
              compat_access_token_id,
              refresh_token,
              created_at)
            SELECT * FROM UNNEST(
              $1::UUID[],
              $2::UUID[],
              $3::UUID[],
              $4::TEXT[],
              $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &[
                &refresh_token_ids as &(dyn ToSql + Sync),
                &session_ids,
                &access_token_ids,
                &refresh_tokens,
                &created_ats,
            ],
        )
        .await
        .into_database("writing compat refresh tokens to Pasion")?;

        Ok(())
    }
}

/// The 'version' of the password hashing scheme used for passwords when they
/// are migrated from Palpo to Pasion.
/// This is version 1, as in the previous syn2mas script.
// TODO hardcoding version to `1` may not be correct long-term?
pub const MIGRATED_PASSWORD_VERSION: u16 = 1;

/// List of all Pasion tables that are written to by syn2mas.
pub const MAS_TABLES_AFFECTED_BY_MIGRATION: &[&str] = &[
    "users",
    "user_passwords",
    "user_emails",
    "user_unsupported_third_party_ids",
    "upstream_oauth_links",
    "compat_sessions",
    "compat_access_tokens",
    "compat_refresh_tokens",
];

/// Detect whether a syn2mas migration has started on the given database.
///
/// Concretly, this checks for the presence of syn2mas restoration tables.
///
/// Returns `true` if syn2mas has started, or `false` if it hasn't.
///
/// # Errors
///
/// Errors are returned under the following circumstances:
///
/// - If any database error occurs whilst querying the database.
/// - If some, but not all, syn2mas restoration tables are present. (This
///   shouldn't be possible without syn2mas having been sabotaged!)
pub async fn is_syn2mas_in_progress(client: &Client) -> Result<bool, Error> {
    // Names of tables used for syn2mas resumption
    let restore_table_names: Vec<String> = vec![
        "syn2mas_restore_constraints".to_owned(),
        "syn2mas_restore_indices".to_owned(),
    ];

    let rows = client
        .query(
            r#"
            SELECT 1 AS _dummy FROM pg_tables WHERE schemaname = current_schema
            AND tablename = ANY($1)
            "#,
            &[&restore_table_names],
        )
        .await
        .into_database("failed to query count of resumption tables")?;

    let num_resumption_tables = rows.len();

    if num_resumption_tables == 0 {
        Ok(false)
    } else if num_resumption_tables == restore_table_names.len() {
        Ok(true)
    } else {
        Err(Error::inconsistent(
            "some, but not all, syn2mas resumption tables were found",
        ))
    }
}

/// Execute multiple SQL statements from a script string.
/// tokio-postgres doesn't have `execute_many`, so we split on semicolons
/// and execute each statement individually.
async fn execute_sql_script(client: &Client, sql: &str) -> Result<(), tokio_postgres::Error> {
    for statement in sql.split(';') {
        let statement = statement.trim();
        if statement.is_empty() || statement.starts_with("--") {
            continue;
        }
        client.execute(statement, &[]).await?;
    }
    Ok(())
}

impl MasWriter {
    /// Creates a new Pasion writer.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[tracing::instrument(name = "syn2mas.mas_writer.new", skip_all)]
    pub async fn new(
        conn: LockedMasDatabase,
        writer_connections: Vec<Client>,
        dry_run: bool,
    ) -> Result<Self, Error> {
        // Given that we don't have any concurrent transactions here,
        // the READ COMMITTED isolation level is sufficient.
        conn.client()
            .execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
            .await
            .into_database("begin Pasion transaction")?;

        let syn2mas_started = is_syn2mas_in_progress(conn.client()).await?;

        let indices_to_restore;
        let constraints_to_restore;

        if syn2mas_started {
            // We are resuming from a partially-done syn2mas migration
            // We should reset the database so that we're starting from scratch.
            warn!("Partial syn2mas migration has already been done; resetting.");
            for table in MAS_TABLES_AFFECTED_BY_MIGRATION {
                conn.client()
                    .execute(&format!("TRUNCATE syn2mas__{table}"), &[])
                    .await
                    .into_database_with(|| format!("failed to truncate table syn2mas__{table}"))?;
            }

            let index_rows = conn
                .client()
                .query(
                    "SELECT table_name, name, definition FROM syn2mas_restore_indices ORDER BY order_key",
                    &[],
                )
                .await
                .into_database("failed to get syn2mas restore data (index descriptions)")?;
            indices_to_restore = index_rows.iter().map(IndexDescription::from).collect();

            let constraint_rows = conn
                .client()
                .query(
                    "SELECT table_name, name, definition FROM syn2mas_restore_constraints ORDER BY order_key",
                    &[],
                )
                .await
                .into_database("failed to get syn2mas restore data (constraint descriptions)")?;
            constraints_to_restore = constraint_rows
                .iter()
                .map(ConstraintDescription::from)
                .collect();
        } else {
            info!("Starting new syn2mas migration");

            execute_sql_script(
                conn.client(),
                include_str!("syn2mas_temporary_tables.sql"),
            )
            .await
            .into_database("could not create temporary tables")?;

            // Pause (temporarily drop) indices and constraints in order to improve
            // performance of bulk data loading.
            (indices_to_restore, constraints_to_restore) =
                Self::pause_indices(conn.client()).await?;

            // Persist these index and constraint definitions.
            for IndexDescription {
                name,
                table_name,
                definition,
            } in &indices_to_restore
            {
                conn.client()
                    .execute(
                        "INSERT INTO syn2mas_restore_indices (name, table_name, definition) VALUES ($1, $2, $3)",
                        &[name, table_name, definition],
                    )
                    .await
                    .into_database("failed to save restore data (index)")?;
            }
            for ConstraintDescription {
                name,
                table_name,
                definition,
            } in &constraints_to_restore
            {
                conn.client()
                    .execute(
                        "INSERT INTO syn2mas_restore_constraints (name, table_name, definition) VALUES ($1, $2, $3)",
                        &[name, table_name, definition],
                    )
                    .await
                    .into_database("failed to save restore data (index)")?;
            }
        }

        conn.client()
            .execute("COMMIT", &[])
            .await
            .into_database("begin Pasion transaction")?;

        // Now after all the schema changes have been done, begin writer transactions
        for writer_connection in &writer_connections {
            writer_connection
                .execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
                .await
                .into_database("begin Pasion writer transaction")?;
        }

        Ok(Self {
            conn,
            dry_run,
            writer_pool: WriterConnectionPool::new(writer_connections),
            indices_to_restore,
            constraints_to_restore,
            write_buffer_finish_checker: FinishChecker::default(),
        })
    }

    #[tracing::instrument(skip_all)]
    async fn pause_indices(
        client: &Client,
    ) -> Result<(Vec<IndexDescription>, Vec<ConstraintDescription>), Error> {
        let mut indices_to_restore = Vec::new();
        let mut constraints_to_restore = Vec::new();

        for &unprefixed_table in MAS_TABLES_AFFECTED_BY_MIGRATION {
            let table = format!("syn2mas__{unprefixed_table}");
            // First drop incoming foreign key constraints
            for constraint in
                constraint_pausing::describe_foreign_key_constraints_to_table(client, &table)
                    .await?
            {
                constraint_pausing::drop_constraint(client, &constraint).await?;
                constraints_to_restore.push(constraint);
            }
            // After all incoming foreign key constraints have been removed,
            // we can now drop internal constraints.
            for constraint in
                constraint_pausing::describe_constraints_on_table(client, &table).await?
            {
                constraint_pausing::drop_constraint(client, &constraint).await?;
                constraints_to_restore.push(constraint);
            }
            // After all constraints have been removed, we can drop indices.
            for index in constraint_pausing::describe_indices_on_table(client, &table).await? {
                constraint_pausing::drop_index(client, &index).await?;
                indices_to_restore.push(index);
            }
        }

        Ok((indices_to_restore, constraints_to_restore))
    }

    async fn restore_indices(
        conn: &mut LockedMasDatabase,
        indices_to_restore: &[IndexDescription],
        constraints_to_restore: &[ConstraintDescription],
        progress: &Progress,
    ) -> Result<(), Error> {
        // First restore all indices. The order is not important as far as I know.
        // However the indices are needed before constraints.
        for index in indices_to_restore.iter().rev() {
            progress.rebuild_index(index.name.clone());
            constraint_pausing::restore_index(conn.client(), index).await?;
        }
        // Then restore all constraints.
        // The order here is the reverse of drop order, since some constraints may rely
        // on other constraints to work.
        for constraint in constraints_to_restore.iter().rev() {
            progress.rebuild_constraint(constraint.name.clone());
            constraint_pausing::restore_constraint(conn.client(), constraint).await?;
        }
        Ok(())
    }

    /// Finish writing to the Pasion database, flushing and committing all
    /// changes. It returns the unlocked underlying client.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[tracing::instrument(skip_all)]
    pub async fn finish(mut self, progress: &Progress) -> Result<Client, Error> {
        self.write_buffer_finish_checker.check_all_finished()?;

        // Commit all writer transactions to the database.
        self.writer_pool
            .finish()
            .await
            .map_err(|errors| Error::Multiple(MultipleErrors::from(errors)))?;

        // Now all the data has been migrated, finish off by restoring indices and
        // constraints!
        self.conn
            .client()
            .execute("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
            .await
            .into_database("begin Pasion transaction")?;

        Self::restore_indices(
            &mut self.conn,
            &self.indices_to_restore,
            &self.constraints_to_restore,
            progress,
        )
        .await?;

        execute_sql_script(
            self.conn.client(),
            include_str!("syn2mas_revert_temporary_tables.sql"),
        )
        .await
        .into_database("could not revert temporary tables")?;

        // If we're in dry-run mode, truncate all the tables we've written to
        if self.dry_run {
            warn!("Migration ran in dry-run mode, deleting all imported data");
            let tables = MAS_TABLES_AFFECTED_BY_MIGRATION
                .iter()
                .map(|table| format!("\"{table}\""))
                .collect::<Vec<_>>()
                .join(", ");

            // Note that we do that with CASCADE, because we do that *after*
            // restoring the FK constraints.
            //
            // The alternative would be to list all the tables we have FK to
            // those tables, which would be a hassle, or to do that after
            // restoring the constraints, which would mean we wouldn't validate
            // that we've done valid FKs in dry-run mode.
            self.conn
                .client()
                .execute(&format!("TRUNCATE TABLE {tables} CASCADE"), &[])
                .await
                .into_database_with(|| "failed to truncate all tables")?;
        }

        self.conn
            .client()
            .execute("COMMIT", &[])
            .await
            .into_database("ending Pasion transaction")?;

        let conn = self
            .conn
            .unlock()
            .await
            .into_database("could not unlock Pasion database")?;

        Ok(conn)
    }
}

// How many entries to buffer at once, before writing a batch of rows to the
// database.
const WRITE_BUFFER_BATCH_SIZE: usize = 4096;

/// A buffer for writing rows to the Pasion database.
/// Generic over the type of rows.
pub struct MasWriteBuffer<T> {
    rows: Vec<T>,
    finish_checker_handle: FinishCheckerHandle,
}

impl<T> MasWriteBuffer<T>
where
    T: WriteBatch,
{
    pub fn new(writer: &MasWriter) -> Self {
        MasWriteBuffer {
            rows: Vec::with_capacity(WRITE_BUFFER_BATCH_SIZE),
            finish_checker_handle: writer.write_buffer_finish_checker.handle(),
        }
    }

    pub async fn finish(mut self, writer: &mut MasWriter) -> Result<(), Error> {
        self.flush(writer).await?;
        self.finish_checker_handle.declare_finished();
        Ok(())
    }

    pub async fn flush(&mut self, writer: &mut MasWriter) -> Result<(), Error> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.rows);
        self.rows.reserve_exact(WRITE_BUFFER_BATCH_SIZE);
        writer
            .writer_pool
            .spawn_with_connection(move |conn| T::write_batch(conn, rows).boxed())
            .boxed()
            .await?;
        Ok(())
    }

    pub async fn write(&mut self, writer: &mut MasWriter, row: T) -> Result<(), Error> {
        self.rows.push(row);
        if self.rows.len() >= WRITE_BUFFER_BATCH_SIZE {
            self.flush(writer).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // Tests have been removed as they relied on sqlx test infrastructure.
    // TODO: Re-implement tests using tokio-postgres test helpers.
}
