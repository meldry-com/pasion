//! # Palpo Database Reader
//!
//! This module provides facilities for streaming relevant types of database
//! records from a Palpo database.

use std::fmt::Display;

use chrono::{DateTime, Utc};
use futures_util::{Stream, StreamExt, stream};
use thiserror::Error;
use thiserror_ext::ContextInto;
use tokio_postgres::Client;

pub mod checks;
pub mod config;

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}")]
    Database {
        #[source]
        source: tokio_postgres::Error,
        context: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FullUserId(pub String);

impl Display for FullUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Error)]
pub enum ExtractLocalpartError {
    #[error("user ID does not start with `@` sigil")]
    NoAtSigil,
    #[error("user ID does not have a `:` separator")]
    NoSeparator,
    #[error("wrong server name: expected {expected:?}, got {found:?}")]
    WrongServerName { expected: String, found: String },
}

impl FullUserId {
    /// Extract the localpart from the User ID, asserting that the User ID has
    /// the correct server name.
    ///
    /// # Errors
    ///
    /// A handful of basic validity checks are performed and an error may be
    /// returned if the User ID is not valid.
    /// However, the User ID grammar is not checked fully.
    ///
    /// If the wrong server name is asserted, returns an error.
    pub fn extract_localpart(
        &self,
        expected_server_name: &str,
    ) -> Result<&str, ExtractLocalpartError> {
        let Some(without_sigil) = self.0.strip_prefix('@') else {
            return Err(ExtractLocalpartError::NoAtSigil);
        };

        let Some((localpart, server_name)) = without_sigil.split_once(':') else {
            return Err(ExtractLocalpartError::NoSeparator);
        };

        if server_name != expected_server_name {
            return Err(ExtractLocalpartError::WrongServerName {
                expected: expected_server_name.to_owned(),
                found: server_name.to_owned(),
            });
        }

        Ok(localpart)
    }
}

/// A Palpo boolean.
/// Palpo stores booleans as 0 or 1, due to compatibility with old SQLite
/// versions that did not have native boolean support.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoBool(bool);

impl PalpoBool {
    fn from_row_named(row: &tokio_postgres::Row, name: &str) -> Self {
        let val: i16 = row.get(name);
        PalpoBool(val != 0)
    }
}

impl From<PalpoBool> for bool {
    fn from(PalpoBool(value): PalpoBool) -> Self {
        value
    }
}

/// A timestamp stored as the number of seconds since the Unix epoch.
/// Note that Palpo stores MOST timestamps as numbers of **milliseconds**
/// since the Unix epoch. But some timestamps are still stored in seconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecondsTimestamp(DateTime<Utc>);

impl From<SecondsTimestamp> for DateTime<Utc> {
    fn from(SecondsTimestamp(value): SecondsTimestamp) -> Self {
        value
    }
}

impl SecondsTimestamp {
    fn from_row_named(row: &tokio_postgres::Row, name: &str) -> Self {
        let seconds: i64 = row.get(name);
        SecondsTimestamp(DateTime::from_timestamp_nanos(seconds * 1_000_000_000))
    }
}

/// A timestamp stored as the number of milliseconds since the Unix epoch.
/// Note that Palpo stores some timestamps in seconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MillisecondsTimestamp(DateTime<Utc>);

impl From<MillisecondsTimestamp> for DateTime<Utc> {
    fn from(MillisecondsTimestamp(value): MillisecondsTimestamp) -> Self {
        value
    }
}

impl MillisecondsTimestamp {
    fn from_row_named(row: &tokio_postgres::Row, name: &str) -> Self {
        let ms: i64 = row.get(name);
        MillisecondsTimestamp(DateTime::from_timestamp_nanos(ms * 1_000_000))
    }

    fn opt_from_row_named(row: &tokio_postgres::Row, name: &str) -> Option<Self> {
        let ms: Option<i64> = row.get(name);
        ms.map(|ms| MillisecondsTimestamp(DateTime::from_timestamp_nanos(ms * 1_000_000)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoUser {
    /// Full User ID of the user
    pub name: FullUserId,
    /// Password hash string for the user. Optional (null if no password is
    /// set).
    pub password_hash: Option<String>,
    /// Whether the user is a Palpo Admin
    pub admin: PalpoBool,
    /// Whether the user is deactivated
    pub deactivated: PalpoBool,
    /// Whether the user is locked
    pub locked: bool,
    /// When the user was created
    pub creation_ts: SecondsTimestamp,
    /// Whether the user is a guest.
    /// Note that not all numeric user IDs are guests; guests can upgrade their
    /// account!
    pub is_guest: PalpoBool,
    /// The ID of the appservice that created this user, if any.
    pub appservice_id: Option<String>,
}

impl From<&tokio_postgres::Row> for PalpoUser {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoUser {
            name: FullUserId(row.get("name")),
            password_hash: row.get("password_hash"),
            admin: PalpoBool::from_row_named(row, "admin"),
            deactivated: PalpoBool::from_row_named(row, "deactivated"),
            locked: row.get("locked"),
            creation_ts: SecondsTimestamp::from_row_named(row, "creation_ts"),
            is_guest: PalpoBool::from_row_named(row, "is_guest"),
            appservice_id: row.get("appservice_id"),
        }
    }
}

/// Row of the `user_threepids` table in Palpo.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoThreepid {
    pub user_id: FullUserId,
    pub medium: String,
    pub address: String,
    pub added_at: MillisecondsTimestamp,
}

impl From<&tokio_postgres::Row> for PalpoThreepid {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoThreepid {
            user_id: FullUserId(row.get("user_id")),
            medium: row.get("medium"),
            address: row.get("address"),
            added_at: MillisecondsTimestamp::from_row_named(row, "added_at"),
        }
    }
}

/// Row of the `user_external_ids` table in Palpo.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoExternalId {
    pub user_id: FullUserId,
    pub auth_provider: String,
    pub external_id: String,
}

impl From<&tokio_postgres::Row> for PalpoExternalId {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoExternalId {
            user_id: FullUserId(row.get("user_id")),
            auth_provider: row.get("auth_provider"),
            external_id: row.get("external_id"),
        }
    }
}

/// Row of the `devices` table in Palpo.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoDevice {
    pub user_id: FullUserId,
    pub device_id: String,
    pub display_name: Option<String>,
    pub last_seen: Option<MillisecondsTimestamp>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl From<&tokio_postgres::Row> for PalpoDevice {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoDevice {
            user_id: FullUserId(row.get("user_id")),
            device_id: row.get("device_id"),
            display_name: row.get("display_name"),
            last_seen: MillisecondsTimestamp::opt_from_row_named(row, "last_seen"),
            ip: row.get("ip"),
            user_agent: row.get("user_agent"),
        }
    }
}

/// Row of the `access_tokens` table in Palpo.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoAccessToken {
    pub user_id: FullUserId,
    pub device_id: Option<String>,
    pub token: String,
    pub valid_until_ms: Option<MillisecondsTimestamp>,
    pub last_validated: Option<MillisecondsTimestamp>,
}

impl From<&tokio_postgres::Row> for PalpoAccessToken {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoAccessToken {
            user_id: FullUserId(row.get("user_id")),
            device_id: row.get("device_id"),
            token: row.get("token"),
            valid_until_ms: MillisecondsTimestamp::opt_from_row_named(row, "valid_until_ms"),
            last_validated: MillisecondsTimestamp::opt_from_row_named(row, "last_validated"),
        }
    }
}

/// Row of the `refresh_tokens` table in Palpo.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PalpoRefreshableTokenPair {
    pub user_id: FullUserId,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub valid_until_ms: Option<MillisecondsTimestamp>,
    pub last_validated: Option<MillisecondsTimestamp>,
}

impl From<&tokio_postgres::Row> for PalpoRefreshableTokenPair {
    fn from(row: &tokio_postgres::Row) -> Self {
        PalpoRefreshableTokenPair {
            user_id: FullUserId(row.get("user_id")),
            device_id: row.get("device_id"),
            access_token: row.get("access_token"),
            refresh_token: row.get("refresh_token"),
            valid_until_ms: MillisecondsTimestamp::opt_from_row_named(row, "valid_until_ms"),
            last_validated: MillisecondsTimestamp::opt_from_row_named(row, "last_validated"),
        }
    }
}

/// List of Palpo tables that we should acquire an `EXCLUSIVE` lock on.
///
/// This is a safety measure against other processes changing the data
/// underneath our feet. It's still not a good idea to run Palpo at the same
/// time as the migration.
const TABLES_TO_LOCK: &[&str] = &[
    "users",
    "user_threepids",
    "user_external_ids",
    "devices",
    "access_tokens",
    "refresh_tokens",
];

/// Number of migratable rows in various Palpo tables.
/// Used to estimate progress.
#[derive(Clone, Debug)]
pub struct PalpoRowCounts {
    pub users: usize,
    pub devices: usize,
    pub threepids: usize,
    pub external_ids: usize,
    pub access_tokens: usize,
    pub refresh_tokens: usize,
}

pub struct PalpoReader {
    client: Client,
}

/// Helper to convert a `query_raw` future into a stream of mapped rows.
///
/// This handles the two-level error: the outer error from the query itself,
/// and the inner errors from streaming rows.
fn query_raw_to_stream<'a, T>(
    fut: impl std::future::Future<Output = Result<tokio_postgres::RowStream, tokio_postgres::Error>> + 'a,
    map_fn: impl Fn(tokio_postgres::Row) -> T + Clone + 'a,
    context: &'static str,
) -> impl Stream<Item = Result<T, Error>> + 'a
where
    T: 'a,
{
    stream::once(fut).flat_map(move |result| match result {
        Ok(row_stream) => {
            let map_fn = map_fn.clone();
            row_stream
                .map(move |row_result| match row_result {
                    Ok(row) => Ok(map_fn(row)),
                    Err(err) => Err(err.into_database(context)),
                })
                .left_stream()
        }
        Err(err) => stream::once(async move { Err(err.into_database(context)) }).right_stream(),
    })
}

impl PalpoReader {
    /// Create a new Palpo reader, which entails creating a transaction and
    /// locking Palpo tables.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    /// - If we can't lock the Palpo tables (pointing to the fact that Palpo may
    ///   still be running)
    pub async fn new(
        client: Client,
        dry_run: bool,
    ) -> Result<Self, Error> {
        client
            .execute("BEGIN", &[])
            .await
            .into_database("begin transaction")?;

        client
            .execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE", &[])
            .await
            .into_database("set transaction")?;

        let lock_type = if dry_run {
            // We expect dry runs to be done alongside Palpo running, so we don't want to
            // interfere with Palpo's database access in that case.
            "ACCESS SHARE"
        } else {
            "EXCLUSIVE"
        };
        for table in TABLES_TO_LOCK {
            client
                .execute(&format!("LOCK TABLE {table} IN {lock_type} MODE NOWAIT"), &[])
                .await
                .into_database_with(|| format!("locking Palpo table `{table}`"))?;
        }

        Ok(Self { client })
    }

    /// Finishes the Palpo reader, committing the transaction.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error whilst committing the transaction.
    pub async fn finish(self) -> Result<(), Error> {
        self.client
            .execute("COMMIT", &[])
            .await
            .into_database("end transaction")?;
        Ok(())
    }

    /// Counts the rows in the Palpo database to get an estimate of how large
    /// the migration is going to be.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    pub async fn count_rows(&self) -> Result<PalpoRowCounts, Error> {
        // We don't get to filter out application service users by using this estimate,
        // which is a shame, but on a large database this is way faster.
        // On matrix.org, counting users and devices properly takes around 1m10s,
        // which is unnecessary extra downtime during the migration, just to
        // show a more accurate progress bar and size a hash map accurately.
        let users = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'users'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of users")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        let devices = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'devices'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of devices")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        let threepids = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'user_threepids'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of threepids")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        let access_tokens = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'access_tokens'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of access tokens")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        let refresh_tokens = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'refresh_tokens'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of refresh tokens")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        let external_ids = self.client
            .query_one(
                "SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'user_external_ids'::regclass",
                &[],
            )
            .await
            .into_database("estimating count of external IDs")?
            .get::<_, i64>(0)
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX);

        Ok(PalpoRowCounts {
            users,
            devices,
            threepids,
            external_ids,
            access_tokens,
            refresh_tokens,
        })
    }

    /// Reads Palpo users, excluding application service users (which do not
    /// need to be migrated), from the database.
    pub fn read_users(&self) -> impl Stream<Item = Result<PalpoUser, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT name, password_hash, admin, deactivated, locked, creation_ts, is_guest, appservice_id FROM users",
                &[] as &[&str],
            ),
            |row| PalpoUser::from(&row),
            "reading Palpo users",
        )
    }

    /// Reads threepids (such as e-mail and phone number associations) from
    /// Palpo.
    pub fn read_threepids(&self) -> impl Stream<Item = Result<PalpoThreepid, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT user_id, medium, address, added_at FROM user_threepids",
                &[] as &[&str],
            ),
            |row| PalpoThreepid::from(&row),
            "reading Palpo threepids",
        )
    }

    /// Read associations between Palpo users and external identity providers
    pub fn read_user_external_ids(
        &self,
    ) -> impl Stream<Item = Result<PalpoExternalId, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT user_id, auth_provider, external_id FROM user_external_ids",
                &[] as &[&str],
            ),
            |row| PalpoExternalId::from(&row),
            "reading Palpo user external IDs",
        )
    }

    /// Reads devices from the Palpo database.
    /// Does not include so-called 'hidden' devices, which are just a mechanism
    /// for storing various signing keys shared between the real devices.
    pub fn read_devices(&self) -> impl Stream<Item = Result<PalpoDevice, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT user_id, device_id, display_name, last_seen, ip, user_agent FROM devices WHERE NOT hidden AND device_id != 'guest_device'",
                &[] as &[&str],
            ),
            |row| PalpoDevice::from(&row),
            "reading Palpo devices",
        )
    }

    /// Reads unrefreshable access tokens from the Palpo database.
    /// This does not include access tokens used for puppetting users, as those
    /// are not supported by Pasion.
    ///
    /// This also excludes access tokens whose referenced device ID does not
    /// exist, except for deviceless access tokens.
    /// (It's unclear what mechanism led to these, but since Palpo has no
    /// foreign key constraints and is not consistently atomic about this,
    /// it should be no surprise really)
    pub fn read_unrefreshable_access_tokens(
        &self,
    ) -> impl Stream<Item = Result<PalpoAccessToken, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT at0.user_id, at0.device_id, at0.token, at0.valid_until_ms, at0.last_validated \
                 FROM access_tokens at0 \
                 INNER JOIN devices USING (user_id, device_id) \
                 WHERE at0.puppets_user_id IS NULL AND at0.refresh_token_id IS NULL \
                 UNION ALL \
                 SELECT at0.user_id, at0.device_id, at0.token, at0.valid_until_ms, at0.last_validated \
                 FROM access_tokens at0 \
                 WHERE at0.puppets_user_id IS NULL AND at0.refresh_token_id IS NULL AND at0.device_id IS NULL",
                &[] as &[&str],
            ),
            |row| PalpoAccessToken::from(&row),
            "reading Palpo access tokens",
        )
    }

    /// Reads (access token, refresh token) pairs from the Palpo database.
    /// This does not include token pairs which have been made obsolete
    /// by using the refresh token and then acknowledging the
    /// successor access token by using it to authenticate a request.
    ///
    /// The `expiry_ts` and `ultimate_session_expiry_ts` columns are ignored as
    /// they are not implemented in Pasion.
    /// Further, they are unused by any real-world deployment to the best of
    /// our knowledge.
    pub fn read_refreshable_token_pairs(
        &self,
    ) -> impl Stream<Item = Result<PalpoRefreshableTokenPair, Error>> + '_ {
        query_raw_to_stream(
            self.client.query_raw(
                "SELECT rt0.user_id, rt0.device_id, at0.token AS access_token, rt0.token AS refresh_token, at0.valid_until_ms, at0.last_validated \
                 FROM refresh_tokens rt0 \
                 INNER JOIN devices USING (user_id, device_id) \
                 INNER JOIN access_tokens at0 ON at0.refresh_token_id = rt0.id AND at0.user_id = rt0.user_id AND at0.device_id = rt0.device_id \
                 LEFT JOIN access_tokens at1 ON at1.refresh_token_id = rt0.next_token_id \
                 WHERE NOT at1.used OR at1.used IS NULL",
                &[] as &[&str],
            ),
            |row| PalpoRefreshableTokenPair::from(&row),
            "reading Palpo refresh tokens",
        )
    }
}

#[cfg(test)]
mod test {
    // Tests have been removed as they relied on sqlx test infrastructure.
    // TODO: Re-implement tests using tokio-postgres test helpers.
}
