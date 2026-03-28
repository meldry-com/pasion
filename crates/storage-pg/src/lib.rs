//! An implementation of the storage traits for a PostgreSQL database
//!
//! This backend uses [`sqlx`] to interact with the database. It is being
//! migrated to [`diesel`] with [`diesel_async`].

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::blocks_in_conditions)]

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ::tracing::{Instrument, debug, info, info_span, warn};
use opentelemetry_semantic_conventions::trace::DB_QUERY_TEXT;
use sqlx::{
    Either, PgConnection,
    migrate::{AppliedMigration, Migrate, MigrateError, Migration, Migrator},
    postgres::{PgAdvisoryLock, PgAdvisoryLockKey},
};

pub mod app_session;
pub mod oauth2;
pub mod personal;
pub mod queue;
/// Diesel schema definitions generated from the database
pub mod schema;
pub mod upstream_oauth2;
pub mod user;

// Define `lower()` as a SQL function for Diesel (Diesel doesn't ship one).
diesel::define_sql_function! {
    /// SQL `lower()` function for case-insensitive text comparisons
    fn lower(x: diesel::sql_types::Text) -> diesel::sql_types::Text;
}

mod errors;
pub(crate) mod filter;
pub(crate) mod iden;
pub(crate) mod pagination;
pub(crate) mod policy_data;
pub(crate) mod repository;
pub(crate) mod telemetry;
pub(crate) mod tracing;

pub(crate) use self::errors::DatabaseInconsistencyError;
pub use self::{
    errors::DatabaseError,
    repository::{PgRepository, PgRepositoryFactory},
    tracing::ExecuteExt,
};

/// Embedded migrations in the binary (sqlx format — kept for backward compat)
pub static MIGRATOR: Migrator = sqlx::migrate!();

fn available_migrations() -> BTreeMap<i64, &'static Migration> {
    MIGRATOR.iter().map(|m| (m.version, m)).collect()
}

/// This is the list of migrations we've removed from the migration history but
/// might have been applied in the past
#[allow(clippy::inconsistent_digit_grouping)]
const ALLOWED_MISSING_MIGRATIONS: &[i64] = &[
    // https://github.com/matrix-org/pasion/pull/1585
    20220709_210445,
    20230330_210841,
    20230408_110421,
];

fn allowed_missing_migrations() -> BTreeSet<i64> {
    ALLOWED_MISSING_MIGRATIONS.iter().copied().collect()
}

/// This is a list of possible additional checksums from previous versions of
/// migrations.
#[allow(clippy::inconsistent_digit_grouping)]
const ALLOWED_ALTERNATE_CHECKSUMS: &[(i64, u128)] = &[
    (20250410_000000, 0x8811_c3ef_dbee_8c00_5b49_25da_5d55_9c3f),
    (20250410_000001, 0x7990_37b3_2193_8a5d_c72f_bccd_95fd_82e5),
    (20250410_000002, 0xf2b8_f120_deae_27e7_60d0_79a3_0b77_eea3),
    (20250410_000003, 0x06be_fc2b_cedc_acf4_b981_02c7_b40c_c469),
    (20250410_000004, 0x0a90_9c6a_dba7_545c_10d9_60eb_6d30_2f50),
    (20250410_000006, 0xcc7f_5152_6497_5729_d94b_be0d_9c95_8316),
    (20250410_000007, 0x12e7_cfab_a017_a5a5_4f2c_18fa_541c_ce62),
    (20250410_000008, 0x171d_62e5_ee1a_f0d9_3639_6c5a_277c_54cd),
    (20250410_000009, 0xb1a0_93c7_6645_92ad_df45_b395_57bb_a281),
    (20250410_000010, 0x8089_86ac_7cff_8d86_2850_d287_cdb1_2b57),
    (20250410_000011, 0x8d9d_3fae_02c9_3d3f_81e4_6242_2b39_b5b8),
    (20250410_000012, 0x9805_1372_41aa_d5b0_ebe1_ba9d_28c7_faf6),
    (20250410_000013, 0x7291_9a97_e4d1_0d45_1791_6e8c_3f2d_e34d),
    (20250410_000014, 0x811d_f965_8127_e168_4aa2_f177_a4e6_f077),
    (20250410_000015, 0xa639_0780_aab7_d60d_5fcb_771d_13ed_73ee),
    (20250410_000016, 0x22b6_e909_6de4_39e3_b2b9_c684_7417_fe07),
    (20250410_000017, 0x9dfe_b6d3_89e4_e509_651b_2793_8d8d_cd32),
    (20250410_000018, 0x638f_bdbc_2276_5094_020b_cec1_ab95_c07f),
    (20250410_000019, 0xa283_84bc_5fd5_7cbd_b5fb_b5fe_0255_6845),
    (20250410_000020, 0x17d1_54b1_7c6e_fc48_61dd_da3d_f8a5_9546),
    (20250410_000022, 0xbc36_af82_994a_6f93_8aca_a46b_fc3c_ffde),
    (20250410_000023, 0x54ec_3b07_ac79_443b_9e18_a2b3_2d17_5ab9),
    (20250410_000024, 0x8ab4_4f80_00b6_58b2_d757_c40f_bc72_3d87),
    (20250410_000025, 0x5dc4_2ff3_3042_2f45_046d_10af_ab3a_b583),
    (20250410_000026, 0x5263_c547_0b64_6425_5729_48b2_ce84_7cad),
    (20250410_000027, 0x0aad_cb50_1d6a_7794_9017_d24d_55e7_1b9d),
    (20250410_000028, 0x8fc1_92f8_68df_ca4e_3e2b_cddf_bc12_cffe),
    (20250410_000029, 0x416c_9446_b6a3_1b49_2940_a8ac_c1c2_665a),
    (20250410_000030, 0x83a5_e51e_25a6_77fb_2b79_6ea5_db1e_364f),
    (20250410_000031, 0xfa18_a707_9438_dbc7_2cde_b5f1_ee21_5c7e),
    (20250410_000032, 0xd669_662e_8930_838a_b142_c3fa_7b39_d2a0),
    (20250410_000033, 0x4019_1053_cabc_191c_c02e_9aa9_407c_0de5),
    (20250410_000034, 0xdd59_e595_24e6_4dad_c5f7_fef2_90b8_df57),
    (20250410_000035, 0x09b4_ea53_2da4_9c39_eb10_db33_6a6d_608b),
    (20250410_000036, 0x3ca5_9c78_8480_e342_d729_907c_d293_2049),
    (20250410_000037, 0xc857_2a10_450b_0612_822c_2b86_535a_ea7d),
    (20250410_000038, 0x1642_39da_9c3b_d9fd_b1e1_72b1_db78_b978),
    (20250410_000039, 0xdd70_b211_6016_bb84_0d84_f04e_eb8a_59d9),
    (20250410_000040, 0xe435_ead6_c363_a0b6_e048_dd85_0ecb_9499),
    (20250410_000041, 0xe9f3_122f_70d4_9839_c818_4b18_0192_ae26),
    (20250410_000043, 0xec5e_1400_483d_c4bf_6014_aba4_ffc3_6236),
    (20250410_000044, 0x4750_5eba_4095_6664_78d0_27f9_64bf_64f4),
    (20250410_000045, 0x9a53_bd70_4cad_2bf1_61d4_f143_0c82_681d),
    (20250410_121612, 0x25f0_9d20_a897_df18_162d_1c47_b68e_81bd),
    (20250602_212101, 0xd1a8_782c_b3f0_5045_3f46_49a0_bab0_822b),
    (20250708_155857, 0xb78e_6957_a588_c16a_d292_a0c7_cae9_f290),
    (20250915_092635, 0x6854_d58b_99d7_3ac5_82f8_25e5_b1c3_cc0b),
    (20251127_145951, 0x3bcd_d92e_8391_2a2c_8a18_1d76_354f_96c6),
];

fn alternate_checksums_map() -> BTreeMap<i64, HashSet<u128>> {
    let mut map = BTreeMap::new();
    for (version, checksum) in ALLOWED_ALTERNATE_CHECKSUMS {
        map.entry(*version)
            .or_insert_with(HashSet::new)
            .insert(*checksum);
    }
    map
}

/// Load the list of applied migrations into a map.
async fn applied_migrations_map(
    conn: &mut PgConnection,
) -> Result<BTreeMap<i64, AppliedMigration>, MigrateError> {
    let applied_migrations = conn
        .list_applied_migrations()
        .await?
        .into_iter()
        .map(|m| (m.version, m))
        .collect();

    Ok(applied_migrations)
}

/// Checks if the migration table exists
async fn migration_table_exists(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_name = '_sqlx_migrations'
            ) AS "exists!"
        "#,
    )
    .fetch_one(conn)
    .await
}

/// Run the migrations on the given connection
///
/// This function acquires an advisory lock on the database to ensure that only
/// one migrator is running at a time.
///
/// # Errors
///
/// This function returns an error if the migration fails.
#[::tracing::instrument(name = "db.migrate", skip_all, err)]
pub async fn migrate(conn: &mut PgConnection) -> Result<(), MigrateError> {
    let database_name = sqlx::query_scalar!(r#"SELECT current_database() as "current_database!""#)
        .fetch_one(&mut *conn)
        .await
        .map_err(MigrateError::from)?;

    let lock =
        PgAdvisoryLock::with_key(PgAdvisoryLockKey::BigInt(generate_lock_id(&database_name)));

    let mut backoff = std::time::Duration::from_millis(250);
    let mut conn = conn;
    let mut locked_connection = loop {
        match lock.try_acquire(conn).await? {
            Either::Left(guard) => break guard,
            Either::Right(conn_) => {
                warn!(
                    "Another process is already running migrations on the database, waiting {duration}s and trying again…",
                    duration = backoff.as_secs_f32()
                );
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, std::time::Duration::from_secs(5));
                conn = conn_;
            }
        }
    };

    if !migration_table_exists(locked_connection.as_mut()).await? {
        locked_connection.as_mut().ensure_migrations_table().await?;
    }

    for migration in pending_migrations(locked_connection.as_mut()).await? {
        info!(
            "Applying migration {version}: {description}",
            version = migration.version,
            description = migration.description
        );
        locked_connection
            .as_mut()
            .apply(migration)
            .instrument(info_span!(
                "db.migrate.run_migration",
                db.migration.version = migration.version,
                db.migration.description = &*migration.description,
                { DB_QUERY_TEXT } = &*migration.sql,
            ))
            .await?;
    }

    locked_connection.release_now().await?;

    Ok(())
}

/// Get the list of pending migrations
///
/// # Errors
///
/// This function returns an error if there is a problem checking the applied
/// migrations
pub async fn pending_migrations(
    conn: &mut PgConnection,
) -> Result<Vec<&'static Migration>, MigrateError> {
    let available_migrations = available_migrations();
    let allowed_missing = allowed_missing_migrations();
    let alternate_checksums = alternate_checksums_map();
    let applied_migrations = if migration_table_exists(&mut *conn).await? {
        applied_migrations_map(&mut *conn).await?
    } else {
        BTreeMap::new()
    };

    for applied_migration in applied_migrations.values() {
        if let Some(migration) = available_migrations.get(&applied_migration.version) {
            if applied_migration.checksum != migration.checksum {
                if let Some(alternates) = alternate_checksums.get(&applied_migration.version) {
                    let Some(applied_checksum_prefix) = applied_migration
                        .checksum
                        .get(..16)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u128::from_be_bytes)
                    else {
                        return Err(MigrateError::ExecuteMigration(
                            sqlx::Error::InvalidArgument(
                                "checksum stored in database is invalid".to_owned(),
                            ),
                            applied_migration.version,
                        ));
                    };

                    if !alternates.contains(&applied_checksum_prefix) {
                        warn!(
                            "The database has a migration applied ({version}) which has known alternative checksums {alternates:x?}, but none of them matched {applied_checksum_prefix:x}",
                            version = applied_migration.version,
                        );
                        return Err(MigrateError::VersionMismatch(applied_migration.version));
                    }
                } else {
                    return Err(MigrateError::VersionMismatch(applied_migration.version));
                }
            }
        } else if allowed_missing.contains(&applied_migration.version) {
            debug!(
                "The database has a migration applied ({version}) that doesn't exist anymore, but it was intentionally removed",
                version = applied_migration.version
            );
        } else {
            warn!(
                "The database has a migration applied ({version}) that doesn't exist anymore! This should not happen, unless rolling back to an older version of Pasion.",
                version = applied_migration.version
            );
        }
    }

    Ok(available_migrations
        .values()
        .copied()
        .filter(|migration| {
            !migration.migration_type.is_down_migration()
                && !applied_migrations.contains_key(&migration.version)
        })
        .collect())
}

// Copied from the sqlx source code, so that we generate the same lock ID
fn generate_lock_id(database_name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    0x3d32_ad9e * i64::from(CRC_IEEE.checksum(database_name.as_bytes()))
}
