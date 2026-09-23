// Copyright 2025 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for creating temporary test databases.

use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _,
    pooled_connection::{AsyncDieselConnectionManager, deadpool::Pool},
};

/// Create a diesel connection pool suitable for tests.
///
/// This connects to the database specified by `DATABASE_URL` env var
/// (set by the test harness or CI), creates an isolated database, applies
/// migrations, and returns a pool. Tests can commit without affecting each
/// other.
///
/// # Panics
///
/// Panics if `DATABASE_URL` is unset, a test database cannot be created, the
/// connection pool cannot be built, or migrations fail.
#[allow(
    clippy::unused_async,
    reason = "callers use this as the first step in async database tests"
)]
pub async fn setup_test_pool() -> Pool<AsyncPgConnection> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let name = format!("pasion_test_{}", uuid::Uuid::new_v4().simple());
    let mut admin = AsyncPgConnection::establish(&database_url)
        .await
        .expect("could not connect to PostgreSQL for test database setup");
    diesel::sql_query(format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .expect("could not create test database");
    drop(admin);

    let mut url = url::Url::parse(&database_url).expect("DATABASE_URL must be a valid URL");
    url.set_path(&name);
    let isolated_url = url.to_string();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&isolated_url);
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool");
    super::migrate(&pool, &isolated_url)
        .await
        .expect("could not migrate test database");
    pool
}
