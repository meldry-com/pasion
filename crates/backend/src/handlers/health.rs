// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use diesel_async::{
    AsyncPgConnection, RunQueryDsl, pooled_connection::deadpool::Pool as DieselPool,
};
use salvo::prelude::*;
use tracing::{Instrument, info_span};

use crate::salvo_utils::InternalError;

#[handler]
pub async fn get(depot: &Depot) -> Result<String, InternalError> {
    let pool = depot
        .get::<DieselPool<AsyncPgConnection>>("pg_pool")
        .map_err(|_| InternalError::from_anyhow(anyhow::anyhow!("pg_pool not found in depot")))?;

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut conn = pasion_data::pg::get_connection(pool).await?;
        diesel::sql_query("SELECT 1")
            .execute(&mut *conn)
            .instrument(info_span!("DB health"))
            .await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|error| InternalError::from_anyhow(error.into()))?
    .map_err(InternalError::from_anyhow)?;

    Ok("ok".to_owned())
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
