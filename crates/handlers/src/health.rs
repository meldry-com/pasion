// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_salvo_utils::InternalError;
use salvo::prelude::*;
use sqlx::PgPool;
use tracing::{Instrument, info_span};

#[handler]
pub async fn get(depot: &Depot) -> Result<String, InternalError> {
    let pool = depot
        .get::<PgPool>("pg_pool")
        .ok_or_else(|| anyhow::anyhow!("PgPool not found in depot"))?;

    let mut conn = pool.acquire().await?;

    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&mut *conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok("ok".to_string())
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
