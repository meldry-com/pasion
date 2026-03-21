use pasion_salvo_utils::InternalError;
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
