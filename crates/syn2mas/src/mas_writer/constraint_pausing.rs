use std::time::Instant;

use tokio_postgres::Client;
use tracing::{debug, info};

use super::{Error, IntoDatabase};

/// Description of a constraint, which allows recreating it later.
pub struct ConstraintDescription {
    pub name: String,
    pub table_name: String,
    pub definition: String,
}

impl From<&tokio_postgres::Row> for ConstraintDescription {
    fn from(row: &tokio_postgres::Row) -> Self {
        ConstraintDescription {
            table_name: row.get("table_name"),
            name: row.get("name"),
            definition: row.get("definition"),
        }
    }
}

pub struct IndexDescription {
    pub name: String,
    pub table_name: String,
    pub definition: String,
}

impl From<&tokio_postgres::Row> for IndexDescription {
    fn from(row: &tokio_postgres::Row) -> Self {
        IndexDescription {
            name: row.get("name"),
            table_name: row.get("table_name"),
            definition: row.get("definition"),
        }
    }
}

/// Look up and return the definition of a constraint.
pub async fn describe_constraints_on_table(
    client: &Client,
    table_name: &str,
) -> Result<Vec<ConstraintDescription>, Error> {
    let rows = client
        .query(
            r#"
            SELECT conrelid::regclass::text AS table_name, conname AS name, pg_get_constraintdef(c.oid) AS definition
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE contype IN ('f', 'p', 'u') AND conrelid::regclass::text = $1
            AND n.nspname = current_schema
            "#,
            &[&table_name],
        )
        .await
        .into_database_with(|| {
            format!("could not read constraint definitions of {table_name}")
        })?;
    Ok(rows.iter().map(ConstraintDescription::from).collect())
}

/// Look up and return the definitions of foreign-key constraints whose
/// target table is the one specified.
pub async fn describe_foreign_key_constraints_to_table(
    client: &Client,
    target_table_name: &str,
) -> Result<Vec<ConstraintDescription>, Error> {
    let rows = client
        .query(
            r#"
            SELECT conrelid::regclass::text AS table_name, conname AS name, pg_get_constraintdef(c.oid) AS definition
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE contype = 'f' AND confrelid::regclass::text = $1
            AND n.nspname = current_schema
            "#,
            &[&target_table_name],
        )
        .await
        .into_database_with(|| {
            format!("could not read FK constraint definitions targetting {target_table_name}")
        })?;
    Ok(rows.iter().map(ConstraintDescription::from).collect())
}

/// Look up and return the definitions of all indices on a given table.
pub async fn describe_indices_on_table(
    client: &Client,
    table_name: &str,
) -> Result<Vec<IndexDescription>, Error> {
    let rows = client
        .query(
            r#"
            SELECT indexname AS name, indexdef AS definition, schemaname AS table_name
            FROM pg_indexes
            WHERE schemaname = current_schema AND tablename = $1 AND indexname IS NOT NULL AND indexdef IS NOT NULL
            "#,
            &[&table_name],
        )
        .await
        .into_database("cannot search for indices")?;
    Ok(rows.iter().map(IndexDescription::from).collect())
}

/// Drops a constraint from the database.
///
/// The constraint must exist prior to this call.
pub async fn drop_constraint(
    client: &Client,
    constraint: &ConstraintDescription,
) -> Result<(), Error> {
    let name = &constraint.name;
    let table_name = &constraint.table_name;
    debug!("dropping constraint {name} on table {table_name}");
    client
        .execute(
            &format!("ALTER TABLE {table_name} DROP CONSTRAINT {name}"),
            &[],
        )
        .await
        .into_database_with(|| format!("failed to drop constraint {name} on {table_name}"))?;

    Ok(())
}

/// Drops an index from the database.
///
/// The index must exist prior to this call.
pub async fn drop_index(client: &Client, index: &IndexDescription) -> Result<(), Error> {
    let index_name = &index.name;
    debug!("dropping index {index_name}");
    client
        .execute(&format!("DROP INDEX {index_name}"), &[])
        .await
        .into_database_with(|| format!("failed to temporarily drop {index_name}"))?;

    Ok(())
}

/// Restores (recreates) a constraint.
///
/// The constraint must not exist prior to this call.
#[tracing::instrument(name = "syn2mas.restore_constraint", skip_all, fields(constraint.name = constraint.name))]
pub async fn restore_constraint(
    client: &Client,
    constraint: &ConstraintDescription,
) -> Result<(), Error> {
    let start = Instant::now();

    let ConstraintDescription {
        name,
        table_name,
        definition,
    } = &constraint;

    client
        .execute(
            &format!("ALTER TABLE {table_name} ADD CONSTRAINT {name} {definition}"),
            &[],
        )
        .await
        .into_database_with(|| {
            format!("failed to recreate constraint {name} on {table_name} with {definition}")
        })?;

    info!(
        "constraint {name} rebuilt in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

/// Restores (recreates) a index.
///
/// The index must not exist prior to this call.
#[tracing::instrument(name = "syn2mas.restore_index", skip_all, fields(index.name = index.name))]
pub async fn restore_index(client: &Client, index: &IndexDescription) -> Result<(), Error> {
    let start = Instant::now();

    let IndexDescription {
        name,
        table_name,
        definition,
    } = &index;

    client
        .execute(&format!("{definition}"), &[])
        .await
        .into_database_with(|| {
            format!("failed to recreate index {name} on {table_name} with {definition}")
        })?;

    info!(
        "index {name} rebuilt in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}
