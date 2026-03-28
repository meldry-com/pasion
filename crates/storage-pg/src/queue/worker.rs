//! A module containing the PostgreSQL implementation of the
//! [`QueueWorkerRepository`].

use async_trait::async_trait;
use chrono::Duration;
use diesel::prelude::*;
use diesel::sql_types::{Timestamptz, Uuid as DieselUuid};
use diesel_async::RunQueryDsl;
use pasion_data_model::Clock;
use pasion_storage::queue::{QueueWorkerRepository, Worker};
use rand::RngCore;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{queue_leader, queue_workers};
use crate::DatabaseError;

/// An implementation of [`QueueWorkerRepository`] for a PostgreSQL connection.
pub struct PgQueueWorkerRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgQueueWorkerRepository<'c> {
    /// Create a new [`PgQueueWorkerRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

/// Insertable row for registering a new worker.
#[derive(Insertable)]
#[diesel(table_name = queue_workers)]
struct NewWorker {
    queue_worker_id: Uuid,
    registered_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
impl QueueWorkerRepository for PgQueueWorkerRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_worker.register",
        skip_all,
        fields(
            worker.id,
        ),
        err,
    )]
    async fn register(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<Worker, Self::Error> {
        let now = clock.now();
        let worker_id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("worker.id", tracing::field::display(worker_id));

        let new_worker = NewWorker {
            queue_worker_id: Uuid::from(worker_id),
            registered_at: now,
            last_seen_at: now,
        };

        diesel::insert_into(queue_workers::table)
            .values(&new_worker)
            .execute(self.conn)
            .await?;

        Ok(Worker { id: worker_id })
    }

    #[tracing::instrument(
        name = "db.queue_worker.heartbeat",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn heartbeat(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_workers::table
                .filter(queue_workers::queue_worker_id.eq(Uuid::from(worker.id)))
                .filter(queue_workers::shutdown_at.is_null()),
        )
        .set(queue_workers::last_seen_at.eq(now))
        .execute(self.conn)
        .await?;

        // If no row was updated, the worker was shutdown so we return an error
        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.shutdown",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn shutdown(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let rows_affected = diesel::update(
            queue_workers::table
                .filter(queue_workers::queue_worker_id.eq(Uuid::from(worker.id))),
        )
        .set(queue_workers::shutdown_at.eq(Some(now)))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        // Remove the leader lease if we were holding it
        let rows_affected = diesel::delete(
            queue_leader::table
                .filter(queue_leader::queue_worker_id.eq(Uuid::from(worker.id))),
        )
        .execute(self.conn)
        .await?;

        // If we were holding the leader lease, notify workers
        if rows_affected > 0 {
            diesel::sql_query("NOTIFY queue_leader_stepdown")
                .execute(self.conn)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.shutdown_dead_workers",
        skip_all,
        err,
    )]
    async fn shutdown_dead_workers(
        &mut self,
        clock: &dyn Clock,
        threshold: Duration,
    ) -> Result<(), Self::Error> {
        // Here the threshold is usually set to a few minutes, so we don't need to use
        // the database time, as we can assume worker clocks have less than a minute
        // skew between each other, else other things would break
        let now = clock.now();
        diesel::update(
            queue_workers::table
                .filter(queue_workers::shutdown_at.is_null())
                .filter(queue_workers::last_seen_at.lt(now - threshold)),
        )
        .set(queue_workers::shutdown_at.eq(Some(now)))
        .execute(self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.remove_leader_lease_if_expired",
        skip_all,
        err,
    )]
    async fn remove_leader_lease_if_expired(
        &mut self,
        _clock: &dyn Clock,
    ) -> Result<(), Self::Error> {
        // `expires_at` is a rare exception where we use the database time, as this
        // would be very sensitive to clock skew between workers
        diesel::sql_query("DELETE FROM queue_leader WHERE expires_at < NOW()")
            .execute(self.conn)
            .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.try_get_leader_lease",
        skip_all,
        fields(
            %worker.id,
        ),
        err,
    )]
    async fn try_get_leader_lease(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<bool, Self::Error> {
        let now = clock.now();
        // The queue_leader table is meant to only have a single row, which conflicts on
        // the `active` column.

        // If there is a conflict, we update the `expires_at` column ONLY IF the current
        // leader is ourselves.

        // `expires_at` is a rare exception where we use the database time, as this
        // would be very sensitive to clock skew between workers.
        let rows_affected: usize = diesel::sql_query(
            r"
                INSERT INTO queue_leader (elected_at, expires_at, queue_worker_id)
                VALUES ($1, NOW() + INTERVAL '5 seconds', $2)
                ON CONFLICT (active)
                DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE queue_leader.queue_worker_id = $2
            ",
        )
        .bind::<Timestamptz, _>(now)
        .bind::<DieselUuid, _>(Uuid::from(worker.id))
        .execute(self.conn)
        .await?;

        // We can then detect whether we are the leader or not by checking how many rows
        // were affected by the upsert
        let am_i_the_leader = rows_affected == 1;

        Ok(am_i_the_leader)
    }
}
