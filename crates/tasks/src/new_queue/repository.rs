use chrono::{DateTime, Utc};
use diesel_async::RunQueryDsl as _;
use pasion_data::{PgRepository, RepositoryAccess, queue::Worker};
use tokio_util::sync::CancellationToken;

use super::{
    QueueRunnerError,
    leader::ScheduleDefinition,
    runtime,
    shared::{MAX_CONCURRENT_JOBS, MAX_JOBS_TO_FETCH},
    tracker::JobTracker,
};
use crate::State;

/// Queue transitions must commit together, including replacement attempts.
pub(super) async fn begin_queue_transaction(
    pool: &diesel_async::pooled_connection::deadpool::Pool<diesel_async::AsyncPgConnection>,
) -> Result<PgRepository, QueueRunnerError> {
    let mut conn = pasion_data::pg::get_connection(pool).await?;
    diesel::sql_query("BEGIN")
        .execute(&mut *conn)
        .await
        .map_err(pasion_data::DatabaseError::from)?;
    Ok(PgRepository::new(conn))
}

fn jobs_to_fetch_capacity(running_jobs: usize) -> usize {
    MAX_CONCURRENT_JOBS
        .saturating_sub(running_jobs)
        .min(MAX_JOBS_TO_FETCH)
}

pub(super) async fn register_worker(
    state: &State,
) -> Result<(Worker, DateTime<Utc>), QueueRunnerError> {
    let mut rng = state.rng();
    let clock = state.clock();

    let conn = pasion_data::pg::get_connection(state.pool()).await?;
    let mut repo = PgRepository::new(conn);

    let registration = repo.queue_worker().register(&mut rng, clock).await?;
    Ok((registration, clock.now()))
}

pub(super) async fn setup_schedules(
    state: &State,
    schedules: &[ScheduleDefinition],
) -> Result<(), QueueRunnerError> {
    let schedule_names: Vec<_> = schedules
        .iter()
        .map(|schedule| schedule.schedule_name)
        .collect();

    let conn = pasion_data::pg::get_connection(state.pool()).await?;

    let mut repo = PgRepository::new(conn);
    repo.queue_schedule().setup(&schedule_names).await?;
    Ok(())
}

pub(super) async fn shutdown_worker(
    state: &State,
    registration: &Worker,
    tracker: &mut JobTracker,
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    match tracker.running_jobs() {
        0 => {}
        1 => tracing::warn!("There is one job still running, waiting for it to finish"),
        count => tracing::warn!("There are {count} jobs still running, waiting for them to finish"),
    }

    drain_jobs(state.pool(), clock, tracker).await?;
    let conn = pasion_data::pg::get_connection(state.pool()).await?;
    let mut repo = PgRepository::new(conn);
    repo.queue_worker().shutdown(clock, registration).await?;
    Ok(())
}

pub(super) async fn tick_worker(
    state: &State,
    registration: &Worker,
    last_heartbeat: &mut DateTime<Utc>,
    tracker: &mut JobTracker,
    cancellation_token: &CancellationToken,
) -> Result<bool, QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();
    let now = clock.now();
    let heartbeat_age = now - *last_heartbeat;

    let mut repo = begin_queue_transaction(state.pool()).await?;

    if heartbeat_age >= chrono::Duration::seconds(90) {
        tracing::warn!(
            worker.id = %registration.id,
            heartbeat.age_secs = heartbeat_age.num_seconds(),
            running_jobs = tracker.running_jobs(),
            "Worker heartbeat is overdue"
        );
    }

    if heartbeat_age >= chrono::Duration::minutes(1) {
        tracing::info!(
            worker.id = %registration.id,
            heartbeat.age_secs = heartbeat_age.num_seconds(),
            running_jobs = tracker.running_jobs(),
            "Sending heartbeat"
        );
        repo.queue_worker().heartbeat(clock, registration).await?;
        *last_heartbeat = now;
    }

    repo.queue_worker()
        .remove_leader_lease_if_expired(clock)
        .await?;

    let leader = repo
        .queue_worker()
        .try_get_leader_lease(clock, registration)
        .await?;

    tracker.process_jobs(&mut rng, clock, &mut repo).await?;

    let running_jobs = tracker.running_jobs();
    let max_jobs_to_fetch = jobs_to_fetch_capacity(running_jobs);

    let mut reserved_jobs = Vec::new();
    if max_jobs_to_fetch == 0 {
        tracing::warn!(
            worker.id = %registration.id,
            running_jobs,
            max_concurrent_jobs = MAX_CONCURRENT_JOBS,
            "Internal job queue is full, not fetching any new jobs"
        );
    } else {
        let queues = tracker.queues();
        let jobs = repo
            .queue_job()
            .reserve(clock, registration, &queues, max_jobs_to_fetch)
            .await?;

        if !jobs.is_empty() {
            tracing::info!(
                worker.id = %registration.id,
                running_jobs,
                reserved_jobs = jobs.len(),
                max_jobs_to_fetch,
                "Reserved jobs from the queue"
            );
        }

        reserved_jobs = jobs;
    }

    repo.boxed().save().await?;
    runtime::spawn_reserved_jobs(tracker, state, cancellation_token, reserved_jobs);
    Ok(leader)
}

pub(super) async fn process_all_jobs_in_tests(
    state: &State,
    registration: &Worker,
    tracker: &mut JobTracker,
    cancellation_token: &CancellationToken,
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    let conn = pasion_data::pg::get_connection(state.pool()).await?;
    let mut repo = PgRepository::new(conn);

    let queues = tracker.queues();
    let jobs = repo
        .queue_job()
        .reserve(clock, registration, &queues, 10_000)
        .await?;
    drop(repo);

    runtime::spawn_reserved_jobs(tracker, state, cancellation_token, jobs);
    drain_jobs(state.pool(), clock, tracker).await?;
    Ok(())
}

pub(super) async fn drain_jobs(
    pool: &diesel_async::pooled_connection::deadpool::Pool<diesel_async::AsyncPgConnection>,
    clock: &dyn pasion_data::Clock,
    tracker: &mut JobTracker,
) -> Result<(), QueueRunnerError> {
    use rand_core::SeedableRng as _;
    let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).expect("failed to seed rng");
    while tracker.running_jobs() > 0 {
        // Jobs may need this same pool. Wait before taking a connection, even
        // when the pool has only one slot.
        tracker.collect_next_job().await;
        let mut repo = begin_queue_transaction(pool).await?;
        tracker.process_jobs(&mut rng, clock, &mut repo).await?;
        repo.boxed().save().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::jobs_to_fetch_capacity;

    #[tokio::test]
    async fn retry_failure_rolls_back_the_failed_transition() {
        use diesel_async::RunQueryDsl as _;
        use pasion_data::{PgRepository, RepositoryAccess, clock::SystemClock};
        use rand_core::SeedableRng as _;

        let pool = pasion_data::test_utils::setup_test_pool().await;
        let clock = SystemClock::default();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);
        let mut repo = PgRepository::new(pasion_data::pg::get_connection(&pool).await.unwrap());
        let worker = repo
            .queue_worker()
            .register(&mut rng, &clock)
            .await
            .unwrap();
        repo.queue_job()
            .schedule(
                &mut rng,
                &clock,
                "atomic-retry",
                serde_json::json!({}),
                serde_json::json!({}),
            )
            .await
            .unwrap();
        let job = repo
            .queue_job()
            .reserve(&clock, &worker, &["atomic-retry"], 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let mut conn = repo.into_inner();
        diesel::sql_query("CREATE FUNCTION reject_retry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.attempt > 0 THEN RAISE EXCEPTION 'injected retry failure'; END IF; RETURN NEW; END $$")
            .execute(&mut *conn).await.unwrap();
        diesel::sql_query("CREATE TRIGGER reject_retry BEFORE INSERT ON queue_jobs FOR EACH ROW EXECUTE FUNCTION reject_retry()")
            .execute(&mut *conn).await.unwrap();
        drop(conn);

        let mut repo = super::begin_queue_transaction(&pool).await.unwrap();
        repo.queue_job()
            .mark_as_failed(&clock, job.id, "retryable")
            .await
            .unwrap();
        assert!(
            repo.queue_job()
                .retry(&mut rng, &clock, job.id, chrono::Duration::zero())
                .await
                .is_err()
        );
        repo.boxed().cancel().await.unwrap();

        let mut conn = pasion_data::pg::get_connection(&pool).await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        let row: Count =
            diesel::sql_query("SELECT COUNT(*) AS count FROM queue_jobs WHERE status = 'running'")
                .get_result(&mut *conn)
                .await
                .unwrap();
        assert_eq!(row.count, 1, "the original attempt must remain recoverable");
    }

    #[test]
    fn limits_fetch_to_remaining_capacity() {
        assert_eq!(jobs_to_fetch_capacity(0), 5);
        assert_eq!(jobs_to_fetch_capacity(4), 5);
        assert_eq!(jobs_to_fetch_capacity(7), 3);
        assert_eq!(jobs_to_fetch_capacity(10), 0);
        assert_eq!(jobs_to_fetch_capacity(12), 0);
    }
}
