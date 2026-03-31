use chrono::{DateTime, Utc};
use tokio_util::sync::CancellationToken;

use pasion_data::{PgRepository, RepositoryAccess, queue::Worker};

use crate::State;

use super::{
    leader::ScheduleDefinition,
    runtime,
    shared::{MAX_CONCURRENT_JOBS, MAX_JOBS_TO_FETCH},
    tracker::JobTracker,
    QueueRunnerError,
};

pub(super) async fn register_worker(
    state: &State,
) -> Result<(Worker, DateTime<Utc>), QueueRunnerError> {
    let mut rng = state.rng();
    let clock = state.clock();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    let registration = repo.queue_worker().register(&mut rng, clock).await?;
    Ok((registration, clock.now()))
}

pub(super) async fn setup_schedules(
    state: &State,
    schedules: &[ScheduleDefinition],
) -> Result<(), QueueRunnerError> {
    let schedule_names: Vec<_> = schedules.iter().map(|schedule| schedule.schedule_name).collect();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;

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
    let mut rng = state.rng();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    match tracker.running_jobs() {
        0 => {}
        1 => tracing::warn!("There is one job still running, waiting for it to finish"),
        count => tracing::warn!("There are {count} jobs still running, waiting for them to finish"),
    }

    tracker.process_jobs(&mut rng, clock, &mut repo, true).await?;
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

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    if now - *last_heartbeat >= chrono::Duration::minutes(1) {
        tracing::info!("Sending heartbeat");
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

    tracker.process_jobs(&mut rng, clock, &mut repo, false).await?;

    let max_jobs_to_fetch = MAX_CONCURRENT_JOBS
        .saturating_sub(tracker.running_jobs())
        .max(MAX_JOBS_TO_FETCH);

    if max_jobs_to_fetch == 0 {
        tracing::warn!("Internal job queue is full, not fetching any new jobs");
    } else {
        let queues = tracker.queues();
        let jobs = repo
            .queue_job()
            .reserve(clock, registration, &queues, max_jobs_to_fetch)
            .await?;

        runtime::spawn_reserved_jobs(tracker, state, cancellation_token, jobs);
    }

    Ok(leader)
}

pub(super) async fn process_all_jobs_in_tests(
    state: &State,
    registration: &Worker,
    tracker: &mut JobTracker,
    cancellation_token: &CancellationToken,
) -> Result<(), QueueRunnerError> {
    let clock = state.clock();
    let mut rng = state.rng();

    let conn = state
        .pool()
        .get()
        .await
        .map_err(|e| QueueRunnerError::Pool(Box::new(e)))?;
    let mut repo = PgRepository::new(conn);

    let queues = tracker.queues();
    let jobs = repo
        .queue_job()
        .reserve(clock, registration, &queues, 10_000)
        .await?;

    runtime::spawn_reserved_jobs(tracker, state, cancellation_token, jobs);
    tracker.process_jobs(&mut rng, clock, &mut repo, true).await?;
    Ok(())
}