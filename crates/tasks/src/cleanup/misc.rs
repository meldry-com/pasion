//! Miscellaneous cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use pasion_data::queue::{CleanupQueueJobsJob, PruneStalePolicyDataJob};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupQueueJobsJob {
    #[tracing::instrument(name = "job.cleanup_queue_jobs", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Completed and failed queue jobs older than 30 days are removed.
        let cutoff = state.clock().now() - chrono::Duration::days(30);
        let upper_bound = Ulid::from_parts(
            u64::try_from(cutoff.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );

        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (batch_count, next_cursor) = repo
                .queue_job()
                .cleanup(cursor, upper_bound, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = next_cursor;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no queue jobs to clean up");
        } else {
            info!(count = removed, "cleaned up queue jobs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for PruneStalePolicyDataJob {
    #[tracing::instrument(name = "job.prune_stale_policy_data", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Retain only the 10 most recent policy snapshots.
        let pruned = repo
            .policy_data()
            .prune(10)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;

        if pruned == 0 {
            debug!("no stale policy data to prune");
        } else {
            info!(count = pruned, "pruned stale policy data");
        }

        Ok(())
    }
}
