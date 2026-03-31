//! User-related cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use pasion_data::queue::{
    CleanupUserEmailAuthenticationsJob, CleanupUserRecoverySessionsJob, CleanupUserRegistrationsJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupUserRegistrationsJob {
    #[tracing::instrument(name = "job.cleanup_user_registrations", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Registrations expire after about an hour, but we keep rows around for
        // 30 days so abuse patterns can be investigated.
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
                .user_registration()
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
            debug!("no user registrations to clean up");
        } else {
            info!(count = removed, "cleaned up user registrations");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUserRecoverySessionsJob {
    #[tracing::instrument(name = "job.cleanup_user_recovery_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Recovery tickets expire after 10 minutes, but sessions are retained
        // for 7 days for investigation purposes.
        let cutoff = state.clock().now() - chrono::Duration::days(7);
        let upper_bound = Ulid::from_parts(
            u64::try_from(cutoff.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );

        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (batch_count, next_cursor) = repo
                .user_recovery()
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
            debug!("no user recovery sessions to clean up");
        } else {
            info!(count = removed, "cleaned up user recovery sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUserEmailAuthenticationsJob {
    #[tracing::instrument(name = "job.cleanup_user_email_authentications", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Email authentication codes expire after 10 minutes; rows are kept for
        // 7 days for investigation purposes.
        let cutoff = state.clock().now() - chrono::Duration::days(7);
        let upper_bound = Ulid::from_parts(
            u64::try_from(cutoff.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );

        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (batch_count, next_cursor) = repo
                .user_email()
                .cleanup_authentications(cursor, upper_bound, BATCH_SIZE)
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
            debug!("no user email authentications to clean up");
        } else {
            info!(count = removed, "cleaned up user email authentications");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
