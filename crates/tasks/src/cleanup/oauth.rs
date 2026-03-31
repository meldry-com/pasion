//! OAuth grants and upstream OAuth cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use pasion_data::queue::{
    CleanupOAuthAuthorizationGrantsJob, CleanupOAuthDeviceCodeGrantsJob,
    CleanupUpstreamOAuthLinksJob, CleanupUpstreamOAuthSessionsJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupOAuthAuthorizationGrantsJob {
    #[tracing::instrument(name = "job.cleanup_oauth_authorization_grants", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Authorization grants are short-lived but kept for 7 days for abuse
        // investigation.
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
                .oauth2_authorization_grant()
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
            debug!("no authorization grants to clean up");
        } else {
            info!(count = removed, "cleaned up authorization grants");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupOAuthDeviceCodeGrantsJob {
    #[tracing::instrument(name = "job.cleanup_oauth_device_code_grants", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Device code grants live briefly but we retain them for 7 days.
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
                .oauth2_device_code_grant()
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
            debug!("no device code grants to clean up");
        } else {
            info!(count = removed, "cleaned up device code grants");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUpstreamOAuthSessionsJob {
    #[tracing::instrument(name = "job.cleanup_upstream_oauth_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Pending upstream OAuth sessions older than 7 days are cleaned up.
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
                .upstream_oauth_session()
                .cleanup_orphaned(cursor, upper_bound, BATCH_SIZE)
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
            debug!("no pending upstream OAuth sessions to clean up");
        } else {
            info!(count = removed, "cleaned up pending upstream OAuth sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUpstreamOAuthLinksJob {
    #[tracing::instrument(name = "job.cleanup_upstream_oauth_links", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Orphaned upstream OAuth links older than 7 days are cleaned up.
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
                .upstream_oauth_link()
                .cleanup_orphaned(cursor, upper_bound, BATCH_SIZE)
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
            debug!("no orphaned upstream OAuth links to clean up");
        } else {
            info!(count = removed, "cleaned up orphaned upstream OAuth links");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
