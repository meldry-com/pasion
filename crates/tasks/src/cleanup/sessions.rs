//! Session cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use pasion_data::queue::{
    CleanupFinishedOAuth2SessionsJob, CleanupFinishedUserSessionsJob,
    CleanupInactiveOAuth2SessionIpsJob, CleanupInactiveUserSessionIpsJob,
};
use tracing::{debug, info};

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupFinishedOAuth2SessionsJob {
    #[tracing::instrument(name = "job.cleanup_finished_oauth2_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // OAuth2 sessions that have been finished for over 30 days are removed.
        let cutoff = state.clock().now() - chrono::Duration::days(30);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_finished_at) = repo
                .oauth2_session()
                .cleanup_finished(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_finished_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no finished OAuth2 sessions to clean up");
        } else {
            info!(count = removed, "cleaned up finished OAuth2 sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupFinishedUserSessionsJob {
    #[tracing::instrument(name = "job.cleanup_finished_user_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Browser sessions finished more than 30 days ago are removed, provided
        // they have no remaining child OAuth2 sessions.
        let cutoff = state.clock().now() - chrono::Duration::days(30);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_finished_at) = repo
                .browser_session()
                .cleanup_finished(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_finished_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no finished user sessions to clean up");
        } else {
            info!(count = removed, "cleaned up finished user sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupInactiveOAuth2SessionIpsJob {
    #[tracing::instrument(name = "job.cleanup_inactive_oauth2_session_ips", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Scrub IP addresses from OAuth2 sessions inactive for 30+ days.
        let threshold = state.clock().now() - chrono::Duration::days(30);
        let mut scrubbed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_active_at) = repo
                .oauth2_session()
                .cleanup_inactive_ips(cursor, threshold, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_active_at;
            scrubbed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if scrubbed == 0 {
            debug!("no OAuth2 session IPs to clean up");
        } else {
            info!(count = scrubbed, "cleaned up inactive OAuth2 session IPs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupInactiveUserSessionIpsJob {
    #[tracing::instrument(name = "job.cleanup_inactive_user_session_ips", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Scrub IP addresses from user/browser sessions inactive for 30+ days.
        let threshold = state.clock().now() - chrono::Duration::days(30);
        let mut scrubbed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_active_at) = repo
                .browser_session()
                .cleanup_inactive_ips(cursor, threshold, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_active_at;
            scrubbed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if scrubbed == 0 {
            debug!("no user session IPs to clean up");
        } else {
            info!(count = scrubbed, "cleaned up inactive user session IPs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
