//! OAuth token cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use pasion_data::queue::{
    CleanupConsumedOAuthRefreshTokensJob, CleanupExpiredOAuthAccessTokensJob,
    CleanupRevokedOAuthAccessTokensJob, CleanupRevokedOAuthRefreshTokensJob,
};
use tracing::{debug, info};

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupRevokedOAuthAccessTokensJob {
    #[tracing::instrument(name = "job.cleanup_revoked_oauth_access_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Access tokens that were revoked more than an hour ago can be purged.
        let cutoff = state.clock().now() - chrono::Duration::hours(1);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_revoked_at) = repo
                .oauth2_access_token()
                .cleanup_revoked(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_revoked_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = removed, "cleaned up revoked tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupExpiredOAuthAccessTokensJob {
    #[tracing::instrument(name = "job.cleanup_expired_oauth_access_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Expired access tokens are kept for 30 days because the refresh-token
        // reuse-detection logic needs to know whether an access token was ever
        // used. After that window the data is no longer relevant.
        let cutoff = state.clock().now() - chrono::Duration::days(30);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_expires_at) = repo
                .oauth2_access_token()
                .cleanup_expired(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_expires_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = removed, "cleaned up expired tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(60))
    }
}

#[async_trait]
impl RunnableJob for CleanupRevokedOAuthRefreshTokensJob {
    #[tracing::instrument(name = "job.cleanup_revoked_oauth_refresh_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Refresh tokens revoked over an hour ago are safe to delete.
        let cutoff = state.clock().now() - chrono::Duration::hours(1);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_revoked_at) = repo
                .oauth2_refresh_token()
                .cleanup_revoked(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_revoked_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = removed, "cleaned up revoked tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupConsumedOAuthRefreshTokensJob {
    #[tracing::instrument(name = "job.cleanup_consumed_oauth_refresh_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // A consumed refresh token has already been exchanged for a new one; we
        // keep it for an hour then delete it.
        let cutoff = state.clock().now() - chrono::Duration::hours(1);
        let mut removed = 0;
        let mut cursor = None;

        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (batch_count, last_consumed_at) = repo
                .oauth2_refresh_token()
                .cleanup_consumed(cursor, cutoff, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            cursor = last_consumed_at;
            removed += batch_count;

            if batch_count < BATCH_SIZE {
                break;
            }
        }

        if removed == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = removed, "cleaned up consumed tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
