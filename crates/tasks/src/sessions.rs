use std::collections::HashSet;

use async_trait::async_trait;
use chrono::Duration;
use pasion_data::{
    oauth2::OAuth2SessionFilter,
    queue::{
        ExpireInactiveOAuthSessionsJob, ExpireInactiveSessionsJob, ExpireInactiveUserSessionsJob,
        QueueJobRepositoryExt, SyncDevicesJob,
    },
    user::BrowserSessionFilter,
};

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for ExpireInactiveSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let Some(config) = state.site_config().session_expiration.as_ref() else {
            // Automatic session expiration is not enabled.
            return Ok(());
        };

        let clock = state.clock();
        let mut rng = state.rng();
        let now = clock.now();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Schedule a child job for OAuth sessions if TTL is configured.
        if let Some(ttl) = config.oauth_session_inactivity_ttl {
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    clock,
                    ExpireInactiveOAuthSessionsJob::new(now - ttl),
                )
                .await
                .map_err(JobError::retry)?;
        }

        // Schedule a child job for browser sessions if TTL is configured.
        if let Some(ttl) = config.user_session_inactivity_ttl {
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    clock,
                    ExpireInactiveUserSessionsJob::new(now - ttl),
                )
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveOAuthSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let clock = state.clock();
        let mut rng = state.rng();
        let mut users_synced = HashSet::new();

        // Stagger device-sync jobs so they don't all hit the homeserver at once.
        let mut delay = Duration::minutes(1);

        let filter = OAuth2SessionFilter::new()
            .with_last_active_before(self.threshold())
            .for_any_user()
            .only_dynamic_clients()
            .active_only();

        let pagination = self.pagination(100);

        let page = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .map_err(JobError::retry)?;

        // If there are more sessions beyond this page, schedule a follow-up
        // job to handle the next batch.
        if let Some(continuation) = self.next(&page) {
            tracing::info!("Scheduling job to expire the next batch of inactive sessions");
            repo.queue_job()
                .schedule_job(&mut rng, clock, continuation)
                .await
                .map_err(JobError::retry)?;
        }

        for edge in page.edges {
            // For each distinct user we encounter, schedule a device sync so
            // the homeserver is kept in sync with the expired sessions.
            if let Some(user_id) = edge.node.user_id {
                let is_new = users_synced.insert(user_id);
                if is_new {
                    tracing::info!(user.id = %user_id, "Scheduling devices sync for user");
                    repo.queue_job()
                        .schedule_job_later(
                            &mut rng,
                            clock,
                            SyncDevicesJob::new_for_id(user_id),
                            clock.now() + delay,
                        )
                        .await
                        .map_err(JobError::retry)?;
                    delay += Duration::seconds(10);
                }
            }

            repo.oauth2_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveUserSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let clock = state.clock();
        let mut rng = state.rng();

        let filter = BrowserSessionFilter::new()
            .with_last_active_before(self.threshold())
            .active_only();

        let pagination = self.pagination(100);

        let page = repo
            .browser_session()
            .list(filter, pagination)
            .await
            .map_err(JobError::retry)?;

        if let Some(continuation) = self.next(&page) {
            tracing::info!("Scheduling job to expire the next batch of inactive sessions");
            repo.queue_job()
                .schedule_job(&mut rng, clock, continuation)
                .await
                .map_err(JobError::retry)?;
        }

        for edge in page.edges {
            repo.browser_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
