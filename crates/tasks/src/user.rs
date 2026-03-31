// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Background jobs for user lifecycle management (deactivation / reactivation).

use anyhow::Context;
use async_trait::async_trait;
use pasion_data::{
    RepositoryAccess,
    oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
    queue::{DeactivateUserJob, ReactivateUserJob},
    user::{BrowserSessionFilter, UserEmailFilter, UserRepository},
};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

// ── Deactivate ───────────────────────────────────────────────────────

#[async_trait]
impl RunnableJob for DeactivateUserJob {
    #[tracing::instrument(
        name = "job.deactivate_user",
        fields(user.id = %self.user_id(), erase = %self.hs_erase()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // ── 1. Look up the user ──────────────────────────────────────
        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("user not found")
            .map_err(JobError::fail)?;

        // ── 2. Mark as deactivated in our database ───────────────────
        let user = repo
            .user()
            .deactivate(clock, user)
            .await
            .context("failed to deactivate user")
            .map_err(JobError::retry)?;

        // ── 3. Terminate every session type ──────────────────────────

        let killed_browser = repo
            .browser_session()
            .finish_bulk(
                clock,
                BrowserSessionFilter::new().for_user(&user).active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(count = killed_browser, "terminated browser sessions");

        let killed_oauth = repo
            .oauth2_session()
            .finish_bulk(
                clock,
                OAuth2SessionFilter::new().for_user(&user).active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(count = killed_oauth, "terminated OAuth 2.0 sessions");

        let killed_personal_actor = repo
            .personal_session()
            .revoke_bulk(
                clock,
                PersonalSessionFilter::new()
                    .for_actor_user(&user)
                    .active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(count = killed_personal_actor, "revoked personal sessions (actor)");

        let killed_personal_owner = repo
            .personal_session()
            .revoke_bulk(
                clock,
                PersonalSessionFilter::new()
                    .for_owner_user(&user)
                    .active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(count = killed_personal_owner, "revoked personal sessions (owner)");

        // ── 4. Remove email addresses ────────────────────────────────

        let removed_emails = repo
            .user_email()
            .remove_bulk(UserEmailFilter::new().for_user(&user))
            .await
            .map_err(JobError::retry)?;
        info!(count = removed_emails, "removed email addresses");

        // ── 5. Persist before calling out to the homeserver ──────────
        repo.save().await.map_err(JobError::retry)?;

        // ── 6. Notify the homeserver ─────────────────────────────────
        info!(username = %user.username, "deactivating user on homeserver");
        matrix
            .delete_user(&user.username, self.hs_erase())
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}

// ── Reactivate ───────────────────────────────────────────────────────

#[async_trait]
impl RunnableJob for ReactivateUserJob {
    #[tracing::instrument(
        name = "job.reactivate_user",
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _ctx: JobContext) -> Result<(), JobError> {
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("user not found")
            .map_err(JobError::fail)?;

        // Reactivate on the homeserver first — only mark locally once that
        // succeeds so the user cannot log in before the HS is ready.
        info!(username = %user.username, "reactivating user on homeserver");
        matrix
            .reactivate_user(&user.username)
            .await
            .map_err(JobError::retry)?;

        let _user = repo
            .user()
            .reactivate(user)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;
        Ok(())
    }
}
