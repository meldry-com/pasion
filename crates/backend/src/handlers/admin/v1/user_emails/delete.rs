// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use pasion_data::BoxRng;
use pasion_data::queue::{ProvisionUserJob, QueueJobRepositoryExt as _};
use salvo::{http::StatusCode, prelude::*};

use crate::handlers::admin::{
    call_context::extract_call_context, params::extract_ulid_param,
};
use crate::{AppError, AppResult};

/// Remove a user email by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.delete", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let email_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();

    let entry = repo
        .user_email()
        .lookup(email_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User email ID {email_id} not found")))?;

    let provision_job = ProvisionUserJob::new_for_id(entry.user_id);
    repo.user_email().remove(entry).await?;

    // Notify downstream systems about the change
    repo.queue_job().schedule_job(&mut rng, &clock, provision_job).await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    #[tokio::test]
    async fn test_delete() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a user and an email
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let pasion_data::UserEmail { id, .. } = repo
            .user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/api/admin/v1/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the email was deleted
        let request = Request::get(format!("/api/admin/v1/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let email_id = Ulid::nil();
        let request = Request::delete(format!("/api/admin/v1/user-emails/{email_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
