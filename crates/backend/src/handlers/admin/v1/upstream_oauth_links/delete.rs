// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::{http::StatusCode, prelude::*};

use crate::handlers::admin::{
    call_context::extract_call_context, params::extract_ulid_param,
};
use crate::{AppError, AppResult};

/// Remove an upstream OAuth link by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.delete", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;
    let link_id = extract_ulid_param(req)?;

    let entry = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Upstream OAuth 2.0 Link ID {link_id} not found"))
        })?;

    repo.upstream_oauth_link().remove(&clock, entry).await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use pasion_data::UpstreamOAuthAuthorizationSessionState;
    use ulid::Ulid;

    use super::super::test_utils;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_delete() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        // Pretend it was linked by an authorization session
        let session = repo
            .upstream_oauth_session()
            .add(&mut rng, &state.clock, &provider, String::new(), None, None)
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(&state.clock, session, &link, None, None, None, None)
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/api/admin/v1/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the link was deleted
        let request = Request::get(format!("/api/admin/v1/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        // Verify that the session was marked as unlinked
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            session.state,
            UpstreamOAuthAuthorizationSessionState::Unlinked { .. }
        ));
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let link_id = Ulid::nil();
        let request = Request::delete(format!("/api/admin/v1/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
