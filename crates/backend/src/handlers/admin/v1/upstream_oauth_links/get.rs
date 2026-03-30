use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use ulid::Ulid;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::UpstreamOAuthLink,
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Upstream OAuth 2.0 Link ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_entry_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        res.status_code(status);
        if let Some(event_id) = sentry_entry_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.get", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<UpstreamOAuthLink>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthLink::from(link),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use ulid::Ulid;

    use super::super::test_utils;
    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = state.rng();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject1".to_owned(),
                None,
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let link_id = link.id;
        let request = Request::get(format!("/api/admin/v1/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG09NMZYX8MFYH578R9",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "subject": "subject1",
              "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "human_account_name": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_not_found() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:pasion:admin").await;

        let link_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
