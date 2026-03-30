use crate::record_error;
use salvo::{http::StatusCode, prelude::*};
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UpstreamOAuthLink,
    params::extract_ulid_param,
    response::{ErrorResponse, SingleResponse},
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Upstream OAuth 2.0 Link ID {0} not found")]
    NotFound(Ulid),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::params::UlidPathParamRejection);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
        };
        res.status_code(status);
        if let Some(event_id) = sentry_event_id {
            if let Ok(value) = http::HeaderValue::from_str(&event_id.to_string()) {
                res.headers_mut().insert("x-sentry-event-id", value);
            }
        }
        res.render(Json(error));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestBody {
    user_id: Option<Option<Ulid>>,
    subject: Option<String>,
    human_account_name: Option<Option<String>>,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.update", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<UpstreamOAuthLink>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::rest::make_rng();
    let body: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::BadRequest(e.to_string()))?;

    let link = crate::services::user_admin::patch_upstream_oauth_link(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        id,
        pasion_data::UpstreamOAuthLinkPatch {
            user_id: body.user_id,
            subject: body.subject,
            human_account_name: body.human_account_name,
        },
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthLink::from(link),
    )))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> RouteError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            RouteError::NotFound(id)
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            RouteError::BadRequest(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            RouteError::BadRequest(format!("Provider ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => RouteError::Conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            RouteError::Internal(Box::new(error))
        }
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            RouteError::BadRequest(format!("Unexpected user lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            RouteError::BadRequest(format!("Unexpected user email lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            RouteError::BadRequest("Invalid display name".to_owned())
        }
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            RouteError::BadRequest(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            RouteError::Conflict(format!("User email {email:?} already in use"))
        }
        crate::services::user_admin::UserAdminServiceError::Homeserver(error) => {
            RouteError::Internal(Box::new(std::io::Error::other(error.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
        user::UserRepository,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use ulid::Ulid;

    use super::super::test_utils;
    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_patch_upstream_oauth_link_updates_subject_user_and_name() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let suffix = Ulid::new().to_string().to_lowercase();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, format!("alice{suffix}"))
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, format!("bob{suffix}"))
            .await
            .unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params(&format!("provider-{suffix}")),
            )
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-1"),
                Some("Alice Provider".to_owned()),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .json(serde_json::json!({
                "userId": bob.id,
                "subject": format!("subject-{suffix}-2"),
                "humanAccountName": "Bob Provider"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["subject"],
            format!("subject-{suffix}-2")
        );
        assert_eq!(body["data"]["attributes"]["user_id"], bob.id.to_string());
        assert_eq!(
            body["data"]["attributes"]["human_account_name"],
            "Bob Provider"
        );

        let mut repo = state.repository().await.unwrap();
        let updated = repo
            .upstream_oauth_link()
            .lookup(link.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.user_id, Some(bob.id));
        assert_eq!(updated.subject, format!("subject-{suffix}-2"));
        assert_eq!(updated.human_account_name.as_deref(), Some("Bob Provider"));

        let _ = alice;
    }

    #[tokio::test]
    async fn test_patch_upstream_oauth_link_rejects_duplicate_subject() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let suffix = Ulid::new().to_string().to_lowercase();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, format!("alice{suffix}"))
            .await
            .unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params(&format!("provider-{suffix}")),
            )
            .await
            .unwrap();
        let first = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-1"),
                None,
            )
            .await
            .unwrap();
        let second = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-2"),
                None,
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&first, &alice)
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&second, &alice)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/api/admin/v1/upstream-oauth-links/{}", second.id))
            .bearer(&token)
            .json(serde_json::json!({
                "subject": format!("subject-{suffix}-1")
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }
}
