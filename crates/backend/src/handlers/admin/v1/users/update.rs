use crate::record_error;
use salvo::{http::StatusCode, prelude::*};
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::{
    admin::{
        call_context::extract_call_context,
        model::User,
        params::extract_ulid_param,
        response::{ErrorResponse, SingleResponse},
    },
    rest::DepotExt,
};

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User ID {0} not found")]
    NotFound(Ulid),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
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
    display_name: Option<Option<String>>,
    avatar_url: Option<Option<String>>,
    preferred_locale: Option<Option<String>>,
    admin: Option<bool>,
    locked: Option<bool>,
    deactivated: Option<bool>,
    hs_erase: Option<bool>,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.users.update", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let homeserver = depot.homeserver().map_err(|error| {
        RouteError::Internal(Box::new(std::io::Error::other(error.to_string())))
    })?;
    let mut rng = crate::handlers::rest::make_rng();
    let body: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::BadRequest(e.to_string()))?;

    let patch = pasion_data_model::AdminUserPatch {
        display_name: body.display_name,
        avatar_url: body.avatar_url,
        preferred_locale: body.preferred_locale,
        can_request_admin: body.admin,
        locked: body.locked,
        deactivated: body.deactivated,
    };

    let user = crate::services::user_admin::patch_user(
        &mut repo,
        &mut rng,
        &*clock,
        homeserver.as_ref(),
        admin_user.as_ref(),
        id,
        patch,
        body.hs_erase.unwrap_or(true),
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> RouteError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            RouteError::NotFound(id)
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            RouteError::BadRequest(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            RouteError::BadRequest(format!("Unexpected user email lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            RouteError::BadRequest(format!(
                "Unexpected upstream oauth link lookup failure for {id}"
            ))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            RouteError::BadRequest(format!("Provider ID {id} not found"))
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
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => RouteError::Conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::Homeserver(error) => {
            RouteError::Internal(Box::new(std::io::Error::other(error.to_string())))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            RouteError::Internal(Box::new(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_matrix::{HomeserverConnection, ProvisionRequest};
    use pasion_storage::{RepositoryAccess, user::UserRepository};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use ulid::Ulid;

    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_patch_user_profile_and_state() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.clone())
            .await
            .unwrap();
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "displayName": "Alice Admin",
                "preferredLocale": "zh-CN",
                "admin": true,
                "locked": true
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["display_name"], "Alice Admin");
        assert_eq!(body["data"]["attributes"]["preferred_locale"], "zh-CN");
        assert_eq!(body["data"]["attributes"]["admin"], true);
        assert!(body["data"]["attributes"]["locked_at"].is_string());

        let user = state
            .homeserver_connection
            .query_user(&username)
            .await
            .unwrap();
        assert_eq!(user.displayname.as_deref(), Some("Alice Admin"));
    }

    #[tokio::test]
    async fn test_patch_user_reactivate() {
        setup();
        let pool = pasion_storage_pg::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());
        let mut rng = ChaChaRng::seed_from_u64(unique);

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();
        state
            .homeserver_connection
            .delete_user(&user.username, true)
            .await
            .unwrap();

        let request = Request::patch(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "deactivated": false
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["attributes"]["deactivated_at"], serde_json::Value::Null);

        let matrix_user = state
            .homeserver_connection
            .query_user(&user.username)
            .await
            .unwrap();
        assert!(!matrix_user.deactivated);
    }
}
