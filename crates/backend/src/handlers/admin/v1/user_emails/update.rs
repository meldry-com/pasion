use salvo::prelude::*;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::{
    call_context::extract_call_context,
    model::UserEmail,
    params::extract_ulid_param,
    response::SingleResponse,
};
use crate::{AppError, JsonResult};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestBody {
    email: Option<String>,
    confirmed: Option<bool>,
    is_primary: Option<bool>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.user_emails.update", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UserEmail>> {
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
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let user_email = crate::services::user_admin::patch_user_email(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        id,
        pasion_data::UserEmailPatch {
            email: body.email,
            confirmed: body.confirmed,
            is_primary: body.is_primary,
        },
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(UserEmail::from(
        user_email,
    ))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            AppError::not_found(format!("User email ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            AppError::bad_request(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            AppError::conflict(format!("User email {email:?} already in use"))
        }
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::bad_request(format!("Unexpected user lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            AppError::bad_request(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            AppError::bad_request(format!(
                "Unexpected upstream oauth link lookup failure for {id}"
            ))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            AppError::bad_request(format!("Provider ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            AppError::bad_request("Invalid display name")
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => AppError::conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::Homeserver(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use pasion_data::{
        RepositoryAccess,
        user::{UserEmailRepository, UserRepository},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use ulid::Ulid;

    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_patch_user_email_updates_address_confirmation_and_primary() {
        setup();
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:pasion:admin").await;
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let suffix = Ulid::new().to_string().to_lowercase();
        let username = format!("alice{suffix}");
        let primary_email = format!("alice+{suffix}@example.com");
        let secondary_email = format!("alice+secondary+{suffix}@example.com");
        let updated_email = format!("alice+updated+{suffix}@example.com");

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let primary = repo
            .user_email()
            .add(&mut rng, &state.clock, &user, primary_email)
            .await
            .unwrap();
        let secondary = repo
            .user_email()
            .add(&mut rng, &state.clock, &user, secondary_email)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/api/admin/v1/user-emails/{}", secondary.id))
            .bearer(&token)
            .json(serde_json::json!({
                "email": updated_email.clone(),
                "confirmed": false,
                "isPrimary": true
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["email"], updated_email);
        assert_eq!(body["data"]["attributes"]["is_primary"], true);
        assert_eq!(
            body["data"]["attributes"]["confirmed_at"],
            serde_json::Value::Null
        );

        let mut repo = state.repository().await.unwrap();
        let updated = repo
            .user_email()
            .lookup(secondary.id)
            .await
            .unwrap()
            .unwrap();
        let old_primary = repo.user_email().lookup(primary.id).await.unwrap().unwrap();

        assert_eq!(updated.email, updated_email);
        assert!(updated.is_primary);
        assert!(updated.confirmed_at.is_none());
        assert!(!old_primary.is_primary);
    }
}
