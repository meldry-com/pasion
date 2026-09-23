//! Internal Matrix integration endpoints.
//!
//! These routes are not user-facing OAuth2 endpoints. They are called by a
//! trusted homeserver that already shares `matrix.secret` with Pasion.

use anyhow::Context as _;
use oauth2_types::scope::Scope;
use pasion_data::{
    Pagination, RepositoryAccess, TokenType,
    oauth2::OAuth2SessionFilter,
    personal::{PersonalSessionFilter, session::PersonalSessionOwner},
    user::UserRepository,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::handlers::{
    RequesterFingerprint,
    account::{
        DepotExt,
        service::access::{
            PasswordLoginError, PasswordLoginRequest, PasswordVerificationOutcome,
            verify_password_login,
        },
    },
    common::{RouteError, extract_bound_activity_tracker, make_clock, make_rng},
};

#[derive(Deserialize, ToSchema)]
pub struct MatrixPasswordLoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: String,
    #[serde(default)]
    pub initial_device_display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct MatrixPasswordLoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub user_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_ms: Option<i64>,
}

#[endpoint]
#[tracing::instrument(name = "handler.matrix.password_login", skip_all)]
pub async fn password_login(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<MatrixPasswordLoginResponse>, RouteError> {
    let shared_secret = depot.matrix_shared_secret()?;
    if shared_secret.trim().is_empty() {
        return Err(RouteError::Internal(
            std::io::Error::other("matrix.secret must not be empty").into(),
        ));
    }
    let token = bearer_token(req).ok_or(RouteError::InvalidToken)?;
    if !constant_time_eq(token.as_bytes(), shared_secret.as_bytes()) {
        return Err(RouteError::InvalidToken);
    }

    let mut rng = make_rng();
    let clock = make_clock();
    let password_manager = depot.password_manager()?;
    let site_config = depot.site_config()?;
    let limiter = depot.limiter()?;
    let homeserver = depot.homeserver()?;
    let mut repo = depot.repo().await?;
    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let requester = activity_tracker
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);

    let input: MatrixPasswordLoginRequest = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;
    if input.username.is_empty() || input.password.is_empty() || input.device_id.is_empty() {
        return Err(RouteError::BadRequest(
            "missing required login fields".into(),
        ));
    }

    let outcome = verify_password_login(
        &mut repo,
        &mut rng,
        &clock,
        &password_manager,
        &limiter,
        homeserver.as_ref(),
        &site_config,
        PasswordLoginRequest {
            username_or_email: input.username,
            password: Zeroizing::new(input.password),
            user_agent,
            requester,
            skip_requester_limit: true,
        },
    )
    .await
    .map_err(map_password_login_error)?;

    let user = match outcome {
        PasswordVerificationOutcome::Disabled => {
            return Err(RouteError::BadRequest("password_login_disabled".into()));
        }
        PasswordVerificationOutcome::InvalidCredentials => {
            return Err(RouteError::Unauthorized);
        }
        PasswordVerificationOutcome::RateLimited => {
            return Err(RouteError::RateLimited);
        }
        PasswordVerificationOutcome::AccountDeactivated => {
            return Err(RouteError::BadRequest("account_deactivated".into()));
        }
        PasswordVerificationOutcome::AccountLocked => {
            return Err(RouteError::BadRequest("account_locked".into()));
        }
        PasswordVerificationOutcome::Authenticated { user, .. } => user,
    };

    repo.user().acquire_lock_for_sync(&user).await?;

    repo.oauth2_session()
        .finish_bulk(
            &clock,
            OAuth2SessionFilter::new()
                .for_user(&user)
                .for_device(&input.device_id)
                .active_only(),
        )
        .await?;

    let existing_session_filter = PersonalSessionFilter::new()
        .for_actor_user(&user)
        .for_device(&input.device_id)
        .active_only();
    let mut pagination = Pagination::first(1000);
    loop {
        let page = repo
            .personal_session()
            .list(existing_session_filter, pagination)
            .await?;
        let has_next_page = page.has_next_page;
        let next_cursor = page.edges.last().map(|edge| edge.cursor);

        for session in page.edges.into_iter().map(|edge| edge.node.0) {
            repo.personal_session().revoke(&clock, session).await?;
        }

        if !has_next_page {
            break;
        }
        let Some(cursor) = next_cursor else { break };
        pagination = Pagination::first(1000).after(cursor);
    }

    let raw_token = TokenType::PersonalAccessToken.generate(&mut rng);
    let scope = matrix_device_scope(&input.device_id)?;
    let human_name = input
        .initial_device_display_name
        .clone()
        .unwrap_or_else(|| format!("Matrix device {}", input.device_id));

    let session = repo
        .personal_session()
        .add(
            &mut rng,
            &clock,
            PersonalSessionOwner::User(user.id),
            &user,
            human_name,
            scope,
        )
        .await?;
    repo.personal_access_token()
        .add(&mut rng, &clock, &session, &raw_token, None)
        .await?;
    homeserver
        .upsert_device(
            &user.username,
            &input.device_id,
            input.initial_device_display_name.as_deref(),
        )
        .await
        .context("device provisioning failed")
        .map_err(|e| RouteError::Internal(e.into()))?;
    repo.save().await?;

    Ok(Json(MatrixPasswordLoginResponse {
        access_token: raw_token,
        token_type: "Bearer",
        user_id: homeserver.mxid(&user.username),
        device_id: input.device_id,
        expires_in_ms: None,
    }))
}

fn map_password_login_error(error: PasswordLoginError) -> RouteError {
    match error {
        PasswordLoginError::Repository(error) => RouteError::from(error),
        PasswordLoginError::Password(error) => RouteError::Internal(error.into()),
    }
}

fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right) {
        diff |= l ^ r;
    }
    diff == 0
}

fn matrix_device_scope(device_id: &str) -> Result<Scope, RouteError> {
    if !valid_matrix_device_id(device_id) {
        return Err(RouteError::BadRequest("invalid device id".into()));
    }

    format!("openid urn:matrix:client:api:* urn:matrix:client:device:{device_id}")
        .parse::<Scope>()
        .map_err(|_| RouteError::BadRequest("invalid device id".into()))
}

fn valid_matrix_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'/'
                        | b'-'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_bytes() {
        assert!(constant_time_eq(b"shared-secret", b"shared-secret"));
        assert!(!constant_time_eq(b"shared-secret", b"shared-secreu"));
        assert!(!constant_time_eq(b"shared-secret", b"short"));
    }

    #[test]
    fn matrix_device_scope_includes_matrix_api_and_device() {
        let scope = matrix_device_scope("DEVICEID").unwrap();
        let tokens = scope.iter().map(|token| token.as_str()).collect::<Vec<_>>();

        assert!(tokens.contains(&"openid"));
        assert!(tokens.contains(&"urn:matrix:client:api:*"));
        assert!(tokens.contains(&"urn:matrix:client:device:DEVICEID"));
    }

    #[test]
    fn matrix_device_scope_rejects_invalid_device_ids() {
        for invalid in ["", "DEVICE ID", "DEVICE%ID", "DEVICE?ID", "设备"] {
            assert!(matrix_device_scope(invalid).is_err(), "{invalid}");
        }

        assert!(matrix_device_scope("A").is_ok());
        assert!(matrix_device_scope("AB").is_ok());
        assert!(matrix_device_scope("dev/1").is_ok());
        assert!(matrix_device_scope("DEVICE-01").is_ok());
        assert!(matrix_device_scope("DEVICE_01").is_ok());
        assert!(matrix_device_scope("DEVICE.01").is_ok());
        assert!(matrix_device_scope("DEVICE~01").is_ok());
        assert!(matrix_device_scope("A._~!$&'()*+,;=:/-").is_ok());
    }
}
