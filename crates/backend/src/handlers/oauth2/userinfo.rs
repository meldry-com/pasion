use pasion_data_model::{BoxClock, BoxRng, SystemClock};
use pasion_jose::{
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use pasion_keystore::Keystore;
use pasion_router::UrlBuilder;
use pasion_salvo_utils::{
    record_error,
    sentry::SentryEventID,
    user_authorization::{AuthorizationVerificationError, UserAuthorization},
};
use pasion_storage::{BoxRepository, BoxRepositoryFactory, oauth2::OAuth2ClientRepository};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use serde::Serialize;
use serde_with::skip_serializing_none;
use thiserror::Error;
use ulid::Ulid;


#[skip_serializing_none]
#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
}

#[derive(Serialize)]
struct SignedUserInfo {
    iss: String,
    aud: String,
    #[serde(flatten)]
    user_info: UserInfo,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("failed to authenticate")]
    AuthorizationVerificationError(
        #[from] AuthorizationVerificationError<pasion_storage::RepositoryError>,
    ),

    #[error("session is not allowed to access the userinfo endpoint")]
    Unauthorized,

    #[error("no suitable key found for signing")]
    InvalidSigningKey,

    #[error("failed to load client {0}")]
    NoSuchClient(Ulid),

    #[error("failed to load user {0}")]
    NoSuchUser(Ulid),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(pasion_keystore::WrongAlgorithmError);
impl_from_error_for_route!(pasion_jose::jwt::JwtSignatureError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(_)
            | Self::InvalidSigningKey
            | Self::NoSuchClient(_)
            | Self::NoSuchUser(_) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Text::Plain(self.to_string()));
            }
            Self::AuthorizationVerificationError(_) | Self::Unauthorized => {
                res.status_code(StatusCode::UNAUTHORIZED);
            }
        }

        let sentry_event_id = pasion_salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.userinfo.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_get(req, depot).await {
        Ok(response) => match response {
            UserinfoResponse::Json(user_info) => {
                res.render(Json(user_info));
            }
            UserinfoResponse::Jwt(token) => {
                res.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/jwt"),
                );
                res.render(Text::Plain(token));
            }
        },
        Err(e) => e.render(res),
    }
}

enum UserinfoResponse {
    Json(UserInfo),
    Jwt(String),
}

async fn handle_get(req: &mut Request, depot: &Depot) -> Result<UserinfoResponse, RouteError> {
    let url_builder = depot
        .get::<UrlBuilder>("url_builder")
        .expect("UrlBuilder not found in depot");
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::handlers::rest::extract_bound_activity_tracker(req, depot);

    let clock: BoxClock = Box::new(SystemClock::default());
    #[allow(clippy::disallowed_methods)]
    let mut rng: BoxRng = Box::new(ChaChaRng::from_rng(thread_rng()).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;

    let user_authorization = UserAuthorization::<()>::extract_from_request(req)
        .await
        .map_err(|e| match e {
            pasion_salvo_utils::user_authorization::UserAuthorizationError::Internal(e) => {
                RouteError::Internal(e)
            }
            _ => RouteError::Unauthorized,
        })?;
    let session = user_authorization.protected(&mut repo, &clock).await?;

    // This endpoint requires the `openid` scope.
    if !session.scope.contains("openid") {
        return Err(RouteError::Unauthorized);
    }

    // Fail if the session is not associated with a user.
    let Some(user_id) = session.user_id else {
        return Err(RouteError::Unauthorized);
    };

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NoSuchUser(user_id))?;

    let user_info = UserInfo {
        sub: user.sub.clone(),
        username: user.username.clone(),
    };

    let client = repo
        .oauth2_client()
        .lookup(session.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(session.client_id))?;

    repo.save().await?;

    if let Some(alg) = client.userinfo_signed_response_alg {
        let key = key_store
            .signing_key_for_algorithm(&alg)
            .ok_or(RouteError::InvalidSigningKey)?;

        let signer = key.params().signing_key_for_alg(&alg)?;
        let header = JsonWebSignatureHeader::new(alg)
            .with_kid(key.kid().ok_or(RouteError::InvalidSigningKey)?);

        let signed_user_info = SignedUserInfo {
            iss: url_builder.oidc_issuer().to_string(),
            aud: client.client_id,
            user_info,
        };

        let token = Jwt::sign_with_rng(&mut rng, header, signed_user_info, &signer)?;
        Ok(UserinfoResponse::Jwt(token.into_string()))
    } else {
        Ok(UserinfoResponse::Json(user_info))
    }
}
