use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::RevocationRequest,
};
use pasion_data_model::{BoxClock, BoxRng, SystemClock, TokenType};
use pasion_iana::oauth::OAuthTokenTypeHint;
use pasion_keystore::Encrypter;
use pasion_salvo_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
    sentry::SentryEventID,
};
use pasion_storage::{
    BoxRepository, BoxRepositoryFactory, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;
use salvo::prelude::*;
use thiserror::Error;
use ulid::Ulid;

use crate::impl_from_error_for_route;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("invalid client credentials for client {client_id}")]
    InvalidClientCredentials {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("could not verify client credentials for client {client_id}")]
    ClientCredentialsVerification {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("client is unauthorized")]
    UnauthorizedClient,

    #[error("unsupported token type")]
    UnsupportedTokenType,

    #[error("unknown token")]
    UnknownToken,
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        match self {
            Self::Internal(_) | Self::ClientCredentialsVerification { .. } => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::BadRequest => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRequest)));
            }

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidClient)));
            }

            Self::ClientNotAllowed | Self::UnauthorizedClient => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ClientError::from(ClientErrorCode::UnauthorizedClient)));
            }

            Self::UnsupportedTokenType => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(
                    ClientErrorCode::UnsupportedTokenType,
                )));
            }

            // If the token is unknown, we still return a 200 OK response.
            Self::UnknownToken => {
                res.status_code(StatusCode::OK);
            }
        }

        let sentry_event_id = pasion_salvo_utils::sentry::SentryEventID::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(pasion_salvo_utils::client_authorization::ClientAuthorizationError);

impl From<pasion_data_model::TokenFormatError> for RouteError {
    fn from(_e: pasion_data_model::TokenFormatError) -> Self {
        Self::UnknownToken
    }
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.revoke.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(()) => {
            res.status_code(StatusCode::OK);
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(req: &mut Request, depot: &Depot) -> Result<(), RouteError> {
    let http_client = depot
        .get::<reqwest::Client>("http_client")
        .expect("reqwest::Client not found in depot");
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);

    let clock: BoxClock = Box::new(SystemClock::default());
    #[allow(clippy::disallowed_methods)]
    let mut rng: BoxRng = Box::new(ChaChaRng::from_rng(thread_rng()).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;

    let client_authorization: ClientAuthorization<RevocationRequest> =
        ClientAuthorization::extract_from_request(req).await?;

    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(http_client, encrypter, method, &client)
        .await
        .map_err(|err| {
            if err.is_internal() {
                RouteError::ClientCredentialsVerification {
                    client_id: client.id,
                    source: err,
                }
            } else {
                RouteError::InvalidClientCredentials {
                    client_id: client.id,
                    source: err,
                }
            }
        })?;

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    let token_type = TokenType::check(&form.token)?;

    // Find the ID of the session to end.
    let session_id = match (form.token_type_hint, token_type) {
        (Some(OAuthTokenTypeHint::AccessToken) | None, TokenType::AccessToken) => {
            let access_token = repo
                .oauth2_access_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::UnknownToken);
            }
            access_token.session_id
        }

        (Some(OAuthTokenTypeHint::RefreshToken) | None, TokenType::RefreshToken) => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !refresh_token.is_valid() {
                return Err(RouteError::UnknownToken);
            }

            refresh_token.session_id
        }

        // This case can happen if there is a mismatch between the token type hint and the guessed
        // token type or if the token was a compat access/refresh token. In those cases, we return
        // an unknown token error.
        (Some(OAuthTokenTypeHint::AccessToken | OAuthTokenTypeHint::RefreshToken) | None, _) => {
            return Err(RouteError::UnknownToken);
        }

        (Some(_), _) => return Err(RouteError::UnsupportedTokenType),
    };

    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::UnknownToken)?;

    // Check that the session is still valid.
    if !session.is_valid() {
        return Err(RouteError::UnknownToken);
    }

    // Check that the client ending the session is the same as the client that
    // created it.
    if client.id != session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    // If the session is associated with a user, make sure we schedule a device
    // deletion job for all the devices associated with the session.
    if let Some(user_id) = session.user_id {
        // Fetch the user
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UnknownToken)?;

        // Schedule a job to sync the devices of the user with the homeserver
        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;
    }

    // Now that we checked everything, we can end the session.
    repo.oauth2_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests would need to be updated for Salvo's test utilities
}
