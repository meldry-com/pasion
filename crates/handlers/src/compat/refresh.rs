use chrono::Duration;
use hyper::StatusCode;
use pasion_data_model::{Clock, TokenFormatError, TokenType};
use pasion_salvo_utils::record_error;
use pasion_storage::{
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::{DurationMilliSeconds, serde_as};
use thiserror::Error;
use ulid::Ulid;

use super::MatrixError;
use crate::impl_from_error_for_route;

#[derive(Debug, Deserialize)]
pub struct RequestBody {
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("invalid token")]
    InvalidToken(#[from] TokenFormatError),

    #[error("unknown token")]
    UnknownToken,

    #[error("invalid token type {0}, expected a compat refresh token")]
    InvalidTokenType(TokenType),

    #[error("refresh token already consumed {0}")]
    RefreshTokenConsumed(Ulid),

    #[error("invalid compat session {0}")]
    InvalidSession(Ulid),

    #[error("unknown comapt session {0}")]
    UnknownSession(Ulid),
}

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, Self::Internal(_) | Self::UnknownSession(_));
        let response = match self {
            Self::Internal(_) | Self::UnknownSession(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::InvalidToken(_)
            | Self::UnknownToken
            | Self::InvalidTokenType(_)
            | Self::InvalidSession(_)
            | Self::RefreshTokenConsumed(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid refresh token",
                status: StatusCode::UNAUTHORIZED,
            },
        };

        response.render(res);

        // Add Sentry event ID header if available
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::rest::RouteError);

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    access_token: String,
    refresh_token: String,
    #[serde_as(as = "DurationMilliSeconds<i64>")]
    expires_in_ms: Duration,
}

#[handler]
#[tracing::instrument(name = "handlers.compat.refresh.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot) -> Result<Json<ResponseBody>, RouteError> {
    let mut rng = crate::rest::make_rng();
    let clock = crate::rest::make_clock();
    let mut repo = crate::rest::get_repo_factory(depot)?.create().await?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);
    let site_config = crate::rest::get_site_config(depot)?;

    let input: RequestBody = req
        .parse_json()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let token_type = TokenType::check(&input.refresh_token)?;

    if token_type != TokenType::CompatRefreshToken {
        return Err(RouteError::InvalidTokenType(token_type));
    }

    let refresh_token = repo
        .compat_refresh_token()
        .find_by_token(&input.refresh_token)
        .await?
        .ok_or(RouteError::UnknownToken)?;

    if !refresh_token.is_valid() {
        return Err(RouteError::RefreshTokenConsumed(refresh_token.id));
    }

    let session = repo
        .compat_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::UnknownSession(refresh_token.session_id))?;

    if !session.is_valid() {
        return Err(RouteError::InvalidSession(refresh_token.session_id));
    }

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let access_token = repo
        .compat_access_token()
        .lookup(refresh_token.access_token_id)
        .await?
        .filter(|t| t.is_valid(clock.now()));

    let new_refresh_token_str = TokenType::CompatRefreshToken.generate(&mut rng);
    let new_access_token_str = TokenType::CompatAccessToken.generate(&mut rng);

    let expires_in = site_config.compat_token_ttl;
    let new_access_token = repo
        .compat_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            new_access_token_str,
            Some(expires_in),
        )
        .await?;
    let new_refresh_token = repo
        .compat_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &new_access_token,
            new_refresh_token_str,
        )
        .await?;

    repo.compat_refresh_token()
        .consume_and_replace(&clock, refresh_token, &new_refresh_token)
        .await?;

    if let Some(access_token) = access_token {
        repo.compat_access_token()
            .expire(&clock, access_token)
            .await?;
    }

    repo.save().await?;

    Ok(Json(ResponseBody {
        access_token: new_access_token.token,
        refresh_token: new_refresh_token.token,
        expires_in_ms: expires_in,
    }))
}
