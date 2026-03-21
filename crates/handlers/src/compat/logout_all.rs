use std::sync::LazyLock;

use hyper::StatusCode;
use pasion_data_model::{Clock, TokenType};
use pasion_salvo_utils::record_error;
use pasion_storage::{
    RepositoryAccess,
    compat::{CompatAccessTokenRepository, CompatSessionFilter, CompatSessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use salvo::prelude::*;
use serde::Deserialize;
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

use super::{MatrixError, parse_optional_matrix_json};
use crate::{METER, impl_from_error_for_route};

static LOGOUT_ALL_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.compat.logout_all_request")
        .with_description(
            "How many request to the /logout/all compatibility endpoint have happened",
        )
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Can't load session {0}")]
    CantLoadSession(Ulid),

    #[error("Can't load user {0}")]
    CantLoadUser(Ulid),

    #[error("Token {0} has expired")]
    InvalidToken(Ulid),

    #[error("Session {0} has been revoked")]
    InvalidSession(Ulid),

    #[error("User {0} is locked or deactivated")]
    InvalidUser(Ulid),

    #[error("/logout/all is not supported")]
    NotSupported,

    #[error("Missing access token")]
    MissingAuthorization,

    #[error("Invalid token format")]
    TokenFormat(#[from] pasion_data_model::TokenFormatError),

    #[error("Access token is not a compatibility access token")]
    NotACompatToken,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::rest::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_) | Self::CantLoadSession(_) | Self::CantLoadUser(_)
        );

        // We track separately if the endpoint was called without the custom
        // parameter, so that we know if clients are using this endpoint in the
        // wild
        if matches!(self, Self::NotSupported) {
            LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "not_supported")]);
        } else {
            LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        }

        let response = match self {
            Self::Internal(_) | Self::CantLoadSession(_) | Self::CantLoadUser(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidUser(_)
            | Self::InvalidSession(_)
            | Self::InvalidToken(_)
            | Self::NotACompatToken
            | Self::TokenFormat(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::NotSupported => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "The /logout/all endpoint is not supported by this deployment",
                status: StatusCode::NOT_FOUND,
            },
        };

        response.render(res);

        // Add Sentry event ID header if available
        if let Some(event_id) = sentry_event_id {
            event_id.write_to_response(res);
        }
    }
}

#[derive(Deserialize, Default)]
pub struct RequestBody {
    #[serde(rename = "io.element.only_compat_is_fine", default)]
    only_compat_is_fine: bool,
}

#[handler]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    // Parse the optional body first - it uses MatrixJsonBodyRejection
    let input: Option<RequestBody> = match parse_optional_matrix_json(req).await {
        Ok(v) => v,
        Err(rejection) => {
            rejection.render(res);
            return;
        }
    };

    match handle_post(req, depot, input.unwrap_or_default()).await {
        Ok(body) => {
            res.render(Json(body));
        }
        Err(e) => {
            e.render(res);
        }
    }
}

#[tracing::instrument(name = "handlers.compat.logout_all.post", skip_all)]
async fn handle_post(
    req: &Request,
    depot: &Depot,
    input: RequestBody,
) -> Result<serde_json::Value, RouteError> {
    let clock = crate::rest::make_clock();
    let mut rng = crate::rest::make_rng();
    let mut repo = crate::rest::get_repo_factory(depot)?.create().await?;
    let activity_tracker = crate::rest::extract_bound_activity_tracker(req, depot);

    let token = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(RouteError::MissingAuthorization)?;

    let token_type = TokenType::check(token)?;

    if token_type != TokenType::CompatAccessToken {
        return Err(RouteError::NotACompatToken);
    }

    let token = repo
        .compat_access_token()
        .find_by_token(token)
        .await?
        .ok_or(RouteError::NotACompatToken)?;

    if !token.is_valid(clock.now()) {
        return Err(RouteError::InvalidToken(token.id));
    }

    let session = repo
        .compat_session()
        .lookup(token.session_id)
        .await?
        .ok_or(RouteError::CantLoadSession(token.session_id))?;

    if !session.is_valid() {
        return Err(RouteError::InvalidSession(session.id));
    }

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        .ok_or(RouteError::CantLoadUser(session.user_id))?;

    if !user.is_valid() {
        return Err(RouteError::InvalidUser(session.user_id));
    }

    if !input.only_compat_is_fine {
        return Err(RouteError::NotSupported);
    }

    let filter = CompatSessionFilter::new().for_user(&user).active_only();
    let affected_sessions = repo.compat_session().finish_bulk(&clock, filter).await?;
    info!(
        "Logged out {affected_sessions} sessions for user {user_id}",
        user_id = user.id
    );

    // Schedule a job to sync the devices of the user with the homeserver
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.save().await?;

    LOGOUT_ALL_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    Ok(serde_json::json!({}))
}
