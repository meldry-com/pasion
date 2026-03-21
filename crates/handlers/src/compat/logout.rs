use std::sync::LazyLock;

use hyper::StatusCode;
use pasion_data_model::{Clock, TokenType};
use pasion_salvo_utils::record_error;
use pasion_storage::{
    RepositoryAccess,
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use salvo::prelude::*;
use thiserror::Error;

use super::MatrixError;
use crate::{METER, impl_from_error_for_route};

static LOGOUT_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.compat.logout_request")
        .with_description("How many compatibility logout request have happened")
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Missing access token")]
    MissingAuthorization,

    #[error("Invalid token format")]
    TokenFormat(#[from] pasion_data_model::TokenFormatError),

    #[error("Invalid access token")]
    InvalidAuthorization,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::rest::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        LOGOUT_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let response = match self {
            Self::Internal(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidAuthorization | Self::TokenFormat(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
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

#[handler]
#[tracing::instrument(name = "handlers.compat.logout.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot) -> Result<Json<serde_json::Value>, RouteError> {
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
        return Err(RouteError::InvalidAuthorization);
    }

    let token = repo
        .compat_access_token()
        .find_by_token(token)
        .await?
        .filter(|t| t.is_valid(clock.now()))
        .ok_or(RouteError::InvalidAuthorization)?;

    let session = repo
        .compat_session()
        .lookup(token.session_id)
        .await?
        .filter(|s| s.is_valid())
        .ok_or(RouteError::InvalidAuthorization)?;

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        // XXX: this is probably not the right error
        .ok_or(RouteError::InvalidAuthorization)?;

    // Schedule a job to sync the devices of the user with the homeserver
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.compat_session().finish(&clock, session).await?;

    repo.save().await?;

    LOGOUT_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    Ok(Json(serde_json::json!({})))
}
