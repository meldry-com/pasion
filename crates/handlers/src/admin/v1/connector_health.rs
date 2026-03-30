//! Admin endpoint for checking connector provider health.

use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    admin::call_context::extract_call_context,
    admin::response::ErrorResponse,
    impl_from_error_for_route,
    rest::DepotExt,
};

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorHealthResponse {
    /// The connector provider name.
    provider: String,

    /// The homeserver this connector is pointed at.
    homeserver: String,

    /// Whether the connector is healthy: `"healthy"` or `"unhealthy"`.
    status: &'static str,

    /// If unhealthy, the error message from the health probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::call_context::Rejection);
impl_from_error_for_route!(crate::rest::RouteError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

#[handler]
#[tracing::instrument(name = "handler.admin.v1.connector_health", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ConnectorHealthResponse>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;
    let homeserver = depot.homeserver()?;

    // Try a lightweight operation to check health
    let (status, error) = match homeserver.is_localpart_available("__health_check__").await {
        Ok(_) => ("healthy", None),
        Err(e) => ("unhealthy", Some(e.to_string())),
    };

    call_context.repo.cancel().await?; // read-only, no save needed

    Ok(Json(ConnectorHealthResponse {
        provider: "palpo".to_string(),
        homeserver: homeserver.homeserver().to_string(),
        status,
        error,
    }))
}
