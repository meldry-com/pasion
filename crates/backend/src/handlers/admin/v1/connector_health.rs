//! Admin endpoint for checking connector provider health.

use crate::record_error;
use pasion_matrix::ConnectorRegistry;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::handlers::{
    admin::call_context::extract_call_context, admin::response::ErrorResponse, rest::DepotExt,
};

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderHealth {
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

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorHealthResponse {
    /// Health results for each registered provider.
    providers: Vec<ProviderHealth>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(pasion_data::RepositoryError);
impl_from_error_for_route!(crate::handlers::admin::call_context::Rejection);
impl_from_error_for_route!(crate::handlers::rest::RouteError);

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

/// Try to obtain a [`ConnectorRegistry`] from the depot.
fn get_registry(depot: &Depot) -> Option<ConnectorRegistry> {
    depot
        .get::<ConnectorRegistry>("connector_registry")
        .cloned()
        .ok()
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.connector_health", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ConnectorHealthResponse>, RouteError> {
    let call_context = extract_call_context(req, depot).await?;

    let providers = if let Some(registry) = get_registry(depot) {
        // Use the registry: check health for every registered provider.
        let health_results = registry.check_all_health().await;
        health_results
            .into_iter()
            .map(|(name, result)| {
                let provider_ref = registry.get(name);
                let homeserver = provider_ref
                    .map(|p| p.homeserver().to_owned())
                    .unwrap_or_default();
                let (status, error) = match result {
                    Ok(()) => ("healthy", None),
                    Err(e) => ("unhealthy", Some(e)),
                };
                ProviderHealth {
                    provider: name.to_owned(),
                    homeserver,
                    status,
                    error,
                }
            })
            .collect()
    } else {
        // Fallback: use the single homeserver connection directly.
        let homeserver = depot.homeserver()?;
        let (status, error) = match homeserver.is_localpart_available("__health_check__").await {
            Ok(_) => ("healthy", None),
            Err(e) => ("unhealthy", Some(e.to_string())),
        };
        vec![ProviderHealth {
            provider: "palpo".to_string(),
            homeserver: homeserver.homeserver().to_string(),
            status,
            error,
        }]
    };

    call_context.repo.cancel().await?; // read-only, no save needed

    Ok(Json(ConnectorHealthResponse { providers }))
}
