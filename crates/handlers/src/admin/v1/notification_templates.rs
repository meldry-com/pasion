//! Admin endpoints for notification template management.
//!
//! - `GET  /api/admin/v1/notification-templates` — list known template keys
//! - `POST /api/admin/v1/notification-templates/publish` — placeholder for
//!   publishing a template version (returns 501 Not Implemented)

use pasion_salvo_utils::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    admin::call_context::extract_call_context,
    admin::response::ErrorResponse,
    impl_from_error_for_route,
};

/// Describes a single notification template key.
#[derive(Serialize, JsonSchema)]
pub struct NotificationTemplate {
    /// The template key, e.g. `"verification"` or `"recovery"`.
    pub key: String,

    /// A short human-readable description of the template's purpose.
    pub description: String,
}

/// Response listing all known notification template keys.
#[derive(Serialize, JsonSchema)]
pub struct NotificationTemplatesResponse {
    /// The list of known notification templates.
    pub templates: Vec<NotificationTemplate>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("not implemented")]
    NotImplemented,
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
impl_from_error_for_route!(crate::admin::call_context::Rejection);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
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

/// List all known notification template keys.
#[handler]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<NotificationTemplatesResponse>, RouteError> {
    let _call_context = extract_call_context(req, depot).await?;

    // For MVP, return a hardcoded list of known template keys.
    let templates = vec![
        NotificationTemplate {
            key: "verification".to_owned(),
            description: "Email or phone verification code".to_owned(),
        },
        NotificationTemplate {
            key: "recovery".to_owned(),
            description: "Account recovery / password reset".to_owned(),
        },
    ];

    Ok(Json(NotificationTemplatesResponse { templates }))
}

/// Placeholder for publishing a notification template version.
///
/// Returns `501 Not Implemented` until the template publishing workflow
/// is fully designed.
#[handler]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.publish", skip_all)]
pub async fn publish_handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<serde_json::Value>, RouteError> {
    let _call_context = extract_call_context(req, depot).await?;

    Err(RouteError::NotImplemented)
}
