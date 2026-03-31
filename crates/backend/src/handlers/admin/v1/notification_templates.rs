//! Admin endpoints for notification template management.
//!
//! - `GET  /api/admin/v1/notification-templates` — list known template keys
//! - `POST /api/admin/v1/notification-templates/publish` — placeholder for
//!   publishing a template version (returns 501 Not Implemented)

use salvo::prelude::*;
use schemars::JsonSchema;
use salvo::oapi::ToSchema;
use serde::Serialize;

use crate::handlers::admin::call_context::extract_call_context;
use crate::{AppError, JsonResult};

/// Describes a single notification template key.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct NotificationTemplate {
    /// The template key, e.g. `"verification"` or `"recovery"`.
    pub key: String,

    /// A short human-readable description of the template's purpose.
    pub description: String,
}

/// Response listing all known notification template keys.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct NotificationTemplatesResponse {
    /// The list of known notification templates.
    pub templates: Vec<NotificationTemplate>,
}

/// List all known notification template keys.

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<NotificationTemplatesResponse> {
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

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.publish", skip_all)]
pub async fn publish_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<serde_json::Value> {
    let _call_context = extract_call_context(req, depot).await?;

    Err(AppError::not_implemented("not implemented"))
}
