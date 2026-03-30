//! Admin endpoint for checking notification channel status.
//!
//! Returns a list of configured notification channels and their status.
//! Since the [`NotificationCenter`] is not available in the HTTP depot,
//! channel availability is inferred from the site configuration flags.

use crate::record_error;
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::handlers::{
    admin::call_context::extract_call_context,
    admin::response::ErrorResponse,
    rest::DepotExt,
};

/// Status of an individual notification channel.
#[derive(Serialize, JsonSchema)]
pub struct ChannelStatus {
    /// Channel name, e.g. `"email"` or `"sms"`.
    channel: String,

    /// Whether this channel is considered configured based on site config.
    configured: bool,
}

/// Response listing all known notification channels.
#[derive(Serialize, JsonSchema)]
pub struct NotificationChannelsResponse {
    /// The list of notification channels and their configuration status.
    channels: Vec<ChannelStatus>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(pasion_storage::RepositoryError);
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

#[handler]
#[tracing::instrument(name = "handler.admin.v1.notification_channels", skip_all)]
pub async fn handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<NotificationChannelsResponse>, RouteError> {
    let _call_context = extract_call_context(req, depot).await?;
    let site_config = depot.site_config()?;

    // Email is considered configured when account recovery (which requires
    // sending emails) is enabled or when email changes are allowed.
    let email_configured =
        site_config.account_recovery_allowed || site_config.email_change_allowed;

    // SMS availability cannot be directly determined from the site config;
    // contact-required registration is the closest signal (it implies at
    // least one of email or SMS is expected to be available).
    let sms_configured = site_config.password_registration_contact_required && !email_configured;

    let channels = vec![
        ChannelStatus {
            channel: "email".to_string(),
            configured: email_configured,
        },
        ChannelStatus {
            channel: "sms".to_string(),
            configured: sms_configured,
        },
    ];

    Ok(Json(NotificationChannelsResponse { channels }))
}
