//! REST endpoints for user notification preferences.
//!
//! - `GET  /api/v1/viewer/notification-preferences` — returns available
//!   channels and the user's current preference settings.
//! - `PUT  /api/v1/viewer/notification-preferences` — updates the user's
//!   notification preferences.
//!
//! **MVP note:** There is no `notification_preference` table yet, so the GET
//! endpoint returns placeholder preference data derived from the site
//! configuration, and the PUT endpoint echoes back the submitted preferences
//! without persisting them.

use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock,
};

// ── Response / request types ─────────────────────────────────

/// Availability status of a single notification channel.
#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelAvailability {
    /// Channel name, e.g. `"email"` or `"sms"`.
    pub channel: String,

    /// Whether this channel is enabled on the server.
    pub enabled: bool,
}

/// Per-channel preference of the current user.
#[derive(Serialize, Deserialize, Clone, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPreference {
    /// Channel name, e.g. `"email"` or `"sms"`.
    pub channel: String,

    /// Whether the user wants to receive notifications on this channel.
    pub enabled: bool,
}

/// Response for `GET /api/v1/viewer/notification-preferences`.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPreferencesResponse {
    /// Server-side channel availability.
    pub available_channels: Vec<ChannelAvailability>,

    /// The user's current preferences (one entry per channel).
    pub preferences: Vec<ChannelPreference>,
}

/// Request body for `PUT /api/v1/viewer/notification-preferences`.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPreferencesRequest {
    /// The updated list of per-channel preferences.
    pub preferences: Vec<ChannelPreference>,
}

/// Response for `PUT /api/v1/viewer/notification-preferences`.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPreferencesResponse {
    /// The preferences as accepted by the server.
    pub preferences: Vec<ChannelPreference>,
}

// ── GET handler ──────────────────────────────────────────────

/// Returns the available notification channels and the current user's
/// preferences.
#[endpoint]
pub async fn get_notification_preferences(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<NotificationPreferencesResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    // Must be authenticated
    if requester.is_unauthenticated() {
        return Err(RouteError::Unauthorized);
    }

    repo.cancel().await?;

    // Determine channel availability from site config
    let email_enabled =
        config.account_recovery_allowed || config.email_change_allowed;
    let sms_enabled = config.password_registration_contact_required;

    let available_channels = vec![
        ChannelAvailability {
            channel: "email".to_string(),
            enabled: email_enabled,
        },
        ChannelAvailability {
            channel: "sms".to_string(),
            enabled: sms_enabled,
        },
    ];

    // TODO: Load actual user preferences from a notification_preference table
    // once it exists. For now, default to "enabled" for every available channel.
    let preferences = available_channels
        .iter()
        .map(|ch| ChannelPreference {
            channel: ch.channel.clone(),
            enabled: ch.enabled,
        })
        .collect();

    Ok(Json(NotificationPreferencesResponse {
        available_channels,
        preferences,
    }))
}

// ── PUT handler ──────────────────────────────────────────────

/// Updates the user's notification preferences.
#[endpoint]
pub async fn put_notification_preferences(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<UpdateNotificationPreferencesResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    // Must be authenticated
    if requester.is_unauthenticated() {
        return Err(RouteError::Unauthorized);
    }

    let body: UpdateNotificationPreferencesRequest = req
        .parse_json()
        .await
        .map_err(|e| RouteError::BadRequest(e.to_string()))?;

    // TODO: Persist preferences to a notification_preference table once it
    // exists. For now we simply echo back what was submitted.

    repo.cancel().await?;

    Ok(Json(UpdateNotificationPreferencesResponse {
        preferences: body.preferences,
    }))
}
