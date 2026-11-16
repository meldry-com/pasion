//! Admin endpoints for notification template management.
//!
//! - `GET  /api/admin/v1/notification-templates` — list known template keys
//! - `POST /api/admin/v1/notification-templates/publish` — publish a new
//!   template version

use pasion_data::RepositoryAccess;
use pasion_i18n::DataLocale;
use pasion_templates::PublishedNotificationTemplate;
use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::admin::{CreatedJson, call_context::extract_call_context},
};

/// Describes a single notification template key.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct NotificationTemplate {
    /// The template key, e.g. `"verification"` or `"recovery"`.
    pub key: String,
    /// A short human-readable description of the template's purpose.
    pub description: String,
    /// Delivery channels with an actual consumer for this template key.
    pub channels: Vec<String>,
}

/// Response listing all known notification template keys.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct NotificationTemplatesResponse {
    /// The list of known notification templates.
    pub templates: Vec<NotificationTemplate>,
}

/// Request body for publishing a notification template version.
#[derive(Deserialize, JsonSchema, ToSchema)]
pub struct PublishTemplateRequest {
    /// The template key to publish (e.g., "verification", "recovery").
    pub template_key: String,
    /// The delivery channel (e.g., "email", "sms").
    pub channel: String,
    /// Locale for this template version (e.g., "en", "zh-CN").
    #[serde(default = "default_locale")]
    pub locale: String,
    /// Optional subject template (relevant for email channel).
    pub subject_template: Option<String>,
    /// Body template content (Minijinja syntax).
    pub body_template: String,
}

fn default_locale() -> String {
    "en".to_owned()
}

/// Published template version response.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PublishedTemplateResponse {
    /// Stable identifier for this template version.
    pub id: String,
    /// The template key.
    pub template_key: String,
    /// Monotonically increasing version number within the template key and
    /// channel.
    pub version: u32,
    /// The delivery channel.
    pub channel: String,
    /// The locale for this template version.
    pub locale: String,
    /// Optional subject template.
    pub subject_template: Option<String>,
    /// Body template content.
    pub body_template: String,
    /// When this version was created.
    pub created_at: String,
    /// When this version was published.
    pub published_at: Option<String>,
}

/// List all known notification template keys.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<NotificationTemplatesResponse> {
    let _call_context = extract_call_context(req, depot).await?;

    let templates = vec![
        NotificationTemplate {
            key: "verification".to_owned(),
            description: "Email or phone verification code".to_owned(),
            channels: vec!["email".to_owned(), "sms".to_owned()],
        },
        NotificationTemplate {
            key: "recovery".to_owned(),
            description: "Account recovery / password reset".to_owned(),
            channels: vec!["email".to_owned()],
        },
    ];

    Ok(Json(NotificationTemplatesResponse { templates }))
}

/// Publish a new notification template version.
#[endpoint(request_body = PublishTemplateRequest)]
#[tracing::instrument(name = "handler.admin.v1.notification_templates.publish", skip_all)]
pub async fn publish_handler(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<PublishedTemplateResponse> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo, clock, ..
    } = ctx;

    let mut body: PublishTemplateRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("Invalid request body: {e}")))?;

    if body.template_key.is_empty() {
        return Err(AppError::bad_request("template_key is required"));
    }
    if body.body_template.is_empty() {
        return Err(AppError::bad_request("body_template is required"));
    }
    validate_publish_request(&mut body)?;

    let mut rng = crate::handlers::account::make_rng();

    let record = repo
        .notification_template()
        .publish(
            &mut rng,
            &*clock,
            body.template_key,
            body.channel,
            body.locale,
            body.subject_template,
            body.body_template,
        )
        .await?;

    repo.save().await?;

    let channel_str = format!("{:?}", record.channel).to_lowercase();

    let response = PublishedTemplateResponse {
        id: record.id.to_string(),
        template_key: record.template_key,
        version: record.version,
        channel: channel_str,
        locale: record.locale,
        subject_template: record.subject_template,
        body_template: record.body_template,
        created_at: record.created_at.to_rfc3339(),
        published_at: record.published_at.map(|t| t.to_rfc3339()),
    };

    Ok(CreatedJson(response))
}

fn validate_publish_request(body: &mut PublishTemplateRequest) -> Result<(), AppError> {
    if !PublishedNotificationTemplate::supports(&body.template_key, &body.channel) {
        return Err(AppError::bad_request(
            "Unsupported template key/channel combination",
        ));
    }
    body.locale = body
        .locale
        .parse::<DataLocale>()
        .map_err(|_| AppError::bad_request("Invalid template locale"))?
        .to_string();
    if body.channel == "sms" && body.subject_template.is_some() {
        return Err(AppError::bad_request("SMS templates do not have a subject"));
    }
    PublishedNotificationTemplate {
        subject_template: body.subject_template.clone(),
        body_template: body.body_template.clone(),
    }
    .validate()
    .map_err(|_| AppError::bad_request("Invalid notification template syntax"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_template_validation_matches_delivery_capabilities() {
        let mut request = PublishTemplateRequest {
            template_key: "verification".to_owned(),
            channel: "email".to_owned(),
            locale: "zh-cn".to_owned(),
            subject_template: None,
            body_template: "Code {{ authentication_code.code }}".to_owned(),
        };
        validate_publish_request(&mut request).unwrap();
        assert_eq!(request.locale, "zh-CN");
        "fax".clone_into(&mut request.channel);
        assert!(validate_publish_request(&mut request).is_err());
        "sms".clone_into(&mut request.channel);
        request.subject_template = Some("ignored".to_owned());
        assert!(validate_publish_request(&mut request).is_err());
        request.subject_template = None;
        "{% if".clone_into(&mut request.body_template);
        assert!(validate_publish_request(&mut request).is_err());
    }
}
