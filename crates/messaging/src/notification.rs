//! Notification orchestration across delivery channels.

use std::collections::BTreeMap;

use lettre::message::Mailbox;
use pasion_templates::{
    EmailRecoveryContext, EmailVerificationContext, PublishedNotificationTemplate, WithLanguage,
    notification_locale,
};
use thiserror::Error;

use crate::{
    Mailer,
    email::{MailerError, SendResult as EmailSendResult},
    sms::{SmsSender, SmsTransportError},
};

/// Unified notification dispatcher for user-facing delivery channels.
#[derive(Default, Clone)]
pub struct NotificationCenter {
    email: Option<Mailer>,
    sms: Option<SmsSender>,
    fixed_verification_code: Option<String>,
}

/// Result returned after a notification provider accepted a delivery.
#[derive(Debug, Clone, Default)]
pub struct NotificationDispatchResult {
    /// Optional provider-side message identifier.
    pub provider_message_id: Option<String>,
}

/// A standardized outbound notification request.
#[allow(
    clippy::large_enum_variant,
    reason = "notification requests are short-lived and dispatched by value exactly once"
)]
pub enum NotificationRequest {
    /// Send a verification email to a mailbox.
    EmailVerification {
        /// Mailbox receiving the notification.
        to: Mailbox,
        /// Template context for the verification email.
        context: WithLanguage<EmailVerificationContext>,
        /// Provider metadata that should round-trip in delivery callbacks.
        tags: BTreeMap<String, String>,
        /// Selected published override; none uses configured templates.
        template: Option<PublishedNotificationTemplate>,
    },

    /// Send an account recovery email to a mailbox.
    EmailRecovery {
        /// Mailbox receiving the notification.
        to: Mailbox,
        /// Template context for the recovery email.
        context: WithLanguage<EmailRecoveryContext>,
        /// Provider metadata that should round-trip in delivery callbacks.
        tags: BTreeMap<String, String>,
        /// Selected published override; none uses configured templates.
        template: Option<PublishedNotificationTemplate>,
    },

    /// Send a verification code over SMS.
    SmsVerificationCode {
        /// Phone number receiving the notification.
        to: String,
        /// One-time verification code.
        code: String,
        /// IETF language tag used to localize the message body.
        language: String,
        /// Selected published override; none uses the provider default.
        template: Option<PublishedNotificationTemplate>,
    },
}

impl NotificationCenter {
    /// Create a new notification center with the provided channels.
    #[must_use]
    pub fn new(email: Option<Mailer>, sms: Option<SmsSender>) -> Self {
        Self {
            email,
            sms,
            fixed_verification_code: None,
        }
    }

    /// Create a notification center configured only for email delivery.
    #[must_use]
    pub fn email_only(mailer: Mailer) -> Self {
        Self::new(Some(mailer), None)
    }

    /// Create a notification center configured only for SMS delivery.
    #[must_use]
    pub fn sms_only(sender: SmsSender) -> Self {
        Self::new(None, Some(sender))
    }

    /// Attach an email channel to this notification center.
    #[must_use]
    pub fn with_email(mut self, mailer: Mailer) -> Self {
        self.email = Some(mailer);
        self
    }

    /// Attach an SMS channel to this notification center.
    #[must_use]
    pub fn with_sms(mut self, sender: SmsSender) -> Self {
        self.sms = Some(sender);
        self
    }

    /// Configure a fixed contact verification code for development.
    /// The worker persists this code and skips email/SMS notification delivery.
    /// The application configuration validates it before calling this method.
    #[must_use]
    pub fn with_fixed_verification_code(mut self, code: Option<String>) -> Self {
        self.fixed_verification_code = code;
        self
    }

    /// Return the explicitly configured development verification code, if any.
    #[must_use]
    pub fn fixed_verification_code(&self) -> Option<&str> {
        self.fixed_verification_code.as_deref()
    }

    /// Access the configured email channel, if any.
    #[must_use]
    pub fn email(&self) -> Option<&Mailer> {
        self.email.as_ref()
    }

    /// Access the configured SMS channel, if any.
    #[must_use]
    pub fn sms(&self) -> Option<&SmsSender> {
        self.sms.as_ref()
    }

    /// Return the stable provider binding key for the configured email channel.
    #[must_use]
    pub fn email_provider_binding_key(&self) -> Option<&'static str> {
        self.email.as_ref().map(Mailer::provider_binding_key)
    }

    /// Return the stable provider binding key for the configured SMS channel.
    #[must_use]
    pub fn sms_provider_binding_key(&self) -> Option<&'static str> {
        self.sms.as_ref().map(SmsSender::provider_binding_key)
    }

    /// Dispatch a standardized notification request.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested delivery channel is unavailable or if
    /// delivery fails.
    pub async fn dispatch(
        &self,
        request: NotificationRequest,
    ) -> Result<NotificationDispatchResult, NotificationError> {
        match request {
            NotificationRequest::EmailVerification {
                to,
                context,
                tags,
                template,
            } => {
                let mailer = self
                    .email
                    .as_ref()
                    .ok_or(NotificationError::EmailNotConfigured)?;
                let result = mailer
                    .send_verification_email_with_template(to, &context, &tags, template.as_ref())
                    .await?;
                Ok(result.into())
            }
            NotificationRequest::EmailRecovery {
                to,
                context,
                tags,
                template,
            } => {
                let mailer = self
                    .email
                    .as_ref()
                    .ok_or(NotificationError::EmailNotConfigured)?;
                let result = mailer
                    .send_recovery_email_with_template(to, &context, &tags, template.as_ref())
                    .await?;
                Ok(result.into())
            }
            NotificationRequest::SmsVerificationCode {
                to,
                code,
                language,
                template,
            } => {
                let language = notification_locale(&language);
                if let Some(template) = template {
                    let sender = self
                        .sms
                        .as_ref()
                        .ok_or(NotificationError::SmsNotConfigured)?;
                    let rendered =
                        template.render(&serde_json::json!({"code": code, "lang": language}))?;
                    sender.send_rendered(&to, &rendered.body).await?;
                    Ok(NotificationDispatchResult::default())
                } else {
                    self.send_sms_verification_code(&to, &code, &language).await
                }
            }
        }
    }

    /// Send an email verification message through the configured email channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the email channel is unavailable or delivery fails.
    pub async fn send_email_verification(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<NotificationDispatchResult, NotificationError> {
        let mailer = self
            .email
            .as_ref()
            .ok_or(NotificationError::EmailNotConfigured)?;
        let result = mailer
            .send_verification_email(to, context, tags)
            .await
            .map_err(NotificationError::Email)?;
        Ok(result.into())
    }

    /// Send an account recovery email through the configured email channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the email channel is unavailable or delivery fails.
    pub async fn send_email_recovery(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<NotificationDispatchResult, NotificationError> {
        let mailer = self
            .email
            .as_ref()
            .ok_or(NotificationError::EmailNotConfigured)?;
        let result = mailer
            .send_recovery_email(to, context, tags)
            .await
            .map_err(NotificationError::Email)?;
        Ok(result.into())
    }

    /// Send a verification code via SMS through the configured SMS channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the SMS channel is unavailable or delivery fails.
    pub async fn send_sms_verification_code(
        &self,
        to: &str,
        code: &str,
        language: &str,
    ) -> Result<NotificationDispatchResult, NotificationError> {
        let sender = self
            .sms
            .as_ref()
            .ok_or(NotificationError::SmsNotConfigured)?;
        sender
            .send_verification_code(to, code, language)
            .await
            .map_err(NotificationError::Sms)?;
        Ok(NotificationDispatchResult::default())
    }
}

impl From<EmailSendResult> for NotificationDispatchResult {
    fn from(result: EmailSendResult) -> Self {
        Self {
            provider_message_id: result.provider_message_id,
        }
    }
}

/// Errors produced while dispatching notifications.
#[derive(Debug, Error)]
pub enum NotificationError {
    /// A published template failed to render; no provider was called.
    #[error(transparent)]
    Template(#[from] pasion_templates::TemplateError),
    /// An email notification was requested but no email channel is configured.
    #[error("email notifications are not configured")]
    EmailNotConfigured,

    /// An SMS notification was requested but no SMS channel is configured.
    #[error("sms notifications are not configured")]
    SmsNotConfigured,

    /// The email channel failed while sending the notification.
    #[error(transparent)]
    Email(#[from] MailerError),

    /// The SMS channel failed while sending the notification.
    #[error(transparent)]
    Sms(#[from] SmsTransportError),
}

#[cfg(test)]
mod published_delivery_tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method},
    };

    use super::*;

    #[tokio::test]
    async fn sms_dispatch_sends_rendered_override_and_does_not_send_on_render_error() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"body":"Published 654321/zh-CN"}),
            ))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let notifications =
            NotificationCenter::sms_only(SmsSender::new(crate::SmsTransport::http_webhook(
                server.uri().parse().unwrap(),
                None,
                "Pasion".to_owned(),
            )));
        let request = |body: &str| NotificationRequest::SmsVerificationCode {
            to: "+12065550123".to_owned(),
            code: "654321".to_owned(),
            language: "zh-cn".to_owned(),
            template: Some(PublishedNotificationTemplate {
                subject_template: None,
                body_template: body.to_owned(),
            }),
        };
        notifications
            .dispatch(request("Published {{ code }}/{{ lang }}"))
            .await
            .unwrap();
        assert!(matches!(
            notifications.dispatch(request("{{ missing }}")).await,
            Err(NotificationError::Template(_))
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
