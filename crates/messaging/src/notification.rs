//! Notification orchestration across delivery channels.

use lettre::message::Mailbox;
use pasion_templates::{EmailRecoveryContext, EmailVerificationContext, WithLanguage};
use thiserror::Error;

use crate::{
    Mailer,
    email::MailerError,
    sms::{SmsSender, SmsTransportError},
};

/// Unified notification dispatcher for user-facing delivery channels.
#[derive(Default, Clone)]
pub struct NotificationCenter {
    email: Option<Mailer>,
    sms: Option<SmsSender>,
}

impl NotificationCenter {
    /// Create a new notification center with the provided channels.
    #[must_use]
    pub fn new(email: Option<Mailer>, sms: Option<SmsSender>) -> Self {
        Self { email, sms }
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

    /// Send an email verification message through the configured email channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the email channel is unavailable or delivery fails.
    pub async fn send_email_verification(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<(), NotificationError> {
        let mailer = self
            .email
            .as_ref()
            .ok_or(NotificationError::EmailNotConfigured)?;
        mailer
            .send_verification_email(to, context)
            .await
            .map_err(NotificationError::Email)
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
    ) -> Result<(), NotificationError> {
        let mailer = self
            .email
            .as_ref()
            .ok_or(NotificationError::EmailNotConfigured)?;
        mailer
            .send_recovery_email(to, context)
            .await
            .map_err(NotificationError::Email)
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
    ) -> Result<(), NotificationError> {
        let sender = self
            .sms
            .as_ref()
            .ok_or(NotificationError::SmsNotConfigured)?;
        sender
            .send_verification_code(to, code, language)
            .await
            .map_err(NotificationError::Sms)
    }
}

/// Errors produced while dispatching notifications.
#[derive(Debug, Error)]
pub enum NotificationError {
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
