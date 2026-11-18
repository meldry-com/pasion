//! Send emails to users

use std::collections::BTreeMap;

use lettre::message::Mailbox;
use pasion_templates::{
    EmailRecoveryContext, EmailVerificationContext, PublishedNotificationTemplate, Templates,
    WithLanguage,
};
use thiserror::Error;

use super::{
    OutboundEmail, SendResult,
    transport::{Error as TransportError, Transport as MailTransport},
};

/// Helps sending mails to users
#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

/// Errors that can occur while preparing or sending an email.
#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    /// The configured email transport failed.
    Transport(#[from] TransportError),
    /// Rendering the email templates failed.
    Templates(#[from] pasion_templates::TemplateError),
}

impl Mailer {
    /// Constructs a new [`Mailer`]
    #[must_use]
    pub fn new(
        templates: Templates,
        transport: MailTransport,
        from: Mailbox,
        reply_to: Mailbox,
    ) -> Self {
        Self {
            templates,
            transport,
            from,
            reply_to,
        }
    }

    fn outbound_email(
        &self,
        to: Mailbox,
        subject: &str,
        text_body: String,
        html_body: Option<String>,
        tags: &BTreeMap<String, String>,
    ) -> OutboundEmail {
        OutboundEmail {
            from: self.from.clone(),
            reply_to: Some(self.reply_to.clone()),
            to: vec![to],
            subject: subject.trim().to_owned(),
            text_body,
            html_body,
            headers: BTreeMap::new(),
            tags: tags.clone(),
        }
    }

    fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
        template: Option<&PublishedNotificationTemplate>,
    ) -> Result<OutboundEmail, Error> {
        if let Some(template) = template {
            let rendered = template.render(context)?;
            let subject = match rendered.subject {
                Some(subject) => subject,
                None => self.templates.render_email_verification_subject(context)?,
            };
            return Ok(self.outbound_email(to, &subject, rendered.body, None, tags));
        }
        let text_body = self.templates.render_email_verification_txt(context)?;
        let html_body = self.templates.render_email_verification_html(context)?;
        let subject = self.templates.render_email_verification_subject(context)?;

        Ok(self.outbound_email(to, &subject, text_body, Some(html_body), tags))
    }

    fn prepare_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
        template: Option<&PublishedNotificationTemplate>,
    ) -> Result<OutboundEmail, Error> {
        if let Some(template) = template {
            let rendered = template.render(context)?;
            let subject = match rendered.subject {
                Some(subject) => subject,
                None => self.templates.render_email_recovery_subject(context)?,
            };
            return Ok(self.outbound_email(to, &subject, rendered.body, None, tags));
        }
        let text_body = self.templates.render_email_recovery_txt(context)?;
        let html_body = self.templates.render_email_recovery_html(context)?;
        let subject = self.templates.render_email_recovery_subject(context)?;

        Ok(self.outbound_email(to, &subject, text_body, Some(html_body), tags))
    }

    /// Send the verification email to a user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending.
    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<SendResult, Error> {
        self.send_verification_email_with_template(to, context, tags, None)
            .await
    }

    /// Send using an explicitly selected published override, or configured
    /// templates when no published version exists.
    ///
    /// # Errors
    /// Returns an error if rendering or delivery fails.
    #[tracing::instrument(
        name = "email.verification.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
        ),
    )]
    pub async fn send_verification_email_with_template(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
        template: Option<&PublishedNotificationTemplate>,
    ) -> Result<SendResult, Error> {
        let email = self.prepare_verification_email(to, context, tags, template)?;
        Ok(self.transport.send(&email).await?)
    }

    /// Send the recovery email to a user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending.
    pub async fn send_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<SendResult, Error> {
        self.send_recovery_email_with_template(to, context, tags, None)
            .await
    }

    /// Send recovery mail with a selected published override.
    ///
    /// # Errors
    /// Returns an error if rendering or delivery fails.
    #[tracing::instrument(
        name = "email.recovery.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
            user.id = %context.user().id,
            user_recovery_session.id = %context.session().id,
        ),
    )]
    pub async fn send_recovery_email_with_template(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
        template: Option<&PublishedNotificationTemplate>,
    ) -> Result<SendResult, Error> {
        let email = self.prepare_recovery_email(to, context, tags, template)?;
        Ok(self.transport.send(&email).await?)
    }

    /// Test the connection to the mail server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection failed.
    #[tracing::instrument(name = "email.test_connection", skip_all)]
    pub async fn test_connection(&self) -> Result<(), TransportError> {
        self.transport.test_connection(&self.from).await
    }

    /// Return the stable provider binding key for the configured transport.
    #[must_use]
    pub fn provider_binding_key(&self) -> &'static str {
        self.transport.binding_key()
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8Path;
    use pasion_data::{UrlBuilder, UserEmailAuthenticationCode};
    use pasion_templates::{SiteBranding, SiteFeatures, TemplateContext as _};

    use super::*;

    async fn mailer() -> Mailer {
        let root = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let templates = Templates::load(
            root.join("templates"),
            UrlBuilder::new("https://example.com/".parse().unwrap(), None, None),
            root.join("translations"),
            SiteBranding::new("example.com"),
            SiteFeatures {
                password_login: true,
                password_registration: true,
                password_registration_contact_required: true,
                account_recovery: true,
                login_with_email_allowed: true,
            },
            true,
        )
        .await
        .unwrap();
        Mailer::new(
            templates,
            MailTransport::blackhole(),
            "Pasion <auth@example.com>".parse().unwrap(),
            "support@example.com".parse().unwrap(),
        )
    }

    fn context() -> WithLanguage<EmailVerificationContext> {
        let now = jiff::Timestamp::UNIX_EPOCH;
        EmailVerificationContext::new(
            UserEmailAuthenticationCode {
                id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
                user_email_authentication_id: "01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap(),
                code: "sensitive-verification-code-621098".to_owned(),
                created_at: now,
                expires_at: now + jiff::SignedDuration::from_mins(5),
            },
            None,
            None,
        )
        .with_language("en".parse().unwrap())
    }

    #[tokio::test]
    async fn published_body_replaces_visible_content_and_preserves_subject_fallback() {
        let mailer = mailer().await;
        let context = context();
        let to = "user@example.com".parse().unwrap();
        let tags = BTreeMap::new();
        let default = mailer
            .prepare_verification_email(to, &context, &tags, None)
            .unwrap();
        let mut template = PublishedNotificationTemplate {
            subject_template: None,
            body_template: "Published {{ authentication_code.code }}".to_owned(),
        };
        let email = mailer
            .prepare_verification_email(
                "user@example.com".parse().unwrap(),
                &context,
                &tags,
                Some(&template),
            )
            .unwrap();
        assert_eq!(
            email.text_body,
            "Published sensitive-verification-code-621098"
        );
        assert_eq!(email.subject, default.subject);
        assert!(
            email.html_body.is_none(),
            "stale HTML must not hide the published plain text"
        );
        "{{ nonexistent.code }}".clone_into(&mut template.body_template);
        assert!(
            mailer
                .prepare_verification_email(
                    "user@example.com".parse().unwrap(),
                    &context,
                    &tags,
                    Some(&template)
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn notification_sends_do_not_print_credentials() {
        if std::env::var_os("PASION_NOTIFICATION_STDOUT_CHILD").is_some() {
            mailer()
                .await
                .send_verification_email(
                    "user@example.com".parse().unwrap(),
                    &context(),
                    &BTreeMap::new(),
                )
                .await
                .unwrap();
            crate::SmsSender::new(crate::SmsTransport::blackhole())
                .send_verification_code("+12065550123", "sensitive-sms-code-819203", "en")
                .await
                .unwrap();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "email::mailer::tests::notification_sends_do_not_print_credentials",
                "--nocapture",
            ])
            .env("PASION_NOTIFICATION_STDOUT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("sensitive-verification-code-621098"));
        assert!(!stdout.contains("sensitive-sms-code-819203"));
        assert!(!stdout.contains("user@example.com"));
    }
}
