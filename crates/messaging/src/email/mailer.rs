//! Send emails to users

use lettre::{
    AsyncTransport, Message,
    message::{Mailbox, MessageBuilder, MultiPart},
};
use pasion_templates::{EmailRecoveryContext, EmailVerificationContext, Templates, WithLanguage};
use thiserror::Error;

use super::Transport as MailTransport;

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
    Transport(#[from] super::transport::Error),
    /// Rendering the email templates failed.
    Templates(#[from] pasion_templates::TemplateError),
    /// Building the email message content failed.
    Content(#[from] lettre::error::Error),
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

    fn base_message(&self) -> MessageBuilder {
        Message::builder()
            .from(self.from.clone())
            .reply_to(self.reply_to.clone())
    }

    fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<Message, Error> {
        let plain = self.templates.render_email_verification_txt(context)?;

        let html = self.templates.render_email_verification_html(context)?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let subject = self.templates.render_email_verification_subject(context)?;

        let message = self
            .base_message()
            .subject(subject.trim())
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    fn prepare_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
    ) -> Result<Message, Error> {
        let plain = self.templates.render_email_recovery_txt(context)?;

        let html = self.templates.render_email_recovery_html(context)?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let subject = self.templates.render_email_recovery_subject(context)?;

        let message = self
            .base_message()
            .subject(subject.trim())
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    /// Send the verification email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
    #[tracing::instrument(
        name = "email.verification.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
        ),
    )]
    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<(), Error> {
        println!(
            "[EMAIL] prepare verification email to={to}, code={}",
            context.code()
        );
        let message = self.prepare_verification_email(to, context)?;
        println!("[EMAIL] sending verification email...");
        self.transport.send(message).await?;
        println!("[EMAIL] verification email sent OK");
        Ok(())
    }

    /// Send the recovery email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
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
    pub async fn send_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
    ) -> Result<(), Error> {
        println!("[EMAIL] prepare recovery email to={to}");
        let message = self.prepare_recovery_email(to, context)?;
        println!("[EMAIL] sending recovery email...");
        self.transport.send(message).await?;
        println!("[EMAIL] recovery email sent OK");
        Ok(())
    }

    /// Test the connetion to the mail server
    ///
    /// # Errors
    ///
    /// Returns an error if the connection failed
    #[tracing::instrument(name = "email.test_connection", skip_all)]
    pub async fn test_connection(&self) -> Result<(), super::transport::Error> {
        self.transport.test_connection().await
    }

    /// Return the stable provider binding key for the configured transport.
    #[must_use]
    pub fn provider_binding_key(&self) -> &'static str {
        self.transport.binding_key()
    }
}
