//! Helps sending emails to users, with different email backends

#![deny(missing_docs)]

mod mailer;
mod transport;

pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use mas_templates::EmailVerificationContext;

pub use self::{
    mailer::Mailer,
    transport::{SmtpMode, Transport as MailTransport},
};
