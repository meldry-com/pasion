//! Helps sending emails to users, with different email backends

mod mailer;
mod transport;

pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use pasion_templates::EmailVerificationContext;

pub use self::{
    mailer::{Error as MailerError, Mailer},
    transport::{SmtpMode, Transport},
};
