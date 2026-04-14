//! Unified notification delivery for the Pasion authentication service.
//!
//! Provides email and SMS transports behind a common trait interface.

#![deny(missing_docs)]

pub mod email;
mod notification;
pub mod sms;

pub use self::email::{Mailer, SmtpMode, Transport as MailTransport};
pub use self::notification::{NotificationCenter, NotificationError, NotificationRequest};
pub use self::sms::{SmsSender, SmsTransport, SmsTransportError};

// Re-export commonly used types from email for backward compatibility
pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use pasion_templates::EmailVerificationContext;
