//! Send SMS messages to users

use crate::transport::{SmsTransport, SmsTransportError};

/// Helps sending SMS messages to users
#[derive(Clone)]
pub struct SmsSender {
    transport: SmsTransport,
}

impl SmsSender {
    /// Constructs a new [`SmsSender`]
    #[must_use]
    pub fn new(transport: SmsTransport) -> Self {
        Self { transport }
    }

    /// Send a verification code via SMS
    ///
    /// # Errors
    ///
    /// Returns an error if the SMS failed to send
    pub async fn send_verification_code(
        &self,
        to: &str,
        code: &str,
    ) -> Result<(), SmsTransportError> {
        let body = format!("Your verification code is: {code}");
        println!("[SMS] send_verification_code to={to}, code={code}");
        self.transport.send(to, &body).await
    }
}
