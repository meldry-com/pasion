//! Email transport backends

use std::{ffi::OsString, num::NonZeroU16, sync::Arc};

use async_trait::async_trait;
use lettre::{
    AsyncTransport, Tokio1Executor,
    address::Envelope,
    transport::{
        sendmail::AsyncSendmailTransport,
        smtp::{AsyncSmtpTransport, authentication::Credentials},
    },
};
use thiserror::Error;

/// Encryption mode to use
#[derive(Debug, Clone, Copy)]
pub enum SmtpMode {
    /// Plain text
    Plain,
    /// `StartTLS` (starts as plain text then upgrade to TLS)
    StartTls,
    /// TLS
    Tls,
}

/// A wrapper around many [`AsyncTransport`]s
#[derive(Default, Clone)]
pub struct Transport {
    inner: Arc<TransportInner>,
}

#[derive(Default)]
enum TransportInner {
    #[default]
    Blackhole,
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    Sendmail(AsyncSendmailTransport<Tokio1Executor>),
}

impl Transport {
    fn new(inner: TransportInner) -> Self {
        let inner = Arc::new(inner);
        Self { inner }
    }

    /// Construct a blackhole transport
    #[must_use]
    pub fn blackhole() -> Self {
        Self::new(TransportInner::Blackhole)
    }

    /// Construct a SMTP transport
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying SMTP transport could not be built
    pub fn smtp(
        mode: SmtpMode,
        hostname: &str,
        port: Option<NonZeroU16>,
        credentials: Option<Credentials>,
    ) -> Result<Self, lettre::transport::smtp::Error> {
        let mut t = match mode {
            SmtpMode::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(hostname),
            SmtpMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(hostname)?,
            SmtpMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(hostname)?,
        };

        if let Some(credentials) = credentials {
            t = t.credentials(credentials);
        }

        if let Some(port) = port {
            t = t.port(port.into());
        }

        Ok(Self::new(TransportInner::Smtp(t.build())))
    }

    /// Construct a Sendmail transport
    #[must_use]
    pub fn sendmail(command: Option<impl Into<OsString>>) -> Self {
        let transport = if let Some(command) = command {
            AsyncSendmailTransport::new_with_command(command)
        } else {
            AsyncSendmailTransport::new()
        };
        Self::new(TransportInner::Sendmail(transport))
    }
}

impl Transport {
    /// Test the connection to the underlying transport. Only works with the
    /// SMTP backend for now
    ///
    /// # Errors
    ///
    /// Will return `Err` if the connection test failed
    pub async fn test_connection(&self) -> Result<(), Error> {
        match self.inner.as_ref() {
            TransportInner::Smtp(t) => {
                t.test_connection().await?;
            }
            TransportInner::Blackhole | TransportInner::Sendmail(_) => {}
        }

        Ok(())
    }

    /// Return the stable provider binding key for this transport.
    #[must_use]
    pub fn binding_key(&self) -> &'static str {
        match self.inner.as_ref() {
            TransportInner::Blackhole => "email.blackhole",
            TransportInner::Smtp(_) => "email.smtp",
            TransportInner::Sendmail(_) => "email.sendmail",
        }
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    Smtp(#[from] lettre::transport::smtp::Error),
    Sendmail(#[from] lettre::transport::sendmail::Error),
}

#[async_trait]
impl AsyncTransport for Transport {
    type Ok = ();
    type Error = Error;

    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        let from = envelope.from().map(|a| a.to_string()).unwrap_or_default();
        let to: Vec<String> = envelope.to().iter().map(|a| a.to_string()).collect();
        println!("[EMAIL] send_raw called: from={from}, to={to:?}");

        match self.inner.as_ref() {
            TransportInner::Blackhole => {
                println!("[EMAIL] transport=blackhole, email NOT sent");
                tracing::warn!(
                    "An email was supposed to be sent but no email backend is configured"
                );
            }
            TransportInner::Smtp(t) => {
                println!("[EMAIL] transport=smtp, sending email...");
                if let Err(e) = t.send_raw(envelope, email).await {
                    println!("[EMAIL] smtp send FAILED: {e}");
                    return Err(Error::Smtp(e));
                }
                println!("[EMAIL] smtp send SUCCESS");
            }
            TransportInner::Sendmail(t) => {
                println!("[EMAIL] transport=sendmail, sending email...");
                t.send_raw(envelope, email).await?;
                println!("[EMAIL] sendmail send SUCCESS");
            }
        }

        Ok(())
    }
}
