//! Email transport backends

use std::{collections::BTreeMap, ffi::OsString, num::NonZeroU16, sync::Arc};

use async_trait::async_trait;
use lettre::{
    AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart},
    transport::{
        sendmail::AsyncSendmailTransport,
        smtp::{AsyncSmtpTransport, authentication::Credentials},
    },
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Encryption mode to use for SMTP transports.
#[derive(Debug, Clone, Copy)]
pub enum SmtpMode {
    /// Plain text
    Plain,
    /// `StartTLS` (starts as plain text then upgrades to TLS)
    StartTls,
    /// TLS
    Tls,
}

/// Provider-agnostic outbound email payload.
#[derive(Debug, Clone)]
pub struct OutboundEmail {
    /// Envelope sender displayed to recipients.
    pub from: Mailbox,
    /// Optional reply-to address.
    pub reply_to: Option<Mailbox>,
    /// Recipients of the message.
    pub to: Vec<Mailbox>,
    /// Localized subject line.
    pub subject: String,
    /// Plain-text body.
    pub text_body: String,
    /// Optional HTML body.
    pub html_body: Option<String>,
    /// Provider-specific extra headers.
    pub headers: BTreeMap<String, String>,
    /// Provider-specific tags or metadata.
    pub tags: BTreeMap<String, String>,
}

/// Result returned by an email provider after accepting a message.
#[derive(Debug, Clone, Default)]
pub struct SendResult {
    /// Optional provider-side message identifier.
    pub provider_message_id: Option<String>,
}

#[async_trait]
/// A delivery backend capable of accepting rendered email payloads.
pub trait EmailProvider: Send + Sync {
    /// Returns the stable provider binding key recorded on notification
    /// deliveries for this backend.
    fn binding_key(&self) -> &'static str;

    /// Sends a rendered outbound email through the provider.
    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error>;

    /// Performs a lightweight connectivity check when the provider supports
    /// it.
    async fn test_connection(&self) -> Result<(), Error>;
}

/// A cloneable wrapper around an email provider implementation.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<dyn EmailProvider>,
}

impl Default for Transport {
    fn default() -> Self {
        Self::blackhole()
    }
}

impl Transport {
    fn new(provider: impl EmailProvider + 'static) -> Self {
        Self {
            inner: Arc::new(provider),
        }
    }

    /// Construct a blackhole transport.
    #[must_use]
    pub fn blackhole() -> Self {
        Self::new(BlackholeProvider)
    }

    /// Construct a SMTP transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying SMTP transport could not be built.
    pub fn smtp(
        mode: SmtpMode,
        hostname: &str,
        port: Option<NonZeroU16>,
        credentials: Option<Credentials>,
    ) -> Result<Self, lettre::transport::smtp::Error> {
        let mut builder = match mode {
            SmtpMode::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(hostname),
            SmtpMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(hostname)?,
            SmtpMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(hostname)?,
        };

        if let Some(credentials) = credentials {
            builder = builder.credentials(credentials);
        }

        if let Some(port) = port {
            builder = builder.port(port.into());
        }

        Ok(Self::new(SmtpProvider {
            transport: builder.build(),
        }))
    }

    /// Construct a Sendmail transport.
    #[must_use]
    pub fn sendmail(command: Option<impl Into<OsString>>) -> Self {
        let transport = if let Some(command) = command {
            AsyncSendmailTransport::new_with_command(command)
        } else {
            AsyncSendmailTransport::new()
        };

        Self::new(SendmailProvider { transport })
    }

    /// Construct a generic HTTP webhook email transport.
    #[must_use]
    pub fn http_webhook(
        client: Client,
        url: Url,
        api_key: Option<String>,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self::new(HttpWebhookProvider {
            client,
            url,
            api_key,
            headers,
        })
    }

    /// Send an outbound email through the configured provider.
    pub async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        self.inner.send(email).await
    }

    /// Test the connection to the underlying transport when supported.
    pub async fn test_connection(&self) -> Result<(), Error> {
        self.inner.test_connection().await
    }

    /// Return the stable provider binding key for this transport.
    #[must_use]
    pub fn binding_key(&self) -> &'static str {
        self.inner.binding_key()
    }
}

#[derive(Debug, Error)]
/// Errors that can occur while handing an email to a delivery provider.
pub enum Error {
    /// The payload could not be converted into a provider-specific message.
    #[error(transparent)]
    Message(#[from] lettre::error::Error),

    /// The SMTP transport failed.
    #[error(transparent)]
    Smtp(#[from] lettre::transport::smtp::Error),

    /// The sendmail transport failed.
    #[error(transparent)]
    Sendmail(#[from] lettre::transport::sendmail::Error),

    /// The HTTP client failed before a provider response was received.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The provider returned a non-success response payload.
    #[error("email provider returned status {status}: {body}")]
    ProviderError {
        /// HTTP status code returned by the provider.
        status: u16,
        /// Optional provider error code.
        code: Option<String>,
        /// Raw response body captured for diagnostics.
        body: String,
        /// Whether the provider failure is safe to retry.
        retryable: bool,
    },
}

struct BlackholeProvider;

#[async_trait]
impl EmailProvider for BlackholeProvider {
    fn binding_key(&self) -> &'static str {
        "email.blackhole"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let to: Vec<String> = email.to.iter().map(ToString::to_string).collect();
        println!("[EMAIL] transport=blackhole, email NOT sent: to={to:?}");
        tracing::warn!("An email was supposed to be sent but no email backend is configured");
        Ok(SendResult::default())
    }

    async fn test_connection(&self) -> Result<(), Error> {
        Ok(())
    }
}

struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

#[async_trait]
impl EmailProvider for SmtpProvider {
    fn binding_key(&self) -> &'static str {
        "email.smtp"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let message = build_lettre_message(email)?;
        self.transport.send(message).await?;
        Ok(SendResult::default())
    }

    async fn test_connection(&self) -> Result<(), Error> {
        self.transport.test_connection().await?;
        Ok(())
    }
}

struct SendmailProvider {
    transport: AsyncSendmailTransport<Tokio1Executor>,
}

#[async_trait]
impl EmailProvider for SendmailProvider {
    fn binding_key(&self) -> &'static str {
        "email.sendmail"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let message = build_lettre_message(email)?;
        self.transport.send(message).await?;
        Ok(SendResult::default())
    }

    async fn test_connection(&self) -> Result<(), Error> {
        Ok(())
    }
}

struct HttpWebhookProvider {
    client: Client,
    url: Url,
    api_key: Option<String>,
    headers: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct HttpWebhookRequest<'a> {
    from: String,
    reply_to: Option<String>,
    to: Vec<String>,
    subject: &'a str,
    text_body: &'a str,
    html_body: Option<&'a str>,
    headers: &'a BTreeMap<String, String>,
    tags: &'a BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct HttpWebhookResponse {
    id: Option<String>,
    message_id: Option<String>,
    provider_message_id: Option<String>,
    code: Option<String>,
}

#[async_trait]
impl EmailProvider for HttpWebhookProvider {
    fn binding_key(&self) -> &'static str {
        "email.http_webhook"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = HttpWebhookRequest {
            from: email.from.to_string(),
            reply_to: email.reply_to.as_ref().map(ToString::to_string),
            to: email.to.iter().map(ToString::to_string).collect(),
            subject: &email.subject,
            text_body: &email.text_body,
            html_body: email.html_body.as_deref(),
            headers: &email.headers,
            tags: &email.tags,
        };

        let mut request = self.client.post(self.url.clone()).json(&payload);

        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            let parsed = serde_json::from_str::<HttpWebhookResponse>(&body).ok();
            return Err(Error::ProviderError {
                status: status.as_u16(),
                code: parsed.and_then(|value| value.code),
                body,
                retryable: status.as_u16() == 429 || status.is_server_error(),
            });
        }

        Ok(SendResult {
            provider_message_id: extract_provider_message_id(&headers, &body),
        })
    }

    async fn test_connection(&self) -> Result<(), Error> {
        Ok(())
    }
}

fn build_lettre_message(email: &OutboundEmail) -> Result<Message, lettre::error::Error> {
    let mut builder = Message::builder()
        .from(email.from.clone())
        .subject(email.subject.trim());

    if let Some(reply_to) = &email.reply_to {
        builder = builder.reply_to(reply_to.clone());
    }

    for mailbox in &email.to {
        builder = builder.to(mailbox.clone());
    }

    match &email.html_body {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            email.text_body.clone(),
            html.clone(),
        )),
        None => builder.singlepart(SinglePart::plain(email.text_body.clone())),
    }
}

fn extract_provider_message_id(headers: &reqwest::header::HeaderMap, body: &str) -> Option<String> {
    for header_name in ["x-provider-message-id", "x-message-id", "x-request-id"] {
        if let Some(value) = headers.get(header_name) {
            if let Ok(value) = value.to_str() {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }

    serde_json::from_str::<HttpWebhookResponse>(body)
        .ok()
        .and_then(|payload| {
            payload
                .provider_message_id
                .or(payload.message_id)
                .or(payload.id)
        })
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::extract_provider_message_id;

    #[test]
    fn extracts_message_id_from_headers_first() {
        let mut headers = HeaderMap::new();
        headers.insert("x-provider-message-id", HeaderValue::from_static("msg-123"));

        let id = extract_provider_message_id(&headers, r#"{"message_id":"msg-456"}"#);

        assert_eq!(id.as_deref(), Some("msg-123"));
    }

    #[test]
    fn extracts_message_id_from_json_body() {
        let headers = HeaderMap::new();

        let id = extract_provider_message_id(&headers, r#"{"provider_message_id":"msg-456"}"#);

        assert_eq!(id.as_deref(), Some("msg-456"));
    }
}
