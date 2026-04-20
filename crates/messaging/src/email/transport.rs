//! Email transport backends

use std::{collections::BTreeMap, ffi::OsString, num::NonZeroU16, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use hmac::{Hmac, Mac};
use lettre::{
    AsyncTransport, Message, Tokio1Executor,
    message::{
        Mailbox, MultiPart, SinglePart,
        header::{HeaderName, HeaderValue},
    },
    transport::{
        sendmail::AsyncSendmailTransport,
        smtp::{AsyncSmtpTransport, authentication::Credentials},
    },
};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

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
    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error>;
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

    /// Construct a Resend email API transport.
    #[must_use]
    pub fn resend(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(ResendProvider {
            client,
            base_url,
            api_key,
        })
    }

    /// Construct a SendGrid email API transport.
    #[must_use]
    pub fn sendgrid(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(SendgridLikeProvider {
            client,
            base_url,
            api_key,
            binding_key: "email.sendgrid",
        })
    }

    /// Construct a Twilio SendGrid email API transport.
    #[must_use]
    pub fn twilio(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(SendgridLikeProvider {
            client,
            base_url,
            api_key,
            binding_key: "email.twilio",
        })
    }

    /// Construct a Brevo transactional email API transport.
    #[must_use]
    pub fn brevo(client: Client, base_url: Url, api_key: String) -> Self {
        Self::new(BrevoProvider {
            client,
            base_url,
            api_key,
        })
    }

    /// Construct an AWS SES v2 email API transport.
    #[must_use]
    pub fn aws_ses(
        client: Client,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        endpoint: Option<Url>,
        configuration_set_name: Option<String>,
    ) -> Self {
        let endpoint = endpoint.unwrap_or_else(|| {
            Url::parse(&format!("https://email.{region}.amazonaws.com"))
                .expect("default AWS SES endpoint must be valid")
        });

        Self::new(AwsSesProvider {
            client,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            configuration_set_name,
        })
    }

    /// Send an outbound email through the configured provider.
    pub async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        self.inner.send(email).await
    }

    /// Test the connection to the underlying transport when supported.
    pub async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        self.inner.test_connection(from).await
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

    /// The email payload could not be serialized for the provider.
    #[error("failed to serialize email payload: {0}")]
    Json(#[from] serde_json::Error),

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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
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

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
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

        execute_provider_request(request).await
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        Ok(())
    }
}

struct ResendProvider {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    to: Vec<String>,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<ProviderTag<'a>>,
}

#[derive(Debug, Deserialize)]
struct ResendDomainsResponse {
    #[serde(default)]
    data: Vec<ResendDomain>,
}

#[derive(Debug, Deserialize)]
struct ResendDomain {
    name: String,
    capabilities: ResendDomainCapabilities,
}

#[derive(Debug, Deserialize)]
struct ResendDomainCapabilities {
    sending: String,
}

#[async_trait]
impl EmailProvider for ResendProvider {
    fn binding_key(&self) -> &'static str {
        "email.resend"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = ResendRequest {
            from: email.from.to_string(),
            reply_to: email.reply_to.as_ref().map(ToString::to_string),
            to: email.to.iter().map(ToString::to_string).collect(),
            subject: &email.subject,
            text: Some(email.text_body.as_str()),
            html: email.html_body.as_deref(),
            headers: &email.headers,
            tags: provider_tags(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/emails"))
            .bearer_auth(&self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let response: ResendDomainsResponse = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/domains"))
                .bearer_auth(&self.api_key),
        )
        .await?;

        let sender_domain = sender_domain(from).ok_or_else(|| {
            provider_client_error(
                "invalid_sender",
                format!("sender address {from} does not contain a domain"),
            )
        })?;

        if response.data.iter().any(|domain| {
            domain.name.eq_ignore_ascii_case(&sender_domain)
                && domain.capabilities.sending.eq_ignore_ascii_case("enabled")
        }) {
            return Ok(());
        }

        Err(provider_client_error(
            "sender_domain_unverified",
            format!(
                "Resend domain {sender_domain} is not configured or sending is not enabled"
            ),
        ))
    }
}

struct SendgridLikeProvider {
    client: Client,
    base_url: Url,
    api_key: String,
    binding_key: &'static str,
}

#[derive(Serialize)]
struct ProviderMailbox<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Serialize)]
struct SendgridPersonalization<'a> {
    to: Vec<ProviderMailbox<'a>>,
}

#[derive(Serialize)]
struct SendgridContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct SendgridRequest<'a> {
    personalizations: Vec<SendgridPersonalization<'a>>,
    from: ProviderMailbox<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<ProviderMailbox<'a>>,
    subject: &'a str,
    content: Vec<SendgridContent<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_args: Option<&'a BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct SendgridScopesResponse {
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SendgridAuthenticatedDomain {
    domain: String,
    valid: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SendgridVerifiedSendersResponse {
    #[serde(default)]
    results: Vec<SendgridVerifiedSender>,
}

#[derive(Debug, Deserialize)]
struct SendgridVerifiedSender {
    from_email: String,
    verified: bool,
}

#[async_trait]
impl EmailProvider for SendgridLikeProvider {
    fn binding_key(&self) -> &'static str {
        self.binding_key
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let mut content = vec![SendgridContent {
            content_type: "text/plain",
            value: &email.text_body,
        }];

        if let Some(html) = email.html_body.as_deref() {
            content.push(SendgridContent {
                content_type: "text/html",
                value: html,
            });
        }

        let payload = SendgridRequest {
            personalizations: vec![SendgridPersonalization {
                to: email.to.iter().map(provider_mailbox).collect(),
            }],
            from: provider_mailbox(&email.from),
            reply_to: email.reply_to.as_ref().map(provider_mailbox),
            subject: &email.subject,
            content,
            headers: map_ref(&email.headers),
            custom_args: map_ref(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/v3/mail/send"))
            .bearer_auth(&self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let scopes: SendgridScopesResponse = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/v3/scopes"))
                .bearer_auth(&self.api_key),
        )
        .await?;

        if !scopes.scopes.iter().any(|scope| scope == "mail.send") {
            return Err(provider_client_error(
                "missing_scope",
                "Twilio SendGrid API key is missing the mail.send scope",
            ));
        }

        validate_sendgrid_sender(self, from).await
    }
}

struct BrevoProvider {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Serialize)]
struct BrevoRequest<'a> {
    sender: ProviderMailbox<'a>,
    to: Vec<ProviderMailbox<'a>>,
    #[serde(rename = "replyTo", skip_serializing_if = "Option::is_none")]
    reply_to: Option<ProviderMailbox<'a>>,
    subject: &'a str,
    #[serde(rename = "textContent")]
    text_content: &'a str,
    #[serde(rename = "htmlContent", skip_serializing_if = "Option::is_none")]
    html_content: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[async_trait]
impl EmailProvider for BrevoProvider {
    fn binding_key(&self) -> &'static str {
        "email.brevo"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let payload = BrevoRequest {
            sender: provider_mailbox(&email.from),
            to: email.to.iter().map(provider_mailbox).collect(),
            reply_to: email.reply_to.as_ref().map(provider_mailbox),
            subject: &email.subject,
            text_content: &email.text_body,
            html_content: email.html_body.as_deref(),
            headers: map_ref(&email.headers),
            tags: brevo_tags(&email.tags),
        };

        let request = self
            .client
            .post(provider_url(&self.base_url, "/v3/smtp/email"))
            .header("api-key", &self.api_key)
            .json(&payload);

        execute_provider_request(request).await
    }

    async fn test_connection(&self, _from: &Mailbox) -> Result<(), Error> {
        let _: serde_json::Value = execute_provider_json_request(
            self.client
                .get(provider_url(&self.base_url, "/v3/account"))
                .header("api-key", &self.api_key),
        )
        .await?;
        Ok(())
    }
}

struct AwsSesProvider {
    client: Client,
    endpoint: Url,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    configuration_set_name: Option<String>,
}

#[derive(Serialize)]
struct AwsSesRequest<'a> {
    #[serde(rename = "FromEmailAddress")]
    from_email_address: String,
    #[serde(rename = "Destination")]
    destination: AwsSesDestination,
    #[serde(rename = "Content")]
    content: AwsSesContent,
    #[serde(
        rename = "ConfigurationSetName",
        skip_serializing_if = "Option::is_none"
    )]
    configuration_set_name: Option<&'a str>,
    #[serde(rename = "EmailTags", skip_serializing_if = "Vec::is_empty")]
    email_tags: Vec<AwsSesTag<'a>>,
}

#[derive(Serialize)]
struct AwsSesDestination {
    #[serde(rename = "ToAddresses")]
    to_addresses: Vec<String>,
}

#[derive(Serialize)]
struct AwsSesContent {
    #[serde(rename = "Raw")]
    raw: AwsSesRawContent,
}

#[derive(Serialize)]
struct AwsSesRawContent {
    #[serde(rename = "Data")]
    data: String,
}

#[derive(Serialize)]
struct AwsSesTag<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Value")]
    value: &'a str,
}

#[derive(Debug, Deserialize)]
struct AwsSesAccountResponse {
    #[serde(rename = "ProductionAccessEnabled")]
    production_access_enabled: bool,
    #[serde(rename = "SendingEnabled")]
    sending_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct AwsSesIdentityResponse {
    #[serde(rename = "VerificationStatus")]
    verification_status: Option<String>,
    #[serde(rename = "VerifiedForSendingStatus")]
    verified_for_sending_status: bool,
}

#[derive(Serialize)]
struct ProviderTag<'a> {
    name: &'a str,
    value: &'a str,
}

#[async_trait]
impl EmailProvider for AwsSesProvider {
    fn binding_key(&self) -> &'static str {
        "email.aws_ses"
    }

    async fn send(&self, email: &OutboundEmail) -> Result<SendResult, Error> {
        let raw_message = build_lettre_message(email)?.formatted();
        let payload = AwsSesRequest {
            from_email_address: email.from.email.to_string(),
            destination: AwsSesDestination {
                to_addresses: email
                    .to
                    .iter()
                    .map(|mailbox| mailbox.email.to_string())
                    .collect(),
            },
            content: AwsSesContent {
                raw: AwsSesRawContent {
                    data: BASE64.encode(raw_message),
                },
            },
            configuration_set_name: self.configuration_set_name.as_deref(),
            email_tags: aws_ses_tags(&email.tags),
        };

        let body = serde_json::to_string(&payload)?;
        let url = provider_url(&self.endpoint, "/v2/email/outbound-emails");
        execute_provider_request(
            self.aws_signed_request(Method::POST, url, Some(body), Some("application/json"))?,
        )
        .await
    }

    async fn test_connection(&self, from: &Mailbox) -> Result<(), Error> {
        let account: AwsSesAccountResponse = execute_provider_json_request(
            self.aws_signed_request(
                Method::GET,
                provider_url(&self.endpoint, "/v2/email/account"),
                None,
                None,
            )?,
        )
        .await?;

        if !account.sending_enabled {
            return Err(provider_client_error(
                "sending_disabled",
                "AWS SES account sending is disabled in this region",
            ));
        }

        if !account.production_access_enabled {
            return Err(provider_client_error(
                "sandbox_mode",
                "AWS SES account is still in sandbox mode in this region",
            ));
        }

        self.ensure_verified_sender(from).await
    }
}

impl AwsSesProvider {
    fn aws_signed_request(
        &self,
        method: Method,
        url: Url,
        body: Option<String>,
        content_type: Option<&str>,
    ) -> Result<RequestBuilder, Error> {
        let host = url
            .host_str()
            .expect("AWS SES endpoint must contain a hostname");
        let body = body.unwrap_or_default();
        let payload_hash = hex_sha256(body.as_bytes());
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let mut canonical_headers = BTreeMap::from([
            ("host".to_owned(), host.to_owned()),
            ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ]);

        if let Some(content_type) = content_type {
            canonical_headers.insert("content-type".to_owned(), content_type.to_owned());
        }

        if let Some(session_token) = &self.session_token {
            canonical_headers.insert("x-amz-security-token".to_owned(), session_token.clone());
        }

        let canonical_headers_text = canonical_headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", normalize_aws_header_value(value)))
            .collect::<String>();
        let signed_headers = canonical_headers
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}{signed_headers}\n{payload_hash}",
            method.as_str(),
            canonical_uri(url.path()),
            canonical_query(url.query()),
            canonical_headers_text,
        );
        let credential_scope = format!("{date_stamp}/{}/ses/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes()),
        );
        let signing_key =
            aws_signing_key(&self.secret_access_key, &date_stamp, &self.region, "ses");
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id,
        );

        let mut request = self
            .client
            .request(method, url)
            .header("Authorization", authorization)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", amz_date);

        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }

        if let Some(session_token) = &self.session_token {
            request = request.header("x-amz-security-token", session_token);
        }

        if !body.is_empty() {
            request = request.body(body);
        }

        Ok(request)
    }

    async fn ensure_verified_sender(&self, from: &Mailbox) -> Result<(), Error> {
        let sender_email = from.email.to_string();

        if let Some(identity) = self
            .get_email_identity(&sender_email)
            .await?
            .filter(|identity| identity.verified_for_sending_status)
        {
            if identity
                .verification_status
                .as_deref()
                .unwrap_or("SUCCESS")
                .eq_ignore_ascii_case("SUCCESS")
            {
                return Ok(());
            }
        }

        let sender_domain = sender_domain(from).ok_or_else(|| {
            provider_client_error(
                "invalid_sender",
                format!("sender address {from} does not contain a domain"),
            )
        })?;

        if let Some(identity) = self
            .get_email_identity(&sender_domain)
            .await?
            .filter(|identity| identity.verified_for_sending_status)
        {
            if identity
                .verification_status
                .as_deref()
                .unwrap_or("SUCCESS")
                .eq_ignore_ascii_case("SUCCESS")
            {
                return Ok(());
            }
        }

        Err(provider_client_error(
            "sender_identity_unverified",
            format!(
                "AWS SES sender {sender_email} or domain {sender_domain} is not verified for sending"
            ),
        ))
    }

    async fn get_email_identity(
        &self,
        identity: &str,
    ) -> Result<Option<AwsSesIdentityResponse>, Error> {
        let mut url = self.endpoint.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| provider_client_error("invalid_endpoint", "AWS SES endpoint path is invalid"))?;
            segments.clear();
            segments.extend(["v2", "email", "identities", identity]);
        }
        url.set_query(None);
        url.set_fragment(None);

        execute_optional_provider_json_request(
            self.aws_signed_request(Method::GET, url, None, None)?,
            &[StatusCode::NOT_FOUND],
        )
        .await
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

async fn execute_provider_request(request: RequestBuilder) -> Result<SendResult, Error> {
    let response = request.send().await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(provider_error(status.as_u16(), body));
    }

    Ok(SendResult {
        provider_message_id: extract_provider_message_id(&headers, &body),
    })
}

fn provider_error(status: u16, body: String) -> Error {
    Error::ProviderError {
        status,
        code: extract_provider_error_code(&body),
        retryable: status == 429 || status >= 500,
        body,
    }
}

fn provider_url(base_url: &Url, path: &str) -> Url {
    let mut url = base_url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn provider_mailbox(mailbox: &Mailbox) -> ProviderMailbox<'_> {
    ProviderMailbox {
        email: mailbox.email.as_ref(),
        name: mailbox_name(mailbox),
    }
}

fn mailbox_name(mailbox: &Mailbox) -> Option<&str> {
    mailbox
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn map_ref(map: &BTreeMap<String, String>) -> Option<&BTreeMap<String, String>> {
    (!map.is_empty()).then_some(map)
}

fn provider_tags(tags: &BTreeMap<String, String>) -> Vec<ProviderTag<'_>> {
    tags.iter()
        .map(|(name, value)| ProviderTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
}

fn brevo_tags(tags: &BTreeMap<String, String>) -> Vec<String> {
    tags.iter()
        .map(|(name, value)| {
            if value.trim().is_empty() {
                name.clone()
            } else {
                format!("{name}:{value}")
            }
        })
        .collect()
}

fn aws_ses_tags(tags: &BTreeMap<String, String>) -> Vec<AwsSesTag<'_>> {
    tags.iter()
        .map(|(name, value)| AwsSesTag {
            name: name.as_str(),
            value: value.as_str(),
        })
        .collect()
}

fn canonical_uri(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn normalize_aws_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aws_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let date_key = hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, b"aws4_request")
}

#[derive(Debug, Default, Deserialize)]
struct ProviderResponse {
    id: Option<String>,
    message_id: Option<String>,
    #[serde(rename = "messageId")]
    message_id_camel: Option<String>,
    #[serde(rename = "MessageId")]
    message_id_pascal: Option<String>,
    provider_message_id: Option<String>,
    code: Option<String>,
    error: Option<String>,
    #[serde(default)]
    errors: Vec<ProviderResponseError>,
}

#[derive(Debug, Default, Deserialize)]
struct ProviderResponseError {
    code: Option<String>,
    field: Option<String>,
    id: Option<String>,
    message: Option<String>,
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

    serde_json::from_str::<ProviderResponse>(body)
        .ok()
        .and_then(|payload| {
            payload
                .provider_message_id
                .or(payload.message_id)
                .or(payload.message_id_camel)
                .or(payload.message_id_pascal)
                .or(payload.id)
        })
        .filter(|value| !value.trim().is_empty())
}

fn extract_provider_error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ProviderResponse>(body)
        .ok()
        .and_then(|payload| {
            payload.code.or(payload.error).or_else(|| {
                payload
                    .errors
                    .into_iter()
                    .find_map(|error| error.code.or(error.id).or(error.field).or(error.message))
            })
        })
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::{extract_provider_error_code, extract_provider_message_id};

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

    #[test]
    fn extracts_message_id_from_pascal_case_json_body() {
        let headers = HeaderMap::new();

        let id = extract_provider_message_id(&headers, r#"{"MessageId":"msg-789"}"#);

        assert_eq!(id.as_deref(), Some("msg-789"));
    }

    #[test]
    fn extracts_nested_provider_error_code() {
        let code = extract_provider_error_code(
            r#"{"errors":[{"field":"personalizations.0.to.0.email","message":"invalid email"}]}"#,
        );

        assert_eq!(code.as_deref(), Some("personalizations.0.to.0.email"));
    }
}
