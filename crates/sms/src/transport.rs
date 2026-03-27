//! SMS transport backends

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;
use thiserror::Error;
use url::Url;

/// Errors that can occur when sending an SMS
#[derive(Debug, Error)]
pub enum SmsTransportError {
    /// An error occurred in the HTTP client
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// The SMS provider returned a non-success status
    #[error("SMS provider returned status {status}: {body}")]
    ProviderError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },
}

/// A wrapper around multiple SMS transport backends
#[derive(Clone)]
pub struct SmsTransport {
    inner: Arc<SmsTransportInner>,
}

enum SmsTransportInner {
    Blackhole,
    Twilio {
        client: Client,
        account_sid: String,
        auth_token: String,
        from_number: String,
    },
    HttpWebhook {
        client: Client,
        url: Url,
        api_key: Option<String>,
        from_number: String,
    },
}

impl Default for SmsTransport {
    fn default() -> Self {
        Self::blackhole()
    }
}

impl SmsTransport {
    fn new(inner: SmsTransportInner) -> Self {
        let inner = Arc::new(inner);
        Self { inner }
    }

    /// Construct a blackhole transport that discards all messages
    #[must_use]
    pub fn blackhole() -> Self {
        Self::new(SmsTransportInner::Blackhole)
    }

    /// Construct a Twilio transport
    #[must_use]
    pub fn twilio(account_sid: String, auth_token: String, from_number: String) -> Self {
        Self::new(SmsTransportInner::Twilio {
            client: Client::new(),
            account_sid,
            auth_token,
            from_number,
        })
    }

    /// Construct an HTTP webhook transport
    #[must_use]
    pub fn http_webhook(url: Url, api_key: Option<String>, from_number: String) -> Self {
        Self::new(SmsTransportInner::HttpWebhook {
            client: Client::new(),
            url,
            api_key,
            from_number,
        })
    }

    /// Send an SMS message
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport fails to send the message
    pub async fn send(&self, to: &str, body: &str) -> Result<(), SmsTransportError> {
        println!("[SMS] send called: to={to}, body={body}");

        match self.inner.as_ref() {
            SmsTransportInner::Blackhole => {
                println!("[SMS] transport=blackhole, SMS NOT sent");
                tracing::warn!("An SMS was supposed to be sent but no SMS backend is configured");
            }

            SmsTransportInner::Twilio {
                client,
                account_sid,
                auth_token,
                from_number,
            } => {
                println!("[SMS] transport=twilio, sending SMS...");
                let url = format!(
                    "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
                );
                let credentials = BASE64.encode(format!("{account_sid}:{auth_token}"));

                let response = client
                    .post(&url)
                    .header("Authorization", format!("Basic {credentials}"))
                    .form(&[("To", to), ("From", from_number.as_str()), ("Body", body)])
                    .send()
                    .await?;

                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    println!("[SMS] twilio send FAILED: status={status}, body={body}");
                    return Err(SmsTransportError::ProviderError {
                        status: status.as_u16(),
                        body,
                    });
                }
                println!("[SMS] twilio send SUCCESS");
            }

            SmsTransportInner::HttpWebhook {
                client,
                url,
                api_key,
                from_number,
            } => {
                println!("[SMS] transport=http_webhook, sending SMS...");
                let payload = serde_json::json!({
                    "to": to,
                    "from": from_number,
                    "body": body,
                });

                let mut request = client.post(url.as_str()).json(&payload);

                if let Some(api_key) = api_key {
                    request = request.header("Authorization", format!("Bearer {api_key}"));
                }

                let response = request.send().await?;

                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    println!("[SMS] http_webhook send FAILED: status={status}, body={body}");
                    return Err(SmsTransportError::ProviderError {
                        status: status.as_u16(),
                        body,
                    });
                }
                println!("[SMS] http_webhook send SUCCESS");
            }
        }

        Ok(())
    }
}
