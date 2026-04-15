//! SMS transport backends

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;
use thiserror::Error;
use url::Url;

use super::{aliyun::AliyunSmsTransport, tencent::TencentSmsTransport};

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
    AliyunSms(AliyunSmsTransport),
    TencentCloudSms(TencentSmsTransport),
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

    /// Construct an Aliyun SMS transport
    #[must_use]
    pub fn aliyun(
        access_key_id: String,
        access_key_secret: String,
        sign_name: String,
        template_code: String,
    ) -> Self {
        Self::new(SmsTransportInner::AliyunSms(AliyunSmsTransport {
            client: Client::new(),
            access_key_id,
            access_key_secret,
            sign_name,
            template_code,
        }))
    }

    /// Construct a Tencent Cloud SMS transport
    #[must_use]
    pub fn tencent_cloud(
        secret_id: String,
        secret_key: String,
        sdk_app_id: String,
        sign_name: String,
        template_id: String,
    ) -> Self {
        Self::new(SmsTransportInner::TencentCloudSms(TencentSmsTransport {
            client: Client::new(),
            secret_id,
            secret_key,
            sdk_app_id,
            sign_name,
            template_id,
        }))
    }

    /// Returns `true` if this transport is the Aliyun SMS backend
    #[must_use]
    pub fn is_aliyun(&self) -> bool {
        matches!(self.inner.as_ref(), SmsTransportInner::AliyunSms(_))
    }

    /// Returns `true` if this transport is the Tencent Cloud SMS backend
    #[must_use]
    pub fn is_tencent_cloud(&self) -> bool {
        matches!(self.inner.as_ref(), SmsTransportInner::TencentCloudSms(_))
    }

    /// Return the stable provider binding key for this transport.
    #[must_use]
    pub fn binding_key(&self) -> &'static str {
        match self.inner.as_ref() {
            SmsTransportInner::Blackhole => "sms.blackhole",
            SmsTransportInner::Twilio { .. } => "sms.twilio",
            SmsTransportInner::HttpWebhook { .. } => "sms.http_webhook",
            SmsTransportInner::AliyunSms(_) => "sms.aliyun",
            SmsTransportInner::TencentCloudSms(_) => "sms.tencent_cloud",
        }
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

            SmsTransportInner::AliyunSms(transport) => {
                println!("[SMS] transport=aliyun, sending SMS...");
                // Parse body as template params: try JSON first, fall back to
                // {"code": body}
                let params: std::collections::HashMap<String, String> = serde_json::from_str(body)
                    .unwrap_or_else(|_| {
                        let mut m = std::collections::HashMap::new();
                        m.insert("code".to_owned(), body.to_owned());
                        m
                    });
                transport.send(to, &params).await?;
                println!("[SMS] aliyun send SUCCESS");
            }

            SmsTransportInner::TencentCloudSms(transport) => {
                println!("[SMS] transport=tencent_cloud, sending SMS...");
                // Parse body as template params: try JSON array first, fall
                // back to [body]
                let params: Vec<String> =
                    serde_json::from_str(body).unwrap_or_else(|_| vec![body.to_owned()]);
                transport.send(to, &params).await?;
                println!("[SMS] tencent_cloud send SUCCESS");
            }
        }

        Ok(())
    }
}
