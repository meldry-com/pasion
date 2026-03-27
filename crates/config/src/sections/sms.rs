//! Configuration related to sending SMS messages

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};

use super::ConfigurationSection;

/// What backend should be used when sending SMS messages
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SmsTransportKind {
    /// Don't send SMS anywhere
    #[default]
    Blackhole,

    /// Send SMS via Twilio
    Twilio,

    /// Send SMS via an HTTP webhook
    HttpWebhook,
}

/// Configuration related to sending SMS messages
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct SmsConfig {
    /// What backend should be used when sending SMS messages
    #[serde(default)]
    pub transport: SmsTransportKind,

    /// HTTP webhook transport: URL to send SMS requests to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,

    /// Twilio transport: Account SID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,

    /// Twilio transport: Auth token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    /// Phone number to send SMS from
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_number: Option<String>,

    /// HTTP webhook transport: API key for authorization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

impl SmsConfig {
    pub(crate) fn is_default(&self) -> bool {
        matches!(self.transport, SmsTransportKind::Blackhole)
            && self.api_url.is_none()
            && self.account_sid.is_none()
            && self.auth_token.is_none()
            && self.from_number.is_none()
            && self.api_key.is_none()
    }
}

impl ConfigurationSection for SmsConfig {
    const PATH: Option<&'static str> = Some("sms");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), field.to_owned()];
            error
        };

        let missing_field = |field: &'static str| {
            error_on_field(figment::error::Error::missing_field(field), field)
        };

        match self.transport {
            SmsTransportKind::Blackhole => {}

            SmsTransportKind::Twilio => {
                if self.account_sid.is_none() {
                    return Err(missing_field("account_sid").into());
                }

                if self.auth_token.is_none() {
                    return Err(missing_field("auth_token").into());
                }

                if self.from_number.is_none() {
                    return Err(missing_field("from_number").into());
                }
            }

            SmsTransportKind::HttpWebhook => {
                if self.api_url.is_none() {
                    return Err(missing_field("api_url").into());
                }

                if self.from_number.is_none() {
                    return Err(missing_field("from_number").into());
                }
            }
        }

        Ok(())
    }
}
