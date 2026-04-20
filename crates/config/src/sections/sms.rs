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

    /// Send SMS via Aliyun (阿里云短信)
    AliyunSms,

    /// Send SMS via Tencent Cloud (腾讯云短信)
    TencentCloudSms,

    /// Submit SMS payloads to Paloud's internal notification API
    PaloudInternal,
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

    /// Aliyun SMS transport: Access Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliyun_access_key_id: Option<String>,

    /// Aliyun SMS transport: Access Key Secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliyun_access_key_secret: Option<String>,

    /// Aliyun SMS transport: Sign name (签名)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliyun_sign_name: Option<String>,

    /// Aliyun SMS transport: Template code (模板编号)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliyun_template_code: Option<String>,

    /// Tencent Cloud SMS transport: Secret ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tencent_secret_id: Option<String>,

    /// Tencent Cloud SMS transport: Secret Key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tencent_secret_key: Option<String>,

    /// Tencent Cloud SMS transport: SDK App ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tencent_sdk_app_id: Option<String>,

    /// Tencent Cloud SMS transport: Sign name (签名)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tencent_sign_name: Option<String>,

    /// Tencent Cloud SMS transport: Template ID (模板 ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tencent_template_id: Option<String>,

    /// Paloud internal SMS transport: fully qualified dispatch endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paloud_internal_url: Option<String>,

    /// Shared key identifier sent in `X-Paloud-Key-Id`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paloud_internal_key_id: Option<String>,

    /// Shared secret used to sign the request with `HMAC-SHA256`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paloud_internal_secret: Option<String>,

    /// Optional workspace UUID or subdomain used for provider routing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paloud_internal_workspace: Option<String>,
}

impl SmsConfig {
    pub(crate) fn is_default(&self) -> bool {
        matches!(self.transport, SmsTransportKind::Blackhole)
            && self.api_url.is_none()
            && self.account_sid.is_none()
            && self.auth_token.is_none()
            && self.from_number.is_none()
            && self.api_key.is_none()
            && self.aliyun_access_key_id.is_none()
            && self.aliyun_access_key_secret.is_none()
            && self.aliyun_sign_name.is_none()
            && self.aliyun_template_code.is_none()
            && self.tencent_secret_id.is_none()
            && self.tencent_secret_key.is_none()
            && self.tencent_sdk_app_id.is_none()
            && self.tencent_sign_name.is_none()
            && self.tencent_template_id.is_none()
            && self.paloud_internal_url.is_none()
            && self.paloud_internal_key_id.is_none()
            && self.paloud_internal_secret.is_none()
            && self.paloud_internal_workspace.is_none()
    }
}

impl ConfigurationSection for SmsConfig {
    const PATH: &'static str = "sms";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH);

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.to_owned(), field.to_owned()];
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

            SmsTransportKind::AliyunSms => {
                if self.aliyun_access_key_id.is_none() {
                    return Err(missing_field("aliyun_access_key_id").into());
                }

                if self.aliyun_access_key_secret.is_none() {
                    return Err(missing_field("aliyun_access_key_secret").into());
                }

                if self.aliyun_sign_name.is_none() {
                    return Err(missing_field("aliyun_sign_name").into());
                }

                if self.aliyun_template_code.is_none() {
                    return Err(missing_field("aliyun_template_code").into());
                }
            }

            SmsTransportKind::TencentCloudSms => {
                if self.tencent_secret_id.is_none() {
                    return Err(missing_field("tencent_secret_id").into());
                }

                if self.tencent_secret_key.is_none() {
                    return Err(missing_field("tencent_secret_key").into());
                }

                if self.tencent_sdk_app_id.is_none() {
                    return Err(missing_field("tencent_sdk_app_id").into());
                }

                if self.tencent_sign_name.is_none() {
                    return Err(missing_field("tencent_sign_name").into());
                }

                if self.tencent_template_id.is_none() {
                    return Err(missing_field("tencent_template_id").into());
                }
            }

            SmsTransportKind::PaloudInternal => {
                if self.paloud_internal_url.is_none() {
                    return Err(missing_field("paloud_internal_url").into());
                }

                if self.paloud_internal_key_id.is_none() {
                    return Err(missing_field("paloud_internal_key_id").into());
                }

                if self.paloud_internal_secret.is_none() {
                    return Err(missing_field("paloud_internal_secret").into());
                }
            }
        }

        Ok(())
    }
}
