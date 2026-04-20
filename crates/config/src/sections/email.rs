#![allow(deprecated)]

use std::{collections::BTreeMap, num::NonZeroU16, str::FromStr};

use lettre::message::Mailbox;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use url::Url;

use super::ConfigurationSection;

/// Wire encryption mode for the SMTP relay
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmailSmtpMode {
    /// Unencrypted connection
    Plain,
    /// Opportunistic upgrade (`STARTTLS`)
    StartTls,
    /// Implicit TLS from the start
    Tls,
}

/// SMTP relay delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SmtpEmailProviderConfig {
    /// SMTP connection encryption mode
    pub mode: EmailSmtpMode,

    /// SMTP relay hostname
    #[schemars(with = "crate::schema::Hostname")]
    pub hostname: String,

    /// SMTP relay port (defaults: 25 plain, 465 TLS, 587 STARTTLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: Option<NonZeroU16>,

    /// SMTP authentication username (must accompany `password`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// SMTP authentication password (must accompany `username`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

fn sendmail_command_default() -> String {
    "sendmail".to_owned()
}

fn resend_base_url_default() -> String {
    "https://api.resend.com".to_owned()
}

fn sendgrid_base_url_default() -> String {
    "https://api.sendgrid.com".to_owned()
}

fn brevo_base_url_default() -> String {
    "https://api.brevo.com".to_owned()
}

/// Sendmail delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SendmailEmailProviderConfig {
    /// Path to the sendmail-compatible binary
    #[serde(default = "sendmail_command_default")]
    pub command: String,
}

/// Generic HTTP email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct HttpWebhookEmailProviderConfig {
    /// API endpoint accepting outbound email requests
    pub url: String,

    /// Optional bearer token sent as `Authorization: Bearer ...`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Static headers to attach to every outbound request
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

/// Resend email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResendEmailProviderConfig {
    /// Resend API key
    pub api_key: String,

    /// Base URL for the Resend API
    #[serde(default = "resend_base_url_default")]
    pub base_url: String,
}

/// SendGrid email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SendgridEmailProviderConfig {
    /// SendGrid API key
    pub api_key: String,

    /// Base URL for the SendGrid API
    #[serde(default = "sendgrid_base_url_default")]
    pub base_url: String,
}

/// Twilio email API delivery settings.
///
/// Twilio email delivery is implemented via Twilio SendGrid's mail send API.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TwilioEmailProviderConfig {
    /// Twilio SendGrid API key
    pub api_key: String,

    /// Base URL for the Twilio SendGrid API
    #[serde(default = "sendgrid_base_url_default")]
    pub base_url: String,
}

/// Brevo transactional email API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BrevoEmailProviderConfig {
    /// Brevo API key
    pub api_key: String,

    /// Base URL for the Brevo API
    #[serde(default = "brevo_base_url_default")]
    pub base_url: String,
}

/// AWS SES API delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AwsSesEmailProviderConfig {
    /// AWS region that hosts the SES API endpoint
    pub region: String,

    /// AWS access key ID
    pub access_key_id: String,

    /// AWS secret access key
    pub secret_access_key: String,

    /// Optional AWS session token for temporary credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,

    /// Optional SES endpoint override, useful for proxies or AWS partitions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Optional SES configuration set name applied to every message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_set_name: Option<String>,
}

/// Which provider delivers outbound emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailProviderConfig {
    /// Silently discard all emails (useful for development)
    #[default]
    Blackhole,

    /// Relay through an SMTP server
    Smtp(SmtpEmailProviderConfig),

    /// Pipe through the local `sendmail` binary
    Sendmail(SendmailEmailProviderConfig),

    /// Submit email payloads to a generic HTTP endpoint
    HttpWebhook(HttpWebhookEmailProviderConfig),

    /// Deliver through the Resend email API
    Resend(ResendEmailProviderConfig),

    /// Deliver through the SendGrid email API
    Sendgrid(SendgridEmailProviderConfig),

    /// Deliver through Twilio SendGrid
    Twilio(TwilioEmailProviderConfig),

    /// Deliver through the Brevo transactional email API
    Brevo(BrevoEmailProviderConfig),

    /// Deliver through the AWS SES v2 email API
    AwsSes(AwsSesEmailProviderConfig),
}

const DEFAULT_FROM_ADDRESS: &str = r#""Authentication Service" <root@localhost>"#;

fn from_address_default() -> String {
    DEFAULT_FROM_ADDRESS.to_owned()
}

/// Outbound email delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    /// Envelope From / sender address
    #[serde(default = "from_address_default")]
    pub from: String,

    /// Reply-To header value
    #[serde(default = "from_address_default")]
    pub reply_to: String,

    /// Active email delivery provider
    #[serde(default)]
    pub provider: EmailProviderConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            from: from_address_default(),
            reply_to: from_address_default(),
            provider: EmailProviderConfig::Blackhole,
        }
    }
}

impl ConfigurationSection for EmailConfig {
    const PATH: &'static str = "email";

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

        let ensure_non_empty =
            |value: &str, field: &'static str| -> Result<(), figment::error::Error> {
                if value.trim().is_empty() {
                    return Err(error_on_field(
                        figment::error::Error::custom("value must not be empty"),
                        field,
                    ));
                }

                Ok(())
            };

        let ensure_valid_url =
            |value: &str, field: &'static str| -> Result<(), figment::error::Error> {
                Url::parse(value).map_err(|error| {
                    error_on_field(figment::error::Error::custom(error), field)
                })?;
                Ok(())
            };

        if let Err(error) = Mailbox::from_str(&self.from) {
            return Err(error_on_field(figment::error::Error::custom(error), "from").into());
        }

        if let Err(error) = Mailbox::from_str(&self.reply_to) {
            return Err(error_on_field(figment::error::Error::custom(error), "reply_to").into());
        }

        match &self.provider {
            EmailProviderConfig::Blackhole => {}

            EmailProviderConfig::Smtp(provider) => {
                match (provider.username.is_some(), provider.password.is_some()) {
                    (true, false) => {
                        return Err(error_on_field(
                            figment::error::Error::missing_field("password"),
                            "provider.password",
                        )
                        .into());
                    }
                    (false, true) => {
                        return Err(error_on_field(
                            figment::error::Error::missing_field("username"),
                            "provider.username",
                        )
                        .into());
                    }
                    _ => {}
                }
            }

            EmailProviderConfig::Sendmail(provider) => {
                ensure_non_empty(&provider.command, "provider.command")?;
            }

            EmailProviderConfig::HttpWebhook(provider) => {
                ensure_valid_url(&provider.url, "provider.url")?;
            }

            EmailProviderConfig::Resend(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
            }

            EmailProviderConfig::Sendgrid(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
            }

            EmailProviderConfig::Twilio(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
            }

            EmailProviderConfig::Brevo(provider) => {
                ensure_non_empty(&provider.api_key, "provider.api_key")?;
                ensure_valid_url(&provider.base_url, "provider.base_url")?;
            }

            EmailProviderConfig::AwsSes(provider) => {
                ensure_non_empty(&provider.region, "provider.region")?;
                ensure_non_empty(&provider.access_key_id, "provider.access_key_id")?;
                ensure_non_empty(&provider.secret_access_key, "provider.secret_access_key")?;

                if let Some(endpoint) = &provider.endpoint {
                    ensure_valid_url(endpoint, "provider.endpoint")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    #[test]
    fn load_smtp_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: smtp
                        mode: tls
                        hostname: smtp.example.com
                        port: 465
                        username: smtp-user
                        password: smtp-password
                "#,
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<EmailConfig>("email")?;

            assert_eq!(config.from, "Pasion <noreply@example.com>");
            match config.provider {
                EmailProviderConfig::Smtp(provider) => {
                    assert_eq!(provider.hostname, "smtp.example.com");
                    assert_eq!(provider.port.map(NonZeroU16::get), Some(465));
                }
                other => panic!("expected smtp provider, got {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn load_resend_provider_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: resend
                        api_key: re_test_123
                        base_url: https://api.resend.com
                "#,
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<EmailConfig>("email")?;

            match config.provider {
                EmailProviderConfig::Resend(provider) => {
                    assert_eq!(provider.api_key, "re_test_123");
                    assert_eq!(provider.base_url, "https://api.resend.com");
                }
                other => panic!("expected resend provider, got {other:?}"),
            }

            Ok(())
        });
    }

    #[test]
    fn reject_unpaired_smtp_credentials() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: smtp
                        mode: starttls
                        hostname: smtp.example.com
                        username: smtp-user
                "#,
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("password"));

            Ok(())
        });
    }

    #[test]
    fn reject_invalid_http_webhook_url() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: http_webhook
                        url: '::not-a-url::'
                "#,
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.url"));

            Ok(())
        });
    }

    #[test]
    fn reject_invalid_sendgrid_base_url() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: sendgrid
                        api_key: SG.test
                        base_url: '::not-a-url::'
                "#,
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.base_url"));

            Ok(())
        });
    }

    #[test]
    fn reject_empty_aws_ses_region() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                    email:
                      from: 'Pasion <noreply@example.com>'
                      reply_to: 'Support <support@example.com>'
                      provider:
                        type: aws_ses
                        region: ''
                        access_key_id: AKIATEST
                        secret_access_key: secret
                "#,
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<EmailConfig>("email")?;
            let error = config
                .validate(&figment)
                .expect_err("config should be invalid");

            assert!(error.to_string().contains("provider.region"));

            Ok(())
        });
    }
}
