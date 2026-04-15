#![allow(deprecated)]

use std::{num::NonZeroU16, str::FromStr};

use lettre::message::Mailbox;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};

use super::ConfigurationSection;

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Credentials {
    /// SMTP login name
    pub username: String,
    /// SMTP password
    pub password: String,
}

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

/// Which transport delivers outbound emails
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum EmailTransportKind {
    /// Silently discard all emails (useful for development)
    #[default]
    Blackhole,
    /// Relay through an SMTP server
    Smtp,
    /// Pipe through the local `sendmail` binary
    Sendmail,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_FROM_ADDRESS: &str = r#""Authentication Service" <root@localhost>"#;

fn from_address_default() -> String {
    DEFAULT_FROM_ADDRESS.to_owned()
}

#[allow(clippy::unnecessary_wraps)]
fn sendmail_binary_default() -> Option<String> {
    Some("sendmail".to_owned())
}

// ---------------------------------------------------------------------------
// Main struct
// ---------------------------------------------------------------------------

/// Outbound email delivery settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    /// Envelope From / sender address
    #[serde(default = "from_address_default")]
    #[schemars(email)]
    pub from: String,

    /// Reply-To header value
    #[serde(default = "from_address_default")]
    #[schemars(email)]
    pub reply_to: String,

    /// Transport backend selection
    transport: EmailTransportKind,

    /// SMTP: connection encryption mode
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<EmailSmtpMode>,

    /// SMTP: relay hostname
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<crate::schema::Hostname>")]
    hostname: Option<String>,

    /// SMTP: relay port (defaults: 25 plain, 465 TLS, 587 STARTTLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    port: Option<NonZeroU16>,

    /// SMTP: authentication username (must accompany `password`)
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,

    /// SMTP: authentication password (must accompany `username`)
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,

    /// Sendmail: path to the sendmail-compatible binary
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default = "sendmail_binary_default")]
    command: Option<String>,
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

impl EmailConfig {
    /// Active transport backend
    #[must_use]
    pub fn transport(&self) -> EmailTransportKind {
        self.transport
    }

    /// SMTP encryption mode, if configured
    #[must_use]
    pub fn mode(&self) -> Option<EmailSmtpMode> {
        self.mode
    }

    /// SMTP relay hostname, if configured
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// SMTP port override, if configured
    #[must_use]
    pub fn port(&self) -> Option<NonZeroU16> {
        self.port
    }

    /// SMTP authentication username
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// SMTP authentication password
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Sendmail binary path
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            from: from_address_default(),
            reply_to: from_address_default(),
            transport: EmailTransportKind::Blackhole,
            mode: None,
            hostname: None,
            port: None,
            username: None,
            password: None,
            command: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl ConfigurationSection for EmailConfig {
    const PATH: &'static str = "email";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let meta = figment.find_metadata(Self::PATH);

        let field_error = |mut e: figment::error::Error, field: &'static str| {
            e.metadata = meta.cloned();
            e.profile = Some(figment::Profile::Default);
            e.path = vec![Self::PATH.to_owned(), field.to_owned()];
            e
        };

        let require =
            |field: &'static str| field_error(figment::error::Error::missing_field(field), field);

        let reject = |field: &'static str, allowed: &'static [&'static str]| {
            field_error(figment::error::Error::unknown_field(field, allowed), field)
        };

        match self.transport {
            EmailTransportKind::Blackhole => { /* nothing to check */ }

            EmailTransportKind::Smtp => {
                // Validate sender addresses
                if let Err(e) = Mailbox::from_str(&self.from) {
                    return Err(field_error(figment::error::Error::custom(e), "from").into());
                }
                if let Err(e) = Mailbox::from_str(&self.reply_to) {
                    return Err(field_error(figment::error::Error::custom(e), "reply_to").into());
                }

                // Username and password must be paired
                match (self.username.is_some(), self.password.is_some()) {
                    (true, false) => return Err(require("password").into()),
                    (false, true) => return Err(require("username").into()),
                    _ => {}
                }

                if self.mode.is_none() {
                    return Err(require("mode").into());
                }
                if self.hostname.is_none() {
                    return Err(require("hostname").into());
                }
                if self.command.is_some() {
                    return Err(reject(
                        "command",
                        &[
                            "from",
                            "reply_to",
                            "transport",
                            "mode",
                            "hostname",
                            "port",
                            "username",
                            "password",
                        ],
                    )
                    .into());
                }
            }

            EmailTransportKind::Sendmail => {
                const ALLOWED: &[&str] = &["from", "reply_to", "transport", "command"];

                if let Err(e) = Mailbox::from_str(&self.from) {
                    return Err(field_error(figment::error::Error::custom(e), "from").into());
                }
                if let Err(e) = Mailbox::from_str(&self.reply_to) {
                    return Err(field_error(figment::error::Error::custom(e), "reply_to").into());
                }

                if self.command.is_none() {
                    return Err(require("command").into());
                }
                for (flag, name) in [
                    (self.mode.is_some(), "mode"),
                    (self.hostname.is_some(), "hostname"),
                    (self.port.is_some(), "port"),
                    (self.username.is_some(), "username"),
                    (self.password.is_some(), "password"),
                ] {
                    if flag {
                        return Err(reject(name, ALLOWED).into());
                    }
                }
            }
        }

        Ok(())
    }
}
