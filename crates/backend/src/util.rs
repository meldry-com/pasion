use std::{sync::Arc, time::Duration};

use crate::handlers::passwords::PasswordManager;
use anyhow::Context;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use pasion_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, DatabaseConfig, EmailConfig, EmailSmtpMode,
    EmailTransportKind, ExperimentalConfig, HomeserverKind, MatrixConfig, PasswordsConfig,
    PolicyConfig, PolicyEngine, SmsConfig, SmsTransportKind, TemplatesConfig,
};
use pasion_data::UrlBuilder;
use pasion_data::{BoxRepositoryFactory, RepositoryAccess, RepositoryFactory};
use pasion_data::{SessionExpirationConfig, SessionLimitConfig, SiteConfig};
use pasion_matrix::{ConnectorRegistry, HomeserverConnection, ReadOnlyHomeserverConnection};
use pasion_matrix_palpo::PalpoConnection;
use pasion_messaging::{MailTransport, Mailer, NotificationCenter, SmsSender, SmsTransport};
use pasion_policy::PolicyFactory;
use pasion_templates::{SiteConfigExt, Templates};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;

/// Check whether `c` is a valid character for a username.
fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

/// Check whether `username` is a valid username.
///
/// Usernames must be non-empty, at most 255 characters, must not start with
/// an underscore, and may only contain lowercase ASCII letters, digits, and
/// the characters `= _ - . / +`.
pub fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    if !config.enabled() {
        return Ok(PasswordManager::disabled());
    }

    let schemes = config.load().await?.into_iter().map(
        |(version, algorithm, cost, secret, unicode_normalization)| {
            use crate::handlers::passwords::Hasher;
            let hasher = match algorithm {
                pasion_config::PasswordAlgorithm::Pbkdf2 => {
                    Hasher::pbkdf2(secret, unicode_normalization)
                }
                pasion_config::PasswordAlgorithm::Bcrypt => {
                    Hasher::bcrypt(cost, secret, unicode_normalization)
                }
                pasion_config::PasswordAlgorithm::Argon2id => {
                    Hasher::argon2id(secret, unicode_normalization)
                }
            };

            (version, hasher)
        },
    );

    PasswordManager::new(config.minimum_complexity(), schemes)
}

pub fn mailer_from_config(
    config: &EmailConfig,
    templates: &Templates,
) -> Result<Mailer, anyhow::Error> {
    let from = config
        .from
        .parse()
        .context("invalid email configuration: invalid 'from' address")?;
    let reply_to = config
        .reply_to
        .parse()
        .context("invalid email configuration: invalid 'reply_to' address")?;
    let transport = match config.transport() {
        EmailTransportKind::Blackhole => MailTransport::blackhole(),
        EmailTransportKind::Smtp => {
            // This should have been set ahead of time
            let hostname = config
                .hostname()
                .context("invalid email configuration: missing hostname")?;

            let mode = config
                .mode()
                .context("invalid email configuration: missing mode")?;

            let credentials = match (config.username(), config.password()) {
                (Some(username), Some(password)) => Some(pasion_messaging::SmtpCredentials::new(
                    username.to_owned(),
                    password.to_owned(),
                )),
                (None, None) => None,
                _ => {
                    anyhow::bail!("invalid email configuration: missing username or password");
                }
            };

            let mode = match mode {
                EmailSmtpMode::Plain => pasion_messaging::SmtpMode::Plain,
                EmailSmtpMode::StartTls => pasion_messaging::SmtpMode::StartTls,
                EmailSmtpMode::Tls => pasion_messaging::SmtpMode::Tls,
            };

            MailTransport::smtp(mode, hostname, config.port(), credentials)
                .context("failed to build SMTP transport")?
        }
        EmailTransportKind::Sendmail => MailTransport::sendmail(config.command()),
    };

    Ok(Mailer::new(templates.clone(), transport, from, reply_to))
}

pub fn sms_sender_from_config(config: &SmsConfig) -> Result<SmsSender, anyhow::Error> {
    let transport = match config.transport {
        SmsTransportKind::Blackhole => SmsTransport::blackhole(),
        SmsTransportKind::Twilio => SmsTransport::twilio(
            config
                .account_sid
                .clone()
                .context("invalid sms configuration: missing account_sid")?,
            config
                .auth_token
                .clone()
                .context("invalid sms configuration: missing auth_token")?,
            config
                .from_number
                .clone()
                .context("invalid sms configuration: missing from_number")?,
        ),
        SmsTransportKind::HttpWebhook => SmsTransport::http_webhook(
            config
                .api_url
                .as_deref()
                .context("invalid sms configuration: missing api_url")?
                .parse()
                .context("invalid sms configuration: invalid api_url")?,
            config.api_key.clone(),
            config
                .from_number
                .clone()
                .context("invalid sms configuration: missing from_number")?,
        ),
        SmsTransportKind::AliyunSms => SmsTransport::aliyun(
            config
                .aliyun_access_key_id
                .clone()
                .context("invalid sms configuration: missing aliyun_access_key_id")?,
            config
                .aliyun_access_key_secret
                .clone()
                .context("invalid sms configuration: missing aliyun_access_key_secret")?,
            config
                .aliyun_sign_name
                .clone()
                .context("invalid sms configuration: missing aliyun_sign_name")?,
            config
                .aliyun_template_code
                .clone()
                .context("invalid sms configuration: missing aliyun_template_code")?,
        ),
        SmsTransportKind::TencentCloudSms => SmsTransport::tencent_cloud(
            config
                .tencent_secret_id
                .clone()
                .context("invalid sms configuration: missing tencent_secret_id")?,
            config
                .tencent_secret_key
                .clone()
                .context("invalid sms configuration: missing tencent_secret_key")?,
            config
                .tencent_sdk_app_id
                .clone()
                .context("invalid sms configuration: missing tencent_sdk_app_id")?,
            config
                .tencent_sign_name
                .clone()
                .context("invalid sms configuration: missing tencent_sign_name")?,
            config
                .tencent_template_id
                .clone()
                .context("invalid sms configuration: missing tencent_template_id")?,
        ),
    };

    Ok(SmsSender::new(transport))
}

pub fn notification_center_from_config(
    email_config: &EmailConfig,
    sms_config: &SmsConfig,
    templates: &Templates,
) -> Result<NotificationCenter, anyhow::Error> {
    let mailer = mailer_from_config(email_config, templates)?;
    let sms = sms_sender_from_config(sms_config)?;
    Ok(NotificationCenter::email_only(mailer).with_sms(sms))
}

/// Test the connection to the mailer in a background task
pub fn test_mailer_in_background(mailer: &Mailer, timeout: Duration) {
    let mailer = mailer.clone();

    let span = tracing::info_span!("cli.test_mailer");
    tokio::spawn(async move {
        match tokio::time::timeout(timeout, mailer.test_connection()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    error = &err as &dyn std::error::Error,
                    "Could not connect to the mail backend, tasks sending mails may fail!"
                );
            }
            Err(_) => {
                tracing::warn!("Timed out while testing the mail backend connection, tasks sending mails may fail!");
            }
        }
    }
    .instrument(span));
}

pub async fn policy_factory_from_config(
    config: &PolicyConfig,
    matrix_config: &MatrixConfig,
    experimental_config: &ExperimentalConfig,
) -> Result<PolicyFactory, anyhow::Error> {
    match config.engine {
        PolicyEngine::Opa => {
            let policy_file = tokio::fs::File::open(&config.wasm_module)
                .await
                .context("failed to open OPA WASM policy file")?;

            let entrypoints = pasion_policy::Entrypoints {
                register: config.register_entrypoint.clone(),
                client_registration: config.client_registration_entrypoint.clone(),
                authorization_grant: config.authorization_grant_entrypoint.clone(),
                email: config.email_entrypoint.clone(),
            };

            let session_limit_config =
                experimental_config
                    .session_limit
                    .as_ref()
                    .map(|c| SessionLimitConfig {
                        soft_limit: c.soft_limit,
                        hard_limit: c.hard_limit,
                    });

            let data =
                pasion_policy::Data::new(matrix_config.homeserver.clone(), session_limit_config)
                    .with_rest(config.data.clone());

            PolicyFactory::load(policy_file, data, entrypoints)
                .await
                .context("failed to load the OPA policy")
        }

        PolicyEngine::Cedar => {
            #[cfg(feature = "cedar")]
            {
                let path = config
                    .cedar_policy_file
                    .as_ref()
                    .context("cedar_policy_file must be set when using the Cedar engine")?;
                PolicyFactory::load_cedar_from_file(path.as_str())
                    .await
                    .context("failed to load Cedar policy")
            }

            #[cfg(not(feature = "cedar"))]
            anyhow::bail!(
                "Cedar policy engine is not available. \
                 Recompile with the `cedar` feature to enable it."
            )
        }

        PolicyEngine::Remote => {
            #[cfg(feature = "remote")]
            {
                let endpoint = config
                    .remote_endpoint
                    .as_ref()
                    .context("remote_endpoint must be set when using the Remote engine")?;
                let client = reqwest::Client::new();
                PolicyFactory::load_remote(endpoint.clone(), client)
                    .context("failed to create remote policy factory")
            }

            #[cfg(not(feature = "remote"))]
            anyhow::bail!(
                "Remote policy engine is not available. \
                 Recompile with the `remote` feature to enable it."
            )
        }
    }
}

pub fn captcha_config_from_config(
    captcha_config: &CaptchaConfig,
) -> Result<Option<pasion_data::CaptchaConfig>, anyhow::Error> {
    let Some(service) = captcha_config.service else {
        return Ok(None);
    };

    let service = match service {
        pasion_config::CaptchaServiceKind::RecaptchaV2 => pasion_data::CaptchaService::RecaptchaV2,
        pasion_config::CaptchaServiceKind::CloudflareTurnstile => {
            pasion_data::CaptchaService::CloudflareTurnstile
        }
        pasion_config::CaptchaServiceKind::HCaptcha => pasion_data::CaptchaService::HCaptcha,
    };

    Ok(Some(pasion_data::CaptchaConfig {
        service,
        site_key: captcha_config
            .site_key
            .clone()
            .context("missing site key")?,
        secret_key: captcha_config
            .secret_key
            .clone()
            .context("missing secret key")?,
    }))
}

pub fn site_config_from_config(
    branding_config: &BrandingConfig,
    matrix_config: &MatrixConfig,
    experimental_config: &ExperimentalConfig,
    password_config: &PasswordsConfig,
    account_config: &AccountConfig,
    captcha_config: &CaptchaConfig,
) -> Result<SiteConfig, anyhow::Error> {
    let captcha = captcha_config_from_config(captcha_config)?;
    let session_expiration = experimental_config
        .inactive_session_expiration
        .as_ref()
        .map(|c| SessionExpirationConfig {
            oauth_session_inactivity_ttl: c.expire_oauth_sessions.then_some(c.ttl),
            user_session_inactivity_ttl: c.expire_user_sessions.then_some(c.ttl),
        });

    Ok(SiteConfig {
        access_token_ttl: experimental_config.access_token_ttl,
        server_name: matrix_config.homeserver.clone(),
        policy_uri: branding_config.policy_uri.clone(),
        tos_uri: branding_config.tos_uri.clone(),
        imprint: branding_config.imprint.clone(),
        password_login_enabled: password_config.enabled(),
        password_registration_enabled: password_config.enabled()
            && account_config.password_registration_enabled,
        password_registration_contact_required: account_config
            .password_registration_contact_required,
        registration_token_required: account_config.registration_token_required,
        email_change_allowed: account_config.email_change_allowed,
        displayname_change_allowed: account_config.displayname_change_allowed,
        password_change_allowed: password_config.enabled()
            && account_config.password_change_allowed,
        account_recovery_allowed: password_config.enabled()
            && account_config.password_recovery_enabled,
        account_deactivation_allowed: account_config.account_deactivation_allowed,
        captcha,
        minimum_password_complexity: password_config.minimum_complexity(),
        session_expiration,
        login_with_email_allowed: account_config.login_with_email_allowed,
        plan_management_iframe_uri: experimental_config.plan_management_iframe_uri.clone(),
        session_limit: experimental_config
            .session_limit
            .as_ref()
            .map(|c| SessionLimitConfig {
                soft_limit: c.soft_limit,
                hard_limit: c.hard_limit,
            }),
        flow_engine_enabled: false,
    })
}

pub async fn templates_from_config(
    config: &TemplatesConfig,
    site_config: &SiteConfig,
    url_builder: &UrlBuilder,
    strict: bool,
) -> Result<Templates, anyhow::Error> {
    Templates::load(
        config.path.clone(),
        url_builder.clone(),
        config.translations_path.clone(),
        site_config.templates_branding(),
        site_config.templates_features(),
        strict,
    )
    .await
    .with_context(|| format!("Failed to load the templates at {}", config.path))
}

/// Build a connection string from the [`DatabaseConfig`] for use with diesel-async.
///
/// This mirrors the logic from [`database_connect_options_from_config`] but
/// produces a plain URL string suitable for
/// [`AsyncDieselConnectionManager`].
pub fn database_url_from_config(config: &DatabaseConfig) -> Result<String, anyhow::Error> {
    if let Some(uri) = config.uri.as_deref() {
        return Ok(uri.to_owned());
    }

    let mut url = String::from("postgres://");
    if let Some(username) = config.username.as_deref() {
        url.push_str(username);
        if let Some(password) = config.password.as_deref() {
            url.push(':');
            url.push_str(password);
        }
        url.push('@');
    }
    if let Some(host) = config.host.as_deref() {
        url.push_str(host);
    } else {
        url.push_str("localhost");
    }
    if let Some(port) = config.port {
        url.push(':');
        url.push_str(&port.to_string());
    }
    if let Some(database) = config.database.as_deref() {
        url.push('/');
        url.push_str(database);
    }
    url.push_str("?application_name=pasion");

    Ok(url)
}

/// Create a diesel-async deadpool connection pool from the configuration.
///
/// This pool is used by [`PgRepositoryFactory`] for all non-migration
/// database access.
#[tracing::instrument(name = "db.connect.diesel", skip_all)]
pub async fn diesel_pool_from_config(
    config: &DatabaseConfig,
) -> Result<DieselPool<AsyncPgConnection>, anyhow::Error> {
    let url = database_url_from_config(config)?;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = DieselPool::builder(manager)
        .max_size(config.max_connections.get() as usize)
        .wait_timeout(Some(config.connect_timeout))
        .create_timeout(Some(config.connect_timeout))
        .recycle_timeout(Some(std::time::Duration::from_secs(5)))
        .runtime(deadpool::Runtime::Tokio1)
        .build()
        .context("could not build diesel connection pool")?;
    Ok(pool)
}

/// Update the policy factory dynamic data from the database and spawn a task to
/// periodically update it
// XXX: this could be put somewhere else?
pub async fn load_policy_factory_dynamic_data_continuously(
    policy_factory: &Arc<PolicyFactory>,
    repository_factory: BoxRepositoryFactory,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), anyhow::Error> {
    let policy_factory = policy_factory.clone();

    load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await?;

    task_tracker.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => {
                    return;
                }
                _ = interval.tick() => {}
            }

            if let Err(err) =
                load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await
            {
                tracing::error!(
                    error = ?err,
                    "Failed to load policy factory dynamic data"
                );
                cancellation_token.cancel();
                return;
            }
        }
    });

    Ok(())
}

/// Update the policy factory dynamic data from the database
#[tracing::instrument(name = "policy.load_dynamic_data", skip_all)]
pub async fn load_policy_factory_dynamic_data(
    policy_factory: &PolicyFactory,
    repository_factory: &(dyn RepositoryFactory + Send + Sync),
) -> Result<(), anyhow::Error> {
    let mut repo = repository_factory
        .create()
        .await
        .context("Failed to acquire database connection")?;

    if let Some(data) = repo.policy_data().get().await? {
        let id = data.id;
        let updated = policy_factory.set_dynamic_data(data).await?;
        if updated {
            tracing::info!(policy_data.id = %id, "Loaded dynamic policy data from the database");
        }
    }

    Ok(())
}

/// Create a clonable, type-erased [`HomeserverConnection`] and a
/// [`ConnectorRegistry`] from the configuration.
///
/// The returned registry contains the connector as its primary provider,
/// while the `Arc<dyn HomeserverConnection>` is kept for backward
/// compatibility with code that accesses the homeserver directly.
pub async fn homeserver_connection_from_config(
    config: &MatrixConfig,
    http_client: reqwest::Client,
) -> anyhow::Result<(Arc<dyn HomeserverConnection>, ConnectorRegistry)> {
    let mut registry = ConnectorRegistry::new();

    Ok(match config.kind {
        HomeserverKind::Palpo | HomeserverKind::PalpoModern => {
            let palpo = Arc::new(PalpoConnection::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            ));
            registry.register(Arc::clone(&palpo) as _);
            (palpo as Arc<dyn HomeserverConnection>, registry)
        }
        HomeserverKind::PalpoReadOnly => {
            let connection = PalpoConnection::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            );
            let readonly = Arc::new(ReadOnlyHomeserverConnection::new(connection));
            registry.register(Arc::clone(&readonly) as _);
            (readonly as Arc<dyn HomeserverConnection>, registry)
        }
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use zeroize::Zeroizing;

    use super::*;

    #[tokio::test]
    async fn test_password_manager_from_config() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new("hunter2".to_owned());

        // Test a valid, enabled config
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 10,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(manager.is_enabled());
        let hashed = manager.hash(&mut rng, password.clone()).await;
        assert!(hashed.is_ok());
        let (version, hashed) = hashed.unwrap();
        assert_eq!(version, 42);
        assert!(hashed.starts_with("$argon2id$"));

        // Test a valid, disabled config
        let config = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "schemes": []
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(!manager.is_enabled());
        let res = manager.hash(&mut rng, password.clone()).await;
        assert!(res.is_err());

        // Test an invalid config
        // Repeat the same version twice
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 42,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());

        // Empty schemes
        let config = serde_json::from_value(serde_json::json!({
            "schemes": []
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());
    }
}
