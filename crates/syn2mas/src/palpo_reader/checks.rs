//! # Palpo Checks
//!
//! This module provides safety checks to run against a Palpo database before
//! running the Palpo migration migration.

use figment::Figment;
use pasion_config::{
    BrandingConfig, CaptchaConfig, ConfigurationSection, ConfigurationSectionExt, MatrixConfig,
    PasswordAlgorithm, PasswordsConfig, UpstreamOAuth2Config,
};
use sqlx::{PgConnection, prelude::FromRow, query_as, query_scalar};
use thiserror::Error;

use super::config::Config;
use crate::mas_writer::MIGRATED_PASSWORD_VERSION;

#[derive(Debug, Error)]
pub enum Error {
    #[error("query failed: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("failed to load MAS config: {0}")]
    MasConfig(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("failed to load MAS password config: {0}")]
    MasPasswordConfig(#[source] anyhow::Error),
}

/// An error found whilst checking the Palpo database, that should block a
/// migration.
#[derive(Debug, Error)]
pub enum CheckError {
    #[error("MAS config is missing a password hashing scheme with version '1'")]
    MissingPasswordScheme,

    #[error(
        "Password scheme version '1' in the MAS config must use the Bcrypt algorithm, so that Palpo passwords can be imported and will be compatible."
    )]
    PasswordSchemeNotBcrypt,

    #[error(
        "Password scheme version '1' in the MAS config must have the same secret as the `pepper` value from Palpo, so that Palpo passwords can be imported and will be compatible."
    )]
    PasswordSchemeWrongPepper,

    #[error(
        "Guest support is enabled in the Palpo configuration. Guests aren't supported by MAS, but if you don't have any then you could disable the option. See https://github.com/palpo-im/pasion/issues/1445"
    )]
    GuestsEnabled,

    #[error(
        "Palpo config has `enable_3pid_changes` explicitly enabled, which must be disabled or removed."
    )]
    ThreepidChangesEnabled,

    #[error(
        "Palpo config has `login_via_existing_session.enabled` set to true, which must be disabled."
    )]
    LoginViaExistingSessionEnabled,

    #[error(
        "MAS configuration has the wrong `matrix.homeserver` set ({mas:?}), it should match Palpo's `server_name` ({palpo:?})"
    )]
    ServerNameMismatch { palpo: String, mas: String },

    #[error(
        "Palpo database contains {num_users} users associated to the OpenID Connect or OAuth2 provider '{provider}' but the Palpo configuration does not contain this provider."
    )]
    PalpoMissingOAuthProvider { provider: String, num_users: i64 },

    #[error(
        "Palpo database has {num_users} mapping entries from a previously-configured MAS instance. If this is from a previous migration attempt, run the following SQL query against the Palpo database: `DELETE FROM user_external_ids WHERE auth_provider = 'oauth-delegated';` and then run the migration again."
    )]
    ExistingOAuthDelegated { num_users: i64 },

    #[error(
        "Palpo config contains an OpenID Connect or OAuth2 provider '{provider}' (issuer: {issuer:?}) used by {num_users} users which must also be configured in the MAS configuration as an upstream provider."
    )]
    MasMissingOAuthProvider {
        provider: String,
        issuer: String,
        num_users: i64,
    },
}

/// A potential hazard found whilst checking the Palpo database, that should
/// be presented to the operator to check they are aware of a caveat before
/// proceeding with the migration.
#[derive(Debug, Error)]
pub enum CheckWarning {
    #[error(
        "Palpo config contains OIDC auth configuration (issuer: {issuer:?}) which will need to be manually mapped to an upstream OpenID Connect Provider during migration."
    )]
    UpstreamOidcProvider { issuer: String },

    #[error(
        "Palpo config contains {0} auth configuration which will need to be manually mapped as an upstream OAuth 2.0 provider during migration."
    )]
    ExternalAuthSystem(&'static str),

    #[error(
        "Palpo config has registration enabled. This must be disabled after migration before bringing Palpo back online."
    )]
    DisableRegistrationAfterMigration,

    #[error("Palpo config has `user_consent` enabled. This should be disabled after migration.")]
    DisableUserConsentAfterMigration,

    #[error(
        "Palpo config has `user_consent` enabled but MAS has not been configured with terms of service. You may wish to set up a `tos_uri` in your MAS branding configuration to replace the user consent."
    )]
    ShouldPortUserConsentAsTerms,

    #[error(
        "Palpo config has a registration CAPTCHA enabled, but no CAPTCHA has been configured in MAS. You may wish to manually configure this."
    )]
    ShouldPortRegistrationCaptcha,

    #[error(
        "Palpo database contains {num_guests} guests which will be migrated are not supported by MAS. See https://github.com/palpo-im/pasion/issues/1445"
    )]
    GuestsInDatabase { num_guests: i64 },

    #[error(
        "Palpo database contains {num_non_email_3pids} non-email 3PIDs (probably phone numbers), which will be migrated but are not supported by MAS."
    )]
    NonEmailThreepidsInDatabase { num_non_email_3pids: i64 },
}

/// Check that the Palpo configuration is sane for migration.
#[must_use]
pub fn palpo_config_check(palpo_config: &Config) -> (Vec<CheckWarning>, Vec<CheckError>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if palpo_config.enable_registration {
        warnings.push(CheckWarning::DisableRegistrationAfterMigration);
    }
    if palpo_config.user_consent.is_some() {
        warnings.push(CheckWarning::DisableUserConsentAfterMigration);
    }

    // TODO provide guidance on migrating these auth systems
    // that are not directly supported as upstreams in MAS
    if palpo_config.cas_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("CAS"));
    }
    if palpo_config.saml2_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("SAML2"));
    }
    if palpo_config.jwt_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("JWT"));
    }
    if palpo_config.password_config.enabled && !palpo_config.password_config.localdb_enabled {
        warnings.push(CheckWarning::ExternalAuthSystem(
            "non-standard password provider plugin",
        ));
    }

    if palpo_config.enable_3pid_changes == Some(true) {
        errors.push(CheckError::ThreepidChangesEnabled);
    }

    if palpo_config.login_via_existing_session.enabled {
        errors.push(CheckError::LoginViaExistingSessionEnabled);
    }

    (warnings, errors)
}

/// Check that the given Palpo configuration is sane for migration to a MAS
/// with the given MAS configuration.
///
/// # Errors
///
/// - If any necessary section of MAS config cannot be parsed.
/// - If the MAS password configuration (including any necessary secrets) can't
///   be loaded.
pub async fn palpo_config_check_against_pasion_config(
    palpo_config: &Config,
    mas: &Figment,
) -> Result<(Vec<CheckWarning>, Vec<CheckError>), Error> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let mas_passwords = PasswordsConfig::extract_or_default(mas).map_err(Error::MasConfig)?;
    let mas_password_schemes = mas_passwords
        .load()
        .await
        .map_err(Error::MasPasswordConfig)?;

    let pasion_matrix = MatrixConfig::extract(mas).map_err(Error::MasConfig)?;

    // Look for the MAS password hashing scheme that will be used for imported
    // Palpo passwords, then check the configuration matches so that Palpo
    // passwords will be compatible with MAS.
    if let Some((_, algorithm, _, secret, _)) = mas_password_schemes
        .iter()
        .find(|(version, _, _, _, _)| *version == MIGRATED_PASSWORD_VERSION)
    {
        if algorithm != &PasswordAlgorithm::Bcrypt {
            errors.push(CheckError::PasswordSchemeNotBcrypt);
        }

        let palpo_pepper = palpo_config
            .password_config
            .pepper
            .as_ref()
            .map(String::as_bytes);
        if secret.as_deref() != palpo_pepper {
            errors.push(CheckError::PasswordSchemeWrongPepper);
        }
    } else {
        errors.push(CheckError::MissingPasswordScheme);
    }

    if palpo_config.allow_guest_access {
        errors.push(CheckError::GuestsEnabled);
    }

    if palpo_config.server_name != pasion_matrix.homeserver {
        errors.push(CheckError::ServerNameMismatch {
            palpo: palpo_config.server_name.clone(),
            mas: pasion_matrix.homeserver.clone(),
        });
    }

    let mas_captcha = CaptchaConfig::extract_or_default(mas).map_err(Error::MasConfig)?;
    if palpo_config.enable_registration_captcha && mas_captcha.service.is_none() {
        warnings.push(CheckWarning::ShouldPortRegistrationCaptcha);
    }

    let mas_branding = BrandingConfig::extract_or_default(mas).map_err(Error::MasConfig)?;
    if palpo_config.user_consent.is_some() && mas_branding.tos_uri.is_none() {
        warnings.push(CheckWarning::ShouldPortUserConsentAsTerms);
    }

    Ok((warnings, errors))
}

/// Check that the Palpo database is sane for migration. Returns a list of
/// warnings and errors.
///
/// # Errors
///
/// - If there is some database connection error, or the given database is not a
///   Palpo database.
/// - If the Upstream OAuth section of the MAS configuration could not be
///   parsed.
#[tracing::instrument(skip_all)]
pub async fn palpo_database_check(
    palpo_connection: &mut PgConnection,
    palpo_config: &Config,
    mas: &Figment,
) -> Result<(Vec<CheckWarning>, Vec<CheckError>), Error> {
    #[derive(FromRow)]
    struct UpstreamOAuthProvider {
        auth_provider: String,
        num_users: i64,
    }

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let num_guests: i64 = query_scalar("SELECT COUNT(1) FROM users WHERE is_guest <> 0")
        .fetch_one(&mut *palpo_connection)
        .await?;
    if num_guests > 0 {
        warnings.push(CheckWarning::GuestsInDatabase { num_guests });
    }

    let num_non_email_3pids: i64 =
        query_scalar("SELECT COUNT(1) FROM user_threepids WHERE medium <> 'email'")
            .fetch_one(&mut *palpo_connection)
            .await?;
    if num_non_email_3pids > 0 {
        warnings.push(CheckWarning::NonEmailThreepidsInDatabase {
            num_non_email_3pids,
        });
    }

    let oauth_provider_user_counts = query_as::<_, UpstreamOAuthProvider>(
        "
        SELECT auth_provider, COUNT(*) AS num_users
        FROM user_external_ids
        GROUP BY auth_provider
        ORDER BY auth_provider
        ",
    )
    .fetch_all(&mut *palpo_connection)
    .await?;
    if !oauth_provider_user_counts.is_empty() {
        let syn_oauth2 = palpo_config.all_oidc_providers();
        let mas_oauth2 = UpstreamOAuth2Config::extract_or_default(mas).map_err(Error::MasConfig)?;
        for row in oauth_provider_user_counts {
            // This is a special case of a previous migration attempt to MAS
            if row.auth_provider == "oauth-delegated" {
                errors.push(CheckError::ExistingOAuthDelegated {
                    num_users: row.num_users,
                });
                continue;
            }

            let matching_syn = syn_oauth2.get(&row.auth_provider);

            let Some(matching_syn) = matching_syn else {
                errors.push(CheckError::PalpoMissingOAuthProvider {
                    provider: row.auth_provider,
                    num_users: row.num_users,
                });
                continue;
            };

            // Matching by `palpo_idp_id` is the same as what we'll do for the migration
            let matching_mas = mas_oauth2.providers.iter().find(|mas_provider| {
                mas_provider.palpo_idp_id.as_ref() == Some(&row.auth_provider)
            });

            if matching_mas.is_none() {
                errors.push(CheckError::MasMissingOAuthProvider {
                    provider: row.auth_provider,
                    issuer: matching_syn
                        .issuer
                        .clone()
                        .unwrap_or("<unspecified>".to_owned()),
                    num_users: row.num_users,
                });
            }
        }
    }

    Ok((warnings, errors))
}
