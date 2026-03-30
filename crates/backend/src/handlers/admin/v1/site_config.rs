use pasion_salvo_utils::InternalError;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Serialize;

use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::rest::DepotExt;

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, JsonSchema)]
pub struct SiteConfig {
    /// The Matrix server name for which this instance is configured
    server_name: String,

    /// Whether password login is enabled.
    pub password_login_enabled: bool,

    /// Whether password registration is enabled.
    pub password_registration_enabled: bool,

    /// Whether at least one contact method (email or phone) is required for
    /// password registrations.
    pub password_registration_contact_required: bool,

    /// Whether registration tokens are required for password registrations.
    pub registration_token_required: bool,

    /// Whether users can change their email.
    pub email_change_allowed: bool,

    /// Whether users can change their display name.
    pub displayname_change_allowed: bool,

    /// Whether users can change their password.
    pub password_change_allowed: bool,

    /// Whether users can recover their account via email.
    pub account_recovery_allowed: bool,

    /// Whether users can delete their own account.
    pub account_deactivation_allowed: bool,

    /// Whether CAPTCHA during registration is enabled.
    pub captcha_enabled: bool,

    /// Minimum password complexity, between 0 and 4.
    /// This is a score from zxcvbn.
    #[schemars(range(min = 0, max = 4))]
    pub minimum_password_complexity: u8,
}

#[handler]
#[tracing::instrument(name = "handler.admin.v1.site_config", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> Result<Json<SiteConfig>, InternalError> {
    let _call_context = extract_call_context(req, depot).await?;
    let site_config = depot.site_config()?;

    Ok(Json(SiteConfig {
        server_name: site_config.server_name,
        password_login_enabled: site_config.password_login_enabled,
        password_registration_enabled: site_config.password_registration_enabled,
        password_registration_contact_required: site_config.password_registration_contact_required,
        registration_token_required: site_config.registration_token_required,
        email_change_allowed: site_config.email_change_allowed,
        displayname_change_allowed: site_config.displayname_change_allowed,
        password_change_allowed: site_config.password_change_allowed,
        account_recovery_allowed: site_config.account_recovery_allowed,
        account_deactivation_allowed: site_config.account_deactivation_allowed,
        captcha_enabled: site_config.captcha.is_some(),
        minimum_password_complexity: site_config.minimum_password_complexity,
    }))
}
