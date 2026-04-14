use pasion_data::SiteConfig;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::Serialize;

use super::{DepotExt, RouteError};

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiteConfigResponse {
    pub id: Option<String>,
    pub email_change_allowed: bool,
    pub password_login_enabled: bool,
    pub account_deactivation_allowed: bool,
    pub display_name_change_allowed: bool,
    pub password_registration_enabled: bool,
    pub minimum_password_complexity: u8,
    pub imprint: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub plan_management_iframe_uri: Option<String>,
}

/// Build a [`SiteConfigResponse`] from the domain [`SiteConfig`].
pub fn from_site_config(config: &SiteConfig) -> SiteConfigResponse {
    SiteConfigResponse {
        id: Some("site_config".to_owned()),
        email_change_allowed: config.email_change_allowed,
        password_login_enabled: config.password_login_enabled,
        account_deactivation_allowed: config.account_deactivation_allowed,
        display_name_change_allowed: config.displayname_change_allowed,
        password_registration_enabled: config.password_registration_enabled,
        minimum_password_complexity: config.minimum_password_complexity,
        imprint: config.imprint.clone(),
        tos_uri: config.tos_uri.as_ref().map(|u| u.to_string()),
        policy_uri: config.policy_uri.as_ref().map(|u| u.to_string()),
        plan_management_iframe_uri: config.plan_management_iframe_uri.clone(),
    }
}

/// GET /api/v1/site-config
#[endpoint]
pub async fn get(depot: &Depot) -> Result<Json<SiteConfigResponse>, RouteError> {
    let config = depot.site_config()?;

    Ok(Json(from_site_config(&config)))
}
