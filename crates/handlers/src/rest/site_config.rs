use salvo::prelude::*;
use serde::Serialize;

use super::{RouteError, get_site_config};

#[derive(Serialize)]
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

/// GET /api/v1/site-config
#[handler]
pub async fn get(depot: &Depot) -> Result<Json<SiteConfigResponse>, RouteError> {
    let config = get_site_config(depot)?;

    Ok(Json(SiteConfigResponse {
        id: Some("site_config".to_owned()),
        email_change_allowed: config.email_change_allowed,
        password_login_enabled: config.password_login_enabled,
        account_deactivation_allowed: config.account_deactivation_allowed,
        display_name_change_allowed: config.displayname_change_allowed,
        password_registration_enabled: config.password_registration_enabled,
        minimum_password_complexity: config.minimum_password_complexity,
        imprint: config.imprint,
        tos_uri: config.tos_uri.as_ref().map(|u| u.to_string()),
        policy_uri: config.policy_uri.as_ref().map(|u| u.to_string()),
        plan_management_iframe_uri: config.plan_management_iframe_uri,
    }))
}
