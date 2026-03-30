use serde::{Deserialize, Serialize};

use crate::traits::*;

/// Actions parameters as defined by MSC4191
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AccountAction {
    #[serde(rename = "org.matrix.profile")]
    OrgMatrixProfile,
    #[serde(rename = "profile")]
    Profile,

    #[serde(rename = "org.matrix.devices_list")]
    OrgMatrixDevicesList,
    #[serde(rename = "org.matrix.sessions_list")]
    OrgMatrixSessionsList,
    #[serde(rename = "sessions_list")]
    SessionsList,

    #[serde(rename = "org.matrix.device_view")]
    OrgMatrixDeviceView { device_id: String },
    #[serde(rename = "org.matrix.session_view")]
    OrgMatrixSessionView { device_id: String },
    #[serde(rename = "session_view")]
    SessionView { device_id: String },

    #[serde(rename = "org.matrix.device_delete")]
    OrgMatrixDeviceDelete { device_id: String },
    #[serde(rename = "org.matrix.session_end")]
    OrgMatrixSessionEnd { device_id: String },
    #[serde(rename = "session_end")]
    SessionEnd { device_id: String },

    #[serde(rename = "org.matrix.cross_signing_reset")]
    OrgMatrixCrossSigningReset,
}

/// `GET /account/`
#[derive(Default, Debug, Clone)]
pub struct Account {
    action: Option<AccountAction>,
}

impl Account {
    #[must_use]
    pub const fn new(action: Option<AccountAction>) -> Self {
        Self { action }
    }
}

impl Route for Account {
    type Query = AccountAction;

    fn route() -> &'static str {
        "/account/"
    }

    fn query(&self) -> Option<&Self::Query> {
        self.action.as_ref()
    }
}

/// `GET /account/*`
#[derive(Default, Debug, Clone)]
pub struct AccountWildcard;

impl SimpleRoute for AccountWildcard {
    const PATH: &'static str = "/account/{*rest}";
}

/// `GET /account/password/change`
///
/// Handled by the React frontend; this struct definition is purely for
/// redirects.
#[derive(Default, Debug, Clone)]
pub struct AccountPasswordChange;

impl SimpleRoute for AccountPasswordChange {
    const PATH: &'static str = "/account/password/change";
}
