mod account;
mod auth;
mod oauth2;
mod system;
mod upstream;

pub use self::account::*;
pub use self::auth::*;
pub use self::oauth2::*;
pub use self::system::*;
pub use self::upstream::*;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::UrlBuilder;
pub use crate::traits::*;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PostAuthAction {
    ContinueAuthorizationGrant {
        id: Ulid,
    },
    ContinueDeviceCodeGrant {
        id: Ulid,
    },
    ChangePassword,
    LinkUpstream {
        id: Ulid,
    },
    ManageAccount {
        #[serde(flatten)]
        action: Option<AccountAction>,
    },
}

impl PostAuthAction {
    #[must_use]
    pub const fn continue_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueAuthorizationGrant { id }
    }

    #[must_use]
    pub const fn continue_device_code_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueDeviceCodeGrant { id }
    }

    #[must_use]
    pub const fn link_upstream(id: Ulid) -> Self {
        PostAuthAction::LinkUpstream { id }
    }

    #[must_use]
    pub const fn manage_account(action: Option<AccountAction>) -> Self {
        PostAuthAction::ManageAccount { action }
    }
}

// --- Redirect helper ---
//
// `go_next` is an HTTP-layer convenience that translates a `PostAuthAction`
// into a Salvo redirect response.  It lives in a separate `impl` block to
// make it clear this is *not* part of the core data-type definition — it
// couples the enum to the URL layer and specific endpoint types.

impl PostAuthAction {
    /// Produce a redirect response that sends the user to whichever page
    /// corresponds to this post-authentication action.
    pub fn go_next(&self, url_builder: &UrlBuilder) -> salvo::writing::Redirect {
        match self {
            Self::ContinueAuthorizationGrant { id } => url_builder.redirect(&Consent(*id)),
            Self::ContinueDeviceCodeGrant { id } => {
                url_builder.redirect(&DeviceCodeConsent::new(*id))
            }
            Self::ChangePassword => url_builder.redirect(&AccountPasswordChange),
            Self::LinkUpstream { id } => url_builder.redirect(&UpstreamOAuth2Link::new(*id)),
            Self::ManageAccount { action } => {
                url_builder.redirect(&Account::new(action.clone()))
            }
        }
    }
}
