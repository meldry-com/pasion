pub mod account;
pub mod account_settings;
pub mod browser_sessions;
pub mod client_detail;
pub mod device_redirect;
pub mod email_in_use;
pub mod email_verify;
pub mod password_change;
pub mod password_change_success;
pub mod password_recovery;
pub mod plan;
pub mod reset_cross_signing;
pub mod session_detail;
pub mod sessions;

// Re-export page components for the router
use account_settings::AccountSettings;
use browser_sessions::BrowserSessions;
use client_detail::ClientDetail;
use device_redirect::DeviceRedirect;
use dioxus::prelude::*;
use email_in_use::EmailInUse;
use email_verify::EmailVerify;
use password_change::PasswordChange;
use password_change_success::PasswordChangeSuccess;
use password_recovery::PasswordRecovery;
use plan::Plan;
use reset_cross_signing::ResetCrossSigning;
use session_detail::SessionDetail;
use sessions::Sessions;

use crate::components::{error::NotFound, layout::Layout};

/// Application route definition.
/// Mirrors the TanStack Router file-based routes from the React frontend.
#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    // Account layout with nested routes
    #[layout(AccountLayout)]
        #[route("/")]
        AccountSettings {},
        #[route("/sessions")]
        Sessions {},
        #[route("/sessions/browsers")]
        BrowserSessions {},
        #[route("/plan")]
        Plan {},
    #[end_layout]

    // Standalone pages
    #[route("/password/change")]
    PasswordChange {},
    #[route("/password/change/success")]
    PasswordChangeSuccess {},
    #[route("/password/recovery")]
    PasswordRecovery {},
    #[route("/emails/:id/verify")]
    EmailVerify { id: String },
    #[route("/emails/:id/in-use")]
    EmailInUse { id: String },
    #[route("/sessions/:id")]
    SessionDetail { id: String },
    #[route("/reset-cross-signing")]
    ResetCrossSigning {},
    #[route("/clients/:id")]
    ClientDetail { id: String },
    #[route("/devices/:..route")]
    DeviceRedirect { route: Vec<String> },

    // Catch-all 404
    #[route("/:..route")]
    PageNotFound { route: Vec<String> },
}

/// Account layout wrapping the account-related pages (settings, sessions,
/// plan).
#[component]
fn AccountLayout() -> Element {
    rsx! {
        account::AccountPage {}
    }
}

/// 404 page component.
#[component]
fn PageNotFound(route: Vec<String>) -> Element {
    rsx! {
        Layout {
            NotFound {}
        }
    }
}
