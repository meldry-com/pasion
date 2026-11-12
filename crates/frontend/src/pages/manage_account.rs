//! Resolve Matrix account-management actions after authentication.
use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

fn action_destination(action: Option<&str>, device: Option<&str>) -> Route {
    match action {
        Some("org.matrix.profile" | "profile") => Route::AccountSettings {},
        Some("org.matrix.cross_signing_reset") => Route::ResetCrossSigning {},
        Some("org.matrix.devices_list" | "org.matrix.sessions_list" | "sessions_list") => {
            Route::Devices {}
        }
        Some(
            "org.matrix.device_view"
            | "org.matrix.device_delete"
            | "org.matrix.session_view"
            | "org.matrix.session_end"
            | "session_view"
            | "session_end",
        ) => device
            .filter(|id| !id.is_empty())
            .map_or(Route::Devices {}, |id| Route::DeviceRedirect {
                route: id.split('/').map(str::to_owned).collect(),
            }),
        _ => Route::AccountOverview {},
    }
}

fn encode_query(value: &str) -> String {
    value.bytes().map(|byte| format!("%{byte:02X}")).collect()
}

fn login_path(action: Option<&str>, device: Option<&str>) -> String {
    let mut path = "/login?kind=manage_account".to_owned();
    if let Some(action) = action {
        path.push_str(&format!("&action={}", encode_query(action)));
    }
    if let Some(device) = device {
        path.push_str(&format!("&device_id={}", encode_query(device)));
    }
    crate::config::app_path(&path)
}

fn management_intent(query: &str) -> (Option<String>, Option<String>) {
    let mut action = None;
    let mut device = None;
    for (name, value) in form_urlencoded::parse(query.trim_start_matches('?').as_bytes()) {
        match name.as_ref() {
            "action" if action.is_none() => action = Some(value.into_owned()),
            "device_id" if device.is_none() => device = Some(value.into_owned()),
            _ => {}
        }
    }
    (action, device)
}

#[component]
pub fn ManageAccount() -> Element {
    // Dioxus decodes a complete query before splitting its arguments. Read
    // the original browser query retained before Router initialization so a
    // device ID containing '&' remains one value.
    let intent = use_signal(|| {
        let intent = management_intent(&super::login::current_query_string());
        super::login::clear_preserved_login_query();
        intent
    });
    let (action, device_id) = intent();
    let viewer = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let authenticated =
        matches!(&*viewer.read(), Some(Ok(data)) if data.viewer.as_user().is_some());
    crate::utils::use_redirect(
        authenticated,
        action_destination(action.as_deref(), device_id.as_deref()),
    );
    rsx! {
        Layout {
            match &*viewer.read() {
                Some(Ok(_)) if !authenticated => rsx! {
                    h1 { "Sign in to manage your account" }
                    a { class: "btn btn-primary", href: login_path(action.as_deref(), device_id.as_deref()), "Sign in" }
                },
                Some(Err(error)) => rsx! { p { role: "alert", "{error}" } },
                _ => rsx! { LoadingScreen {} },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_and_legacy_actions_select_the_requested_device() {
        assert_eq!(
            action_destination(Some("org.matrix.cross_signing_reset"), None),
            Route::ResetCrossSigning {}
        );
        assert_eq!(
            action_destination(Some("org.matrix.profile"), None),
            Route::AccountSettings {}
        );
        for action in [
            "org.matrix.device_view",
            "org.matrix.device_delete",
            "org.matrix.session_view",
            "org.matrix.session_end",
        ] {
            assert_eq!(
                action_destination(Some(action), Some("A/B")),
                Route::DeviceRedirect {
                    route: vec!["A".into(), "B".into()]
                }
            );
            assert_eq!(action_destination(Some(action), None), Route::Devices {});
        }
        assert_eq!(
            action_destination(Some("unknown"), None),
            Route::AccountOverview {}
        );
    }

    #[test]
    fn login_continuation_cannot_inject_query_parameters() {
        assert_eq!(encode_query("A&B=C"), "%41%26%42%3D%43");
        assert_eq!(
            management_intent("action=org.matrix.device_view&device_id=A%2FB%26C"),
            (Some("org.matrix.device_view".into()), Some("A/B&C".into()))
        );
    }
}
