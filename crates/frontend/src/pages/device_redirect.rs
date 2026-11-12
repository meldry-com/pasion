use dioxus::prelude::*;
use serde::Deserialize;

use crate::components::{layout::Layout, loading::LoadingScreen};

#[derive(Deserialize)]
struct DeviceDetail {
    device_id: String,
    session_count: usize,
}

#[derive(Deserialize)]
struct DeviceCollection {
    devices: Vec<DeviceDetail>,
}

fn device_query(device: &str) -> String {
    if device.is_empty() {
        return "/devices".into();
    }
    // Query encoding preserves IDs containing '/' without route ambiguity.
    let encoded: String = device.bytes().map(|byte| format!("%{byte:02X}")).collect();
    format!("/devices?device_id={encoded}")
}

#[component]
pub fn Devices() -> Element {
    rsx! { DeviceRedirect { route: Vec::new() } }
}

#[component]
pub fn DeviceRedirect(route: Vec<String>) -> Element {
    let device = route.join("/");
    let listing = device.is_empty();
    let query = use_memo(use_reactive!(|device| device_query(&device)));
    let data =
        use_resource(
            move || async move { crate::api::api_get::<DeviceCollection>(&query()).await },
        );
    let mut deleting = use_signal(|| false);
    let mut deleted = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    use_effect(move || {
        let _ = query();
        deleted.set(false);
        error.set(None);
    });

    rsx! {
        Layout {
            if deleted() {
                h1 { "Device signed out" }
            } else {
                match &*data.read() {
                    Some(Ok(collection)) if listing => rsx! {
                        h1 { "Your devices" }
                        if collection.devices.is_empty() { p { "No active devices." } }
                        for detail in &collection.devices {
                            p { Link { to: crate::pages::Route::DeviceRedirect { route: detail.device_id.split('/').map(str::to_owned).collect() }, "{detail.device_id} ({detail.session_count} sessions)" } }
                        }
                    },
                    Some(Ok(collection)) => rsx! {
                        for detail in &collection.devices {
                        h1 { "Device {detail.device_id}" }
                        p { "{detail.session_count} active session(s) belong to this device." }
                        p { "Signing out revokes all sessions for this device. Other devices stay signed in." }
                        button {
                            class: "btn btn-danger",
                            disabled: deleting(),
                            onclick: move |_| {
                                let path = query();
                                deleting.set(true);
                                spawn(async move {
                                    match crate::api::api_delete::<serde_json::Value>(&path).await {
                                        Ok(_) if query() == path => deleted.set(true),
                                        Ok(_) => {},
                                        Err(message) => error.set(Some(message)),
                                    }
                                    deleting.set(false);
                                });
                            },
                            "Sign out this device"
                        }
                        }
                    },
                    Some(Err(message)) => rsx! { p { role: "alert", "{message}" } },
                    None => rsx! { LoadingScreen {} },
                }
            }
            if let Some(message) = error() {
                p { role: "alert", "{message}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_cannot_add_query_parameters_or_change_the_target() {
        assert_eq!(device_query(""), "/devices");
        assert_eq!(
            device_query("A/B&device_id=C"),
            "/devices?device_id=%41%2F%42%26%64%65%76%69%63%65%5F%69%64%3D%43"
        );
    }
}
