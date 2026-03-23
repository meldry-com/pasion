use dioxus::prelude::*;

use crate::{
    api::types::{AppSession, ViewerResponse},
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

#[component]
pub fn DeviceRedirect(route: Vec<String>) -> Element {
    let device_id = route.join("/");
    let nav = navigator();

    let data = use_resource(move || {
        let _device_id = device_id.clone();
        async move {
            // Get the combined viewer data (includes app sessions)
            crate::api::api_get::<ViewerResponse>("/viewer").await
        }
    });

    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => {
                    return rsx! {
                        Layout {
                            p { "Not authenticated." }
                        }
                    };
                }
            };

            // Check if we found a session
            if let Some(ref app_sessions) = user.app_sessions {
                if let Some(edge) = app_sessions.edges.first() {
                    let session_id = match &edge.node {
                        AppSession::Oauth2Session(s) => s.id.clone(),
                        AppSession::CompatSession(s) => s.id.clone(),
                    };
                    nav.push(Route::SessionDetail { id: session_id });
                    return rsx! { LoadingScreen {} };
                }
            }

            rsx! {
                Layout {
                    div { class: "flex flex-col gap-4",
                        p { "Device not found." }
                        Link {
                            class: "text-sm text-secondary",
                            to: Route::Sessions {},
                            "Back to sessions"
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
