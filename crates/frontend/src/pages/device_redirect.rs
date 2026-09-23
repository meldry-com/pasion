use dioxus::prelude::*;

use crate::{
    api::types::{AppSession, ViewerResponse},
    components::{layout::Layout, loading::LoadingScreen, page_heading::PageHeading},
    pages::Route,
};

#[component]
pub fn DeviceRedirect(route: Vec<String>) -> Element {
    let device_id = route.join("/");

    let data = use_resource(move || {
        let _device_id = device_id.clone();
        async move {
            // Get the combined viewer data (includes app sessions)
            crate::api::api_get::<ViewerResponse>("/viewer").await
        }
    });

    // Resolve the target session (if any) and redirect to its detail page.
    let target_session_id: Option<String> = match &*data.read() {
        Some(Ok(result)) => result
            .viewer
            .as_user()
            .and_then(|user| user.app_sessions.as_ref())
            .and_then(|app_sessions| app_sessions.edges.first())
            .map(|edge| match &edge.node {
                AppSession::Oauth2Session(s) => s.id.clone(),
            }),
        _ => None,
    };
    crate::utils::use_redirect(
        target_session_id.is_some(),
        Route::SessionDetail {
            id: target_session_id.clone().unwrap_or_default(),
        },
    );

    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let Some(user) = result.viewer.as_user() else {
                return rsx! {
                    Layout {
                        div { class: "flex flex-col gap-10",
                            PageHeading {
                                icon: "🔒".to_owned(),
                                title: "Not authenticated".to_owned(),
                                subtitle: "Please sign in to view device information.".to_owned(),
                            }
                            Link { class: "btn btn-primary", to: Route::Login {},
                                "Sign in"
                            }
                        }
                    }
                };
            };

            // A matching session triggers a redirect (handled by use_redirect
            // above); show a loading screen while it happens.
            if let Some(ref app_sessions) = user.app_sessions
                && !app_sessions.edges.is_empty()
            {
                return rsx! { LoadingScreen {} };
            }

            rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "?".to_owned(),
                            title: "Device not found".to_owned(),
                            subtitle: "The device you are looking for could not be found.".to_owned(),
                        }
                        Link { class: "btn btn-primary", to: Route::Sessions {},
                            "Back to sessions"
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "flex flex-col gap-10",
                    PageHeading {
                        icon: "!".to_owned(),
                        title: "Error".to_owned(),
                        subtitle: e.clone(),
                    }
                    Link { class: "btn btn-primary", to: Route::Sessions {},
                        "Back to sessions"
                    }
                }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
