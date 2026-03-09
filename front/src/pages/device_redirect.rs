use dioxus::prelude::*;

use crate::components::layout::Layout;
use crate::components::loading::LoadingScreen;
use crate::graphql::types::{AppSession, DeviceRedirectData};
use crate::pages::Route;

const VIEWER_QUERY: &str = r#"
    query DeviceRedirectViewer {
        viewer {
            __typename
            ... on User {
                id
            }
        }
    }
"#;

const QUERY: &str = r#"
    query DeviceRedirect($deviceId: String!, $userId: ID!) {
        viewer {
            __typename
            ... on User {
                id
                appSessions(first: 1, device: $deviceId) {
                    edges {
                        node {
                            __typename
                            ... on Oauth2Session { id }
                            ... on CompatSession { id }
                        }
                    }
                }
            }
        }
    }
"#;

#[component]
pub fn DeviceRedirect(route: Vec<String>) -> Element {
    let device_id = route.join("/");
    let nav = navigator();

    let data = use_resource(move || {
        let device_id = device_id.clone();
        async move {
            // First, get the current user ID
            let viewer_result =
                crate::graphql::graphql_request::<DeviceRedirectData>(VIEWER_QUERY, None).await;

            let user_id = match viewer_result {
                Ok(ref data) => match data.viewer.as_user() {
                    Some(u) => u.id.clone(),
                    None => return Err("Not authenticated.".to_string()),
                },
                Err(e) => return Err(e),
            };

            // Then query for the device session
            crate::graphql::graphql_request::<DeviceRedirectData>(
                QUERY,
                Some(serde_json::json!({
                    "deviceId": device_id,
                    "userId": user_id,
                })),
            )
            .await
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
                    nav.push(Route::SessionDetail {
                        id: session_id,
                    });
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
