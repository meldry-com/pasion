use dioxus::prelude::*;

use crate::components::layout::Layout;
use crate::components::loading::LoadingScreen;
use crate::graphql::types::{ClientDetailData, ClientNode};
use crate::pages::Route;

const QUERY: &str = r#"
    query OAuth2Client($id: ID!) {
        node(id: $id) {
            __typename
            ... on Oauth2Client {
                id clientId clientName clientUri tosUri policyUri logoUri
            }
        }
    }
"#;

#[component]
pub fn ClientDetail(id: String) -> Element {
    let id_clone = id.clone();
    let data = use_resource(move || {
        let id = id_clone.clone();
        async move {
            crate::graphql::graphql_request::<ClientDetailData>(
                QUERY,
                Some(serde_json::json!({ "id": id })),
            )
            .await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => match &result.node {
            Some(ClientNode::Oauth2Client(client)) => rsx! {
                Layout {
                    ClientDetailView {
                        client_id: client.client_id.clone(),
                        client_name: client.client_name.clone(),
                        client_uri: client.client_uri.clone(),
                        tos_uri: client.tos_uri.clone(),
                        policy_uri: client.policy_uri.clone(),
                        logo_uri: client.logo_uri.clone(),
                    }
                }
            },
            None => rsx! {
                Layout {
                    p { "Client not found." }
                }
            },
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn ClientDetailView(
    client_id: String,
    client_name: Option<String>,
    client_uri: Option<String>,
    tos_uri: Option<String>,
    policy_uri: Option<String>,
    logo_uri: Option<String>,
) -> Element {
    let name = client_name
        .clone()
        .unwrap_or_else(|| "Unknown client".to_string());

    rsx! {
        div { class: "flex flex-col gap-6",
            // Back link
            Link {
                class: "text-sm text-secondary",
                to: Route::Sessions {},
                "Back to sessions"
            }

            // Header with optional logo
            div { class: "flex items-center gap-4",
                if let Some(ref uri) = logo_uri {
                    img {
                        class: "w-12 h-12 rounded",
                        src: "{uri}",
                        alt: "{name}",
                    }
                }
                h3 { class: "heading-xs", "{name}" }
            }

            // Client info
            div { class: "flex flex-col gap-2",
                div { class: "flex flex-col gap-1",
                    span { class: "text-sm text-secondary", "Client ID" }
                    span { class: "text-sm", "{client_id}" }
                }

                if let Some(ref uri) = client_uri {
                    div { class: "flex flex-col gap-1",
                        span { class: "text-sm text-secondary", "Client URI" }
                        a {
                            class: "text-sm text-link",
                            href: "{uri}",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "{uri}"
                        }
                    }
                }

                if let Some(ref uri) = tos_uri {
                    div { class: "flex flex-col gap-1",
                        span { class: "text-sm text-secondary", "Terms of Service" }
                        a {
                            class: "text-sm text-link",
                            href: "{uri}",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "{uri}"
                        }
                    }
                }

                if let Some(ref uri) = policy_uri {
                    div { class: "flex flex-col gap-1",
                        span { class: "text-sm text-secondary", "Privacy Policy" }
                        a {
                            class: "text-sm text-link",
                            href: "{uri}",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            "{uri}"
                        }
                    }
                }
            }
        }
    }
}
