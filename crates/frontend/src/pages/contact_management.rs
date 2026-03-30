use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Contact management page.
///
/// Fetches `GET /api/v1/viewer` to obtain the user's email list and displays
/// each email with its verification status. Provides placeholder buttons for
/// "Add Email" and "Remove" actions.
#[component]
pub fn ContactManagement() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let session = match result.viewer_session.as_browser_session() {
                Some(s) => s,
                None => {
                    return rsx! { p { "Not authenticated." } };
                }
            };

            let user = match &session.user {
                Some(u) => u,
                None => {
                    return rsx! { p { "User data unavailable." } };
                }
            };

            let emails: Vec<_> = user
                .emails
                .as_ref()
                .map(|ec| ec.edges.iter().map(|e| e.node.clone()).collect())
                .unwrap_or_default();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Contact Information" }

                    // Email addresses
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Email addresses" }
                        p { class: "text-md text-secondary",
                            "Manage the email addresses associated with your account."
                        }
                    }

                    if emails.is_empty() {
                        p { class: "text-md text-secondary", style: "font-style: italic;",
                            "No email addresses on file."
                        }
                    } else {
                        div { class: "flex flex-col gap-3",
                            for email in emails.iter() {
                                div {
                                    class: "flex items-center justify-between p-3 rounded-lg border",
                                    div { class: "flex flex-col gap-1",
                                        span { class: "text-md font-semibold", "{email.email}" }
                                        if email.confirmed_at.is_some() {
                                            span { class: "badge badge-success", "Verified" }
                                        } else {
                                            span { class: "badge badge-warning", "Unverified" }
                                        }
                                    }
                                    // Placeholder remove button
                                    button {
                                        class: "btn btn-destructive btn-sm",
                                        disabled: true,
                                        title: "Remove email (not yet implemented)",
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Placeholder add email button
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Add email" }
                        button {
                            class: "btn btn-secondary",
                            disabled: true,
                            title: "Add email (not yet implemented)",
                            "Add email address"
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Phone numbers (placeholder section)
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Phone numbers" }
                        p { class: "text-md text-secondary",
                            "Phone number management is not yet available."
                        }
                    }

                    Separator {}
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
