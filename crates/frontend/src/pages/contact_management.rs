use dioxus::prelude::*;

use crate::{
    api::types::{RemoveEmailPayload, ViewerResponse},
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
    pages::Route,
};

/// Contact management page.
///
/// Fetches `GET /api/v1/viewer` to obtain the user's email list and displays
/// each email with its verification status. The "Remove" button calls
/// `DELETE /api/v1/user-emails/{id}` and the "Add email" button starts the
/// email verification flow via the account settings page.
#[component]
pub fn ContactManagement() -> Element {
    let mut data =
        use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let mut feedback: Signal<Option<Result<String, String>>> = use_signal(|| None);
    let mut removing: Signal<Option<String>> = use_signal(|| None);
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

            let email_count = emails.len();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Contact Information" }

                    // Feedback messages
                    if let Some(ref result) = *feedback.read() {
                        match result {
                            Ok(msg) => rsx! {
                                div { class: "alert alert-success", "{msg}" }
                            },
                            Err(msg) => rsx! {
                                div { class: "alert alert-critical", "{msg}" }
                            },
                        }
                    }

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
                                {
                                    let email_id = email.id.clone();
                                    let email_addr = email.email.clone();
                                    let is_primary = email.is_primary;
                                    let is_removing = removing.read().as_ref() == Some(&email_id);
                                    // Prevent removing the last email or the primary email
                                    let can_remove = email_count > 1 && !is_primary;
                                    rsx! {
                                        div {
                                            class: "flex items-center justify-between p-3 rounded-lg border",
                                            div { class: "flex flex-col gap-1",
                                                div { class: "flex items-center gap-2",
                                                    span { class: "text-md font-semibold", "{email.email}" }
                                                    if is_primary {
                                                        span { class: "badge badge-neutral", "Primary" }
                                                    }
                                                }
                                                if email.confirmed_at.is_some() {
                                                    span { class: "badge badge-success", "Verified" }
                                                } else {
                                                    span { class: "badge badge-warning", "Unverified" }
                                                }
                                            }
                                            button {
                                                class: "btn btn-destructive btn-sm",
                                                disabled: !can_remove || is_removing,
                                                title: if !can_remove { "Cannot remove primary or only email" } else { "Remove this email" },
                                                onclick: move |_| {
                                                    let id = email_id.clone();
                                                    let addr = email_addr.clone();
                                                    removing.set(Some(id.clone()));
                                                    feedback.set(None);
                                                    spawn(async move {
                                                        let result = crate::api::api_delete::<RemoveEmailPayload>(
                                                            &format!("/user-emails/{id}"),
                                                        ).await;
                                                        removing.set(None);
                                                        match result {
                                                            Ok(_) => {
                                                                feedback.set(Some(Ok(format!("{addr} removed."))));
                                                                data.restart();
                                                            }
                                                            Err(e) => {
                                                                feedback.set(Some(Err(e)));
                                                            }
                                                        }
                                                    });
                                                },
                                                if is_removing { "Removing…" } else { "Remove" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Add email via email-auth flow
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Add email" }
                        p { class: "text-md text-secondary",
                            "Add a new email address to your account. You will need to verify it via a code sent to that address."
                        }
                        Link {
                            to: Route::AccountSettings {},
                            class: "btn btn-secondary",
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
