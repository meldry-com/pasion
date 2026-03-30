use dioxus::prelude::*;

use crate::{
    api::types::LinkedAccountsResponse,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Identity bindings page.
///
/// Fetches `GET /api/v1/linked-accounts` and displays each linked upstream
/// account with provider name and subject. Includes a placeholder "Unlink"
/// button on each entry.
#[component]
pub fn IdentityBindings() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<LinkedAccountsResponse>("/linked-accounts").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let accounts = &result.accounts;

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Identity bindings" }

                    // Linked accounts
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Linked accounts" }
                        p { class: "text-md text-secondary",
                            "External identity providers currently linked to your account. You can sign in with any of these."
                        }
                    }

                    if accounts.is_empty() {
                        p { class: "text-md text-secondary", style: "font-style: italic;",
                            "No external accounts linked."
                        }
                    } else {
                        div { class: "flex flex-col gap-3",
                            for account in accounts.iter() {
                                {
                                    let display_name = account.human_account_name.clone()
                                        .or_else(|| Some(account.subject.clone()))
                                        .unwrap_or_default();
                                    let provider_label = account.provider_name.clone()
                                        .or_else(|| account.provider_brand.clone())
                                        .unwrap_or_else(|| "External provider".to_string());
                                    rsx! {
                                        div {
                                            class: "flex items-center justify-between p-3 rounded-lg border",
                                            div { class: "flex flex-col gap-1",
                                                span { class: "text-md font-semibold", "{provider_label}" }
                                                span { class: "text-sm text-secondary", "{display_name}" }
                                            }
                                            // Placeholder unlink button
                                            button {
                                                class: "btn btn-destructive btn-sm",
                                                disabled: true,
                                                title: "Unlink account (not yet implemented)",
                                                "Unlink"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Link new provider (placeholder)
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Link a new provider" }
                        p { class: "text-md text-secondary",
                            "Connect an additional external account (e.g. Google, GitHub) to enable more sign-in options."
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
