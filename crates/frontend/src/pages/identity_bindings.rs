use dioxus::prelude::*;

use crate::components::separator::{Separator, SeparatorKind};

/// Identity bindings page.
///
/// Planned sections:
/// - List of linked upstream OAuth / OIDC accounts
/// - Link a new external identity provider
/// - Unlink an existing external identity
#[component]
pub fn IdentityBindings() -> Element {
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

            Separator { kind: SeparatorKind::Section }

            // Link new provider
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Link a new provider" }
                p { class: "text-md text-secondary",
                    "Connect an additional external account (e.g. Google, GitHub) to enable more sign-in options."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Unlink provider
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Unlink a provider" }
                p { class: "text-md text-secondary",
                    "Remove an external identity link. You will no longer be able to sign in with that provider."
                }
            }

            Separator {}
        }
    }
}
