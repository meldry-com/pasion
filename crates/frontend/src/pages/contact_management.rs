use dioxus::prelude::*;

use crate::components::separator::{Separator, SeparatorKind};

/// Contact management page.
///
/// Planned sections:
/// - Email addresses (list, add, remove, verify, set primary)
/// - Phone numbers (list, add, remove, verify)
#[component]
pub fn ContactManagement() -> Element {
    rsx! {
        div { class: "flex flex-col gap-6",
            h3 { class: "heading-xs", "Contact management" }

            // Email addresses
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Email addresses" }
                p { class: "text-md text-secondary",
                    "Manage the email addresses associated with your account. Add new addresses, remove old ones, or verify pending addresses."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Phone numbers
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Phone numbers" }
                p { class: "text-md text-secondary",
                    "Manage the phone numbers associated with your account. Add, remove, or verify phone numbers used for authentication and notifications."
                }
            }

            Separator {}
        }
    }
}
