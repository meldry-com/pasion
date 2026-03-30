use dioxus::prelude::*;

use crate::components::separator::{Separator, SeparatorKind};

/// Security center page.
///
/// Planned sections:
/// - Password status (set / not set, last changed)
/// - Recent login activity
/// - Active sessions summary
#[component]
pub fn SecurityCenter() -> Element {
    rsx! {
        div { class: "flex flex-col gap-6",
            h3 { class: "heading-xs", "Security center" }

            // Password status
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Password status" }
                p { class: "text-md text-secondary",
                    "View and manage your account password. Check when it was last changed and update it if needed."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Recent login activity
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Recent login activity" }
                p { class: "text-md text-secondary",
                    "Review recent sign-in attempts to your account, including timestamps and locations."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Active sessions summary
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Active sessions" }
                p { class: "text-md text-secondary",
                    "A summary of your currently active browser and app sessions."
                }
            }

            Separator {}
        }
    }
}
