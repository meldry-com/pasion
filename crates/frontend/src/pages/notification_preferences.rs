use dioxus::prelude::*;

use crate::components::separator::{Separator, SeparatorKind};

/// Notification preferences page.
///
/// Planned sections:
/// - Email notification channel toggle
/// - SMS notification channel toggle
/// - Language / locale preference for notifications
#[component]
pub fn NotificationPreferences() -> Element {
    rsx! {
        div { class: "flex flex-col gap-6",
            h3 { class: "heading-xs", "Notification preferences" }

            // Email channel
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Email notifications" }
                p { class: "text-md text-secondary",
                    "Enable or disable email notifications for account activity and security alerts."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // SMS channel
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "SMS notifications" }
                p { class: "text-md text-secondary",
                    "Enable or disable SMS notifications for account verification and alerts."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Language preference
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Language preference" }
                p { class: "text-md text-secondary",
                    "Choose the language for notification messages sent to you."
                }
            }

            Separator {}
        }
    }
}
