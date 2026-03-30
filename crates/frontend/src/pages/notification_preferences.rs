use dioxus::prelude::*;

use crate::{
    api::types::SiteConfig,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Notification preferences page.
///
/// Fetches `GET /api/v1/site-config` to determine which notification channels
/// are available (e.g. email configured, password login enabled as a proxy for
/// system capabilities). Displays placeholder toggles since no dedicated
/// notification preferences API exists yet.
// NOTE: A proper notification preferences API (e.g. GET/PUT
// /api/v1/viewer/notification-preferences) does not exist yet. This page
// currently only shows channel *availability* from site-config. When the
// backend adds user-specific preference endpoints, this page should be
// updated to fetch and persist actual per-user toggle state.
#[component]
pub fn NotificationPreferences() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<SiteConfig>("/site-config").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(config)) => {
            // Derive channel availability from site config.
            // email_change_allowed is used as a proxy: if the site allows email
            // changes, email delivery is configured.
            let email_configured = config.email_change_allowed;
            // There is no explicit SMS flag in site-config; default to false.
            let sms_configured = false;

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Notification preferences" }

                    // Email channel
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Email notifications" }
                        div { class: "flex items-center gap-3",
                            span {
                                class: if email_configured { "badge badge-success" } else { "badge badge-warning" },
                                if email_configured { "Email delivery configured" } else { "Email delivery not configured" }
                            }
                        }
                        p { class: "text-md text-secondary",
                            "Enable or disable email notifications for account activity and security alerts."
                        }
                        // Placeholder toggle -- actual preferences API does not exist yet
                        label { class: "flex items-center gap-2",
                            input {
                                r#type: "checkbox",
                                checked: email_configured,
                                disabled: true,
                                title: "Toggle not yet functional (preferences API pending)",
                            }
                            span { class: "text-md", "Receive email notifications" }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // SMS channel
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "SMS notifications" }
                        div { class: "flex items-center gap-3",
                            span {
                                class: if sms_configured { "badge badge-success" } else { "badge badge-warning" },
                                if sms_configured { "SMS delivery configured" } else { "SMS delivery not configured" }
                            }
                        }
                        p { class: "text-md text-secondary",
                            "Enable or disable SMS notifications for account verification and alerts."
                        }
                        // Placeholder toggle -- actual preferences API does not exist yet
                        label { class: "flex items-center gap-2",
                            input {
                                r#type: "checkbox",
                                checked: sms_configured,
                                disabled: true,
                                title: "Toggle not yet functional (preferences API pending)",
                            }
                            span { class: "text-md", "Receive SMS notifications" }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Language preference (placeholder)
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Language preference" }
                        p { class: "text-md text-secondary",
                            "Choose the language for notification messages sent to you. This setting is not yet available."
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
