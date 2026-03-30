use dioxus::prelude::*;

use crate::{
    api::types::{SecuritySummaryResponse, WorkflowInboxResponse},
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
    pages::Route,
};

/// Account overview page.
///
/// Aggregates key account information from multiple API endpoints into a
/// single dashboard view with links to detail pages:
/// - Security status summary (password, sessions, verified emails, providers)
/// - Contact points summary (email/phone counts)
/// - Identity bindings summary (linked providers count)
/// - Pending workflow count
#[component]
pub fn AccountOverview() -> Element {
    let security = use_resource(|| async {
        crate::api::api_get::<SecuritySummaryResponse>("/viewer/security").await
    });
    let workflows = use_resource(|| async {
        crate::api::api_get::<WorkflowInboxResponse>("/viewer/workflow-inbox").await
    });

    let sec_binding = security.read();
    let wf_binding = workflows.read();

    // Wait for at least the security data before rendering.
    let summary = match &*sec_binding {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            return rsx! {
                div { class: "alert alert-critical", "{e}" }
            };
        }
        None => {
            return rsx! { LoadingScreen {} };
        }
    };

    let pending_count = match &*wf_binding {
        Some(Ok(wf)) => Some(wf.pending_count),
        Some(Err(_)) => None, // silently degrade
        None => None,
    };

    let password_label = if summary.has_password {
        "Password is set"
    } else {
        "No password set"
    };
    let password_class = if summary.has_password {
        "badge badge-success"
    } else {
        "badge badge-warning"
    };

    rsx! {
        div { class: "flex flex-col gap-6",
            h3 { class: "heading-xs", "Account Overview" }

            // ── Security status ──────────────────────────────
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Security status" }
                div { class: "flex items-center gap-2",
                    span { class: "{password_class}", "{password_label}" }
                }
                p { class: "text-md text-secondary",
                    "{summary.active_sessions_count} active session(s)"
                }
                Link {
                    class: "btn btn-secondary btn-sm",
                    to: Route::SecurityCenter {},
                    "Go to Security Center"
                }
            }

            Separator { kind: SeparatorKind::Section }

            // ── Contact points ───────────────────────────────
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Contact points" }
                p { class: "text-md",
                    "{summary.verified_emails_count} verified email(s)"
                }
                p { class: "text-md",
                    "{summary.verified_phones_count} verified phone(s)"
                }
                Link {
                    class: "btn btn-secondary btn-sm",
                    to: Route::ContactManagement {},
                    "Manage contacts"
                }
            }

            Separator { kind: SeparatorKind::Section }

            // ── Identity bindings ────────────────────────────
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Identity bindings" }
                p { class: "text-md",
                    "{summary.linked_providers_count} linked provider(s)"
                }
                Link {
                    class: "btn btn-secondary btn-sm",
                    to: Route::IdentityBindings {},
                    "Manage identities"
                }
            }

            Separator { kind: SeparatorKind::Section }

            // ── Pending workflows ────────────────────────────
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Pending workflows" }
                match pending_count {
                    Some(count) => rsx! {
                        p { class: "text-md",
                            "{count} pending workflow(s)"
                        }
                    },
                    None => rsx! {
                        p { class: "text-md text-secondary", style: "font-style: italic;",
                            "Workflow status unavailable."
                        }
                    },
                }
            }

            Separator { kind: SeparatorKind::Section }

            // ── Quick links ──────────────────────────────────
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Quick links" }
                div { class: "flex flex-wrap gap-2",
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::SecurityCenter {},
                        "Security"
                    }
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::ContactManagement {},
                        "Contacts"
                    }
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::IdentityBindings {},
                        "Identities"
                    }
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::NotificationPreferences {},
                        "Notifications"
                    }
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::Sessions {},
                        "Sessions"
                    }
                }
            }

            Separator {}
        }
    }
}
