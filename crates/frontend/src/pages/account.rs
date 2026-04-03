use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{
        layout::{Layout, LayoutWidth},
        loading::LoadingScreen,
        user_greeting::UserGreeting,
    },
    pages::Route,
};

/// A sidebar navigation item for the account layout.
#[component]
fn SidebarItem(to: Route, children: Element) -> Element {
    let current_route = use_route::<Route>();
    let is_active = std::mem::discriminant(&current_route) == std::mem::discriminant(&to);
    let active_class = if is_active { " active" } else { "" };

    rsx! {
        Link { class: "sidebar-item{active_class}", to: to, {children} }
    }
}

#[component]
pub fn AccountPage() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => {
                    let nav = navigator();
                    nav.push(Route::Login {});
                    return rsx! {
                        Layout { p { "Redirecting to login..." } }
                    };
                }
            };

            let matrix = match &user.matrix {
                Some(m) => m.clone(),
                None => {
                    return rsx! {
                        Layout { p { "User data unavailable." } }
                    };
                }
            };
            let profile = user
                .profile
                .clone()
                .unwrap_or(crate::api::types::UserProfile {
                    display_name: matrix.display_name.clone(),
                    avatar_url: None,
                    preferred_locale: None,
                    updated_at: String::new(),
                });

            let has_plan = result.site_config.plan_management_iframe_uri.is_some();
            let display_name_change_allowed = result.site_config.display_name_change_allowed;

            rsx! {
                Layout { width: LayoutWidth::Full,
                    div { class: "account-layout",
                        nav { class: "account-sidebar",
                            // Profile card at top of sidebar
                            div { class: "sidebar-profile",
                                UserGreeting {
                                    matrix: matrix,
                                    profile: profile,
                                    display_name_change_allowed: display_name_change_allowed,
                                }
                            }

                            // Navigation group
                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Account" }
                                SidebarItem { to: Route::AccountOverview {}, "Overview" }
                                SidebarItem { to: Route::AccountSettings {}, "Settings" }
                                SidebarItem { to: Route::ContactManagement {}, "Contacts" }
                                SidebarItem { to: Route::IdentityBindings {}, "Identities" }
                            }

                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Security" }
                                SidebarItem { to: Route::SecurityCenter {}, "Security" }
                                SidebarItem { to: Route::Sessions {}, "Devices" }
                            }

                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Preferences" }
                                SidebarItem { to: Route::NotificationPreferences {}, "Notifications" }
                                SidebarItem { to: Route::WorkflowInbox {}, "Workflows" }
                                if has_plan {
                                    SidebarItem { to: Route::Plan {}, "Plan" }
                                }
                            }
                        }

                        div { class: "account-content",
                            Outlet::<Route> {}
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
