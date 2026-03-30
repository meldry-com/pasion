use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{
        layout::Layout,
        loading::LoadingScreen,
        nav_bar::{NavBar, NavItem},
        user_greeting::UserGreeting,
    },
    pages::Route,
};

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
            let profile = user.profile.clone().unwrap_or(crate::api::types::UserProfile {
                display_name: matrix.display_name.clone(),
                avatar_url: None,
                preferred_locale: None,
                updated_at: String::new(),
            });

            let has_plan = result.site_config.plan_management_iframe_uri.is_some();
            let display_name_change_allowed = result.site_config.display_name_change_allowed;

            rsx! {
                Layout { wide: true,
                    div { class: "flex flex-col gap-10",
                        h1 { class: "heading-md", "Account" }
                        div { class: "flex flex-col gap-4",
                            UserGreeting {
                                matrix: matrix,
                                profile: profile,
                                display_name_change_allowed: display_name_change_allowed,
                            }
                            NavBar {
                                NavItem { to: Route::AccountOverview {}, "Overview" }
                                NavItem { to: Route::AccountSettings {}, "Settings" }
                                NavItem { to: Route::SecurityCenter {}, "Security" }
                                NavItem { to: Route::ContactManagement {}, "Contacts" }
                                NavItem { to: Route::IdentityBindings {}, "Identities" }
                                NavItem { to: Route::NotificationPreferences {}, "Notifications" }
                                NavItem { to: Route::Sessions {}, "Devices" }
                                NavItem { to: Route::WorkflowInbox {}, "Workflows" }
                                if has_plan {
                                    NavItem { to: Route::Plan {}, "Plan" }
                                }
                            }
                        }
                    }
                    Outlet::<Route> {}
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
