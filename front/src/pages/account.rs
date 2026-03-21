use dioxus::prelude::*;

use crate::components::layout::Layout;
use crate::components::loading::LoadingScreen;
use crate::components::nav_bar::{NavBar, NavItem};
use crate::components::user_greeting::UserGreeting;
use crate::graphql::types::ViewerResponse;
use crate::pages::Route;

#[component]
pub fn AccountPage() -> Element {
    let data = use_resource(|| async {
        crate::graphql::api_get::<ViewerResponse>("/viewer").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => {
                    return rsx! {
                        Layout { p { "Not authenticated." } }
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

            let has_plan = result.site_config.plan_management_iframe_uri.is_some();
            let display_name_change_allowed = result.site_config.display_name_change_allowed;
            let user_id = user.id.clone();

            rsx! {
                Layout { wide: true,
                    div { class: "flex flex-col gap-10",
                        h1 { class: "heading-md", "Account" }
                        div { class: "flex flex-col gap-4",
                            UserGreeting {
                                matrix: matrix,
                                user_id: user_id,
                                display_name_change_allowed: display_name_change_allowed,
                            }
                            NavBar {
                                NavItem { to: Route::AccountSettings {}, "Settings" }
                                NavItem { to: Route::Sessions {}, "Devices" }
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
