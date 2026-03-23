use dioxus::prelude::*;

use crate::components::loading::LoadingScreen;
use crate::api::types::SiteConfig;
use crate::pages::Route;

#[component]
pub fn Plan() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<SiteConfig>("/site-config").await
    });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => match &result.plan_management_iframe_uri {
            Some(uri) => {
                let uri = uri.clone();
                rsx! {
                    iframe {
                        class: "plan-iframe",
                        title: "Plan management",
                        src: "{uri}",
                        scrolling: "no",
                    }
                }
            }
            None => {
                nav.push(Route::AccountSettings {});
                rsx! {}
            }
        },
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
