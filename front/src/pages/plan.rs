use dioxus::prelude::*;

use crate::components::loading::LoadingScreen;
use crate::graphql::types::PlanManagementData;
use crate::pages::Route;

const QUERY: &str = r#"
    query PlanManagementTab {
        siteConfig {
            planManagementIframeUri
        }
    }
"#;

#[component]
pub fn Plan() -> Element {
    let data = use_resource(|| async {
        crate::graphql::graphql_request::<PlanManagementData>(QUERY, None).await
    });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => match &result.site_config.plan_management_iframe_uri {
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
