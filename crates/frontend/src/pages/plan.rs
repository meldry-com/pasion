use dioxus::prelude::*;

use crate::{components::loading::LoadingScreen, pages::Route};

#[component]
pub fn Plan() -> Element {
    let data = crate::use_site_config().0;
    let binding = data.read();

    // When site-config has loaded but there is no plan iframe, redirect to the
    // overview. Computed at the top level so the hook order stays stable.
    let no_plan = matches!(
        &*binding,
        Some(Ok(result)) if result.plan_management_iframe_uri.is_none()
    );
    crate::utils::use_redirect(no_plan, Route::AccountOverview {});

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
            None => rsx! {},
        },
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
