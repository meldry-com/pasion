use dioxus::prelude::*;

use super::footer::Footer;
use crate::graphql::types::SiteConfig;

#[component]
pub fn Layout(wide: Option<bool>, children: Element) -> Element {
    let wide_class = if wide.unwrap_or(false) { " wide" } else { "" };

    rsx! {
        div { class: "layout-container{wide_class}",
            {children}
            FooterSection {}
        }
    }
}

#[component]
fn FooterSection() -> Element {
    let site_config = use_resource(fetch_footer_config);
    let binding = site_config.read();

    match &*binding {
        Some(Ok(config)) => rsx! {
            Footer { site_config: config.clone() }
        },
        _ => rsx! {},
    }
}

async fn fetch_footer_config() -> Result<SiteConfig, String> {
    let data: crate::graphql::types::FooterData = crate::graphql::graphql_request(
        r#"query Footer {
            siteConfig {
                id
                imprint
                tosUri
                policyUri
            }
        }"#,
        None,
    )
    .await?;
    Ok(data.site_config)
}
