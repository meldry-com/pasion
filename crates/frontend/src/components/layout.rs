use dioxus::prelude::*;

use super::footer::Footer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LayoutWidth {
    #[default]
    Normal,
    Wide,
    Full,
}

#[component]
pub fn Layout(wide: Option<bool>, width: Option<LayoutWidth>, children: Element) -> Element {
    let cls = match width.unwrap_or_else(|| {
        if wide.unwrap_or(false) {
            LayoutWidth::Wide
        } else {
            LayoutWidth::Normal
        }
    }) {
        LayoutWidth::Normal => "",
        LayoutWidth::Wide => " wide",
        LayoutWidth::Full => " full",
    };

    rsx! {
        div { class: "layout-container{cls}",
            {children}
            FooterSection {}
        }
    }
}

#[component]
fn FooterSection() -> Element {
    let site_config = crate::use_site_config().0;
    let binding = site_config.read();

    match &*binding {
        Some(Ok(config)) => rsx! {
            Footer { site_config: config.clone() }
        },
        _ => rsx! {},
    }
}
