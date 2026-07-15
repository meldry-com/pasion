mod api;
mod components;
mod config;
mod pages;
mod utils;

use dioxus::prelude::*;

use crate::{
    api::types::SiteConfig,
    components::theme::{ThemeToggle, init_theme},
    config::get_config,
    pages::{Route, error_pages::ErrorPage},
};

const MAIN_CSS: Asset = asset!("/assets/main.css");

/// Shared, app-wide site configuration.
///
/// Fetched once at the root via [`use_context_provider`] and consumed
/// throughout the tree with [`use_site_config`], so individual pages and the
/// footer don't each re-request `/site-config`.
#[derive(Clone, Copy)]
pub struct SiteConfigContext(pub Resource<Result<SiteConfig, String>>);

/// Read the shared site-config resource from context.
pub fn use_site_config() -> SiteConfigContext {
    use_context::<SiteConfigContext>()
}

fn main() {
    crate::pages::login::preserve_login_query();
    init_theme();
    dioxus::launch(app);
}

fn app() -> Element {
    let cfg = get_config();

    // Fetch site-config once and share it app-wide via context.
    let site_config =
        use_resource(|| async { crate::api::api_get::<SiteConfig>("/site-config").await });
    use_context_provider(|| SiteConfigContext(site_config));

    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        ThemeToggle {}

        if let Some(error) = cfg.error {
            // The backend injected an error state — show the error page
            // instead of the normal SPA routes.
            ErrorPage { error }
        } else {
            Router::<Route> {}
        }
    }
}
