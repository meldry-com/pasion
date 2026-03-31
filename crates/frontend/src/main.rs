mod api;
mod components;
mod config;
mod pages;
mod utils;

use dioxus::prelude::*;

use crate::config::get_config;
use crate::pages::Route;
use crate::pages::error_pages::ErrorPage;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    crate::pages::login::preserve_login_query();
    dioxus::launch(app);
}

fn app() -> Element {
    let cfg = get_config();

    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }

        if let Some(error) = cfg.error {
            // The backend injected an error state — show the error page
            // instead of the normal SPA routes.
            ErrorPage { error }
        } else {
            Router::<Route> {}
        }
    }
}
