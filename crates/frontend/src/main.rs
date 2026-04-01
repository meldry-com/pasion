mod api;
mod components;
mod config;
mod pages;
mod utils;

use dioxus::prelude::*;
use crate::components::theme::{init_theme, ThemeToggle};
use crate::pages::Route;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    crate::pages::login::preserve_login_query();
    init_theme();
    dioxus::launch(app);
}

fn app() -> Element {
    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        ThemeToggle {}
        Router::<Route> {}
    }
}
