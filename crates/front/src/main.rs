mod api;
mod components;
mod config;
mod pages;
mod utils;

use dioxus::prelude::*;

use crate::pages::Route;

fn main() {
    dioxus::launch(app);
}

fn app() -> Element {
    rsx! {
        Router::<Route> {}
    }
}
