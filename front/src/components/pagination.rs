use dioxus::prelude::*;

use crate::pages::Route;

#[component]
pub fn PaginationControls(
    has_previous: bool,
    has_next: bool,
    on_previous: Option<Route>,
    on_next: Option<Route>,
) -> Element {
    if !has_previous && !has_next {
        return rsx! {};
    }

    rsx! {
        div { class: "pagination-controls",
            if let Some(prev_route) = on_previous {
                Link {
                    class: if has_previous { "btn btn-secondary btn-sm" } else { "btn btn-secondary btn-sm" },
                    to: prev_route,
                    "Previous"
                }
            } else {
                button {
                    class: "btn btn-secondary btn-sm",
                    disabled: true,
                    "Previous"
                }
            }
            // Spacer
            div {}
            if let Some(next_route) = on_next {
                Link {
                    class: if has_next { "btn btn-secondary btn-sm" } else { "btn btn-secondary btn-sm" },
                    to: next_route,
                    "Next"
                }
            } else {
                button {
                    class: "btn btn-secondary btn-sm",
                    disabled: true,
                    "Next"
                }
            }
        }
    }
}
