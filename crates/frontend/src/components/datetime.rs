use dioxus::prelude::*;

use crate::utils::format_date;

#[component]
pub fn DateTime(datetime: String) -> Element {
    let formatted = format_date(&datetime);
    rsx! {
        time { datetime: "{datetime}", "{formatted}" }
    }
}
