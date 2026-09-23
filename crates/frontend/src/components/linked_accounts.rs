use dioxus::prelude::*;

use crate::api::types::{LinkedAccount, UpstreamProvider};

/// A single linked upstream account with an "Unlink" action.
///
/// Shared between the account settings page and the identity bindings page.
/// The parent owns the unlink state machine and receives the account id via
/// `on_unlink`.
#[component]
pub fn LinkedAccountRow(
    account: LinkedAccount,
    /// Whether this specific row's unlink request is in flight (shows a
    /// spinner).
    is_unlinking: bool,
    /// Whether the unlink button is disabled (e.g. another request in flight,
    /// or this is the last connected account).
    unlink_disabled: bool,
    /// Optional tooltip for the unlink button.
    title: Option<String>,
    on_unlink: EventHandler<String>,
) -> Element {
    let account_id = account.id.clone();
    let display_name = account
        .human_account_name
        .clone()
        .or_else(|| Some(account.subject.clone()))
        .unwrap_or_default();
    let provider_label = account
        .provider_name
        .clone()
        .or_else(|| account.provider_brand.clone())
        .unwrap_or_else(|| "External provider".to_owned());

    rsx! {
        div { class: "flex items-center justify-between p-3 rounded-lg border",
            div { class: "flex flex-col gap-1",
                span { class: "text-md font-semibold", "{provider_label}" }
                span { class: "text-sm text-secondary", "{display_name}" }
            }
            button {
                class: "btn btn-destructive btn-sm",
                disabled: unlink_disabled,
                title: title,
                onclick: move |_| on_unlink.call(account_id.clone()),
                if is_unlinking { "Unlinking…" } else { "Unlink" }
            }
        }
    }
}

/// A row of "Link <provider>" buttons for upstream providers that are not yet
/// linked. `providers` is expected to already be filtered to the unlinked set.
#[component]
pub fn LinkProvidersRow(providers: Vec<UpstreamProvider>) -> Element {
    rsx! {
        div { class: "flex flex-wrap gap-2",
            for provider in providers.iter() {
                a {
                    class: "btn btn-secondary btn-sm",
                    href: "{provider.authorize_url}",
                    "Link {provider.human_name.clone().unwrap_or_else(|| provider.id.clone())}"
                }
            }
        }
    }
}
