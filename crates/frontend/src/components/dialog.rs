use dioxus::prelude::*;

/// A controlled modal dialog.
///
/// Visibility is driven entirely by the `open` signal. Clicking the overlay
/// backdrop closes it; clicks inside the content are not propagated.
///
/// - `open`: controlled visibility signal.
/// - `title`: optional heading rendered as a `.dialog-title`.
/// - `trigger`: optional element rendered before the dialog that sets
///   `open` to `true` when clicked. Omit it for fully-controlled dialogs
///   whose open state is managed by an external button.
/// - `children`: dialog body (forms, actions, etc.).
#[component]
pub fn Dialog(
    mut open: Signal<bool>,
    title: Option<String>,
    trigger: Option<Element>,
    children: Element,
) -> Element {
    rsx! {
        if let Some(trigger) = trigger {
            div {
                onclick: move |_| open.set(true),
                {trigger}
            }
        }

        if open() {
            div {
                class: "dialog-overlay",
                onclick: move |_| open.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |e| e.stop_propagation(),
                    if let Some(title) = title {
                        h3 { class: "dialog-title", "{title}" }
                    }
                    {children}
                }
            }
        }
    }
}

#[component]
pub fn DialogTitle(children: Element) -> Element {
    rsx! {
        h3 { class: "dialog-title", {children} }
    }
}

#[component]
pub fn DialogClose(open: Signal<bool>, children: Element) -> Element {
    rsx! {
        div {
            onclick: move |_| open.set(false),
            {children}
        }
    }
}
