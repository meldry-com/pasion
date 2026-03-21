use dioxus::prelude::*;

use crate::graphql::types::MatrixUser;

#[component]
pub fn UserGreeting(
    matrix: MatrixUser,
    user_id: String,
    display_name_change_allowed: bool,
) -> Element {
    let mut show_edit_dialog = use_signal(|| false);
    let initial = matrix
        .display_name
        .as_ref()
        .and_then(|n| n.chars().next())
        .or_else(|| matrix.mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    rsx! {
        div { class: "user-greeting",
            div { class: "user-avatar", "{initial}" }
            div { class: "user-meta",
                if let Some(ref display_name) = matrix.display_name {
                    span { class: "text-lg font-semibold", "{display_name}" }
                    span { class: "user-mxid", "{matrix.mxid}" }
                } else {
                    span { class: "text-lg font-semibold", "{matrix.mxid}" }
                }
            }
            if display_name_change_allowed {
                button {
                    class: "btn btn-tertiary btn-sm",
                    onclick: move |_| show_edit_dialog.set(true),
                    "Edit"
                }
            }
        }

        // Edit display name dialog
        if show_edit_dialog() {
            EditDisplayNameDialog {
                open: show_edit_dialog,
                user_id: user_id.clone(),
                matrix: matrix.clone(),
            }
        }
    }
}

#[component]
fn EditDisplayNameDialog(open: Signal<bool>, user_id: String, matrix: MatrixUser) -> Element {
    let mut display_name_value = use_signal(|| {
        matrix.display_name.clone().unwrap_or_default()
    });
    let mut saving = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let user_id_clone = user_id.clone();

    rsx! {
        div {
            class: "dialog-overlay",
            onclick: move |_| open.set(false),
            div {
                class: "dialog-content",
                onclick: move |e| e.stop_propagation(),

                h3 { class: "dialog-title", "Edit profile" }

                div { class: "user-avatar self-center",
                    style: "width: 88px; height: 88px; font-size: 32px;",
                    {matrix.display_name.as_ref()
                        .and_then(|n| n.chars().next())
                        .or_else(|| matrix.mxid.chars().nth(1))
                        .unwrap_or('?')
                        .to_uppercase()
                        .to_string()}
                }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { class: "alert-title", "Error" }
                        p { "{err}" }
                    }
                }

                form {
                    class: "form-root",
                    onsubmit: move |e| {
                        e.stop_propagation();
                        let name = display_name_value.to_string();
                        let uid = user_id_clone.clone();
                        saving.set(true);
                        error.set(None);
                        spawn(async move {
                            let display_name = if name.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(name) };
                            let result = crate::graphql::api_post::<crate::graphql::types::SetDisplayNamePayload>(
                                "/viewer/display-name",
                                serde_json::json!({
                                    "userId": uid,
                                    "displayName": display_name,
                                }),
                            ).await;
                            saving.set(false);
                            match result {
                                Ok(data) if data.status == crate::graphql::types::SetDisplayNameStatus::Set => {
                                    open.set(false);
                                }
                                Ok(_) => {
                                    error.set(Some("Invalid display name.".to_string()));
                                }
                                Err(e) => {
                                    error.set(Some(e));
                                }
                            }
                        });
                    },

                    div { class: "form-field",
                        label { class: "form-label", "Display name" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            autocomplete: "name",
                            value: "{display_name_value}",
                            oninput: move |e| display_name_value.set(e.value()),
                        }
                        span { class: "form-help", "Your display name is shown to other users." }
                    }

                    div { class: "form-field",
                        label { class: "form-label", "Username" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            value: "{matrix.mxid}",
                            readonly: true,
                        }
                    }

                    button {
                        class: "btn btn-primary",
                        r#type: "submit",
                        disabled: saving(),
                        if saving() {
                            span { class: "loading-spinner inline" }
                        }
                        "Save"
                    }
                }

                button {
                    class: "btn btn-tertiary",
                    onclick: move |_| open.set(false),
                    "Cancel"
                }
            }
        }
    }
}
