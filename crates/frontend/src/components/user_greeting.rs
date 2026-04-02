use dioxus::prelude::*;

use crate::api::types::{MatrixUser, PatchViewerProfileResponse, UserProfile};

#[component]
pub fn UserGreeting(
    matrix: MatrixUser,
    profile: UserProfile,
    display_name_change_allowed: bool,
) -> Element {
    let mut show_edit_dialog = use_signal(|| false);
    let mut current_profile = use_signal(|| profile.clone());
    let mut current_matrix = use_signal(|| matrix.clone());

    let display_name = current_profile
        .read()
        .display_name
        .clone()
        .or_else(|| current_matrix.read().display_name.clone());
    let initial = display_name
        .as_ref()
        .and_then(|name| name.chars().next())
        .or_else(|| current_matrix.read().mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    rsx! {
        div { class: "user-greeting",
            div { class: "user-avatar", "{initial}" }
            div { class: "user-meta",
                if let Some(display_name) = display_name {
                    span { class: "text-lg font-semibold", "{display_name}" }
                    span { class: "user-mxid", "{current_matrix.read().mxid}" }
                } else {
                    span { class: "text-lg font-semibold", "{current_matrix.read().mxid}" }
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

        if show_edit_dialog() {
            EditProfileDialog {
                open: show_edit_dialog,
                profile: current_profile.read().clone(),
                matrix: current_matrix.read().clone(),
                on_saved: move |response: PatchViewerProfileResponse| {
                    current_profile.set(response.profile);
                    current_matrix.set(response.matrix);
                },
            }
        }
    }
}

#[component]
fn EditProfileDialog(
    open: Signal<bool>,
    profile: UserProfile,
    matrix: MatrixUser,
    on_saved: EventHandler<PatchViewerProfileResponse>,
) -> Element {
    let mut display_name_value = use_signal(|| profile.display_name.clone().unwrap_or_default());
    let mut avatar_url_value = use_signal(|| profile.avatar_url.clone().unwrap_or_default());
    let mut preferred_locale_value =
        use_signal(|| profile.preferred_locale.clone().unwrap_or_default());
    let mut saving = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let avatar_initial = profile
        .display_name
        .as_ref()
        .or(matrix.display_name.as_ref())
        .and_then(|name| name.chars().next())
        .or_else(|| matrix.mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

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
                    "{avatar_initial}"
                }

                if let Some(err) = error.read().clone() {
                    div { class: "alert alert-critical",
                        p { class: "alert-title", "Error" }
                        p { "{err}" }
                    }
                }

                form {
                    class: "form-root",
                    onsubmit: move |e| {
                        e.stop_propagation();
                        let display_name = display_name_value.to_string();
                        let avatar_url = avatar_url_value.to_string();
                        let preferred_locale = preferred_locale_value.to_string();
                        saving.set(true);
                        error.set(None);
                        spawn(async move {
                            let response = crate::api::api_patch::<PatchViewerProfileResponse>(
                                "/viewer/profile",
                                serde_json::json!({
                                    "displayName": if display_name.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(display_name) },
                                    "avatarUrl": if avatar_url.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(avatar_url) },
                                    "preferredLocale": if preferred_locale.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(preferred_locale) },
                                }),
                            ).await;

                            saving.set(false);
                            match response {
                                Ok(data) => {
                                    on_saved.call(data);
                                    open.set(false);
                                }
                                Err(err_msg) => error.set(Some(err_msg)),
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
                        label { class: "form-label", "Avatar URL" }
                        input {
                            class: "form-input",
                            r#type: "url",
                            placeholder: "https://example.com/avatar.png",
                            value: "{avatar_url_value}",
                            oninput: move |e| avatar_url_value.set(e.value()),
                        }
                        span { class: "form-help", "Optional avatar image URL stored by Pasion." }
                    }

                    div { class: "form-field",
                        label { class: "form-label", "Preferred locale" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "zh-CN",
                            value: "{preferred_locale_value}",
                            oninput: move |e| preferred_locale_value.set(e.value()),
                        }
                        span { class: "form-help", "Used for localized notifications and future profile settings." }
                    }

                    div { class: "form-field",
                        label { class: "form-label", "Matrix ID" }
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
