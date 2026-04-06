use dioxus::prelude::*;

use crate::api::types::{MatrixUser, PatchViewerProfileResponse, UserProfile};

#[component]
pub fn UserGreeting(
    matrix: MatrixUser,
    profile: UserProfile,
    display_name_change_allowed: bool,
    on_edit: EventHandler,
) -> Element {
    let display_name = profile
        .display_name
        .clone()
        .or_else(|| matrix.display_name.clone());
    let initial = display_name
        .as_ref()
        .and_then(|name| name.chars().next())
        .or_else(|| matrix.mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    let avatar_url = profile.avatar_url.clone();

    rsx! {
        div { class: "user-greeting",
            if let Some(ref url) = avatar_url {
                img {
                    class: "user-avatar",
                    src: "{url}",
                    alt: "Avatar",
                }
            } else {
                div { class: "user-avatar", "{initial}" }
            }
            div { class: "user-meta",
                if let Some(display_name) = display_name {
                    span { class: "text-lg font-semibold", "{display_name}" }
                    span { class: "user-mxid", "{matrix.mxid}" }
                } else {
                    span { class: "text-lg font-semibold", "{matrix.mxid}" }
                }
            }
            if display_name_change_allowed {
                button {
                    class: "btn btn-tertiary btn-sm",
                    onclick: move |_| on_edit.call(()),
                    "Edit"
                }
            }
        }
    }
}

#[component]
pub fn EditProfileDialog(
    open: Signal<bool>,
    profile: UserProfile,
    matrix: MatrixUser,
    on_saved: EventHandler<PatchViewerProfileResponse>,
) -> Element {
    let mut display_name_value = use_signal(|| profile.display_name.clone().unwrap_or_default());
    let mut preferred_locale_value =
        use_signal(|| profile.preferred_locale.clone().unwrap_or_default());
    let mut saving = use_signal(|| false);
    let mut uploading_avatar = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut current_avatar_url = use_signal(|| profile.avatar_url.clone());

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

                // Avatar section with upload
                div { class: "flex flex-col items-center gap-3",
                    if let Some(ref url) = *current_avatar_url.read() {
                        img {
                            class: "user-avatar self-center",
                            style: "width: 88px; height: 88px; object-fit: cover;",
                            src: "{url}",
                            alt: "Avatar",
                        }
                    } else {
                        div { class: "user-avatar self-center",
                            style: "width: 88px; height: 88px; font-size: 32px;",
                            "{avatar_initial}"
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        r#type: "button",
                        disabled: uploading_avatar(),
                        onclick: move |_| {
                            uploading_avatar.set(true);
                            error.set(None);
                            spawn(async move {
                                let js = r#"
                                    return await new Promise((resolve, reject) => {
                                        const input = document.createElement('input');
                                        input.type = 'file';
                                        input.accept = 'image/png,image/jpeg,image/gif,image/webp';
                                        input.onchange = async () => {
                                            try {
                                                const file = input.files[0];
                                                if (!file) { resolve(null); return; }
                                                if (file.size > 5 * 1024 * 1024) {
                                                    reject('File too large (max 5 MB)');
                                                    return;
                                                }
                                                const formData = new FormData();
                                                formData.append('avatar', file);
                                                const response = await fetch('/api/v1/viewer/avatar', {
                                                    method: 'POST',
                                                    body: formData,
                                                    credentials: 'same-origin',
                                                });
                                                if (!response.ok) {
                                                    const text = await response.text();
                                                    reject(text);
                                                    return;
                                                }
                                                const result = await response.json();
                                                resolve(result.avatarUrl);
                                            } catch (e) {
                                                reject(e.message || 'Upload failed');
                                            }
                                        };
                                        input.click();
                                    });
                                "#;
                                match document::eval(js).await {
                                    Ok(val) => {
                                        if let Some(url) = val.as_str() {
                                            current_avatar_url.set(Some(url.to_string()));
                                        }
                                    }
                                    Err(e) => {
                                        error.set(Some(format!("Avatar upload failed: {e}")));
                                    }
                                }
                                uploading_avatar.set(false);
                            });
                        },
                        if uploading_avatar() {
                            span { class: "loading-spinner inline" }
                            "Uploading..."
                        } else {
                            "Upload avatar"
                        }
                    }
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
                        let preferred_locale = preferred_locale_value.to_string();
                        let avatar_url = current_avatar_url.read().clone();
                        saving.set(true);
                        error.set(None);
                        spawn(async move {
                            let response = crate::api::api_patch::<PatchViewerProfileResponse>(
                                "/viewer/profile",
                                serde_json::json!({
                                    "displayName": if display_name.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(display_name) },
                                    "avatarUrl": match avatar_url {
                                        Some(url) => serde_json::Value::String(url),
                                        None => serde_json::Value::Null,
                                    },
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
