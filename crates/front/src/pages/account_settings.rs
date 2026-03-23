use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{
        collapsible::CollapsibleSection,
        loading::LoadingScreen,
        password_input::AccountManagementPasswordPreview,
        separator::{Separator, SeparatorKind},
        user_email::UserEmailList,
        user_profile::AddEmailForm,
    },
    pages::Route,
};

#[component]
pub fn AccountSettings() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let session = match result.viewer_session.as_browser_session() {
                Some(s) => s,
                None => {
                    return rsx! { p { "Not authenticated." } };
                }
            };

            let user = match &session.user {
                Some(u) => u,
                None => {
                    return rsx! { p { "User data unavailable." } };
                }
            };

            let emails: Vec<_> = user
                .emails
                .as_ref()
                .map(|ec| ec.edges.iter().map(|e| e.node.clone()).collect())
                .unwrap_or_default();
            let email_count = user.emails.as_ref().map(|ec| ec.total_count).unwrap_or(0);
            let has_password = user.has_password.unwrap_or(false);
            let email_change_allowed = result.site_config.email_change_allowed;
            let password_login_enabled = result.site_config.password_login_enabled;
            let account_deactivation_allowed = result.site_config.account_deactivation_allowed;
            let session_id = session.id.clone();
            let user_id = user.id.clone();
            let user_mxid = user
                .matrix
                .as_ref()
                .map(|m| m.mxid.clone())
                .unwrap_or_default();

            rsx! {
                div { class: "flex flex-col gap-6",
                    // Email section
                    if email_change_allowed || email_count > 0 {
                        CollapsibleSection { title: "Contact info".to_string(), default_open: true,
                            UserEmailList {
                                emails: emails,
                                email_change_allowed: email_change_allowed,
                            }
                            if email_change_allowed {
                                AddEmailForm {
                                    user_id: user_id.clone(),
                                    on_add: move |id: String| {
                                        nav.push(Route::EmailVerify { id });
                                    },
                                }
                            }
                        }
                        Separator { kind: SeparatorKind::Section }
                    }

                    // Password section
                    if password_login_enabled && has_password {
                        CollapsibleSection { title: "Account password".to_string(), default_open: true,
                            AccountManagementPasswordPreview {}
                        }
                        Separator { kind: SeparatorKind::Section }
                    }

                    // E2EE section
                    CollapsibleSection { title: "Encryption".to_string(),
                        p { class: "text-md text-secondary",
                            "Resetting your end-to-end encryption keys will clear your current encryption keys and force a re-verification of all sessions."
                        }
                        Link {
                            class: "btn btn-secondary",
                            to: Route::ResetCrossSigning {},
                            "Reset encryption"
                        }
                    }
                    Separator { kind: SeparatorKind::Section }

                    // Sign out
                    SignOutButton { session_id: session_id.clone() }

                    // Account deactivation
                    if account_deactivation_allowed {
                        Separator {}
                        AccountDeleteButton {
                            user_id: user_id.clone(),
                            mxid: user_mxid.clone(),
                            has_password: has_password,
                            password_login_enabled: password_login_enabled,
                        }
                    }

                    Separator {}
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn SignOutButton(session_id: String) -> Element {
    let mut show_dialog = use_signal(|| false);
    let mut signing_out = use_signal(|| false);
    let session_id_clone = session_id.clone();

    rsx! {
        button {
            class: "btn btn-destructive btn-lg",
            onclick: move |_| show_dialog.set(true),
            "Sign out"
        }

        if show_dialog() {
            div {
                class: "dialog-overlay",
                onclick: move |_| show_dialog.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |e| e.stop_propagation(),

                    h3 { class: "dialog-title", "Sign out" }

                    button {
                        class: "btn btn-destructive",
                        disabled: signing_out(),
                        onclick: {
                            let sid = session_id_clone.clone();
                            move |_| {
                                let sid = sid.clone();
                                signing_out.set(true);
                                spawn(async move {
                                    let _ = crate::api::api_delete::<crate::api::types::EndSessionPayload>(
                                        &format!("/browser-sessions/{}", sid),
                                    ).await;
                                    #[cfg(target_arch = "wasm32")]
                                    {
                                        if let Some(win) = web_sys::window() {
                                            let _ = win.location().reload();
                                        }
                                    }
                                });
                            }
                        },
                        if signing_out() {
                            span { class: "loading-spinner inline" }
                        }
                        "Sign out"
                    }

                    button {
                        class: "btn btn-tertiary",
                        onclick: move |_| show_dialog.set(false),
                        "Cancel"
                    }
                }
            }
        }
    }
}

#[component]
fn AccountDeleteButton(
    user_id: String,
    mxid: String,
    has_password: bool,
    password_login_enabled: bool,
) -> Element {
    let mut show_dialog = use_signal(|| false);
    let mut deactivating = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut erase_data = use_signal(|| false);
    let mut confirm_enabled = use_signal(|| false);
    let mut password = use_signal(String::new);
    let mut mxid_confirm = use_signal(String::new);
    let mxid_clone = mxid.clone();
    let mxid_for_check = mxid.clone();

    let use_password_mode = has_password && password_login_enabled;

    // When dialog opens, start a delay before enabling the confirm button
    let _delay_effect = use_effect(move || {
        if show_dialog() {
            confirm_enabled.set(false);
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(3000).await;
                confirm_enabled.set(true);
            });
        }
    });

    // Check if confirmation is valid
    let form_valid = if use_password_mode {
        !password.read().is_empty()
    } else {
        *mxid_confirm.read() == mxid_for_check
    };

    rsx! {
        button {
            class: "btn btn-tertiary",
            style: "color: var(--color-destructive);",
            onclick: move |_| {
                erase_data.set(false);
                error.set(None);
                password.set(String::new());
                mxid_confirm.set(String::new());
                show_dialog.set(true);
            },
            "Deactivate account"
        }

        if show_dialog() {
            div {
                class: "dialog-overlay",
                onclick: move |_| show_dialog.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |e| e.stop_propagation(),

                    h3 { class: "dialog-title", "Deactivate account" }

                    if !mxid_clone.is_empty() {
                        p { class: "text-md",
                            "Account: "
                            strong { "{mxid_clone}" }
                        }
                    }

                    p { class: "text-md text-secondary",
                        "Are you sure you want to deactivate your account? This action cannot be undone."
                    }

                    // Erase data checkbox
                    label {
                        class: "flex items-center gap-2",
                        style: "cursor: pointer; margin: 8px 0;",
                        input {
                            r#type: "checkbox",
                            checked: erase_data(),
                            onchange: move |e| erase_data.set(e.checked()),
                        }
                        span { class: "text-md", "Erase all my data" }
                    }

                    if erase_data() {
                        div { class: "alert alert-critical",
                            style: "margin-bottom: 8px;",
                            p { class: "alert-title", "Warning" }
                            p { "All your messages and media will be permanently deleted from the server. This cannot be reversed." }
                        }
                    }

                    // Password or MXID confirmation
                    if use_password_mode {
                        div { class: "form-field",
                            label { class: "form-label", "Enter your password to confirm" }
                            input {
                                class: "form-input",
                                r#type: "password",
                                autocomplete: "current-password",
                                value: "{password}",
                                oninput: move |e| password.set(e.value()),
                            }
                        }
                    } else if !mxid_clone.is_empty() {
                        div { class: "form-field",
                            label { class: "form-label",
                                "Type "
                                strong { "{mxid_clone}" }
                                " to confirm"
                            }
                            input {
                                class: "form-input",
                                r#type: "text",
                                value: "{mxid_confirm}",
                                oninput: move |e| mxid_confirm.set(e.value()),
                            }
                        }
                    }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical", "{err}" }
                    }

                    button {
                        class: "btn btn-destructive",
                        disabled: deactivating() || !confirm_enabled() || !form_valid,
                        onclick: {
                            move |_| {
                                let hs_erase = erase_data();
                                let pw = if use_password_mode {
                                    Some(password.to_string())
                                } else {
                                    None
                                };
                                deactivating.set(true);
                                error.set(None);
                                spawn(async move {
                                    let mut body = serde_json::json!({
                                        "hsErase": hs_erase,
                                    });
                                    if let Some(ref pw_val) = pw {
                                        body.as_object_mut().unwrap().insert(
                                            "password".to_string(),
                                            serde_json::Value::String(pw_val.clone()),
                                        );
                                    }
                                    let result = crate::api::api_post::<crate::api::types::DeactivateUserPayload>(
                                        "/viewer/deactivate",
                                        body,
                                    ).await;
                                    deactivating.set(false);
                                    match result {
                                        Ok(data) => match data.status {
                                            crate::api::types::DeactivateUserStatus::Deactivated => {
                                                #[cfg(target_arch = "wasm32")]
                                                {
                                                    if let Some(win) = web_sys::window() {
                                                        let _ = win.location().reload();
                                                    }
                                                }
                                            }
                                            crate::api::types::DeactivateUserStatus::NotFound => {
                                                error.set(Some("Account not found.".to_string()));
                                            }
                                            crate::api::types::DeactivateUserStatus::IncorrectPassword => {
                                                error.set(Some("Incorrect password.".to_string()));
                                            }
                                        },
                                        Err(e) => {
                                            error.set(Some(e));
                                        }
                                    }
                                });
                            }
                        },
                        if deactivating() {
                            span { class: "loading-spinner inline" }
                        }
                        if !confirm_enabled() {
                            "Please wait..."
                        } else {
                            "Deactivate"
                        }
                    }

                    button {
                        class: "btn btn-tertiary",
                        onclick: move |_| show_dialog.set(false),
                        "Cancel"
                    }
                }
            }
        }
    }
}
