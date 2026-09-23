use dioxus::prelude::*;

use crate::{
    api::types::{
        BootstrapAdminStatus, ClaimBootstrapAdminResponse, LinkedAccount, ProvidersResponse,
        ViewerResponse,
    },
    components::{
        collapsible::CollapsibleSection,
        dialog::Dialog,
        linked_accounts::{LinkProvidersRow, LinkedAccountRow},
        loading::LoadingScreen,
        password_input::{AccountManagementPasswordPreview, PasswordInput},
        separator::{Separator, SeparatorKind},
        user_email::UserEmailList,
        user_profile::AddEmailForm,
    },
    pages::Route,
};

#[component]
pub fn AccountSettings() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let bootstrap_status = use_resource(|| async {
        crate::api::api_get::<BootstrapAdminStatus>("/bootstrap-admin-status").await
    });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let Some(session) = result.viewer_session.as_browser_session() else {
                return rsx! { p { "Not authenticated." } };
            };

            let Some(user) = result.viewer.as_user() else {
                return rsx! { p { "User data unavailable." } };
            };

            let emails: Vec<_> = user
                .emails
                .as_ref()
                .map(|ec| ec.edges.iter().map(|e| e.node.clone()).collect())
                .unwrap_or_default();
            let email_count = user.emails.as_ref().map_or(0, |ec| ec.total_count);
            let has_password = user.has_password.unwrap_or(false);
            let linked_accounts: Vec<LinkedAccount> =
                user.linked_accounts.clone().unwrap_or_default();
            let email_change_allowed = result.site_config.email_change_allowed;
            let password_login_enabled = result.site_config.password_login_enabled;
            let account_deactivation_allowed = result.site_config.account_deactivation_allowed;
            let can_claim_admin = !user.can_request_admin
                && matches!(&*bootstrap_status.read(), Some(Ok(status)) if status.setup_required);
            let session_id = session.id.clone();
            let user_mxid = user
                .matrix
                .as_ref()
                .map(|m| m.mxid.clone())
                .unwrap_or_default();

            rsx! {
                div { class: "flex flex-col gap-6",
                    // Email section
                    if email_change_allowed || email_count > 0 {
                        CollapsibleSection { title: "Contact info".to_owned(), default_open: true,
                            UserEmailList {
                                emails: emails,
                                email_change_allowed: email_change_allowed,
                            }
                            if email_change_allowed {
                                AddEmailForm {
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
                        CollapsibleSection { title: "Account password".to_owned(), default_open: true,
                            AccountManagementPasswordPreview {}
                        }
                        Separator { kind: SeparatorKind::Section }
                    }

                    // Linked accounts section
                    LinkedAccountsSection { accounts: linked_accounts.clone() }
                    Separator { kind: SeparatorKind::Section }

                    // E2EE section
                    CollapsibleSection { title: "Encryption".to_owned(),
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

                    if can_claim_admin {
                        ClaimAdminSection {}
                        Separator { kind: SeparatorKind::Section }
                    }

                    // Sign out
                    SignOutButton { session_id: session_id.clone() }

                    // Account deactivation
                    if account_deactivation_allowed {
                        Separator {}
                        AccountDeleteButton {
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
fn ClaimAdminSection() -> Element {
    let mut show_dialog = use_signal(|| false);
    let mut token = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    rsx! {
        CollapsibleSection { title: "Administrator access".to_owned(), default_open: true,
            p { class: "text-md text-secondary",
                "This site has no administrator yet. Enter the bootstrap token to claim the first administrator account."
            }
            button {
                class: "btn btn-secondary",
                r#type: "button",
                onclick: move |_| {
                    token.set(String::new());
                    error.set(None);
                    show_dialog.set(true);
                },
                "Become an administrator"
            }
        }

        Dialog { open: show_dialog, title: "Become an administrator".to_owned(),
            form {
                class: "form-root",
                onsubmit: move |event| {
                    event.prevent_default();
                    let submitted_token = token.to_string();
                    if submitted_token.trim().is_empty() {
                        error.set(Some("Enter the bootstrap token.".to_owned()));
                        return;
                    }
                    submitting.set(true);
                    error.set(None);
                    spawn(async move {
                        let result = crate::api::api_post::<ClaimBootstrapAdminResponse>(
                            "/bootstrap-admin-status/claim",
                            serde_json::json!({ "token": submitted_token }),
                        ).await;
                        submitting.set(false);
                        match result {
                            Ok(response) if response.status == "claimed" => {
                                token.set(String::new());
                                if let Some(window) = web_sys::window() {
                                    let _ = window.location().reload();
                                }
                            }
                            Ok(response) if response.status == "invalid_token" => {
                                error.set(Some("The bootstrap token is invalid.".to_owned()));
                            }
                            Ok(response) if response.status == "unavailable" => {
                                error.set(Some("Administrator setup is no longer available.".to_owned()));
                            }
                            Ok(_) => error.set(Some("Could not claim administrator access.".to_owned())),
                            Err(message) => error.set(Some(message)),
                        }
                    });
                },
                div { class: "form-field",
                    label { class: "form-label", r#for: "bootstrap-admin-token", "Bootstrap token" }
                    PasswordInput {
                        id: "bootstrap-admin-token",
                        name: "bootstrap_admin_token",
                        autocomplete: "off".to_owned(),
                        value: token.read().clone(),
                        oninput: move |event: FormEvent| token.set(event.value()),
                    }
                }
                if let Some(ref message) = *error.read() {
                    div { class: "alert alert-critical", role: "alert", "{message}" }
                }
                button {
                    class: "btn btn-primary",
                    r#type: "submit",
                    disabled: submitting() || token.read().trim().is_empty(),
                    if submitting() { span { class: "loading-spinner inline" } }
                    "Claim administrator access"
                }
                button {
                    class: "btn btn-tertiary",
                    r#type: "button",
                    disabled: submitting(),
                    onclick: move |_| show_dialog.set(false),
                    "Cancel"
                }
            }
        }
    }
}

#[component]
fn SignOutButton(session_id: String) -> Element {
    let nav = navigator();
    let mut show_dialog = use_signal(|| false);
    let mut signing_out = use_signal(|| false);
    let session_id_clone = session_id.clone();

    rsx! {
        button {
            class: "btn btn-destructive btn-lg",
            onclick: move |_| show_dialog.set(true),
            "Sign out"
        }

        Dialog { open: show_dialog, title: "Sign out".to_owned(),
            button {
                class: "btn btn-destructive-solid",
                disabled: signing_out(),
                onclick: {
                    let sid = session_id_clone.clone();
                    move |_| {
                        let sid = sid.clone();
                        let nav = nav;
                        signing_out.set(true);
                        spawn(async move {
                            let _ = crate::api::api_delete::<crate::api::types::EndSessionPayload>(
                                &format!("/browser-sessions/{sid}"),
                            ).await;
                            nav.push(Route::Login {});
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

// ── Linked accounts section ─────────────────────────────────────

#[component]
fn LinkedAccountsSection(accounts: Vec<LinkedAccount>) -> Element {
    let mut accounts_signal = use_signal(|| accounts.clone());
    let mut unlinking_id = use_signal(|| None::<String>);
    let mut error = use_signal(|| None::<String>);

    // Fetch available providers to show "Link" buttons for unlinked ones
    let providers_data = use_resource(|| async {
        crate::api::api_get::<ProvidersResponse>("/auth/providers").await
    });

    rsx! {
        CollapsibleSection { title: "Linked accounts".to_owned(), default_open: true,
            p { class: "text-md text-secondary",
                "Connect external accounts to enable additional sign-in methods."
            }

            // Show currently linked accounts
            if accounts_signal.read().is_empty() {
                p { class: "text-md text-secondary text-italic",
                    "No external accounts linked."
                }
            } else {
                div { class: "flex flex-col gap-3",
                    for account in accounts_signal.read().iter() {
                        {
                            let account_id = account.id.clone();
                            let is_unlinking = unlinking_id.read().as_deref() == Some(&account_id);
                            rsx! {
                                LinkedAccountRow {
                                    account: account.clone(),
                                    is_unlinking: is_unlinking,
                                    unlink_disabled: unlinking_id.read().is_some(),
                                    on_unlink: move |aid: String| {
                                        unlinking_id.set(Some(aid.clone()));
                                        error.set(None);
                                        spawn(async move {
                                            let result = crate::api::api_delete::<crate::api::types::UnlinkResponse>(
                                                &format!("/linked-accounts/{aid}"),
                                            ).await;
                                            match result {
                                                Ok(_) => {
                                                    accounts_signal.write().retain(|a| a.id != aid);
                                                }
                                                Err(e) => {
                                                    error.set(Some(e));
                                                }
                                            }
                                            unlinking_id.set(None);
                                        });
                                    },
                                }
                            }
                        }
                    }
                }
            }

            if let Some(ref err) = *error.read() {
                div { class: "alert alert-critical mt-2", "{err}" }
            }

            // Show available providers that can be linked
            if let Some(Ok(providers)) = &*providers_data.read() {
                {
                    let linked_provider_ids: Vec<String> = accounts_signal.read()
                        .iter()
                        .map(|a| a.provider_id.clone())
                        .collect();
                    let unlinked: Vec<_> = providers.providers.iter()
                        .filter(|p| !linked_provider_ids.contains(&p.id))
                        .cloned()
                        .collect::<Vec<_>>();
                    if unlinked.is_empty() {
                        rsx! {}
                    } else {
                        rsx! {
                            div { class: "mt-3",
                                LinkProvidersRow { providers: unlinked }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AccountDeleteButton(mxid: String, has_password: bool, password_login_enabled: bool) -> Element {
    let nav = navigator();
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
            class: "btn btn-tertiary text-destructive",
            onclick: move |_| {
                erase_data.set(false);
                error.set(None);
                password.set(String::new());
                mxid_confirm.set(String::new());
                show_dialog.set(true);
            },
            "Deactivate account"
        }

        Dialog { open: show_dialog, title: "Deactivate account".to_owned(),
            {
                rsx! {
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
                    label { class: "checkbox-label",
                        input {
                            r#type: "checkbox",
                            checked: erase_data(),
                            onchange: move |e| erase_data.set(e.checked()),
                        }
                        "Erase all my data"
                    }

                    if erase_data() {
                        div { class: "alert alert-critical",
                            p { class: "alert-title", "Warning" }
                            p { "All your messages and media will be permanently deleted from the server. This cannot be reversed." }
                        }
                    }

                    // Password or MXID confirmation
                    if use_password_mode {
                        div { class: "form-field",
                            label { class: "form-label", r#for: "deactivate-password", "Enter your password to confirm" }
                            PasswordInput {
                                id: "deactivate-password",
                                name: "password",
                                autocomplete: "current-password".to_owned(),
                                value: password.read().clone(),
                                oninput: move |e: FormEvent| password.set(e.value()),
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
                        class: "btn btn-destructive-solid",
                        disabled: deactivating() || !confirm_enabled() || !form_valid,
                        onclick: {
                            move |_| {
                                let hs_erase = erase_data();
                                let pw = if use_password_mode {
                                    Some(password.to_string())
                                } else {
                                    None
                                };
                                let nav = nav;
                                deactivating.set(true);
                                error.set(None);
                                spawn(async move {
                                    let mut body = serde_json::json!({
                                        "hs_erase": hs_erase,
                                    });
                                    if let Some(ref pw_val) = pw {
                                        body.as_object_mut().unwrap().insert(
                                            "password".to_owned(),
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
                                                nav.push(Route::Login {});
                                            }
                                            crate::api::types::DeactivateUserStatus::NotFound => {
                                                error.set(Some("Account not found.".to_owned()));
                                            }
                                            crate::api::types::DeactivateUserStatus::IncorrectPassword => {
                                                error.set(Some("Incorrect password.".to_owned()));
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
