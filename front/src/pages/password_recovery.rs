use dioxus::prelude::*;

use crate::components::layout::Layout;
use crate::components::loading::{LoadingScreen, LoadingSpinner};
use crate::components::page_heading::PageHeading;
use crate::components::password_input::PasswordCreationDoubleInput;
use crate::api::types::{
    ResendRecoveryEmailPayload, SetPasswordPayload, SetPasswordStatus, SiteConfig,
};

/// Recovery ticket state based on query/mutation responses.
#[derive(Debug, Clone, PartialEq)]
enum RecoveryState {
    Loading,
    Valid,
    Expired,
    Consumed,
    Success,
    Error(String),
}

/// Extract the `ticket` query parameter from the current URL.
fn get_ticket_from_url() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(href) = win.location().href() {
                if let Ok(url) = web_sys::Url::new(&href) {
                    let params = url.search_params();
                    if let Some(ticket) = params.get("ticket") {
                        return ticket;
                    }
                }
            }
        }
    }
    String::new()
}

#[component]
pub fn PasswordRecovery() -> Element {
    let ticket = use_signal(|| get_ticket_from_url());
    let new_password = use_signal(String::new);
    let new_password_again = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut resending = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut invalid_new = use_signal(|| false);
    let mut recovery_state = use_signal(|| RecoveryState::Loading);

    let ticket_value = ticket.read().clone();

    // Fetch site config to validate the ticket exists
    let _data = use_resource({
        let ticket_val = ticket_value.clone();
        move || {
            let ticket_val = ticket_val.clone();
            async move {
                if ticket_val.is_empty() {
                    recovery_state.set(RecoveryState::Error(
                        "No recovery ticket found in URL.".to_string(),
                    ));
                    return;
                }
                let result = crate::api::api_get::<SiteConfig>(
                    "/site-config",
                )
                .await;
                match result {
                    Ok(_) => {
                        recovery_state.set(RecoveryState::Valid);
                    }
                    Err(e) => {
                        if e.contains("expired") {
                            recovery_state.set(RecoveryState::Expired);
                        } else if e.contains("consumed") || e.contains("already used") {
                            recovery_state.set(RecoveryState::Consumed);
                        } else {
                            // Default to valid and let the mutation handle errors
                            recovery_state.set(RecoveryState::Valid);
                        }
                    }
                }
            }
        }
    });

    let current_state = recovery_state.read().clone();

    match current_state {
        RecoveryState::Loading => {
            return rsx! { LoadingScreen {} };
        }

        RecoveryState::Success => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "✓".to_string(),
                            title: "Password reset".to_string(),
                            subtitle: "Your password has been reset successfully. You can now sign in with your new password.".to_string(),
                        }
                    }
                }
            };
        }

        RecoveryState::Consumed => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "✗".to_string(),
                            title: "Recovery link already used".to_string(),
                            subtitle: "This password recovery link has already been used. Please request a new one if you still need to reset your password.".to_string(),
                        }
                    }
                }
            };
        }

        RecoveryState::Expired => {
            let ticket_for_resend = ticket_value.clone();
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "⏰".to_string(),
                            title: "Recovery link expired".to_string(),
                            subtitle: "This password recovery link has expired. You can request a new one.".to_string(),
                        }

                        if let Some(ref err) = *error.read() {
                            div { class: "alert alert-critical",
                                p { class: "alert-title", "Error" }
                                p { "{err}" }
                            }
                        }

                        button {
                            class: "btn btn-primary",
                            disabled: resending(),
                            onclick: {
                                let ticket_val = ticket_for_resend.clone();
                                move |_| {
                                    let ticket_val = ticket_val.clone();
                                    resending.set(true);
                                    error.set(None);
                                    spawn(async move {
                                        let result = crate::api::api_post::<ResendRecoveryEmailPayload>(
                                            "/password-recovery/resend",
                                            serde_json::json!({ "ticket": ticket_val }),
                                        ).await;
                                        resending.set(false);
                                        match result {
                                            Ok(_) => {
                                                error.set(None);
                                                recovery_state.set(RecoveryState::Error(
                                                    "A new recovery email has been sent. Please check your inbox.".to_string(),
                                                ));
                                            }
                                            Err(e) => {
                                                error.set(Some(e));
                                            }
                                        }
                                    });
                                }
                            },
                            if resending() {
                                LoadingSpinner { inline: true }
                            }
                            "Resend recovery email"
                        }
                    }
                }
            };
        }

        RecoveryState::Error(ref msg) => {
            return rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "⚠".to_string(),
                            title: "Password recovery".to_string(),
                            subtitle: msg.clone(),
                        }
                    }
                }
            };
        }

        RecoveryState::Valid => {
            // Show the password reset form
        }
    }

    let ticket_for_submit = ticket_value.clone();

    rsx! {
        Layout {
            div { class: "flex flex-col gap-10",
                PageHeading {
                    icon: "🔒".to_string(),
                    title: "Reset your password".to_string(),
                    subtitle: "Enter a new password for your account.".to_string(),
                }

                form {
                    class: "form-root",
                    onsubmit: {
                        let ticket_val = ticket_for_submit.clone();
                        move |e: FormEvent| {
                            e.stop_propagation();
                            let new_pw = new_password.to_string();
                            let new_pw2 = new_password_again.to_string();

                            if new_pw != new_pw2 {
                                error.set(Some("Passwords do not match.".to_string()));
                                return;
                            }

                            let ticket_val = ticket_val.clone();
                            submitting.set(true);
                            error.set(None);
                            invalid_new.set(false);

                            spawn(async move {
                                let result = crate::api::api_post::<SetPasswordPayload>(
                                    "/password-recovery/set",
                                    serde_json::json!({
                                        "ticket": ticket_val,
                                        "newPassword": new_pw,
                                    }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(data) => match data.status {
                                        SetPasswordStatus::Allowed => {
                                            recovery_state.set(RecoveryState::Success);
                                        }
                                        SetPasswordStatus::InvalidNewPassword => {
                                            invalid_new.set(true);
                                            error.set(Some("New password does not meet the requirements.".to_string()));
                                        }
                                        SetPasswordStatus::ExpiredRecoveryTicket => {
                                            recovery_state.set(RecoveryState::Expired);
                                        }
                                        SetPasswordStatus::NoSuchRecoveryTicket => {
                                            recovery_state.set(RecoveryState::Error(
                                                "Invalid recovery ticket.".to_string(),
                                            ));
                                        }
                                        SetPasswordStatus::RecoveryTicketAlreadyUsed => {
                                            recovery_state.set(RecoveryState::Consumed);
                                        }
                                        _ => {
                                            error.set(Some("An error occurred while resetting your password.".to_string()));
                                        }
                                    },
                                    Err(e) => {
                                        error.set(Some(e));
                                    }
                                }
                            });
                        }
                    },

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { class: "alert-title", "Error" }
                            p { "{err}" }
                        }
                    }

                    PasswordCreationDoubleInput {
                        new_password: new_password,
                        new_password_again: new_password_again,
                        force_invalid: invalid_new(),
                    }

                    button {
                        class: "btn btn-primary",
                        r#type: "submit",
                        disabled: submitting(),
                        if submitting() {
                            LoadingSpinner { inline: true }
                        }
                        "Reset password"
                    }
                }
            }
        }
    }
}
