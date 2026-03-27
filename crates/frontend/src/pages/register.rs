use dioxus::prelude::*;

use crate::{
    api::types::{ProvidersResponse, RegisterResponse, StepResponse},
    components::{
        layout::Layout, loading::LoadingSpinner, password_input::PasswordCreationDoubleInput,
    },
    pages::Route,
};

/// Registration entry page — shows password registration form and/or upstream
/// provider buttons.
#[component]
pub fn Register() -> Element {
    let providers_data = use_resource(|| async {
        crate::api::api_get::<ProvidersResponse>("/auth/providers").await
    });
    let binding = providers_data.read();

    match &*binding {
        Some(Ok(data)) => rsx! {
            Layout {
                RegisterPage { providers: data.clone() }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! {
            Layout {
                RegisterPage {
                    providers: ProvidersResponse {
                        providers: vec![],
                        password_login_enabled: true,
                        password_registration_enabled: true,
                    },
                }
            }
        },
    }
}

#[component]
fn RegisterPage(providers: ProvidersResponse) -> Element {
    let mut username = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut phone = use_signal(String::new);
    let new_password = use_signal(String::new);
    let new_password_again = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let has_providers = !providers.providers.is_empty();
    let reg_enabled = providers.password_registration_enabled;

    rsx! {
        div { class: "login-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Create account" }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                if reg_enabled {
                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let user = username.to_string();
                            let em = email.to_string();
                            let ph = phone.to_string();
                            let pw = new_password.to_string();
                            let pw2 = new_password_again.to_string();

                            if user.is_empty() {
                                error.set(Some("Username is required.".to_string()));
                                return;
                            }
                            if pw.is_empty() {
                                error.set(Some("Password is required.".to_string()));
                                return;
                            }
                            if pw != pw2 {
                                error.set(Some("Passwords do not match.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<RegisterResponse>(
                                    "/auth/register",
                                    serde_json::json!({
                                        "username": user,
                                        "email": if em.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(em) },
                                        "phone": if ph.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(ph) },
                                        "password": pw,
                                        "password_confirm": pw2,
                                    }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        if let Some(id) = resp.id {
                                            match resp.next_step.as_deref() {
                                                Some("verify_email") => {
                                                    nav.push(Route::RegisterVerifyEmail { id });
                                                }
                                                Some("verify_phone") => {
                                                    nav.push(Route::RegisterVerifyPhone { id });
                                                }
                                                Some("display_name") => {
                                                    nav.push(Route::RegisterDisplayName { id });
                                                }
                                                _ => {
                                                    nav.push(Route::RegisterFinish { id });
                                                }
                                            }
                                        }
                                    }
                                    Ok(resp) => {
                                        let msg = resp.error.unwrap_or_else(|| "Registration failed.".to_string());
                                        error.set(Some(msg));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Username" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "username",
                                required: true,
                                placeholder: "Choose a username",
                                value: "{username}",
                                oninput: move |e| username.set(e.value()),
                            }
                        }

                        div { class: "form-field",
                            label { class: "form-label", "Email (optional)" }
                            input {
                                class: "form-input",
                                r#type: "email",
                                autocomplete: "email",
                                placeholder: "your@email.com",
                                value: "{email}",
                                oninput: move |e| email.set(e.value()),
                            }
                        }

                        div { class: "form-field",
                            label { class: "form-label", "Phone (optional)" }
                            input {
                                class: "form-input",
                                r#type: "tel",
                                autocomplete: "tel",
                                placeholder: "+1234567890",
                                value: "{phone}",
                                oninput: move |e| phone.set(e.value()),
                            }
                        }

                        PasswordCreationDoubleInput {
                            new_password: new_password,
                            new_password_again: new_password_again,
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Create account"
                        }
                    }
                }

                if has_providers && reg_enabled {
                    div { class: "login-divider",
                        span { "or" }
                    }
                }

                if has_providers {
                    div { class: "login-providers",
                        for provider in providers.providers.iter() {
                            a {
                                class: "btn btn-secondary btn-block",
                                href: "{provider.authorize_url}",
                                {provider.human_name.clone().unwrap_or_else(|| format!("Sign up with {}", provider.id))}
                            }
                        }
                    }
                }

                div { class: "login-register",
                    span { "Already have an account? " }
                    Link { class: "link", to: Route::Login {},
                        "Sign in"
                    }
                }
            }
        }
    }
}

/// Email verification step during registration.
#[component]
pub fn RegisterVerifyEmail(id: String) -> Element {
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Verify your email" }
                    p { class: "text-secondary", "We sent a verification code to your email address. Please enter it below." }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let c = code.to_string();
                            if c.is_empty() {
                                error.set(Some("Please enter the verification code.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/verify-email"),
                                    serde_json::json!({ "code": c }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        match resp.next_step.as_deref() {
                                            Some("display_name") => { nav.push(Route::RegisterDisplayName { id: rid }); }
                                            _ => { nav.push(Route::RegisterFinish { id: rid }); }
                                        }
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Invalid code.".to_string())));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Verification code" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "one-time-code",
                                required: true,
                                placeholder: "6-digit code",
                                value: "{code}",
                                oninput: move |e| code.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Verify"
                        }
                    }
                }
            }
        }
    }
}

/// Phone verification step during registration.
#[component]
pub fn RegisterVerifyPhone(id: String) -> Element {
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Verify your phone" }
                    p { class: "text-secondary", "We sent a verification code to your phone number. Please enter it below." }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let c = code.to_string();
                            if c.is_empty() {
                                error.set(Some("Please enter the verification code.".to_string()));
                                return;
                            }

                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/verify-phone"),
                                    serde_json::json!({ "code": c }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        match resp.next_step.as_deref() {
                                            Some("verify_email") => { nav.push(Route::RegisterVerifyEmail { id: rid }); }
                                            Some("display_name") => { nav.push(Route::RegisterDisplayName { id: rid }); }
                                            _ => { nav.push(Route::RegisterFinish { id: rid }); }
                                        }
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Invalid code.".to_string())));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Verification code" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                autocomplete: "one-time-code",
                                required: true,
                                placeholder: "6-digit code",
                                value: "{code}",
                                oninput: move |e| code.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Verify"
                        }
                    }
                }
            }
        }
    }
}

/// Display name step during registration.
#[component]
pub fn RegisterDisplayName(id: String) -> Element {
    let mut display_name = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let nav = navigator();
    let reg_id = id.clone();
    let reg_id2 = id.clone();

    rsx! {
        Layout {
            div { class: "login-page",
                div { class: "login-container",
                    h1 { class: "heading-md login-title", "Choose a display name" }
                    p { class: "text-secondary", "This is how others will see you. You can change it later." }

                    if let Some(ref err) = *error.read() {
                        div { class: "alert alert-critical",
                            p { "{err}" }
                        }
                    }

                    form {
                        class: "form-root",
                        onsubmit: move |e| {
                            e.prevent_default();
                            e.stop_propagation();
                            let name = display_name.to_string();
                            submitting.set(true);
                            error.set(None);
                            let nav = nav.clone();
                            let rid = reg_id.clone();

                            spawn(async move {
                                let result = crate::api::api_post::<StepResponse>(
                                    &format!("/auth/register/{rid}/display-name"),
                                    serde_json::json!({ "display_name": name }),
                                ).await;
                                submitting.set(false);
                                match result {
                                    Ok(resp) if resp.status == "success" => {
                                        nav.push(Route::RegisterFinish { id: rid });
                                    }
                                    Ok(resp) => {
                                        error.set(Some(resp.error.unwrap_or_else(|| "Failed.".to_string())));
                                    }
                                    Err(e) => error.set(Some(e)),
                                }
                            });
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Display name" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                placeholder: "Your name",
                                value: "{display_name}",
                                oninput: move |e| display_name.set(e.value()),
                            }
                        }

                        button {
                            class: "btn btn-primary btn-block",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() {
                                LoadingSpinner { inline: true }
                            }
                            "Continue"
                        }

                        button {
                            class: "btn btn-tertiary btn-block",
                            r#type: "button",
                            disabled: submitting(),
                            onclick: move |_| {
                                submitting.set(true);
                                error.set(None);
                                let nav = nav.clone();
                                let rid = reg_id2.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<StepResponse>(
                                        &format!("/auth/register/{rid}/display-name"),
                                        serde_json::json!({ "skip": true }),
                                    ).await;
                                    submitting.set(false);
                                    match result {
                                        Ok(_) => { nav.push(Route::RegisterFinish { id: rid }); }
                                        Err(e) => error.set(Some(e)),
                                    }
                                });
                            },
                            "Skip"
                        }
                    }
                }
            }
        }
    }
}

/// Final registration step — creates the user account.
#[component]
pub fn RegisterFinish(id: String) -> Element {
    let nav = navigator();
    let reg_id = id.clone();

    let finish_result = use_resource(move || {
        let rid = reg_id.clone();
        async move {
            crate::api::api_post::<StepResponse>(
                &format!("/auth/register/{rid}/finish"),
                serde_json::json!({}),
            )
            .await
        }
    });
    let binding = finish_result.read();

    match &*binding {
        Some(Ok(resp)) if resp.status == "success" => {
            // Auto-navigate to account page after successful registration
            nav.push(Route::AccountSettings {});
            rsx! {
                Layout {
                    div { class: "login-page",
                        div { class: "login-container",
                            h1 { class: "heading-md login-title", "Account created!" }
                            p { "Redirecting..." }
                        }
                    }
                }
            }
        }
        Some(Ok(resp)) => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        h1 { class: "heading-md login-title", "Registration failed" }
                        div { class: "alert alert-critical",
                            p { {resp.error.clone().unwrap_or_else(|| "Could not complete registration.".to_string())} }
                        }
                        Link { class: "btn btn-primary", to: Route::Register {},
                            "Try again"
                        }
                    }
                }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        div { class: "alert alert-critical", "{e}" }
                        Link { class: "btn btn-primary", to: Route::Register {},
                            "Try again"
                        }
                    }
                }
            }
        },
        None => rsx! {
            Layout {
                div { class: "login-page",
                    div { class: "login-container",
                        h1 { class: "heading-md login-title", "Creating your account..." }
                        LoadingSpinner {}
                    }
                }
            }
        },
    }
}
