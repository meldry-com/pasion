use dioxus::prelude::*;

use crate::{
    api::types::{ConsentDataResponse, ConsentSubmitResponse},
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

/// `OAuth2` consent page — shows what permissions a client is requesting.
#[component]
pub fn Consent(grant_id: String) -> Element {
    let gid = grant_id.clone();
    let data = use_resource(move || {
        let id = gid.clone();
        async move { crate::api::api_get::<ConsentDataResponse>(&format!("/oauth2/consent/{id}")).await }
    });
    // Redirect to login when the consent endpoint reports no session.
    let needs_login = matches!(
        &*data.read(),
        Some(Ok(resp)) if resp.error.as_deref() == Some("not_authenticated")
    );
    crate::utils::use_redirect(needs_login, Route::Login {});

    let binding = data.read();

    match &*binding {
        Some(Ok(resp)) => {
            if resp.error.as_deref() == Some("not_authenticated") {
                return rsx! { Layout { p { "Redirecting to login..." } } };
            }
            if resp.policy_violation {
                return rsx! {
                    Layout {
                        div { class: "login-page",
                            div { class: "login-container",
                                h1 { class: "heading-md login-title", "Access Denied" }
                                div { class: "alert alert-critical",
                                    if resp.admin_required {
                                        p { "This application requires an administrator account. The account you are signed in with is not an administrator." }
                                    } else {
                                        p { "This authorization request was denied by policy." }
                                    }
                                }
                            }
                        }
                    }
                };
            }
            rsx! {
                Layout {
                    ConsentForm {
                        data: resp.clone(),
                        grant_id: grant_id.clone(),
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn ConsentForm(data: ConsentDataResponse, grant_id: String) -> Element {
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    let client_name = data
        .client
        .client_name
        .clone()
        .unwrap_or_else(|| data.client.client_id.clone());

    let scopes: Vec<&str> = data.scope.split_whitespace().collect();

    rsx! {
        div { class: "login-page consent-page",
            div { class: "login-container",
                h1 { class: "heading-md login-title", "Authorize {client_name}" }

                if let Some(ref uri) = data.client.logo_uri {
                    div { class: "consent-logo",
                        img { src: "{uri}", alt: "{client_name}", width: "64", height: "64" }
                    }
                }

                p { class: "text-secondary",
                    strong { "{client_name}" }
                    " wants to access your account as "
                    strong { "{data.user.mxid}" }
                }

                if !scopes.is_empty() {
                    div { class: "consent-scopes",
                        p { class: "form-label", "This will allow the application to:" }
                        ul {
                            for scope in scopes.iter() {
                                li { {scope_description(scope)} }
                            }
                        }
                    }
                }

                if let Some(ref err) = *error.read() {
                    div { class: "alert alert-critical",
                        p { "{err}" }
                    }
                }

                div { class: "consent-actions",
                    button {
                        class: "btn btn-primary btn-block",
                        disabled: submitting(),
                        onclick: {
                            let gid = grant_id.clone();
                            move |_| {
                                submitting.set(true);
                                error.set(None);
                                let gid = gid.clone();

                                spawn(async move {
                                    let result = crate::api::api_post::<ConsentSubmitResponse>(
                                        &format!("/oauth2/consent/{gid}"),
                                        serde_json::json!({ "action": "consent" }),
                                    ).await;
                                    match result {
                                        Ok(resp) if resp.status == "success" => {
                                            if let Some(_url) = resp.redirect_url {
                                                // Keep the button disabled: we are about to
                                                // navigate away, and re-enabling it opens a
                                                // window for a duplicate submit that the
                                                // backend would reject with "grant is not
                                                // pending".
                                                #[cfg(target_arch = "wasm32")]
                                                {
                                                    if let Some(win) = web_sys::window() {
                                                        // Use assign() for a full navigation
                                                        // (more reliable than set_href in some
                                                        // WASM scenarios).
                                                        let _ = win.location().assign(&_url);
                                                    }
                                                }
                                            } else {
                                                submitting.set(false);
                                                error.set(Some("No redirect URL in response.".to_owned()));
                                            }
                                        }
                                        // A 401 comes back from `api_post` as `Err`, not `Ok`
                                        // (see `api::request`), so the session-expired case is
                                        // handled in the `Err` arm below.
                                        Ok(resp) => {
                                            submitting.set(false);
                                            error.set(Some(resp.error.unwrap_or_else(|| "Authorization failed.".to_owned())));
                                        }
                                        Err(e) => {
                                            submitting.set(false);
                                            if e == "not_authenticated" {
                                                // Session expired — redirect to login so the
                                                // user can re-authenticate and retry.
                                                navigator().push(Route::Login {});
                                            } else {
                                                error.set(Some(e));
                                            }
                                        }
                                    }
                                });
                            }
                        },
                        "Allow"
                    }
                }

                if let Some(ref uri) = data.client.client_uri {
                    div { class: "login-register",
                        a { class: "link", href: "{uri}", target: "_blank",
                            "About {client_name}"
                        }
                    }
                }
            }
        }
    }
}

fn scope_description(scope: &str) -> String {
    match scope {
        "openid" => "Verify your identity".to_owned(),
        "profile" => "View your profile information".to_owned(),
        "email" => "View your email address".to_owned(),
        "phone" => "View your phone number".to_owned(),
        "address" => "View your address".to_owned(),
        "urn:matrix:org.matrix.msc2967.client:api:*" => {
            "Access the Matrix API on your behalf".to_owned()
        }
        "urn:matrix:org.matrix.msc2967.client:device:*" => "Manage your devices".to_owned(),
        other if other.starts_with("urn:pasion:admin") || other.starts_with("urn:mas:admin") => {
            "Administrative access".to_owned()
        }
        other => other.to_owned(),
    }
}
