use dioxus::prelude::*;

use crate::components::last_active::LastActive;
use crate::components::layout::Layout;
use crate::components::loading::LoadingScreen;
use crate::components::session_card::*;
use crate::graphql::types::{DeviceType, SessionDetailData, SessionNode};
use crate::utils::format_date;

const QUERY: &str = r#"
    query SessionDetail($id: ID!) {
        node(id: $id) {
            __typename
            ... on BrowserSession {
                id displayName
                userAgent { name model os deviceType }
                lastActiveIp lastActiveAt createdAt
                lastAuthentication { id createdAt }
            }
            ... on Oauth2Session {
                id scope displayName
                client { id clientId clientName clientUri logoUri }
                userAgent { name model os deviceType }
                lastActiveIp lastActiveAt createdAt
            }
            ... on CompatSession {
                id deviceId displayName
                userAgent { name model os deviceType }
                lastActiveIp lastActiveAt createdAt
                ssoLogin { id redirectUri }
            }
        }
    }
"#;

const SET_OAUTH2_SESSION_NAME_MUTATION: &str = r#"
    mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String) {
        setOauth2SessionDisplayName(input: { oauth2SessionId: $sessionId, humanName: $displayName }) { status }
    }
"#;

const SET_COMPAT_SESSION_NAME_MUTATION: &str = r#"
    mutation SetCompatSessionName($sessionId: ID!, $displayName: String) {
        setCompatSessionDisplayName(input: { compatSessionId: $sessionId, humanName: $displayName }) { status }
    }
"#;

#[component]
pub fn SessionDetail(id: String) -> Element {
    let id_clone = id.clone();
    let data = use_resource(move || {
        let id = id_clone.clone();
        async move {
            crate::graphql::graphql_request::<SessionDetailData>(
                QUERY,
                Some(serde_json::json!({ "id": id })),
            )
            .await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => match &result.node {
            Some(node) => rsx! {
                Layout {
                    SessionDetailView { node: node.clone() }
                }
            },
            None => rsx! {
                Layout {
                    p { "Session not found." }
                }
            },
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn SessionDetailView(node: SessionNode) -> Element {
    match node {
        SessionNode::BrowserSession(session) => {
            let device_type = session
                .user_agent
                .as_ref()
                .map(|ua| ua.device_type.clone())
                .unwrap_or(DeviceType::Unknown);
            let name = session
                .display_name
                .clone()
                .or_else(|| session.user_agent.as_ref().and_then(|ua| ua.name.clone()))
                .unwrap_or_else(|| "Unknown session".to_string());
            let session_id = session.id.clone();
            let created_at = session.created_at.clone();
            let last_active_at = session.last_active_at.clone();
            let last_active_ip = session.last_active_ip.clone();
            let os = session.user_agent.as_ref().and_then(|ua| ua.os.clone());
            let browser = session.user_agent.as_ref().and_then(|ua| ua.name.clone());
            let last_auth = session
                .last_authentication
                .as_ref()
                .map(|a| a.created_at.clone());

            rsx! {
                div { class: "flex flex-col gap-6",
                    SessionCardHeader { device_type: device_type,
                        SessionCardName { name: name }
                    }
                    SessionCardMetadata {
                        if let Some(ref created) = created_at {
                            SessionCardInfo { label: "Created".to_string(),
                                span { "{format_date(created)}" }
                            }
                        }
                        if let Some(ref last_active) = last_active_at {
                            SessionCardInfo { label: "Last active".to_string(),
                                LastActive { datetime: last_active.clone() }
                            }
                        }
                        if let Some(ref ip) = last_active_ip {
                            SessionCardInfo { label: "IP address".to_string(),
                                span { "{ip}" }
                            }
                        }
                        if let Some(ref os_name) = os {
                            SessionCardInfo { label: "OS".to_string(),
                                span { "{os_name}" }
                            }
                        }
                        if let Some(ref browser_name) = browser {
                            SessionCardInfo { label: "Browser".to_string(),
                                span { "{browser_name}" }
                            }
                        }
                        if let Some(ref auth_at) = last_auth {
                            SessionCardInfo { label: "Last authenticated".to_string(),
                                span { "{format_date(auth_at)}" }
                            }
                        }
                    }
                    EndSessionButton {
                        session_id: session_id,
                        session_type: SessionType::Browser,
                    }
                }
            }
        }
        SessionNode::Oauth2Session(session) => {
            let device_type = session
                .user_agent
                .as_ref()
                .map(|ua| ua.device_type.clone())
                .unwrap_or(DeviceType::Unknown);
            let name = session
                .display_name
                .clone()
                .or_else(|| {
                    session
                        .client
                        .as_ref()
                        .and_then(|c| c.client_name.clone())
                })
                .unwrap_or_else(|| "Unknown app".to_string());
            let session_id = session.id.clone();
            let client_name = session.client.as_ref().and_then(|c| c.client_name.clone());
            let logo_uri = session.client.as_ref().and_then(|c| c.logo_uri.clone());
            let scope = session.scope.clone();
            let created_at = session.created_at.clone();
            let last_active_at = session.last_active_at.clone();
            let last_active_ip = session.last_active_ip.clone();

            rsx! {
                div { class: "flex flex-col gap-6",
                    div { class: "flex items-center gap-2",
                        SessionCardHeader { device_type: device_type,
                            SessionCardName { name: name.clone() }
                            if let Some(ref cn) = client_name {
                                SessionCardClient {
                                    name: cn.clone(),
                                    logo_uri: logo_uri,
                                }
                            }
                        }
                        EditSessionName {
                            session_id: session_id.clone(),
                            current_name: session.display_name.clone().unwrap_or_default(),
                            session_type: EditableSessionType::Oauth2,
                        }
                    }
                    SessionCardMetadata {
                        if let Some(ref s) = scope {
                            SessionCardInfo { label: "Scope".to_string(),
                                span { "{s}" }
                            }
                        }
                        if let Some(ref created) = created_at {
                            SessionCardInfo { label: "Created".to_string(),
                                span { "{format_date(created)}" }
                            }
                        }
                        if let Some(ref last_active) = last_active_at {
                            SessionCardInfo { label: "Last active".to_string(),
                                LastActive { datetime: last_active.clone() }
                            }
                        }
                        if let Some(ref ip) = last_active_ip {
                            SessionCardInfo { label: "IP address".to_string(),
                                span { "{ip}" }
                            }
                        }
                    }
                    EndSessionButton {
                        session_id: session_id,
                        session_type: SessionType::Oauth2,
                    }
                }
            }
        }
        SessionNode::CompatSession(session) => {
            let device_type = session
                .user_agent
                .as_ref()
                .map(|ua| ua.device_type.clone())
                .unwrap_or(DeviceType::Unknown);
            let name = session
                .display_name
                .clone()
                .or_else(|| session.device_id.clone())
                .unwrap_or_else(|| "Unknown session".to_string());
            let session_id = session.id.clone();
            let device_id = session.device_id.clone();
            let created_at = session.created_at.clone();
            let last_active_at = session.last_active_at.clone();
            let last_active_ip = session.last_active_ip.clone();

            rsx! {
                div { class: "flex flex-col gap-6",
                    div { class: "flex items-center gap-2",
                        SessionCardHeader { device_type: device_type,
                            SessionCardName { name: name.clone() }
                        }
                        EditSessionName {
                            session_id: session_id.clone(),
                            current_name: session.display_name.clone().unwrap_or_default(),
                            session_type: EditableSessionType::Compat,
                        }
                    }
                    SessionCardMetadata {
                        if let Some(ref did) = device_id {
                            SessionCardInfo { label: "Device ID".to_string(),
                                span { "{did}" }
                            }
                        }
                        if let Some(ref created) = created_at {
                            SessionCardInfo { label: "Created".to_string(),
                                span { "{format_date(created)}" }
                            }
                        }
                        if let Some(ref last_active) = last_active_at {
                            SessionCardInfo { label: "Last active".to_string(),
                                LastActive { datetime: last_active.clone() }
                            }
                        }
                        if let Some(ref ip) = last_active_ip {
                            SessionCardInfo { label: "IP address".to_string(),
                                span { "{ip}" }
                            }
                        }
                    }
                    EndSessionButton {
                        session_id: session_id,
                        session_type: SessionType::Compat,
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SessionType {
    Browser,
    Oauth2,
    Compat,
}

#[derive(Debug, Clone, PartialEq)]
enum EditableSessionType {
    Oauth2,
    Compat,
}

#[component]
fn EditSessionName(
    session_id: String,
    current_name: String,
    session_type: EditableSessionType,
) -> Element {
    let mut dialog_open = use_signal(|| false);
    let mut display_name = use_signal(|| current_name.clone());
    let mut saving = use_signal(|| false);
    let mut error_msg = use_signal(|| None::<String>);

    rsx! {
        button {
            class: "btn btn-secondary btn-sm",
            onclick: move |_| {
                display_name.set(current_name.clone());
                error_msg.set(None);
                dialog_open.set(true);
            },
            "Edit name"
        }

        if dialog_open() {
            div {
                class: "dialog-overlay",
                onclick: move |_| dialog_open.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |evt| evt.stop_propagation(),
                    h3 { class: "dialog-title", "Edit session name" }

                    if let Some(ref err_text) = *error_msg.read() {
                        div { class: "alert alert-critical", "{err_text}" }
                    }

                    form {
                        class: "form-root",
                        onsubmit: {
                            let sid = session_id.clone();
                            let st = session_type.clone();
                            move |evt: FormEvent| {
                                evt.stop_propagation();
                                let sid = sid.clone();
                                let st = st.clone();
                                let name_val = display_name.to_string();
                                let name_param = if name_val.is_empty() {
                                    serde_json::Value::Null
                                } else {
                                    serde_json::Value::String(name_val)
                                };
                                saving.set(true);
                                error_msg.set(None);
                                spawn(async move {
                                    let query = match st {
                                        EditableSessionType::Oauth2 => SET_OAUTH2_SESSION_NAME_MUTATION,
                                        EditableSessionType::Compat => SET_COMPAT_SESSION_NAME_MUTATION,
                                    };
                                    let result = crate::graphql::graphql_mutation::<serde_json::Value>(
                                        query,
                                        serde_json::json!({
                                            "sessionId": sid,
                                            "displayName": name_param,
                                        }),
                                    ).await;
                                    saving.set(false);
                                    match result {
                                        Ok(_) => {
                                            dialog_open.set(false);
                                            let nav = navigator();
                                            nav.push(crate::pages::Route::Sessions {});
                                        }
                                        Err(err) => {
                                            error_msg.set(Some(err));
                                        }
                                    }
                                });
                            }
                        },

                        div { class: "form-field",
                            label { class: "form-label", "Display name" }
                            input {
                                class: "form-input",
                                r#type: "text",
                                placeholder: "Enter display name",
                                value: "{display_name}",
                                oninput: move |evt| display_name.set(evt.value()),
                            }
                        }

                        div { class: "flex gap-2",
                            button {
                                class: "btn btn-primary",
                                r#type: "submit",
                                disabled: saving(),
                                if saving() {
                                    span { class: "loading-spinner inline" }
                                }
                                "Save"
                            }
                            button {
                                class: "btn btn-tertiary",
                                r#type: "button",
                                disabled: saving(),
                                onclick: move |_| dialog_open.set(false),
                                "Cancel"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn EndSessionButton(session_id: String, session_type: SessionType) -> Element {
    let mut ending = use_signal(|| false);
    let nav = navigator();
    let sid = session_id.clone();
    let st = session_type.clone();

    rsx! {
        button {
            class: "btn btn-destructive",
            disabled: ending(),
            onclick: move |_| {
                let sid = sid.clone();
                let st = st.clone();
                ending.set(true);
                let nav = nav.clone();
                spawn(async move {
                    let (query, var_name) = match st {
                        SessionType::Browser => (
                            r#"mutation EndBrowserSession($id: ID!) {
                                endBrowserSession(input: { browserSessionId: $id }) { status }
                            }"#,
                            "id",
                        ),
                        SessionType::Oauth2 => (
                            r#"mutation EndOAuth2Session($id: ID!) {
                                endOauth2Session(input: { oauth2SessionId: $id }) { status }
                            }"#,
                            "id",
                        ),
                        SessionType::Compat => (
                            r#"mutation EndCompatSession($id: ID!) {
                                endCompatSession(input: { compatSessionId: $id }) { status }
                            }"#,
                            "id",
                        ),
                    };
                    let _ = crate::graphql::graphql_mutation::<serde_json::Value>(
                        query,
                        serde_json::json!({ var_name: sid }),
                    ).await;
                    ending.set(false);
                    nav.push(crate::pages::Route::Sessions {});
                });
            },
            if ending() {
                span { class: "loading-spinner inline" }
            }
            "End session"
        }
    }
}
