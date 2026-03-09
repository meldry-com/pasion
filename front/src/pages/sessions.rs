use dioxus::prelude::*;

use crate::components::compat_session::CompatSessionCard;
use crate::components::empty_state::EmptyState;
use crate::components::loading::LoadingScreen;
use crate::components::oauth2_session::OAuth2SessionCard;
use crate::components::separator::{Separator, SeparatorKind};
use crate::graphql::types::{AppSession, AppSessionsListData, SessionsOverviewData};
use crate::pages::Route;

const OVERVIEW_QUERY: &str = r#"
    query SessionsOverview {
        viewer {
            __typename
            ... on User {
                id
                browserSessions(first: 0, state: ACTIVE) {
                    totalCount
                }
            }
        }
    }
"#;

const LIST_QUERY: &str = r#"
    query AppSessionsList($first: Int, $after: String, $last: Int, $before: String, $lastActive: DateFilter) {
        viewer {
            __typename
            ... on User {
                id
                appSessions(last: $last, before: $before, first: $first, after: $after, state: ACTIVE, lastActive: $lastActive) {
                    edges {
                        cursor
                        node {
                            __typename
                            ... on CompatSession {
                                id deviceId displayName
                                userAgent { name model os deviceType }
                                lastActiveIp lastActiveAt createdAt
                            }
                            ... on Oauth2Session {
                                id scope displayName
                                client { id clientId clientName clientUri logoUri }
                                userAgent { name model os deviceType }
                                lastActiveIp lastActiveAt createdAt
                            }
                        }
                    }
                    totalCount
                    pageInfo { startCursor endCursor hasNextPage hasPreviousPage }
                }
            }
        }
    }
"#;

#[component]
pub fn Sessions() -> Element {
    let mut show_inactive = use_signal(|| false);

    let overview = use_resource(|| async {
        crate::graphql::graphql_request::<SessionsOverviewData>(OVERVIEW_QUERY, None).await
    });

    let sessions = use_resource(move || {
        let inactive = show_inactive();
        async move {
            let mut vars = serde_json::json!({ "last": 6 });
            if inactive {
                let cutoff = crate::utils::get_ninety_days_ago();
                vars.as_object_mut().unwrap().insert(
                    "lastActive".to_string(),
                    serde_json::json!({ "before": cutoff }),
                );
            }
            crate::graphql::graphql_request::<AppSessionsListData>(
                LIST_QUERY,
                Some(vars),
            )
            .await
        }
    });

    let overview_binding = overview.read();
    let sessions_binding = sessions.read();

    match (&*overview_binding, &*sessions_binding) {
        (Some(Ok(overview_data)), Some(Ok(session_data))) => {
            let user = match overview_data.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { p { "Not authenticated." } },
            };

            let session_user = match session_data.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { p { "Not authenticated." } },
            };

            let browser_session_count = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.total_count)
                .unwrap_or(0);

            let app_sessions: Vec<_> = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.edges.iter().rev().collect::<Vec<_>>())
                .unwrap_or_default();

            let total_count = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.total_count)
                .unwrap_or(0);

            let inactive_active = show_inactive();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Sessions" }

                    // Inactive session filter toggle
                    div { class: "flex items-center gap-2",
                        button {
                            class: if inactive_active { "filter-toggle active" } else { "filter-toggle" },
                            onclick: move |_| show_inactive.set(!show_inactive()),
                            "Show inactive (90+ days)"
                        }
                    }

                    // Browser sessions overview
                    div { class: "browser-sessions-overview",
                        Link {
                            class: "session-card compact",
                            to: Route::BrowserSessions {},
                            div { class: "flex items-center justify-between",
                                span { "Browser sessions" }
                                span { class: "text-sm text-secondary", "{browser_session_count} active" }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // App sessions list
                    for edge in app_sessions.iter() {
                        match &edge.node {
                            AppSession::Oauth2Session(session) => rsx! {
                                OAuth2SessionCard { key: "{edge.cursor}", session: session.clone() }
                            },
                            AppSession::CompatSession(session) => rsx! {
                                CompatSessionCard { key: "{edge.cursor}", session: session.clone() }
                            },
                        }
                    }

                    if total_count == 0 {
                        EmptyState { "No active app sessions" }
                    }
                }
            }
        }
        (Some(Err(e)), _) | (_, Some(Err(e))) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        _ => rsx! { LoadingScreen {} },
    }
}
