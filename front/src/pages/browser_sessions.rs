use dioxus::prelude::*;

use crate::components::browser_session::BrowserSessionCard;
use crate::components::empty_state::EmptyState;
use crate::components::loading::LoadingScreen;
use crate::graphql::types::BrowserSessionListData;

const QUERY: &str = r#"
    query BrowserSessionList($first: Int, $after: String, $last: Int, $before: String, $lastActive: DateFilter) {
        viewerSession {
            __typename
            ... on BrowserSession {
                id
                user {
                    id
                    browserSessions(last: $last, before: $before, first: $first, after: $after, state: ACTIVE, lastActive: $lastActive) {
                        totalCount
                        edges {
                            cursor
                            node {
                                id displayName
                                userAgent { name model os deviceType }
                                lastActiveIp lastActiveAt createdAt
                            }
                        }
                        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
                    }
                }
            }
        }
    }
"#;

#[component]
pub fn BrowserSessions() -> Element {
    let mut show_inactive = use_signal(|| false);

    let data = use_resource(move || {
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
            crate::graphql::graphql_request::<BrowserSessionListData>(
                QUERY,
                Some(vars),
            )
            .await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let session = match result.viewer_session.as_browser_session() {
                Some(s) => s,
                None => return rsx! { p { "Not authenticated." } },
            };

            let user = match &session.user {
                Some(u) => u,
                None => return rsx! { p { "User data unavailable." } },
            };

            let browser_sessions: Vec<_> = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.edges.iter().rev().collect::<Vec<_>>())
                .unwrap_or_default();

            let total_count = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.total_count)
                .unwrap_or(0);

            let current_id = &session.id;
            let inactive_active = show_inactive();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h5 { class: "heading-xs", "Browser sessions" }

                    // Inactive session filter toggle
                    div { class: "flex items-center gap-2",
                        button {
                            class: if inactive_active { "filter-toggle active" } else { "filter-toggle" },
                            onclick: move |_| show_inactive.set(!show_inactive()),
                            "Show inactive (90+ days)"
                        }
                    }

                    for edge in browser_sessions.iter() {
                        BrowserSessionCard {
                            key: "{edge.cursor}",
                            session: edge.node.clone(),
                            is_current: *current_id == edge.node.id,
                        }
                    }

                    if total_count == 0 {
                        EmptyState { "No active browser sessions" }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
