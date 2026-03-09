use dioxus::prelude::*;

use crate::graphql::types::{CompatSession as CompatSessionData, DeviceType};
use crate::pages::Route;

use super::session_card::*;

fn session_display_name(session: &CompatSessionData) -> String {
    if let Some(ref name) = session.display_name {
        return name.clone();
    }
    if let Some(ref device_id) = session.device_id {
        return device_id.clone();
    }
    "Unknown session".to_string()
}

#[component]
pub fn CompatSessionCard(session: CompatSessionData) -> Element {
    let device_type = session
        .user_agent
        .as_ref()
        .map(|ua| ua.device_type.clone())
        .unwrap_or(DeviceType::Unknown);
    let name = session_display_name(&session);

    rsx! {
        SessionCardRoot {
            SessionCardLinkBody {
                to: Route::SessionDetail { id: session.id.clone() },
                SessionCardHeader { device_type: device_type,
                    SessionCardName { name: name }
                }
                SessionCardMetadata {
                    if let Some(ref last_active) = session.last_active_at {
                        SessionCardInfo { label: "Last active".to_string(),
                            crate::components::last_active::LastActive { datetime: last_active.clone() }
                        }
                    }
                    if let Some(ref ip) = session.last_active_ip {
                        SessionCardInfo { label: "IP address".to_string(),
                            span { class: "text-sm", "{ip}" }
                        }
                    }
                    if let Some(ref device_id) = session.device_id {
                        SessionCardInfo { label: "Device ID".to_string(),
                            span { class: "text-sm", "{device_id}" }
                        }
                    }
                }
            }
        }
    }
}
