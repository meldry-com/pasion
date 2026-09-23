use dioxus::prelude::*;

/// Declarative redirect hook.
///
/// Must be called unconditionally at the top level of a component to keep
/// hook ordering stable. When `when` becomes `true`, the navigator pushes
/// `to` from inside an effect (i.e. after render), avoiding the
/// render-phase `nav.push()` anti-pattern.
pub fn use_redirect(when: bool, to: crate::pages::Route) {
    use_effect(use_reactive!(|(when, to)| {
        if when {
            navigator().push(to);
        }
    }));
}

/// Like [`use_redirect`] but navigates to an arbitrary URL string (used for
/// external/raw redirect URLs returned by the backend).
pub fn use_redirect_url(when: bool, to: String) {
    use_effect(use_reactive!(|(when, to)| {
        if when {
            navigator().push(to);
        }
    }));
}

/// Format a relative time string from a datetime string.
#[allow(
    clippy::disallowed_methods,
    reason = "relative browser display must compare with the viewer's current wall clock"
)]
pub fn format_last_active(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(dt);

        if duration.num_minutes() < 3 {
            return "Active now".to_owned();
        }
        if duration.num_hours() < 1 {
            let mins = duration.num_minutes();
            return format!("{mins} minutes ago");
        }
        if duration.num_hours() < 24 {
            let hours = duration.num_hours();
            return format!("{hours} hours ago");
        }
        if duration.num_days() < 90 {
            let days = duration.num_days();
            return format!("{days} days ago");
        }
        return "Inactive for 90+ days".to_owned();
    }
    datetime.to_owned()
}

/// Format a datetime string to a readable date.
pub fn format_date(datetime: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(datetime) {
        return dt.format("%b %d, %Y %H:%M").to_string();
    }
    datetime.to_owned()
}
