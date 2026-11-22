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
    if let Ok(dt) = datetime.parse::<jiff::Timestamp>() {
        let now = jiff::Timestamp::now();
        let duration = now.duration_since(dt);

        if duration.as_mins() < 3 {
            return "Active now".to_owned();
        }
        if duration.as_hours() < 1 {
            let mins = duration.as_mins();
            return format!("{mins} minutes ago");
        }
        if duration.as_hours() < 24 {
            let hours = duration.as_hours();
            return format!("{hours} hours ago");
        }
        if (duration.as_hours() / 24) < 90 {
            let days = duration.as_hours() / 24;
            return format!("{days} days ago");
        }
        return "Inactive for 90+ days".to_owned();
    }
    datetime.to_owned()
}

/// Format a datetime string to a readable date.
pub fn format_date(datetime: &str) -> String {
    if let Ok(pieces) = jiff::fmt::temporal::Pieces::parse(datetime)
        && let Some(time) = pieces.time()
        && pieces.offset().is_some()
    {
        return pieces
            .date()
            .to_datetime(time)
            .strftime("%b %d, %Y %H:%M")
            .to_string();
    }
    datetime.to_owned()
}
