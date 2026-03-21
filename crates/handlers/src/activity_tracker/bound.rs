use std::net::IpAddr;

use pasion_data_model::{
    BrowserSession, Clock, CompatSession, Session, personal::session::PersonalSession,
};

use crate::activity_tracker::ActivityTracker;

/// An activity tracker with an IP address bound to it.
#[derive(Clone)]
pub struct Bound {
    tracker: ActivityTracker,
    ip: Option<IpAddr>,
}

impl Bound {
    /// Create a new bound activity tracker.
    #[must_use]
    pub fn new(tracker: ActivityTracker, ip: Option<IpAddr>) -> Self {
        Self { tracker, ip }
    }

    /// Get the IP address bound to this activity tracker.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Record activity in an OAuth 2.0 session.
    pub async fn record_oauth2_session(&self, clock: &dyn Clock, session: &Session) {
        self.tracker
            .record_oauth2_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a personal session.
    pub async fn record_personal_session(&self, clock: &dyn Clock, session: &PersonalSession) {
        self.tracker
            .record_personal_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a compatibility session.
    pub async fn record_compat_session(&self, clock: &dyn Clock, session: &CompatSession) {
        self.tracker
            .record_compat_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(&self, clock: &dyn Clock, session: &BrowserSession) {
        self.tracker
            .record_browser_session(clock, session, self.ip)
            .await;
    }
}
