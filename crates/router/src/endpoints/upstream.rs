use ulid::Ulid;

use crate::traits::*;

use super::PostAuthAction;

/// `GET /upstream/authorize/{id}`
pub struct UpstreamOAuth2Authorize {
    id: Ulid,
    post_auth_action: Option<PostAuthAction>,
}

impl UpstreamOAuth2Authorize {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self {
            id,
            post_auth_action: None,
        }
    }

    #[must_use]
    pub fn and_then(mut self, action: PostAuthAction) -> Self {
        self.post_auth_action = Some(action);
        self
    }
}

impl Route for UpstreamOAuth2Authorize {
    type Query = PostAuthAction;
    fn route() -> &'static str {
        "/upstream/authorize/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/authorize/{}", self.id).into()
    }

    fn query(&self) -> Option<&Self::Query> {
        self.post_auth_action.as_ref()
    }
}

/// `GET /upstream/callback/{id}`
pub struct UpstreamOAuth2Callback {
    id: Ulid,
}

impl UpstreamOAuth2Callback {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Callback {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/callback/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/callback/{}", self.id).into()
    }
}

/// `GET /upstream/link/{id}`
pub struct UpstreamOAuth2Link {
    id: Ulid,
}

impl UpstreamOAuth2Link {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2Link {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/link/{link_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/link/{}", self.id).into()
    }
}

/// `POST /upstream/backchannel-logout/{id}`
pub struct UpstreamOAuth2BackchannelLogout {
    id: Ulid,
}

impl UpstreamOAuth2BackchannelLogout {
    #[must_use]
    pub const fn new(id: Ulid) -> Self {
        Self { id }
    }
}

impl Route for UpstreamOAuth2BackchannelLogout {
    type Query = ();
    fn route() -> &'static str {
        "/upstream/backchannel-logout/{provider_id}"
    }

    fn path(&self) -> std::borrow::Cow<'static, str> {
        format!("/upstream/backchannel-logout/{}", self.id).into()
    }
}
