-- Start tracking the associated user_session directly on the authorization session
ALTER TABLE upstream_oauth_authorization_sessions
    ADD COLUMN user_session_id UUID
    REFERENCES user_sessions (user_session_id)
    ON DELETE SET NULL;
