-- Track what upstream OAuth session to associate during user registration
ALTER TABLE user_registrations
    ADD COLUMN upstream_oauth_authorization_session_id UUID
      REFERENCES upstream_oauth_authorization_sessions (upstream_oauth_authorization_session_id)
      ON DELETE SET NULL;
