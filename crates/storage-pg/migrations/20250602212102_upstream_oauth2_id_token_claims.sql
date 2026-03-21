-- This is the decoded claims from the ID token stored as JSONB
ALTER TABLE upstream_oauth_authorization_sessions
    ADD COLUMN id_token_claims JSONB;
