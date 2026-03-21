-- Add a user-provided human name to OAuth 2.0 sessions
ALTER TABLE oauth2_sessions
    ADD COLUMN human_name TEXT;
