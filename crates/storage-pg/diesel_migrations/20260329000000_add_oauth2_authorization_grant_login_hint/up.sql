ALTER TABLE oauth2_authorization_grants
    ADD COLUMN IF NOT EXISTS login_hint TEXT;
