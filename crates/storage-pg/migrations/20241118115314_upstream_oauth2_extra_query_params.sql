-- Add a column to the upstream_oauth_authorization_sessions table to store
-- extra query parameters
ALTER TABLE "upstream_oauth_authorization_sessions"
    ADD COLUMN "extra_callback_parameters" JSONB;
