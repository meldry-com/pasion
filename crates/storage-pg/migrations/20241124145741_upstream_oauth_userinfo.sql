-- Add columms to upstream_oauth_providers and upstream_oauth_authorization_sessions
-- table to handle userinfo endpoint.
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "fetch_userinfo" BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN "userinfo_endpoint_override" TEXT;

ALTER TABLE "upstream_oauth_authorization_sessions"
  ADD COLUMN "userinfo" JSONB;
