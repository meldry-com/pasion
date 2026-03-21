-- Add the forward_login_hint column to the upstream_oauth_providers table
ALTER TABLE "upstream_oauth_providers"
    ADD COLUMN "forward_login_hint" BOOLEAN NOT NULL DEFAULT FALSE;
