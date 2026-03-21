-- Add the response_mode column to the upstream_oauth_providers table
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "response_mode" text NOT NULL DEFAULT 'query';
