-- Add the human_account_name column to the upstream_oauth_links table to store
-- a human-readable name for the upstream account
ALTER TABLE "upstream_oauth_links"
  ADD COLUMN "human_account_name" TEXT;
