-- no-transaction
-- This adds an index on the revoked_at field on oauth2_refresh_tokens to speed up cleaning them up
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_tokens_revoked_at_idx
  ON oauth2_refresh_tokens (revoked_at) WHERE revoked_at IS NOT NULL;
