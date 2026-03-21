-- no-transaction
-- Add partial index for cleanup of orphaned upstream OAuth sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS upstream_oauth_authorization_sessions_orphaned
    ON upstream_oauth_authorization_sessions (upstream_oauth_authorization_session_id)
    WHERE user_session_id IS NULL;
