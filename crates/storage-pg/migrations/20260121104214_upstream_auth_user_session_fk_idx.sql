-- no-transaction
-- Adds an index on the user_session_id column
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_authorization_sessions_user_session_id_idx
  ON upstream_oauth_authorization_sessions (user_session_id);
