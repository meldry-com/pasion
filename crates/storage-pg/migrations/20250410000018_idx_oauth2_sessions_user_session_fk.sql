-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_sessions_user_session_fk
  ON oauth2_sessions (user_session_id);
