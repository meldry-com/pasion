-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_sessions_user_session_fk
  ON compat_sessions (user_session_id);
