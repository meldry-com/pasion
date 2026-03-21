-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_session_authentications_user_session_fk
  ON user_session_authentications (user_session_id);
