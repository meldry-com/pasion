-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_session_authentications_user_password_fk
  ON user_session_authentications (user_password_id);
