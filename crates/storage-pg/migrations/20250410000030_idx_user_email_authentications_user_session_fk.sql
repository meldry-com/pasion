-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_email_authentications_user_session_fk
  ON user_email_authentications (user_session_id);
