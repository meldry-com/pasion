-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_session_authentications_upstream_oauth_session_fk
  ON user_session_authentications (upstream_oauth_authorization_session_id);
