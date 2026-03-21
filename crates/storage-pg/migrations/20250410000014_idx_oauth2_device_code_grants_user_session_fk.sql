-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_device_code_grants_user_session_fk
  ON oauth2_device_code_grant (user_session_id);
