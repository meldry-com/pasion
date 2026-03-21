-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_device_code_grants_session_fk
  ON oauth2_device_code_grant (oauth2_session_id);
