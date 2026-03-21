-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_device_code_grants_client_fk
  ON oauth2_device_code_grant (oauth2_client_id);
