-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_sso_logins_session_fk
  ON compat_sso_logins (compat_session_id);
