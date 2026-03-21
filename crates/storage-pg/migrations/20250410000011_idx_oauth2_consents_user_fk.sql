-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_consents_user_fk
  ON oauth2_consents (user_id);
