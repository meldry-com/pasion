-- no-transaction
-- Redundant with the `oauth2_sessions_user_fk`
DROP INDEX IF EXISTS oauth2_sessions_user_id_last_active_at;
