-- no-transaction
-- Redundant with the `user_sessions_user_fk`
DROP INDEX IF EXISTS user_sessions_user_id_last_active_at;
