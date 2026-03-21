-- no-transaction
-- Redundant with the `compat_sessions_user_fk`
DROP INDEX IF EXISTS compat_sessions_user_id_last_active_at;
