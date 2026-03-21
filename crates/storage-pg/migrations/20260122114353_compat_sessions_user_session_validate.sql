-- Validate the constraint added in the previous migration.
ALTER TABLE compat_sessions
    VALIDATE CONSTRAINT compat_sessions_user_session_id_fkey;
