-- Change compat_sessions.user_session_id FK from ON DELETE SET NULL to NO ACTION
ALTER TABLE compat_sessions
    DROP CONSTRAINT compat_sessions_user_session_id_fkey,
    ADD CONSTRAINT compat_sessions_user_session_id_fkey
        FOREIGN KEY (user_session_id)
        REFERENCES user_sessions (user_session_id)
        ON DELETE NO ACTION
        NOT VALID;
