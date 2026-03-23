-- Drop the legacy Matrix login compatibility tables.
-- These tables supported the /_matrix/client/*/login compatibility layer
-- which has been removed from Pasion.

-- Drop in dependency order (foreign keys first)
DROP TABLE IF EXISTS compat_refresh_tokens;
DROP TABLE IF EXISTS compat_access_tokens;
DROP TABLE IF EXISTS compat_sso_logins;
DROP TABLE IF EXISTS compat_sessions;
