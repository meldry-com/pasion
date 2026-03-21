
-- Fix a faulty constraint.
-- The condition was incorrectly specified as `revoked_at IS NOT NULL`
-- when `revoked_at IS NULL` was meant.

DROP INDEX personal_access_tokens_personal_session_id_idx;

-- Ensure we can only have one active personal access token in each family.
CREATE UNIQUE INDEX ON personal_access_tokens (personal_session_id) WHERE revoked_at IS NULL;
