-- We stopped reading/writing to this column, but it's not nullable.
-- So we need to add a default value, and drop it in the next release
ALTER TABLE oauth2_authorization_grants
    ALTER COLUMN requires_consent SET DEFAULT false;
