-- Drop the `NOT NULL` requirement on compat sessions, so we can import device-less access tokens from Synapse.
ALTER TABLE compat_sessions ALTER COLUMN device_id DROP NOT NULL;
