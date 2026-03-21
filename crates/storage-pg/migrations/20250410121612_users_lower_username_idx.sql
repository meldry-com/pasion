-- no-transaction
-- Create an index on the username column, lower-cased, so that we can lookup
-- usernames in a case-insensitive manner.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_lower_username_idx
    ON users (LOWER(username));
