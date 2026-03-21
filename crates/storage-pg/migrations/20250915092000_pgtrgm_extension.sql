-- no-transaction
-- This enables the pg_trgm extension, which is used for search filters
-- Starting Posgres 16, this extension is marked as "trusted", meaning it can be
-- installed by non-superusers
CREATE EXTENSION IF NOT EXISTS pg_trgm;
