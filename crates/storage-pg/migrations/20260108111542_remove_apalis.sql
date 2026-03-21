-- We replaced apalis a while back but did not clean the database. This removes
-- everything related to apalis
DROP TRIGGER IF EXISTS notify_workers ON apalis.jobs;
DROP FUNCTION IF EXISTS apalis.notify_new_jobs();
DROP FUNCTION IF EXISTS apalis.get_jobs(text, text, integer);
DROP FUNCTION IF EXISTS apalis.push_job(text, json, text, timestamp with time zone, integer);
DROP TABLE IF EXISTS apalis.jobs;
DROP TABLE IF EXISTS apalis.workers;
DROP SCHEMA IF EXISTS apalis;
