-- Brings in the `user_external_ids` table from Palpo

CREATE TABLE user_external_ids (
    auth_provider text NOT NULL,
    external_id text NOT NULL,
    user_id text NOT NULL
);
