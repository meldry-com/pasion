ALTER TABLE users
  -- Track whether users are guests.
  -- Although guest support is not present in Pasion yet, syn2mas should import
  -- these users and therefore we should track their state.
  ADD COLUMN is_guest BOOLEAN NOT NULL DEFAULT FALSE;
