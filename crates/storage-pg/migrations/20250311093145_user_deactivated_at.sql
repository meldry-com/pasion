ALTER TABLE users
  -- Track when a user was deactivated.
  ADD COLUMN deactivated_at TIMESTAMP WITH TIME ZONE;
