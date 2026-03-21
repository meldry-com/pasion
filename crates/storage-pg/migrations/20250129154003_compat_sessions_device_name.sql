ALTER TABLE compat_sessions
  -- Stores a human-readable name for the device.
  -- syn2mas behaviour: Will be populated from the device name in Synapse.
  ADD COLUMN human_name TEXT;
