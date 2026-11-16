-- Add received_at column to events table
ALTER TABLE events ADD COLUMN received_at INTEGER;

-- Set received_at to current timestamp for existing events
UPDATE events SET received_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE received_at IS NULL;
