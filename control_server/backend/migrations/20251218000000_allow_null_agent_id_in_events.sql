-- Allow NULL agent_id for installation events before agent registration
-- This enables creation of installation events when install keys are used
-- before the agent has registered and has an agent_id

-- Create new events table with nullable agent_id
CREATE TABLE events_new (
    id TEXT PRIMARY KEY,
    agent_id TEXT NULL,
    event_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    data TEXT NOT NULL,
    received_at INTEGER,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

-- Copy existing data
INSERT INTO events_new SELECT * FROM events;

-- Drop old table and rename new one
DROP TABLE events;
ALTER TABLE events_new RENAME TO events;

-- Recreate indexes
CREATE INDEX idx_events_agent_ts ON events(agent_id, timestamp);
CREATE INDEX idx_events_type ON events(event_type);