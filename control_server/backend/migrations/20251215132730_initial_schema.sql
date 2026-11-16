-- Agents table: Fleet management
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    version TEXT NOT NULL,
    ip_address TEXT,
    last_heartbeat INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Events table: Time-series telemetry from agents
CREATE TABLE events (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    data TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX idx_events_agent_ts ON events(agent_id, timestamp);
CREATE INDEX idx_events_type ON events(event_type);

-- Enable WAL mode for concurrent reads/writes
PRAGMA journal_mode = WAL;
