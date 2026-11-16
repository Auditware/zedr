ALTER TABLE agents ADD COLUMN liveness_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE agents ADD COLUMN stop_reason TEXT;

CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    evidence TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    closed_at INTEGER,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE UNIQUE INDEX idx_incidents_open ON incidents(agent_id, incident_type) WHERE closed_at IS NULL;
CREATE INDEX idx_incidents_opened ON incidents(opened_at);
