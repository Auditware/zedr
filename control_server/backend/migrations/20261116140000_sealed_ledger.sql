CREATE TABLE chain_positions (
    agent_id TEXT PRIMARY KEY,
    epoch INTEGER NOT NULL,
    next_window INTEGER NOT NULL,
    next_index INTEGER NOT NULL,
    head TEXT NOT NULL,
    proven_window INTEGER,
    proven_state TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE sealed_windows (
    agent_id TEXT NOT NULL,
    window INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    first_index INTEGER NOT NULL,
    count INTEGER NOT NULL,
    fresh INTEGER NOT NULL,
    gap INTEGER NOT NULL,
    prev_head TEXT NOT NULL,
    root TEXT NOT NULL,
    head TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    proving INTEGER NOT NULL,
    proof TEXT NOT NULL,
    PRIMARY KEY (agent_id, window),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX idx_sealed_windows_proof ON sealed_windows(proof, received_at);
CREATE INDEX idx_sealed_windows_gap ON sealed_windows(agent_id) WHERE gap = 1;

CREATE TABLE sealed_events (
    agent_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    window INTEGER NOT NULL,
    leaf TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    opened_at INTEGER,
    event_id TEXT,
    PRIMARY KEY (agent_id, idx),
    FOREIGN KEY (agent_id, window) REFERENCES sealed_windows(agent_id, window),
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE INDEX idx_sealed_events_window ON sealed_events(agent_id, window);
CREATE INDEX idx_sealed_events_opened ON sealed_events(agent_id, window) WHERE opened_at IS NOT NULL;

CREATE TABLE releases (
    agent_id TEXT NOT NULL,
    window INTEGER NOT NULL,
    trigger_idx INTEGER NOT NULL,
    rule TEXT NOT NULL,
    pid INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    context TEXT NOT NULL,
    proven INTEGER NOT NULL DEFAULT 0,
    finding_event_id TEXT,
    UNIQUE (agent_id, trigger_idx, rule),
    FOREIGN KEY (agent_id, window) REFERENCES sealed_windows(agent_id, window),
    FOREIGN KEY (finding_event_id) REFERENCES events(id)
);

CREATE INDEX idx_releases_window ON releases(agent_id, window);
CREATE INDEX idx_releases_finding ON releases(agent_id, rule, pid, started_at);
CREATE INDEX idx_releases_rule ON releases(rule);

CREATE TABLE proofs (
    agent_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    first_window INTEGER NOT NULL,
    last_window INTEGER NOT NULL,
    image_id TEXT NOT NULL,
    state_in TEXT NOT NULL,
    state_out TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, first_window),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);
