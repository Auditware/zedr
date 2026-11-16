-- Add upgrade commands table
CREATE TABLE IF NOT EXISTS upgrade_commands (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    target_version TEXT NOT NULL,
    install_key_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, downloaded, completed, failed
    created_at INTEGER NOT NULL,
    executed_at INTEGER,
    error TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    FOREIGN KEY (install_key_id) REFERENCES install_keys(id)
);

CREATE INDEX idx_upgrade_commands_agent_status ON upgrade_commands(agent_id, status);
