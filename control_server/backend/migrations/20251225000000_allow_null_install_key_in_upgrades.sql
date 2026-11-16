-- Allow NULL install_key_id for agent_id-based upgrades
-- SQLite doesn't support ALTER COLUMN, so we need to recreate the table

CREATE TABLE upgrade_commands_new (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    target_version TEXT NOT NULL,
    install_key_id TEXT,  -- Made nullable for agent_id-based upgrades
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    executed_at INTEGER,
    error TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    FOREIGN KEY (install_key_id) REFERENCES install_keys(id)
);

-- Copy existing data
INSERT INTO upgrade_commands_new 
SELECT id, agent_id, target_version, install_key_id, status, created_at, executed_at, error 
FROM upgrade_commands;

-- Drop old table and rename
DROP TABLE upgrade_commands;
ALTER TABLE upgrade_commands_new RENAME TO upgrade_commands;

-- Recreate index
CREATE INDEX idx_upgrade_commands_agent_status ON upgrade_commands(agent_id, status);
