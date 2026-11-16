-- Add agent version tracking to install keys
ALTER TABLE install_keys ADD COLUMN agent_version TEXT NOT NULL DEFAULT '0.1.0';

CREATE INDEX idx_install_keys_version ON install_keys(agent_version);
