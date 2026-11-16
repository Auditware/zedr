-- Install keys table: Secure one-time agent installation
CREATE TABLE install_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    key_plaintext TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    revoked_at INTEGER,
    created_by TEXT NOT NULL
);

CREATE INDEX idx_install_keys_hash ON install_keys(key_hash);
CREATE INDEX idx_install_keys_expires ON install_keys(expires_at);

-- Agent installations table: Audit trail
CREATE TABLE agent_installations (
    id TEXT PRIMARY KEY,
    install_key_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    installed_at INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    ip_address TEXT,
    FOREIGN KEY (install_key_id) REFERENCES install_keys(id),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX idx_agent_installations_key ON agent_installations(install_key_id);
CREATE INDEX idx_agent_installations_agent ON agent_installations(agent_id);
