ALTER TABLE agents ADD COLUMN public_key TEXT;

CREATE TABLE agent_sessions (
    agent_id TEXT NOT NULL,
    session INTEGER NOT NULL,
    last_seq INTEGER NOT NULL,
    PRIMARY KEY (agent_id, session),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

ALTER TABLE install_keys ADD COLUMN enrolled_at INTEGER;
ALTER TABLE install_keys ADD COLUMN enrolled_agent_id TEXT;
ALTER TABLE install_keys DROP COLUMN key_plaintext;
