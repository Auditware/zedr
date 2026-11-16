CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    max_uses INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER,
    revoked_at INTEGER,
    revoked_by TEXT
);

CREATE INDEX idx_enrollment_tokens_label ON enrollment_tokens(label);

ALTER TABLE agents ADD COLUMN enrollment_token_id TEXT REFERENCES enrollment_tokens(id);

CREATE INDEX idx_agents_enrollment_token ON agents(enrollment_token_id);
