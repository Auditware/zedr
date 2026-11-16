-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_users_username ON users(username);

-- API keys table
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at);

-- Add user_id to install_keys
ALTER TABLE install_keys ADD COLUMN user_id TEXT;

-- Add user_id to agents
ALTER TABLE agents ADD COLUMN user_id TEXT;

-- Seed admin user (password will be set from ADMIN_PASSWORD env var during app startup)
-- INSERT will be done in code to properly hash the password
