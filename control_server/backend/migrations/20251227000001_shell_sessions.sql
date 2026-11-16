CREATE TABLE IF NOT EXISTS shell_sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    terminated_at INTEGER,
    created_by_user_id TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE INDEX IF NOT EXISTS idx_shell_sessions_agent_id ON shell_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_shell_sessions_expires_at ON shell_sessions(expires_at);

CREATE TABLE IF NOT EXISTS shell_commands (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    command_text TEXT NOT NULL,
    signature BLOB NOT NULL,
    issued_at INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    executed_at INTEGER,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    FOREIGN KEY (session_id) REFERENCES shell_sessions(id),
    UNIQUE(nonce)
);

CREATE INDEX IF NOT EXISTS idx_shell_commands_session_id ON shell_commands(session_id);
CREATE INDEX IF NOT EXISTS idx_shell_commands_executed_at ON shell_commands(executed_at);
