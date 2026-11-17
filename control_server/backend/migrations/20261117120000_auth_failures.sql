CREATE TABLE auth_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    at INTEGER NOT NULL
);

CREATE INDEX idx_auth_failures_subject ON auth_failures(scope, subject);
CREATE INDEX idx_auth_failures_at ON auth_failures(at);
