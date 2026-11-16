CREATE TABLE deployment_signing_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    public_key TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
);
