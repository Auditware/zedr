CREATE TABLE hunt_packages (
    agent_id TEXT NOT NULL,
    manager TEXT NOT NULL,
    name TEXT NOT NULL,
    architecture TEXT NOT NULL,
    version TEXT NOT NULL,
    version_key TEXT NOT NULL,
    previous_version TEXT,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, manager, name, architecture)
);

CREATE INDEX idx_hunt_packages_name ON hunt_packages(name, version_key);

CREATE TABLE hunt_persistence (
    agent_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    command TEXT NOT NULL,
    user TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    hash TEXT,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, kind, path, name)
);

CREATE INDEX idx_hunt_persistence_kind ON hunt_persistence(kind);
