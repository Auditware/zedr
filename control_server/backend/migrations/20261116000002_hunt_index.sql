CREATE TABLE hunt_processes (
    agent_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    command TEXT NOT NULL,
    uid INTEGER NOT NULL,
    parent_pid INTEGER NOT NULL,
    parent_name TEXT,
    parent_path TEXT,
    grandparent_name TEXT,
    PRIMARY KEY (agent_id, pid, started_at)
);

CREATE INDEX idx_hunt_processes_name ON hunt_processes(name);
CREATE INDEX idx_hunt_processes_parent ON hunt_processes(parent_name);
CREATE INDEX idx_hunt_processes_started ON hunt_processes(started_at);

CREATE TABLE hunt_connections (
    agent_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT,
    process_started_at INTEGER,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    at INTEGER NOT NULL
);

CREATE INDEX idx_hunt_connections_dest ON hunt_connections(dest_ip);
CREATE INDEX idx_hunt_connections_at ON hunt_connections(at);

CREATE TABLE hunt_files (
    agent_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT,
    process_started_at INTEGER,
    path TEXT NOT NULL,
    action TEXT NOT NULL,
    at INTEGER NOT NULL
);

CREATE INDEX idx_hunt_files_at ON hunt_files(at);
