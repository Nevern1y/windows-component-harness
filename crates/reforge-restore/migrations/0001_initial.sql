CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    approval_state TEXT NOT NULL,
    approved_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    op_key TEXT NOT NULL UNIQUE,
    component_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    requires_elevation INTEGER NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    input_json TEXT NOT NULL,
    result_json TEXT,
    error_json TEXT,
    backup_json TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    time TEXT NOT NULL,
    level TEXT NOT NULL,
    event_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS manual_actions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL,
    title TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk TEXT NOT NULL,
    instructions_json TEXT NOT NULL,
    acknowledged_at TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS operations_run_id_idx ON operations(run_id);
CREATE INDEX IF NOT EXISTS events_run_seq_idx ON events(run_id, seq);
CREATE INDEX IF NOT EXISTS manual_actions_run_id_idx ON manual_actions(run_id);
