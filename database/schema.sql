CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    executable TEXT,
    command_line TEXT,
    create_time REAL,
    anomaly_score REAL NOT NULL,
    behavior_score REAL NOT NULL,
    threat_score REAL NOT NULL,
    severity TEXT NOT NULL,
    policy_action TEXT NOT NULL DEFAULT 'monitor',
    reasons TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_observed_at ON threats(observed_at);
CREATE INDEX IF NOT EXISTS idx_threats_pid ON threats(pid);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
