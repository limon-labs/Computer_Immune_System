CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    executable TEXT,
    command_line TEXT,
    create_time REAL,
    parent_pid INTEGER,
    parent_name TEXT,
    anomaly_score REAL NOT NULL,
    behavior_score REAL NOT NULL,
    file_reputation_score REAL NOT NULL DEFAULT 0,
    threat_score REAL NOT NULL,
    severity TEXT NOT NULL,
    policy_action TEXT NOT NULL DEFAULT 'monitor',
    reasons TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_observed_at ON threats(observed_at);
CREATE INDEX IF NOT EXISTS idx_threats_pid ON threats(pid);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);

CREATE TABLE IF NOT EXISTS registry_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    key_path TEXT NOT NULL,
    value_name TEXT NOT NULL,
    value_data TEXT,
    hive TEXT,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_events_observed_at ON registry_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_registry_events_key_value ON registry_events(key_path, value_name);

CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    pid INTEGER,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    status TEXT,
    suspicious_port INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_events_observed_at ON network_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_network_events_pid ON network_events(pid);
CREATE INDEX IF NOT EXISTS idx_network_events_remote ON network_events(remote_address, remote_port);

CREATE TABLE IF NOT EXISTS correlated_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score_boost REAL NOT NULL,
    involved_pids TEXT NOT NULL,
    event_types TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_correlated_incidents_observed_at ON correlated_incidents(observed_at);
CREATE INDEX IF NOT EXISTS idx_correlated_incidents_type ON correlated_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_correlated_incidents_severity ON correlated_incidents(severity);

CREATE TABLE IF NOT EXISTS file_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    normalized_path TEXT NOT NULL UNIQUE,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    creation_time REAL NOT NULL,
    modification_time REAL NOT NULL,
    sha256 TEXT,
    signature_status TEXT NOT NULL DEFAULT 'unknown',
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    last_pid INTEGER,
    process_create_time REAL
);

CREATE INDEX IF NOT EXISTS idx_file_inventory_sha256 ON file_inventory(sha256);
CREATE INDEX IF NOT EXISTS idx_file_inventory_last_observed ON file_inventory(last_observed_at);

CREATE TABLE IF NOT EXISTS file_hash_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    normalized_path TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT,
    previous_sha256 TEXT,
    observed_at TEXT NOT NULL,
    change_type TEXT NOT NULL,
    pid INTEGER
);

CREATE INDEX IF NOT EXISTS idx_file_hash_history_path ON file_hash_history(normalized_path, observed_at);
CREATE INDEX IF NOT EXISTS idx_file_hash_history_sha256 ON file_hash_history(sha256);

CREATE TABLE IF NOT EXISTS file_reputation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT,
    pid INTEGER,
    file_reputation_score REAL NOT NULL,
    integrity_changed INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_reputation_observed ON file_reputation_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_file_reputation_path ON file_reputation_events(file_path);
CREATE INDEX IF NOT EXISTS idx_file_reputation_score ON file_reputation_events(file_reputation_score);

CREATE TABLE IF NOT EXISTS immune_memory_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_incident_id INTEGER,
    observed_at TEXT NOT NULL,
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    recurrence_score REAL NOT NULL,
    pattern_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    attack_graph TEXT NOT NULL,
    timeline TEXT NOT NULL,
    evidence TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_immune_memory_observed_at ON immune_memory_incidents(observed_at);
CREATE INDEX IF NOT EXISTS idx_immune_memory_pattern ON immune_memory_incidents(pattern_key);
CREATE INDEX IF NOT EXISTS idx_immune_memory_type ON immune_memory_incidents(incident_type);

CREATE TABLE IF NOT EXISTS behavior_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id INTEGER NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    feature_count INTEGER NOT NULL,
    features TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(memory_id) REFERENCES immune_memory_incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_behavior_fingerprints_hash ON behavior_fingerprints(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_behavior_fingerprints_memory_id ON behavior_fingerprints(memory_id);

CREATE TABLE IF NOT EXISTS digital_dna (
    dna_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    identity TEXT NOT NULL,
    process_lineage TEXT NOT NULL,
    behavior_profile TEXT NOT NULL,
    network_profile TEXT NOT NULL,
    filesystem_profile TEXT NOT NULL,
    registry_profile TEXT NOT NULL,
    security_profile TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence REAL NOT NULL,
    evolution_timestamp TEXT NOT NULL,
    change_history TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_digital_dna_last_seen ON digital_dna(last_seen);
CREATE INDEX IF NOT EXISTS idx_digital_dna_confidence ON digital_dna(confidence);

CREATE TABLE IF NOT EXISTS digital_dna_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dna_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    evolved_at TEXT NOT NULL,
    dna_snapshot TEXT NOT NULL,
    change_summary TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_digital_dna_history_dna ON digital_dna_history(dna_id, version);
CREATE INDEX IF NOT EXISTS idx_digital_dna_history_evolved ON digital_dna_history(evolved_at);

CREATE TABLE IF NOT EXISTS digital_dna_similarity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    left_dna_id TEXT NOT NULL,
    right_dna_id TEXT NOT NULL,
    similarity_score REAL NOT NULL,
    confidence REAL NOT NULL,
    matched_features TEXT NOT NULL,
    different_features TEXT NOT NULL,
    evolution_history TEXT NOT NULL,
    compared_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_digital_dna_similarity_pair ON digital_dna_similarity(left_dna_id, right_dna_id);
CREATE INDEX IF NOT EXISTS idx_digital_dna_similarity_score ON digital_dna_similarity(similarity_score);
