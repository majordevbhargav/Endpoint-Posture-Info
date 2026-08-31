-- 001_init_core.sql
-- Core posture tables, carried over from the original SQLite schema
-- (project plan Section 7.1). Applied automatically by posture_db.init_db()
-- via CREATE TABLE IF NOT EXISTS - this file exists as a readable, ordered
-- record of the schema's evolution, and to run by hand against a fresh
-- database if you'd rather not rely on init_db().

CREATE TABLE IF NOT EXISTS endpoints (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    os TEXT,
    os_version TEXT,
    last_seen TEXT,
    first_seen TEXT,
    apps_count INTEGER DEFAULT 0,
    manufacturer TEXT,
    model TEXT,
    serial_number TEXT,
    cpu_percent REAL,
    memory_percent REAL,
    memory_total_mb REAL,
    memory_free_mb REAL
);

CREATE TABLE IF NOT EXISTS assessments (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    ip TEXT,
    timestamp TEXT NOT NULL,
    status TEXT,
    detail TEXT,
    submitted INTEGER DEFAULT 0,
    submit_error TEXT,
    apps_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS check_results (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    check_name TEXT,
    status TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS needs_attention (
    ip TEXT PRIMARY KEY,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_ports (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    port INTEGER,
    process TEXT,
    pid INTEGER,
    reachable INTEGER,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_processes (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    name TEXT,
    pid INTEGER,
    memory_mb REAL,
    cpu_time_seconds REAL,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_apps (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    name TEXT,
    version TEXT,
    publisher TEXT,
    timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_assessments_mac ON assessments(mac);
CREATE INDEX IF NOT EXISTS idx_assessments_time ON assessments(timestamp);
CREATE INDEX IF NOT EXISTS idx_checks_assessment ON check_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ports_mac ON endpoint_ports(mac);
CREATE INDEX IF NOT EXISTS idx_apps_mac ON endpoint_apps(mac);
CREATE INDEX IF NOT EXISTS idx_processes_mac ON endpoint_processes(mac);
