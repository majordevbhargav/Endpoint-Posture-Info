-- 004_hardware_health.sql
-- Endpoint Hardware Health module (Section 6.1 / Section 7.4 / Phase 3a).

CREATE TABLE IF NOT EXISTS endpoint_hardware_health (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    manufacturer TEXT,
    model TEXT,
    serial_number TEXT,
    bios_version TEXT,
    cpu_score INTEGER,
    memory_score INTEGER,
    storage_score INTEGER,
    battery_score INTEGER,
    overall_score INTEGER,
    hardware_event_count INTEGER,
    warranty_status TEXT,
    warranty_days_remaining INTEGER,
    report_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hardware_health_mac_time
    ON endpoint_hardware_health(mac, timestamp);

CREATE TABLE IF NOT EXISTS endpoint_hardware_recommendations (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    priority TEXT NOT NULL,
    area TEXT NOT NULL,
    action TEXT NOT NULL
);
