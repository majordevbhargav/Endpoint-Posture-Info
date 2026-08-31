-- 002_connection_state.sql
-- Fixes Problem 2 (a device's stored status never expires): tracks whether
-- an endpoint is currently connected, independent of its posture status.
-- Project plan Section 7.2 / Phase 2.

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS connected INTEGER DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS session_started TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_disconnected TEXT;

CREATE TABLE IF NOT EXISTS endpoint_session_log (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    ip TEXT,
    event TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_log_mac ON endpoint_session_log(mac);
