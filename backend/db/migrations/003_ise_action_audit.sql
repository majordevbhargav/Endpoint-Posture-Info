-- 003_ise_action_audit.sql
-- Supports the decoupled enforcement model (Section 2.2 / Section 11):
-- every share-posture / restrict / clear-restriction action is explicit
-- and logged here, success or failure. Project plan Section 7.3 / Phase 1.

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS shared_with_ise_at TEXT;
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS enforcement_state TEXT;

CREATE TABLE IF NOT EXISTS ise_action_audit (
    id SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    mac TEXT NOT NULL,
    action TEXT NOT NULL,      -- SHARE_POSTURE | RESTRICT | CLEAR_RESTRICTION
    operator TEXT,
    result TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_ise_audit_mac ON ise_action_audit(mac);
