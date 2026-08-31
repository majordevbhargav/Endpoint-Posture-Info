-- 005_report_json_jsonb.sql
-- Converts every "report_json" column from TEXT to JSONB.
--
-- Why: these columns hold the full free-form report from each collector
-- (hardware health, endpoint experience, security indicators, Endpoint 360
-- diagnostics) so that a future collector - e.g. a macOS or Linux posture
-- agent with a different report shape than the Windows one - never needs
-- a schema change just to be stored. As plain TEXT that data was opaque:
-- storable, but not queryable. As JSONB it can be queried and indexed
-- directly (e.g. report_json->>'kernel_version'), in the same database,
-- without standing up a second (document) store for this purpose.
--
-- This migration is also applied automatically at runtime by init_db()
-- (posture_db.py), init_endpoint_360_db() (endpoint_360_integration.py),
-- and init_endpoint360_history_db() (posture_ui.py) - each guarded to be
-- a no-op if the column is already jsonb. This file exists as a readable,
-- ordered record, same as 001-004, and so it can be run by hand.
--
-- Safe to run multiple times. Existing values are valid JSON text (they
-- were written via json.dumps()), so ::jsonb reparses them losslessly.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'endpoint_hardware_health'
          AND column_name = 'report_json'
          AND data_type <> 'jsonb'
    ) THEN
        ALTER TABLE endpoint_hardware_health
            ALTER COLUMN report_json TYPE JSONB USING report_json::jsonb;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'endpoint_experience_history'
          AND column_name = 'report_json'
          AND data_type <> 'jsonb'
    ) THEN
        ALTER TABLE endpoint_experience_history
            ALTER COLUMN report_json TYPE JSONB USING report_json::jsonb;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'endpoint_security_history'
          AND column_name = 'report_json'
          AND data_type <> 'jsonb'
    ) THEN
        ALTER TABLE endpoint_security_history
            ALTER COLUMN report_json TYPE JSONB USING report_json::jsonb;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'endpoint_360_diagnostics'
          AND column_name = 'report_json'
          AND data_type <> 'jsonb'
    ) THEN
        ALTER TABLE endpoint_360_diagnostics
            ALTER COLUMN report_json TYPE JSONB USING report_json::jsonb;
    END IF;
END $$;

-- Optional but recommended once you're on JSONB: a GIN index makes
-- "does this report contain X" queries fast. Already added automatically
-- for endpoint_hardware_health in posture_db.py's SCHEMA_SQL; add the
-- others here if/when you actually query into them.
CREATE INDEX IF NOT EXISTS idx_hardware_health_report_gin
    ON endpoint_hardware_health USING GIN (report_json);
