"""
posture_db.py - PostgreSQL data access layer.

This replaces the original SQLite implementation. It keeps the exact same
public surface (db(), get_db(), init_db(), save_assessment(), etc.) so every
other module written against the SQLite version - posture_app.py,
posture_ui.py, application_remediation.py, endpoint_360_integration.py -
keeps working without changes to their own code.

Connection pattern:
    with db() as con:
        con.execute(...)   # SQLite-style .execute() is shimmed below
        rows = con.execute(...).fetchall()   # rows behave like dict rows

Why a shim instead of rewriting every caller to raw psycopg2:
    The existing modules call con.execute("...?...", (params,)) SQLite style
    and read rows as row["col"]. Rewriting every call site across five files
    to psycopg2's %s placeholders and tuple/dict cursors would touch a lot
    of already-working code for no functional gain. _Connection below
    translates "?" placeholders to "%s" and returns dict-like rows, so the
    calling code is unchanged.

Environment variables:
    POSTGRES_HOST       (default "localhost")
    POSTGRES_PORT       (default "5432")
    POSTGRES_DB         (default "posture")
    POSTGRES_USER       (default "posture")
    POSTGRES_PASSWORD   (required in real environments; default "posture" for local dev only)
    DATABASE_URL         if set, overrides the discrete POSTGRES_* vars entirely
"""

from __future__ import annotations

import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import psycopg2.pool
from dotenv import load_dotenv

# Load backend/.env regardless of how this module gets imported - direct
# `python -c "from posture_db import ..."`, pytest, posture_app.py,
# posture_ui.py, or ise_session_watcher.py all end up here. Without this,
# only the three entrypoint scripts that call load_dotenv() themselves
# would pick up .env, and a bare import of posture_db would silently fall
# back to the hardcoded defaults below instead of raising a clear error.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

PG_HOST = os.getenv("POSTGRES_HOST", "localhost")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_DB = os.getenv("POSTGRES_DB", "posture")
PG_USER = os.getenv("POSTGRES_USER", "posture")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "posture")

DB_FILE = DATABASE_URL or f"postgresql://{PG_USER}:***@{PG_HOST}:{PG_PORT}/{PG_DB}"
# ^ kept as DB_FILE for compatibility with posture_ui.py's startup log line,
#   which prints DB_FILE. Password redacted since this string is only for
#   display, never used to actually connect.

_POOL_LOCK = threading.Lock()
_POOL = None


def _dsn():
    if DATABASE_URL:
        return DATABASE_URL
    return (
        f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} "
        f"user={PG_USER} password={PG_PASSWORD}"
    )


def _get_pool():
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                _POOL = psycopg2.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=int(os.getenv("POSTGRES_MAX_CONN", "10")),
                    dsn=_dsn(),
                )
    return _POOL


_PLACEHOLDER_RE = re.compile(r"\?")


def _translate(sql: str) -> str:
    """SQLite '?' placeholders -> psycopg2 '%s' placeholders."""
    return _PLACEHOLDER_RE.sub("%s", sql)


class _Cursor:
    """Thin wrapper so con.execute(...).fetchone()/.fetchall() keeps working."""

    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        # psycopg2 has no lastrowid; callers use RETURNING id instead (see
        # save_assessment()/save_posture() below, which fetch it explicitly).
        return getattr(self, "_lastrowid", None)


class _Connection:
    """Wraps a psycopg2 connection so callers can keep using SQLite-style
    con.execute("... ? ...", (params,)) and con.executescript(...)."""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self._cursor = raw_conn.cursor(
            cursor_factory=psycopg2.extras.RealDictCursor
        )

    def execute(self, sql, params=None):
        self._cursor.execute(_translate(sql), params or ())
        return _Cursor(self._cursor)

    def executescript(self, sql):
        # psycopg2 supports multi-statement execute() directly.
        self._cursor.execute(sql)
        return _Cursor(self._cursor)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


@contextmanager
def _connection_ctx():
    pool = _get_pool()
    raw = pool.getconn()
    conn = _Connection(raw)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(raw)


def db():
    """
    Returns a context-manager-compatible connection, same calling
    convention as the original: `with db() as con: ...`.
    """
    return _connection_ctx()


def get_db():
    """Compatibility wrapper used by posture_ui.py."""
    return db()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
#
# NOTE on report_json columns (endpoint_hardware_health, and the
# equivalent columns owned by endpoint_360_integration.py / posture_ui.py):
# these are JSONB, not TEXT. They hold the full, free-form report from
# each collector (hardware health, experience, security indicators,
# Endpoint 360 diagnostics) - only the fields actually queried/trended are
# broken out into real columns; everything else lives here so a future
# macOS/Linux collector (or any collector whose shape differs from the
# Windows one) doesn't need a schema change to be stored. JSONB (vs plain
# TEXT) lets Postgres actually query *into* that variance later (e.g.
# report_json->>'kernel_version'), and lets psycopg2 hand back/accept
# native Python dicts (via psycopg2.extras.Json) instead of everyone
# having to json.dumps()/json.loads() by hand at every call site.

SCHEMA_SQL = """
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
    memory_free_mb REAL,
    connected INTEGER DEFAULT 0,
    session_started TEXT,
    last_disconnected TEXT,
    shared_with_ise_at TEXT,
    enforcement_state TEXT
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

CREATE TABLE IF NOT EXISTS endpoint_session_log (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    ip TEXT,
    event TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ise_action_audit (
    id SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    mac TEXT NOT NULL,
    action TEXT NOT NULL,
    operator TEXT,
    result TEXT,
    detail TEXT
);

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
    report_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_hardware_recommendations (
    id SERIAL PRIMARY KEY,
    mac TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    priority TEXT NOT NULL,
    area TEXT NOT NULL,
    action TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assessments_mac ON assessments(mac);
CREATE INDEX IF NOT EXISTS idx_assessments_time ON assessments(timestamp);
CREATE INDEX IF NOT EXISTS idx_checks_assessment ON check_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ports_mac ON endpoint_ports(mac);
CREATE INDEX IF NOT EXISTS idx_apps_mac ON endpoint_apps(mac);
CREATE INDEX IF NOT EXISTS idx_processes_mac ON endpoint_processes(mac);
CREATE INDEX IF NOT EXISTS idx_session_log_mac ON endpoint_session_log(mac);
CREATE INDEX IF NOT EXISTS idx_ise_audit_mac ON ise_action_audit(mac);
CREATE INDEX IF NOT EXISTS idx_hardware_health_mac_time ON endpoint_hardware_health(mac, timestamp);
"""
# NOTE: the GIN index on report_json is intentionally NOT here. On a
# database that already has this table (created back when report_json
# was TEXT), CREATE TABLE IF NOT EXISTS is a no-op, so this index would
# be built against a still-TEXT column and Postgres would reject it
# with "data type text has no default operator class for access method
# gin" - before _JSONB_MIGRATION_SQL below ever got a chance to convert
# the column. It's created separately, after the migration, instead.


# ---------------------------------------------------------------------------
# One-time migration: report_json TEXT -> JSONB
#
# CREATE TABLE IF NOT EXISTS never touches a table that already exists, so
# a database created before this change would keep report_json as TEXT
# forever even after SCHEMA_SQL above is updated. This converts it in
# place, guarded so it only runs (and only costs anything) on a database
# that still has the old TEXT column - safe to run on every init_db() call.
# The existing values are valid JSON text (they were written via
# json.dumps()), so ::jsonb reparses them losslessly.
# ---------------------------------------------------------------------------

_JSONB_MIGRATION_SQL = """
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
END $$;
"""

# Created only after the migration above has had a chance to convert an
# existing TEXT column to JSONB - see the note next to SCHEMA_SQL. By
# this point the column is guaranteed to be JSONB (either it always was,
# on a fresh install, or the migration just converted it), so the index
# build is always valid.
_JSONB_GIN_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_hardware_health_report_gin
    ON endpoint_hardware_health USING GIN (report_json);
"""


def init_db():
    with db() as con:
        con.executescript(SCHEMA_SQL)
        con.executescript(_JSONB_MIGRATION_SQL)
        con.executescript(_JSONB_GIN_INDEX_SQL)


def assessment_count():
    with db() as con:
        row = con.execute("SELECT COUNT(*) AS n FROM assessments").fetchone()
        return row["n"]


# ---------------------------------------------------------------------------
# needs_attention
# ---------------------------------------------------------------------------

def needs_attention():
    with db() as con:
        rows = con.execute(
            "SELECT ip FROM needs_attention ORDER BY added_at"
        ).fetchall()
        return [row["ip"] for row in rows]


def add_attention(ip):
    if not ip:
        return
    ip = str(ip).strip()
    if not ip:
        return
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as con:
        con.execute(
            """
            INSERT INTO needs_attention(ip, added_at) VALUES (?, ?)
            ON CONFLICT(ip) DO UPDATE SET added_at = excluded.added_at
            """,
            (ip, now),
        )


def remove_attention(ip):
    if not ip:
        return
    ip = str(ip).strip()
    if not ip:
        return
    with db() as con:
        con.execute("DELETE FROM needs_attention WHERE ip = ?", (ip,))


def mac_from_ip(ip):
    if not ip:
        return None
    with db() as con:
        row = con.execute(
            """
            SELECT mac FROM endpoints WHERE ip = ?
            ORDER BY last_seen DESC LIMIT 1
            """,
            (ip,),
        ).fetchone()
        return row["mac"] if row else None


# ---------------------------------------------------------------------------
# Connection-state tracking (Section 8.4 of the project plan)
# ---------------------------------------------------------------------------

def mark_connected(mac, ip=None):
    if not mac:
        return
    mac = str(mac).upper()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as con:
        row = con.execute(
            "SELECT connected FROM endpoints WHERE mac = ?", (mac,)
        ).fetchone()
        already_connected = bool(row and row["connected"])

        if row is None:
            con.execute(
                """
                INSERT INTO endpoints(mac, ip, connected, session_started, first_seen, last_seen)
                VALUES (?, ?, 1, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip, connected = 1, session_started = excluded.session_started
                """,
                (mac, ip, now, now, now),
            )
        else:
            con.execute(
                """
                UPDATE endpoints SET ip = COALESCE(?, ip), connected = 1,
                    session_started = CASE WHEN connected = 1 THEN session_started ELSE ? END
                WHERE mac = ?
                """,
                (ip, now, mac),
            )

        if not already_connected:
            con.execute(
                """
                INSERT INTO endpoint_session_log(mac, ip, event, timestamp)
                VALUES (?, ?, 'CONNECTED', ?)
                """,
                (mac, ip, now),
            )


def mark_disconnected(mac):
    if not mac:
        return
    mac = str(mac).upper()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as con:
        con.execute(
            """
            UPDATE endpoints SET connected = 0, last_disconnected = ?
            WHERE mac = ?
            """,
            (now, mac),
        )
        con.execute(
            """
            INSERT INTO endpoint_session_log(mac, event, timestamp)
            VALUES (?, 'DISCONNECTED', ?)
            """,
            (mac, now),
        )


# ---------------------------------------------------------------------------
# ISE action audit (Section 7.3 / 8.2)
# ---------------------------------------------------------------------------

def log_ise_action(mac, action, operator=None, result=None, detail=None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as con:
        con.execute(
            """
            INSERT INTO ise_action_audit(timestamp, mac, action, operator, result, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (now, str(mac).upper() if mac else mac, action, operator, result, detail),
        )


def get_ise_audit(limit=200):
    limit = max(1, min(int(limit), 5000))
    with db() as con:
        rows = con.execute(
            """
            SELECT * FROM ise_action_audit
            ORDER BY timestamp DESC, id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# save_assessment / core posture persistence
# ---------------------------------------------------------------------------

def save_assessment(
    *,
    mac,
    ip=None,
    hostname=None,
    os_name=None,
    os_version=None,
    timestamp=None,
    status=None,
    detail=None,
    submitted=False,
    submit_error=None,
    checks=None,
    apps_count=0,
    listening_ports=None,
    installed_apps=None,
    hardware=None,
    resource_usage=None,
    top_processes=None,
):
    if not mac:
        raise ValueError("MAC address is required")

    mac = str(mac).upper()
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hardware = hardware or {}
    resource_usage = resource_usage or {}

    with db() as con:
        con.execute(
            """
            INSERT INTO endpoints(
                mac, ip, hostname, os, os_version, last_seen, first_seen,
                apps_count, manufacturer, model, serial_number,
                cpu_percent, memory_percent, memory_total_mb, memory_free_mb
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = excluded.hostname,
                os = COALESCE(excluded.os, endpoints.os),
                os_version = COALESCE(excluded.os_version, endpoints.os_version),
                last_seen = excluded.last_seen,
                apps_count = excluded.apps_count,
                manufacturer = COALESCE(excluded.manufacturer, endpoints.manufacturer),
                model = COALESCE(excluded.model, endpoints.model),
                serial_number = COALESCE(excluded.serial_number, endpoints.serial_number),
                cpu_percent = excluded.cpu_percent,
                memory_percent = excluded.memory_percent,
                memory_total_mb = excluded.memory_total_mb,
                memory_free_mb = excluded.memory_free_mb
            """,
            (
                mac, ip, hostname, os_name, os_version, timestamp, timestamp,
                apps_count,
                hardware.get("manufacturer"), hardware.get("model"), hardware.get("serial_number"),
                resource_usage.get("cpu_percent"), resource_usage.get("memory_percent"),
                resource_usage.get("memory_total_mb"), resource_usage.get("memory_free_mb"),
            ),
        )

        cur = con.execute(
            """
            INSERT INTO assessments(
                mac, ip, timestamp, status, detail, submitted, submit_error, apps_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (mac, ip, timestamp, status, detail, int(bool(submitted)), submit_error, apps_count),
        )
        assessment_id = cur.fetchone()["id"]

        for check in checks or []:
            name = check.get("Check") or check.get("check") or check.get("check_name") or check.get("name")
            state = check.get("Status") or check.get("status")
            details = check.get("Details") or check.get("detail") or check.get("details")
            con.execute(
                """
                INSERT INTO check_results(assessment_id, check_name, status, detail)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, name, state, details),
            )

        for port in listening_ports or []:
            reachable = port.get("reachable")
            con.execute(
                """
                INSERT INTO endpoint_ports(mac, port, process, pid, reachable, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    mac, port.get("port"), port.get("process"), port.get("pid"),
                    None if reachable is None else int(bool(reachable)), timestamp,
                ),
            )

        if top_processes is not None:
            con.execute("DELETE FROM endpoint_processes WHERE mac = ?", (mac,))
            for proc in top_processes or []:
                con.execute(
                    """
                    INSERT INTO endpoint_processes(mac, name, pid, memory_mb, cpu_time_seconds, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (mac, proc.get("name"), proc.get("pid"), proc.get("memory_mb"),
                     proc.get("cpu_time_seconds"), timestamp),
                )

        if installed_apps is not None:
            con.execute("DELETE FROM endpoint_apps WHERE mac = ?", (mac,))
            for app in installed_apps or []:
                con.execute(
                    """
                    INSERT INTO endpoint_apps(mac, name, version, publisher, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (mac, app.get("name"), app.get("version"), app.get("publisher"), timestamp),
                )

        return assessment_id


def get_assessments(limit=100):
    limit = max(1, int(limit))
    with db() as con:
        rows = con.execute(
            """
            SELECT
                a.*, e.hostname, e.os, e.os_version, e.manufacturer, e.model,
                e.serial_number, e.cpu_percent, e.memory_percent,
                e.memory_total_mb, e.memory_free_mb, e.connected
            FROM assessments AS a
            LEFT JOIN endpoints AS e ON e.mac = a.mac
            ORDER BY a.timestamp DESC, a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        output = []
        for row in rows:
            item = dict(row)
            item["submitted"] = bool(item["submitted"])
            item["checks"] = [
                {"Check": c["check_name"], "Status": c["status"], "Details": c["detail"]}
                for c in con.execute(
                    """
                    SELECT check_name, status, detail FROM check_results
                    WHERE assessment_id = ? ORDER BY id
                    """,
                    (row["id"],),
                ).fetchall()
            ]
            item["listening_ports"] = [
                {
                    "port": p["port"], "process": p["process"], "pid": p["pid"],
                    "reachable": None if p["reachable"] is None else bool(p["reachable"]),
                }
                for p in con.execute(
                    """
                    SELECT port, process, pid, reachable FROM endpoint_ports
                    WHERE mac = ? AND timestamp = ? ORDER BY port
                    """,
                    (row["mac"], row["timestamp"]),
                ).fetchall()
            ]
            output.append(item)
        return output


def get_apps_for_mac(mac):
    if not mac:
        return []
    with db() as con:
        rows = con.execute(
            "SELECT name, version, publisher FROM endpoint_apps WHERE mac = ? ORDER BY name",
            (mac,),
        ).fetchall()
        return [{"name": r["name"], "version": r["version"], "publisher": r["publisher"]} for r in rows]


def get_processes_for_mac(mac):
    if not mac:
        return []
    with db() as con:
        rows = con.execute(
            """
            SELECT name, pid, memory_mb, cpu_time_seconds FROM endpoint_processes
            WHERE mac = ? ORDER BY memory_mb DESC
            """,
            (mac,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_applications():
    with db() as con:
        rows = con.execute(
            """
            SELECT ea.mac, e.hostname, e.ip, ea.name, ea.version, ea.publisher
            FROM endpoint_apps AS ea
            LEFT JOIN endpoints AS e ON e.mac = ea.mac
            ORDER BY ea.name
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_ports():
    with db() as con:
        rows = con.execute(
            """
            SELECT ep.mac, e.hostname, e.ip, ep.port, ep.process, ep.pid, ep.reachable
            FROM endpoint_ports AS ep
            LEFT JOIN endpoints AS e ON e.mac = ep.mac
            JOIN (
                SELECT mac, MAX(timestamp) AS max_ts FROM endpoint_ports GROUP BY mac
            ) AS latest ON latest.mac = ep.mac AND latest.max_ts = ep.timestamp
            ORDER BY ep.port
            """
        ).fetchall()
        return [
            {**dict(r), "reachable": None if r["reachable"] is None else bool(r["reachable"])}
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Compatibility aliases (match the original posture_db.py surface exactly)
# ---------------------------------------------------------------------------

get_results = get_assessments
save_posture = save_assessment

get_needs_attention = needs_attention
add_needs_attention = add_attention
remove_needs_attention = remove_attention

get_endpoint_mac_by_ip = mac_from_ip
get_endpoint_processes = get_processes_for_mac


if __name__ == "__main__":
    init_db()
    print("Postgres DB:", DB_FILE)
    print("Assessments:", assessment_count())
    print("Needs attention:", len(get_needs_attention()))