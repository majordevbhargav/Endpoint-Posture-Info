"""
Posture Console — web UI for the posture-check workflow.

File #2: PostgreSQL-backed UI service (frontend/backend split).

This version keeps the existing queue/PowerShell workflow and dashboard
routes, but uses posture_db.py (now PostgreSQL-backed) as the single
database layer. The dashboard/console HTML now live in the separate
frontend/ folder, per the project plan Section 9.2, rather than next to
this file - FRONTEND_DIR below points at it and is configurable so the
two can be deployed independently later.

Also adds (Phase 1 / Phase 2 of the project plan):
    - /api/v1/endpoints/<mac>/share-posture, /restrict, /clear-restriction
      passthrough routes, forwarding to posture_app.py's admin-triggered
      ISE action endpoints, so the dashboard never talks to ISE directly.
    - /api/audit/ise-actions, reading the ise_action_audit table.
    - connection-state aware dashboard summary (connected vs not_connected).
"""

import datetime
import ipaddress
import socket
import re
import json
import msvcrt
import os
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from dotenv import load_dotenv

# Explicit path so this works regardless of the working directory the
# process is launched from.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import psycopg2.extras
from flask import Flask, Response, jsonify, request

from endpoint_360_integration import register_endpoint_360
from application_remediation import register_remediation
from endpoint_hardware_health_integration import register_hardware_health

from posture_db import (
    DB_FILE,
    PG_DB,
    PG_HOST,
    PG_PORT,
    add_needs_attention,
    get_all_applications,
    get_all_ports,
    get_apps_for_mac,
    get_assessments,
    get_db,
    get_ise_audit,
    get_needs_attention,
    get_processes_for_mac,
    init_db,
    mark_connected,
    mark_disconnected,
    remove_needs_attention,
    save_assessment,
)

QUEUE_FILE = os.environ.get("PENDING_QUEUE_FILE", "pending_devices.txt")
PS_SCRIPT = os.environ.get("PS_SCRIPT", "../agents/posture_agent.ps1")
POSTURE_SERVER = os.environ.get(
    "POSTURE_SERVER",
    "http://127.0.0.1:8000/api/v1/posture",
)
POSTURE_APP_BASE = os.environ.get(
    "POSTURE_APP_BASE",
    "http://127.0.0.1:8000",
)
UI_PORT = int(os.environ.get("UI_PORT", "5000"))
AUTO_WORKER_POLL_SECONDS = float(
    os.environ.get("AUTO_WORKER_POLL_SECONDS", "3")
)
IP_MAC_MAP_FILE = os.environ.get("IP_MAC_MAP_FILE", "ip_mac_map.txt")

# frontend/ sits alongside backend/ at the project root:
#   <root>/backend/app/posture_ui.py   <- this file
#   <root>/frontend/public/dashboard.html
FRONTEND_DIR = Path(
    os.environ.get(
        "FRONTEND_DIR",
        Path(__file__).resolve().parents[2] / "frontend" / "public",
    )
)
DASHBOARD_HTML_PATH = FRONTEND_DIR / "dashboard.html"
CONSOLE_HTML_PATH = FRONTEND_DIR / "console.html"

app = Flask(__name__)
register_endpoint_360(app)
register_remediation(app)
register_hardware_health(app)


def _read_dashboard_html() -> str:
    try:
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (
            "<h1>dashboard.html not found</h1>"
            f"<p>Expected it at {DASHBOARD_HTML_PATH}. "
            "The original console is still available at "
            "<a href='/console'>/console</a>.</p>"
        )


def _read_console_html() -> str:
    try:
        return CONSOLE_HTML_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return INDEX_HTML


def lookup_known_mac(ip: str):
    """Best-effort MAC lookup from SQLite and the watcher's map file."""
    if not ip:
        return None

    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT mac FROM endpoints WHERE ip = ? "
                "ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            ).fetchone()
            if row:
                return row["mac"]
    except Exception:
        pass

    path = Path(IP_MAC_MAP_FILE)
    if not path.exists():
        return None

    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "," not in line:
                continue
            key, value = line.split(",", 1)
            if key.strip() == ip:
                return value.strip()
    except OSError:
        pass

    return None


def _locked(path: str):
    """Open a shared queue file and acquire the same Windows byte lock."""
    if not os.path.exists(path):
        Path(path).touch()

    f = open(path, "r+", encoding="utf-8")
    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    return f


def _unlock_close(f):
    f.seek(0)
    try:
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        f.close()


def read_queue():
    if not os.path.exists(QUEUE_FILE):
        return []

    try:
        return [
            line.strip()
            for line in Path(QUEUE_FILE).read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def remove_from_queue(ip: str):
    f = _locked(QUEUE_FILE)
    try:
        items = [
            line.strip()
            for line in f.read().splitlines()
            if line.strip()
        ]
        items = [item for item in items if item != ip]

        f.seek(0)
        f.truncate()
        if items:
            f.write("\n".join(items) + "\n")
        return items
    finally:
        _unlock_close(f)


def requeue(ip: str):
    """Put an IP back into the shared queue."""
    if not ip:
        return []

    f = _locked(QUEUE_FILE)
    try:
        items = [
            line.strip()
            for line in f.read().splitlines()
            if line.strip()
        ]

        if ip not in items:
            items.append(ip)

        f.seek(0)
        f.truncate()
        if items:
            f.write("\n".join(items) + "\n")
        return items
    finally:
        _unlock_close(f)


def _now():
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def append_result(entry: dict):
    """Persist one check result through the shared SQLite layer."""
    timestamp = entry.get("timestamp")

    if not timestamp:
        date_val = entry.get("date")
        time_val = entry.get("time")

        if date_val and time_val:
            timestamp = f"{date_val}T{time_val}Z"
        else:
            timestamp = _now()

    mac = (entry.get("mac") or entry.get("ip") or "unknown").upper()

    save_assessment(
        mac=mac,
        ip=entry.get("ip"),
        hostname=entry.get("computer"),
        os_name=entry.get("os"),
        os_version=entry.get("osVersion"),
        timestamp=timestamp,
        status=entry.get("status"),
        detail=entry.get("detail"),
        submitted=bool(entry.get("submitted")),
        submit_error=entry.get("submitError"),
        checks=entry.get("checks") or [],
        apps_count=int(entry.get("appsCount") or 0),
        listening_ports=entry.get("listening_ports") or [],
        installed_apps=entry.get("installed_apps") or [],
        hardware=entry.get("hardware") or {},
        resource_usage=entry.get("resource_usage") or {},
        top_processes=entry.get("top_processes") or [],
    )


def run_check(
    ip: str,
    username: str = None,
    password: str = None,
) -> dict:
    """
    Run posture_agent.ps1 against one endpoint.

    A successful COMPLIANT/NON-COMPLIANT result is stored in SQLite.
    A failure is stored and added to the needs-attention table.

    NOTE: when the agent successfully POSTs straight to posture_app.py
    (entry["submitted"] is True), that request has already written a
    full row via save_assessment - including checks, listening ports,
    and installed apps. RESULT_JSON only carries a summary, so we must
    NOT also call append_result() in that case, or we'd overwrite the
    latest-per-mac row with a checks-less duplicate. We only persist
    here ourselves when the direct submit did not happen.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        PS_SCRIPT,
        "-ComputerName",
        ip,
        "-PostureServer",
        POSTURE_SERVER,
    ]

    if username and password:
        cmd += [
            "-Username",
            username,
            "-PlainPassword",
            password,
        ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        add_needs_attention(ip)
        entry = {
            "timestamp": _now(),
            "ip": ip,
            "mac": lookup_known_mac(ip),
            "status": "ERROR",
            "detail": "Timed out waiting for the check to finish.",
            "submitted": False,
        }
        append_result(entry)
        return entry
    except Exception as exc:
        add_needs_attention(ip)
        entry = {
            "timestamp": _now(),
            "ip": ip,
            "mac": lookup_known_mac(ip),
            "status": "ERROR",
            "detail": f"Unexpected error running the check: {exc}",
            "submitted": False,
        }
        append_result(entry)
        return entry

    parsed = None

    for line in proc.stdout.splitlines():
        if not line.startswith("RESULT_JSON:"):
            continue

        try:
            parsed = json.loads(line[len("RESULT_JSON:"):])
        except json.JSONDecodeError:
            parsed = None

    if parsed is None:
        add_needs_attention(ip)

        detail = (
            proc.stderr
            or proc.stdout
            or "No output from the script."
        ).strip()[-1000:]

        entry = {
            "timestamp": _now(),
            "ip": ip,
            "mac": lookup_known_mac(ip),
            "status": "ERROR",
            "detail": detail,
            "submitted": False,
        }
        append_result(entry)
        return entry

    status = parsed.get("status")
    is_error = status == "ERROR"

    entry = {
        "timestamp": _now(),
        "ip": ip,
        "computer": parsed.get("computer"),
        "mac": parsed.get("mac") or lookup_known_mac(ip),
        "os": parsed.get("os"),
        "osVersion": parsed.get("os_version")
        or parsed.get("osVersion"),
        "status": status,
        "detail": parsed.get("detail"),
        "submitted": parsed.get("submitted"),
        "submitError": parsed.get("submitError"),
        "checks": parsed.get("checks") or [],
        "appsCount": parsed.get("appsCount") or 0,
        "listening_ports": parsed.get("listening_ports") or [],
        "installed_apps": parsed.get("installed_apps") or [],
        "hardware": parsed.get("hardware") or {},
        "resource_usage": parsed.get("resource_usage") or {},
        "top_processes": parsed.get("top_processes") or [],
    }

    if is_error:
        add_needs_attention(ip)
    else:
        # A successful retry clears the old attention item.
        remove_needs_attention(ip)

    # Only write our own row when the agent's direct submit to
    # posture_app.py did NOT already happen - otherwise this would
    # overwrite the richer, already-saved row with a checks-less one.
    if is_error or not entry.get("submitted"):
        append_result(entry)

    return entry


def auto_worker():
    """
    Drain the watcher queue automatically.

    The watcher writes pending_devices.txt and this worker removes one item
    before running the PowerShell check. File locking prevents concurrent
    watcher/UI modifications from losing queue entries.
    """
    while True:
        try:
            pending = read_queue()

            if pending:
                ip = pending[0]
                remove_from_queue(ip)
                run_check(ip)

        except Exception as exc:
            print(f"Auto-worker error: {exc}")

        time.sleep(AUTO_WORKER_POLL_SECONDS)


def init_endpoint360_history_db():
    """Create the small diagnostic history table used only by Endpoint 360."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoint_360_diagnostics (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                score INTEGER,
                status TEXT,
                endpoint_latency_ms REAL,
                dns_latency_ms REAL,
                application_latency_ms REAL,
                traceroute_hops INTEGER,
                report_json JSONB NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoint360_diag_ip_time ON endpoint_360_diagnostics(ip, timestamp)")

        # One-time migration for databases created before report_json was
        # switched from TEXT to JSONB (matches the same migration in
        # posture_db.py and endpoint_360_integration.py). No-op once the
        # column is already jsonb.
        conn.execute("""
            DO $$
            BEGIN
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
        """)


def load_state() -> None:
    """Initialize the shared database and perform legacy migration."""
    init_db()
    init_endpoint360_history_db()


@app.route("/")
def dashboard_page():
    return Response(
        _read_dashboard_html(),
        mimetype="text/html",
    )


@app.route("/console")
def index():
    return Response(_read_console_html(), mimetype="text/html")


# ---------------------------------------------------------------------------
# Admin-triggered ISE actions - passthrough to posture_app.py
# (Section 8.2 / Section 11: the dashboard never talks to ISE directly,
# only through posture_app.py's transport-backed routes.)
# ---------------------------------------------------------------------------

def _forward_to_posture_app(method: str, path: str, body: dict | None = None):
    url = f"{POSTURE_APP_BASE}{path}"
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8")), exc.code
        except Exception:
            return {"ok": False, "detail": str(exc)}, exc.code
    except Exception as exc:
        return {"ok": False, "detail": str(exc)}, 502


@app.route("/api/v1/endpoints/<mac>/share-posture", methods=["POST"])
def api_share_posture(mac):
    result, status = _forward_to_posture_app("POST", f"/api/v1/endpoints/{mac}/share-posture")
    return jsonify(result), status


@app.route("/api/v1/endpoints/<mac>/restrict", methods=["POST"])
def api_restrict_endpoint(mac):
    body = request.get_json(silent=True) or {}
    result, status = _forward_to_posture_app("POST", f"/api/v1/endpoints/{mac}/restrict", body)
    return jsonify(result), status


@app.route("/api/v1/endpoints/<mac>/clear-restriction", methods=["POST"])
def api_clear_restriction(mac):
    result, status = _forward_to_posture_app("POST", f"/api/v1/endpoints/{mac}/clear-restriction")
    return jsonify(result), status


@app.route("/api/audit/ise-actions")
def api_ise_audit():
    limit = request.args.get("limit", 200, type=int)
    return jsonify({"entries": get_ise_audit(limit)})


@app.route("/api/needs_attention")
def api_needs_attention():
    return jsonify(
        {"needs_attention": get_needs_attention()}
    )


@app.route("/api/results")
def api_results():
    limit = request.args.get(
        "limit",
        default=50,
        type=int,
    )
    limit = max(1, min(limit, 500))

    results = get_assessments(limit)

    output = []

    for result in results:
        timestamp = result.get("timestamp") or ""

        # Timestamps are stored in UTC. Keep the legacy split "date"/
        # "time" fields (still used by the /console page) but also send
        # the raw ISO-8601 UTC string so newer UI code can convert it
        # to the viewer's local time instead of showing UTC verbatim.
        timestamp_utc = timestamp
        if timestamp_utc and not timestamp_utc.endswith("Z") and "T" in timestamp_utc:
            timestamp_utc = timestamp_utc + "Z"

        if "T" in timestamp:
            date_part, time_part = (
                timestamp.rstrip("Z").split("T", 1)
            )
        else:
            pieces = timestamp.split()
            date_part = pieces[0] if pieces else ""
            time_part = pieces[1] if len(pieces) > 1 else ""

        output.append(
            {
                "time": time_part,
                "date": date_part,
                "timestamp": timestamp_utc,
                "ip": result.get("ip"),
                "computer": result.get("hostname")
                or result.get("ip"),
                "mac": result.get("mac"),
                "os": result.get("os"),
                "osVersion": result.get("os_version"),
                "status": result.get("status"),
                "detail": result.get("detail"),
                "submitted": bool(result.get("submitted")),
                "submitError": result.get("submit_error"),
                "appsCount": result.get("apps_count") or 0,
                "checks": result.get("checks") or [],
                "listening_ports": result.get(
                    "listening_ports"
                )
                or [],
            }
        )

    return jsonify({"results": output})


@app.route("/api/skip", methods=["POST"])
def api_skip():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    mac = lookup_known_mac(ip) or ip.upper()

    remove_needs_attention(ip)

    append_result(
        {
            "timestamp": _now(),
            "ip": ip,
            "mac": mac,
            "status": "SKIPPED",
            "detail": "Skipped - not checked.",
            "submitted": False,
            "submitError": None,
        }
    )

    return jsonify(
        {"needs_attention": get_needs_attention()}
    )


@app.route("/api/check", methods=["POST"])
def api_check():
    """
    Manual retry.

    No credentials means posture_agent.ps1 uses its stored common
    credential. Supplying username/password overrides it for this run.
    """
    data = request.get_json(silent=True) or {}

    ip = str(data.get("ip", "")).strip()
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    remove_needs_attention(ip)

    run_check(
        ip,
        username or None,
        password or None,
    )

    return jsonify(
        {"needs_attention": get_needs_attention()}
    )


def get_category_percent(check_name: str):
    """Calculate compliance percentage from each endpoint's latest result."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT cr.status, COUNT(*) AS cnt
                FROM check_results AS cr
                JOIN (
                    SELECT a.id
                    FROM assessments AS a
                    JOIN (
                        SELECT mac, MAX(timestamp) AS max_ts
                        FROM assessments
                        GROUP BY mac
                    ) AS latest
                    ON latest.mac = a.mac
                    AND latest.max_ts = a.timestamp
                ) AS latest_ids
                ON latest_ids.id = cr.assessment_id
                WHERE cr.check_name = ?
                   OR (? = 'Firewall'
                       AND cr.check_name = 'Windows Firewall')
                GROUP BY cr.status
                """,
                (check_name, check_name),
            ).fetchall()

        total = sum(int(row["cnt"]) for row in rows)
        compliant = sum(
            int(row["cnt"])
            for row in rows
            if row["status"] == "COMPLIANT"
        )

        return round(compliant / total * 100) if total else None

    except Exception as exc:
        print(
            f"Error calculating percent for "
            f"{check_name}: {exc}"
        )
        return None


# "Firewall" and "Open Ports" write real check rows (via posture_agent.ps1),
# and "Application Control" now does too. Everything else in this list
# is still a placeholder that no collector emits yet.
OTHER_CATEGORIES = [
    "OS Patch Level",
    "Disk Encryption",
    "Security Settings",
]


@app.route("/api/dashboard/summary")
def api_dashboard_summary():
    needs = set(get_needs_attention())

    with get_db() as conn:
        latest = conn.execute(
            """
            SELECT a.mac, a.status, a.ip
            FROM assessments AS a
            JOIN (
                SELECT mac, MAX(timestamp) AS max_ts
                FROM assessments
                GROUP BY mac
            ) AS latest
            ON latest.mac = a.mac
            AND latest.max_ts = a.timestamp
            """
        ).fetchall()

        latest_endpoints = {
            row["mac"]: (
                row["status"],
                row["ip"],
            )
            for row in latest
        }

        endpoints = conn.execute(
            "SELECT mac, ip, connected FROM endpoints"
        ).fetchall()

        connected_macs = {
            row["mac"] for row in endpoints if row["connected"]
        }

        for row in endpoints:
            latest_endpoints.setdefault(
                row["mac"],
                ("Never Checked", row["ip"]),
            )

        # Section 8.4 of the project plan: the live compliance counts only
        # reflect endpoints currently connected. A stale, long-disconnected
        # endpoint keeps its historical status (visible on the Endpoints/
        # Assessments pages) but is no longer counted as compliant/
        # non-compliant here, and shows up in not_connected instead.
        compliant = 0
        non_compliant = 0
        not_connected = 0

        for mac, (status, ip) in latest_endpoints.items():
            if mac not in connected_macs:
                not_connected += 1
                continue

            # needs_attention is keyed by IP only (add_attention(ip),
            # table PK is ip - see posture_db.py) - "mac in needs" could
            # never match anything and was dead code that silently
            # depended on needs_attention never being changed to key by
            # MAC. Removed rather than left as misleading no-op logic.
            if ip in needs:
                continue

            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON-COMPLIANT":
                non_compliant += 1

        total = len(latest_endpoints)

        # Timestamps are always stored in UTC (see _now() and the agent's
        # `(Get-Date).ToUniversalTime()`), so "today" must be computed in
        # UTC too - comparing a local-time "today" against UTC-stored
        # rows silently shifts the boundary by the server's UTC offset
        # and can under/over-count assessments near midnight.
        today = datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%d")

        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM assessments
            WHERE timestamp LIKE ?
            """,
            (f"{today}%",),
        ).fetchone()

        assessments_today = int(row["count"])

    at_risk = len(needs)

    score = (
        round(
            (compliant + at_risk * 0.5)
            / total
            * 100
        )
        if total
        else None
    )

    return jsonify(
        {
            "total_endpoints": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "at_risk": at_risk,
            "not_connected": not_connected,
            "assessments_today": assessments_today,
            "compliance_score": score,
        }
    )


@app.route("/api/dashboard/trend")
def api_dashboard_trend():
    days_param = request.args.get(
        "days",
        type=int,
    ) or 7

    days_param = max(1, min(days_param, 90))

    with get_db() as conn:
        if days_param == 1:
            # Bucket boundaries must be computed in UTC - stored
            # timestamps are UTC (see _now()/_parse_timestamp), so a
            # local-time "now" here would shift every bucket by the
            # server's UTC offset.
            now = datetime.datetime.now(
                datetime.timezone.utc
            ).replace(tzinfo=None)
            current_hour = now.replace(
                minute=0,
                second=0,
                microsecond=0,
            )

            hour_starts = [
                current_hour
                - datetime.timedelta(hours=i)
                for i in range(23, -1, -1)
            ]

            keys = [
                hour.strftime("%Y-%m-%d %H")
                for hour in hour_starts
            ]

            # Emit full ISO UTC timestamps rather than pre-formatted
            # "HH:00" strings - formatting in UTC on the backend would
            # show the wrong hour to anyone not in UTC. The frontend
            # converts each of these to the browser's local time.
            labels = [
                hour.strftime("%Y-%m-%dT%H:%M:%SZ")
                for hour in hour_starts
            ]

            buckets = {
                key: {
                    "compliant": 0,
                    "non_compliant": 0,
                    "at_risk": 0,
                }
                for key in keys
            }

            cutoff = (
                hour_starts[0]
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )

            rows = conn.execute(
                """
                SELECT timestamp, status
                FROM assessments
                WHERE timestamp >= ?
                """,
                (cutoff,),
            ).fetchall()

            for row in rows:
                ts = _parse_timestamp(row["timestamp"])

                if ts is None:
                    continue

                key = ts.strftime("%Y-%m-%d %H")

                if key not in buckets:
                    continue

                bucket = buckets[key]

                if row["status"] == "COMPLIANT":
                    bucket["compliant"] += 1
                elif row["status"] == "NON-COMPLIANT":
                    bucket["non_compliant"] += 1
                elif row["status"] == "ERROR":
                    bucket["at_risk"] += 1

            return jsonify(
                {
                    "days": labels,
                    "buckets": [
                        buckets[key] for key in keys
                    ],
                    "granularity": "hourly",
                }
            )

        # Same reasoning as the hourly branch above - use UTC "today"
        # since assessment timestamps are stored in UTC.
        today = datetime.datetime.now(datetime.timezone.utc).date()

        days = [
            (
                today
                - datetime.timedelta(
                    days=i
                )
            ).strftime("%Y-%m-%d")
            for i in range(days_param - 1, -1, -1)
        ]

        buckets = {
            day: {
                "compliant": 0,
                "non_compliant": 0,
                "at_risk": 0,
            }
            for day in days
        }

        cutoff = days[0] + "T00:00:00Z"

        rows = conn.execute(
            """
            SELECT timestamp, status
            FROM assessments
            WHERE timestamp >= ?
            """,
            (cutoff,),
        ).fetchall()

        for row in rows:
            timestamp = row["timestamp"] or ""

            date_key = (
                timestamp.split("T", 1)[0]
                if "T" in timestamp
                else timestamp.split()[0]
            )

            if date_key not in buckets:
                continue

            bucket = buckets[date_key]

            if row["status"] == "COMPLIANT":
                bucket["compliant"] += 1
            elif row["status"] == "NON-COMPLIANT":
                bucket["non_compliant"] += 1
            elif row["status"] == "ERROR":
                bucket["at_risk"] += 1

    return jsonify(
        {
            "days": days,
            "buckets": [
                buckets[day] for day in days
            ],
            "granularity": "daily",
        }
    )


def _parse_timestamp(value):
    if not value:
        return None

    value = value.rstrip("Z")

    try:
        if "T" in value:
            return datetime.datetime.strptime(
                value,
                "%Y-%m-%dT%H:%M:%S",
            )

        return datetime.datetime.strptime(
            value.split(".")[0],
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None


@app.route("/api/dashboard/categories")
def api_dashboard_categories():
    categories = [
        {
            "name": "Firewall",
            "implemented": True,
            "percent": get_category_percent(
                "Firewall"
            ),
        },
        {
            "name": "Open Ports",
            "implemented": True,
            "percent": get_category_percent(
                "Open Ports"
            ),
        },
        {
            "name": "Application Control",
            "implemented": True,
            "percent": get_category_percent(
                "Application Control"
            ),
        },
        {
            "name": "Anti-Virus",
            "implemented": False,
            "percent": None,
        },
    ]

    categories += [
        {
            "name": name,
            "implemented": False,
            "percent": None,
        }
        for name in OTHER_CATEGORIES
    ]

    return jsonify({"categories": categories})


@app.route("/api/dashboard/endpoints")
def api_dashboard_endpoints():
    needs = set(get_needs_attention())

    known_ips = {}

    map_path = Path(IP_MAC_MAP_FILE)

    if map_path.exists():
        try:
            for line in map_path.read_text(
                encoding="utf-8"
            ).splitlines():
                if "," not in line:
                    continue

                ip, mac = line.split(",", 1)
                known_ips[ip.strip()] = mac.strip()
        except OSError:
            pass

    with get_db() as conn:
        ep_rows = conn.execute(
            """
            SELECT mac, ip, hostname, os, os_version,
                   last_seen, apps_count,
                   manufacturer, model, serial_number,
                   cpu_percent, memory_percent,
                   memory_total_mb, memory_free_mb,
                   connected, shared_with_ise_at, enforcement_state
            FROM endpoints
            ORDER BY mac
            """
        ).fetchall()

        rows = []
        seen_keys = set()

        for ep in ep_rows:
            mac = ep["mac"]
            ip = ep["ip"]

            seen_keys.add(mac)

            assessment = conn.execute(
                """
                SELECT id, status, detail, timestamp
                FROM assessments
                WHERE mac = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
                """,
                (mac,),
            ).fetchone()

            status = "Never Checked"
            checks = []

            if assessment:
                # needs_attention is keyed by IP only - see the same note
                # in /api/dashboard/summary above.
                if ip in needs:
                    status = "At Risk"
                else:
                    status = (
                        assessment["status"]
                        or "Unknown"
                    ).title()

                check_rows = conn.execute(
                    """
                    SELECT check_name, status, detail
                    FROM check_results
                    WHERE assessment_id = ?
                    """,
                    (assessment["id"],),
                ).fetchall()

                checks = [
                    {
                        "name": row["check_name"],
                        "status": row["status"],
                        "detail": row["detail"],
                    }
                    for row in check_rows
                ]

            last_seen_date = None
            last_seen_time = None
            last_seen = ep["last_seen"]
            last_seen_utc = None

            if last_seen:
                last_seen_utc = (
                    last_seen
                    if last_seen.endswith("Z") or "T" not in last_seen
                    else last_seen + "Z"
                )

                if "T" in last_seen:
                    (
                        last_seen_date,
                        last_seen_time,
                    ) = last_seen.rstrip("Z").split(
                        "T",
                        1,
                    )
                else:
                    pieces = last_seen.split()
                    last_seen_date = pieces[0]
                    last_seen_time = (
                        pieces[1]
                        if len(pieces) > 1
                        else ""
                    )

            port_rows = conn.execute(
                """
                SELECT port, process, pid, reachable
                FROM endpoint_ports
                WHERE mac = ?
                ORDER BY port ASC
                """,
                (mac,),
            ).fetchall()

            ports = [
                {
                    "port": row["port"],
                    "process": row["process"],
                    "pid": row["pid"],
                    "reachable": (
                        None
                        if row["reachable"] is None
                        else bool(row["reachable"])
                    ),
                }
                for row in port_rows
            ]

            # Split the same port list into the two categories requested
            # for the Ports UI: ports that responded to a reachability
            # probe ("open") vs. ports that were listening locally but
            # could not be reached ("blocked").
            open_ports = [p for p in ports if p["reachable"] is True]
            blocked_ports = [p for p in ports if p["reachable"] is False]

            rows.append(
                {
                    "identity": mac,
                    "ip": ip,
                    "mac": mac,
                    "hostname": ep["hostname"],
                    "os": ep["os"],
                    "os_version": ep["os_version"],
                    "status": status,
                    "connected": bool(ep["connected"]),
                    "shared_with_ise_at": ep["shared_with_ise_at"],
                    "enforcement_state": ep["enforcement_state"],
                    "last_seen": last_seen_time,
                    "last_seen_date": last_seen_date,
                    "last_seen_utc": last_seen_utc,
                    "apps_count": ep["apps_count"],
                    "checks": checks,
                    "ports": ports,
                    "open_ports": open_ports,
                    "blocked_ports": blocked_ports,
                    "apps": get_apps_for_mac(mac),
                    "processes": get_processes_for_mac(mac),
                    "hardware": {
                        "manufacturer": ep["manufacturer"],
                        "model": ep["model"],
                        "serial_number": ep["serial_number"],
                    },
                    "resource_usage": {
                        "cpu_percent": ep["cpu_percent"],
                        "memory_percent": ep["memory_percent"],
                        "memory_total_mb": ep["memory_total_mb"],
                        "memory_free_mb": ep["memory_free_mb"],
                    },
                }
            )

        for ip, mac in sorted(known_ips.items()):
            key = (mac or ip).upper()

            if key in seen_keys:
                continue

            seen_keys.add(key)

            rows.append(
                {
                    "identity": key,
                    "ip": ip,
                    "mac": mac,
                    "hostname": None,
                    "os": None,
                    "os_version": None,
                    "status": (
                        # needs_attention is keyed by IP only - "key in
                        # needs" (key = mac or ip) was dead code.
                        "At Risk"
                        if ip in needs
                        else "Never Checked"
                    ),
                    "connected": False,
                    "shared_with_ise_at": None,
                    "enforcement_state": None,
                    "last_seen": None,
                    "last_seen_date": None,
                    "apps_count": 0,
                    "checks": [],
                    "ports": [],
                    "apps": [],
                }
            )

    rows.sort(
        key=lambda row: (
            row.get("last_seen_date") or "",
            row.get("last_seen") or "",
        ),
        reverse=True,
    )

    return jsonify({"endpoints": rows})



# ---------------------------------------------------------------------------
# Endpoint 360 fleet/selected-endpoint diagnostics
# ---------------------------------------------------------------------------

def _ping_endpoint(ip: str, timeout_ms: int = 1000):
    """Ping one known endpoint from the console host."""
    result = {"reachable": False, "latency_ms": None, "error": None}
    if not ip:
        result["error"] = "No IP address"
        return result
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        result["error"] = "Invalid IP address"
        return result

    try:
        proc = subprocess.run(
            ["ping", "-n", "1", "-w", str(max(100, timeout_ms)), ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(2, timeout_ms / 1000 + 1.5),
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        m = re.search(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", out, re.I)
        if m:
            result["latency_ms"] = float(m.group(1))
            result["reachable"] = proc.returncode == 0
        else:
            result["reachable"] = proc.returncode == 0
        if not result["reachable"]:
            result["error"] = "No ICMP reply"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _endpoint_360_health(row, live):
    """Build a transparent fleet health score from existing posture data + live reachability."""
    score = 100
    reasons = []
    resources = row.get("resource_usage") or {}
    status = str(row.get("status") or "").upper()

    if status == "NON-COMPLIANT":
        score -= 25; reasons.append("Endpoint posture is non-compliant")
    elif status in {"ERROR", "AT RISK"}:
        score -= 30; reasons.append("Endpoint has an assessment error/risk state")
    elif status == "NEVER CHECKED":
        score -= 15; reasons.append("Endpoint has not completed a posture check")

    cpu = resources.get("cpu_percent")
    mem = resources.get("memory_percent")
    try:
        if cpu is not None and float(cpu) >= 90:
            score -= 15; reasons.append(f"High CPU usage ({float(cpu):.0f}%)")
        elif cpu is not None and float(cpu) >= 75:
            score -= 7; reasons.append(f"Elevated CPU usage ({float(cpu):.0f}%)")
    except Exception:
        pass
    try:
        if mem is not None and float(mem) >= 90:
            score -= 15; reasons.append(f"High memory usage ({float(mem):.0f}%)")
        elif mem is not None and float(mem) >= 75:
            score -= 7; reasons.append(f"Elevated memory usage ({float(mem):.0f}%)")
    except Exception:
        pass

    ping_ms = live.get("latency_ms")
    if not live.get("reachable"):
        score -= 30; reasons.append("Endpoint is not reachable from the console")
    elif ping_ms is not None:
        if ping_ms >= 200:
            score -= 20; reasons.append(f"High endpoint latency ({ping_ms:.1f} ms)")
        elif ping_ms >= 100:
            score -= 10; reasons.append(f"Elevated endpoint latency ({ping_ms:.1f} ms)")

    score = max(0, min(100, int(round(score))))
    health = "HEALTHY" if score >= 85 else "DEGRADED" if score >= 60 else "POOR"
    root = "NONE"
    if reasons:
        if not live.get("reachable"):
            root = "REACHABILITY"
        elif any("CPU" in r for r in reasons):
            root = "ENDPOINT_RESOURCE"
        elif any("memory" in r.lower() for r in reasons):
            root = "ENDPOINT_RESOURCE"
        elif any("latency" in r.lower() for r in reasons):
            root = "NETWORK_PATH"
        elif "posture" in reasons[0].lower():
            root = "POSTURE"
        else:
            root = "POSTURE"
    return {"score": score, "status": health, "root_cause": root, "findings": reasons}


def _fleet_endpoint_rows():
    """Return endpoint inventory plus the latest stored assessment; never probes endpoints."""
    try:
        with get_db() as conn:
            rows = conn.execute("""
                SELECT mac, ip, hostname, os, os_version, last_seen, apps_count,
                       manufacturer, model, serial_number,
                       cpu_percent, memory_percent, memory_total_mb, memory_free_mb
                FROM endpoints ORDER BY hostname, ip
            """).fetchall()
            result = []
            for ep in rows:
                mac = ep["mac"]
                assessment = conn.execute("""
                    SELECT id, status, detail, timestamp
                    FROM assessments WHERE mac=?
                    ORDER BY timestamp DESC, id DESC LIMIT 1
                """, (mac,)).fetchone()
                checks = []
                if assessment:
                    checks = [
                        {"name": r["check_name"], "status": r["status"], "detail": r["detail"]}
                        for r in conn.execute("""
                            SELECT check_name, status, detail FROM check_results
                            WHERE assessment_id=? ORDER BY check_name
                        """, (assessment["id"],)).fetchall()
                    ]
                port_rows = conn.execute("""
                    SELECT port, process, pid, reachable FROM endpoint_ports
                    WHERE mac=? ORDER BY port ASC
                """, (mac,)).fetchall()
                result.append({
                    "identity": mac or ep["ip"], "mac": mac, "ip": ep["ip"],
                    "hostname": ep["hostname"], "os": ep["os"], "os_version": ep["os_version"],
                    "apps_count": ep["apps_count"] or 0, "last_seen": ep["last_seen"],
                    "status": assessment["status"] if assessment else "Never Checked",
                    "detail": assessment["detail"] if assessment else None,
                    "assessment_timestamp": assessment["timestamp"] if assessment else None,
                    "checks": checks,
                    "ports": [dict(r) for r in port_rows],
                    "apps": get_apps_for_mac(mac),
                    "processes": get_processes_for_mac(mac),
                    "hardware": {"manufacturer": ep["manufacturer"], "model": ep["model"], "serial_number": ep["serial_number"]},
                    "resource_usage": {"cpu_percent": ep["cpu_percent"], "memory_percent": ep["memory_percent"], "memory_total_mb": ep["memory_total_mb"], "memory_free_mb": ep["memory_free_mb"]},
                })
            return result
    except Exception:
        return []


@app.route("/api/endpoint-360/endpoints")
def api_endpoint_360_endpoints():
    """Return endpoint choices only; no reachability/health checks are run here."""
    endpoints = _fleet_endpoint_rows()
    return jsonify({
        "endpoints": [
            {
                "ip": e.get("ip"),
                "mac": e.get("mac"),
                "hostname": e.get("hostname"),
                "os": e.get("os"),
                "status": e.get("status"),
                "last_seen": e.get("last_seen"),
            }
            for e in endpoints if e.get("ip")
        ]
    })


def _traceroute_endpoint(ip: str, max_hops: int = 12, timeout_ms: int = 800):
    result = {"status": "UNKNOWN", "hops": []}
    if not ip:
        result["status"] = "NO_TARGET"
        return result
    max_hops = max(1, min(int(max_hops), 30))
    timeout_ms = max(200, min(int(timeout_ms), 3000))
    try:
        proc = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), ip],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=max(8, int(max_hops * timeout_ms / 1000) + 5),
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in output.splitlines():
            line = line.strip()
            match = re.match(r"^(\d+)\s+(.+)$", line)
            if not match:
                continue
            hop = int(match.group(1))
            rest = match.group(2)
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
            latency_matches = re.findall(r"<?\s*(\d+)\s*ms", rest, re.I)
            latency = min([int(x) for x in latency_matches], default=None)
            result["hops"].append({"hop": hop, "ip": ip_match.group(1) if ip_match else None, "latency_ms": latency, "raw": rest})
        result["status"] = "COMPLETE" if result["hops"] else "NO_RESPONSE"
    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
    except FileNotFoundError:
        result["status"] = "UNAVAILABLE"
    except Exception as exc:
        result["status"] = "FAILED"
        result["error"] = str(exc)
    return result


@app.route("/api/endpoint-360/diagnostic")
def api_endpoint_360_diagnostic():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    endpoint = next((e for e in _fleet_endpoint_rows() if e.get("ip") == ip), None)
    if endpoint is None:
        return jsonify({"error": "Endpoint not found"}), 404

    live = _ping_endpoint(ip, 1500)
    health = _endpoint_360_health(endpoint, live)

    dns = {"hostname": endpoint.get("hostname"), "resolved_ip": None, "status": "UNKNOWN"}
    try:
        host = endpoint.get("hostname")
        if host:
            dns["resolved_ip"] = socket.gethostbyname(host)
            dns["status"] = "HEALTHY"
    except Exception as exc:
        dns["error"] = str(exc)
        dns["status"] = "FAILED"

    target = request.args.get("target", "outlook.office.com").strip() or "outlook.office.com"
    app_test = {"target": target, "latency_ms": None, "status": "UNKNOWN"}
    try:
        start_time = time.perf_counter()
        with socket.create_connection((target, 443), timeout=5):
            pass
        app_test["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 1)
        app_test["status"] = "HEALTHY" if app_test["latency_ms"] <= 400 else "DEGRADED" if app_test["latency_ms"] <= 1200 else "POOR"
    except Exception as exc:
        app_test["status"] = "FAILED"
        app_test["error"] = str(exc)

    max_hops = request.args.get("max_hops", 12, type=int)
    traceroute = _traceroute_endpoint(ip, max_hops=max_hops)

    diagnostic_payload = {
        "timestamp": _now(),
        "console_ip": _local_console_ip(),
        "endpoint": endpoint,
        "live": live,
        "health": health,
        "dns": dns,
        "application": app_test,
        "traceroute": traceroute,
        "scope_note": "Endpoint assessment, CPU/memory, applications, ports and posture values come from the selected endpoint's latest stored assessment. Live reachability, DNS, application and traceroute tests are measured from this Endpoint 360 console. Wi-Fi signal and remote security-indicator collection are not available from the current local-only collectors.",
    }
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO endpoint_360_diagnostics(
                    timestamp, ip, score, status, endpoint_latency_ms,
                    dns_latency_ms, application_latency_ms, traceroute_hops, report_json
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    diagnostic_payload["timestamp"], ip, health.get("score"), health.get("status"),
                    live.get("latency_ms"), dns.get("latency_ms"), app_test.get("latency_ms"),
                    len(traceroute.get("hops") or []), psycopg2.extras.Json(diagnostic_payload),
                ),
            )
    except Exception:
        pass

    return jsonify(diagnostic_payload)




def _local_console_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return None


@app.route("/api/endpoint-360/history")
def api_endpoint_360_history():
    """Return real diagnostic samples for the selected endpoint only."""
    ip = (request.args.get("ip") or "").strip()
    days = max(1, min(request.args.get("days", 7, type=int), 90))
    limit = max(1, min(request.args.get("limit", 2000, type=int), 10000))
    if not ip:
        return jsonify({"history": []})
    try:
        # Cutoff computed in Python (not via SQLite's datetime('now', ?),
        # which Postgres doesn't have) - see the same fix in
        # endpoint_360_integration.py's _history().
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with get_db() as conn:
            rows = conn.execute("""
                SELECT timestamp, score, status, endpoint_latency_ms,
                       dns_latency_ms, application_latency_ms, traceroute_hops
                FROM endpoint_360_diagnostics
                WHERE ip = ? AND timestamp >= ?
                ORDER BY timestamp ASC, id ASC LIMIT ?
            """, (ip, cutoff, limit)).fetchall()
        return jsonify({"history": [dict(r) for r in rows]})
    except Exception:
        return jsonify({"history": []})

@app.route("/api/v1/applications")
def api_v1_applications():
    """
    Flat, cross-endpoint installed-application inventory for the
    Applications page. Supports simple search over name/publisher and
    an exact-match publisher filter, both applied server-side so the
    browser never has to pull the whole inventory just to filter it.
    """
    search = (request.args.get("q") or "").strip().lower()
    publisher = (request.args.get("publisher") or "").strip().lower()

    apps = get_all_applications()

    if search:
        apps = [
            a for a in apps
            if search in (a.get("name") or "").lower()
            or search in (a.get("publisher") or "").lower()
        ]

    if publisher:
        apps = [
            a for a in apps
            if (a.get("publisher") or "").lower() == publisher
        ]

    return jsonify({
        "total": len(apps),
        "applications": apps,
    })


@app.route("/api/v1/ports")
def api_v1_ports():
    """
    Flat, cross-endpoint listening-port inventory (latest snapshot per
    endpoint) for the Ports page. Supports search over process/hostname
    and an exact-match port filter, applied server-side.
    """
    search = (request.args.get("q") or "").strip().lower()
    port_filter = request.args.get("port")

    ports = get_all_ports()

    if search:
        ports = [
            p for p in ports
            if search in (p.get("process") or "").lower()
            or search in (p.get("hostname") or "").lower()
            or search in (p.get("ip") or "").lower()
        ]

    if port_filter:
        try:
            port_num = int(port_filter)
            ports = [p for p in ports if p.get("port") == port_num]
        except ValueError:
            pass

    return jsonify({
        "total": len(ports),
        # This console currently only collects TCP listening ports
        # (see posture_agent.ps1); protocol is included so the UI/API
        # shape already supports UDP once that collector is added.
        "ports": [{**p, "protocol": "TCP"} for p in ports],
    })


@app.route("/api/v1/endpoints")
def api_v1_endpoints():
    """Alias of /api/dashboard/endpoints under the REST-style /api/v1 path."""
    return api_dashboard_endpoints()


@app.route("/api/v1/endpoints/<mac>/applications")
def api_v1_endpoint_applications(mac):
    return jsonify({"mac": mac.upper(), "applications": get_apps_for_mac(mac.upper())})


@app.route("/api/v1/endpoints/<mac>/ports")
def api_v1_endpoint_ports(mac):
    mac = mac.upper()
    ports = [p for p in get_all_ports() if (p.get("mac") or "").upper() == mac]
    return jsonify({"mac": mac, "ports": [{**p, "protocol": "TCP"} for p in ports]})


@app.route("/api/dashboard/health")
def api_dashboard_health():
    parts = urllib.parse.urlsplit(POSTURE_SERVER)

    health_url = (
        f"{parts.scheme}://{parts.netloc}/health"
    )

    posture_app_ok = False
    ise_configured = None

    try:
        with urllib.request.urlopen(
            health_url,
            timeout=3,
        ) as response:
            body = json.loads(
                response.read().decode("utf-8")
            )
            posture_app_ok = True
            ise_configured = body.get(
                "ise_configured"
            )
    except Exception:
        pass

    watcher_last_seen = None
    watcher_recent = False

    map_path = Path(IP_MAC_MAP_FILE)

    if map_path.exists():
        try:
            age = time.time() - map_path.stat().st_mtime

            if age < 120:
                watcher_last_seen = f"{int(age)}s ago"
            else:
                watcher_last_seen = (
                    f"{int(age // 60)}m ago"
                )

            watcher_recent = age < 300
        except OSError:
            pass

    db_ok = True
    db_note = f"PostgreSQL database active ({PG_HOST}:{PG_PORT}/{PG_DB})."
    try:
        from posture_db import assessment_count
        assessment_count()
    except Exception as exc:
        db_ok = False
        db_note = f"PostgreSQL connection failed: {exc}"

    return jsonify(
        {
            "posture_app": {
                "reachable": posture_app_ok,
                "url": health_url,
            },
            "ise_configured": ise_configured,
            "watcher": {
                "last_activity": watcher_last_seen,
                "recent": watcher_recent,
            },
            "database": {
                "built": db_ok,
                "note": db_note,
                "path": str(DB_FILE),
            },
            "policy_service": {"built": False},
            "report_service": {"built": False},
            "notification_service": {"built": False},
        }
    )


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light only">
<title>ISE Posture Console</title>
<style>
html { color-scheme: light only; }
:root {
  --bg: #ffffff;
  --panel: #ffffff;
  --border: #e5e7eb;
  --border-soft: #f0f1f3;
  --text: #111318;
  --muted: #8a8f98;
  --green: #16a34a;
  --green-bg: #f0faf3;
  --red: #dc2626;
  --red-bg: #fef2f2;
  --blue: #2563eb;
  --gray-bg: #f7f7f8;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.mono { font-family: "SFMono-Regular", Consolas, Menlo, monospace; }
.wrap { max-width: 780px; margin: 0 auto; padding: 48px 20px 80px; }
header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 28px;
}
header h1 {
  font-size: 17px;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin: 0;
}
header .meta { font-size: 12px; color: var(--muted); }
.search-bar { margin-bottom: 16px; }
.search-bar input {
  width: 100%;
  font-family: inherit;
  background: #fff;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 13px;
}
.search-bar input:focus { outline: none; border-color: var(--blue); }
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 20px;
  overflow: hidden;
}
.panel-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  padding: 12px 18px;
  border-bottom: 1px solid var(--border-soft);
  display: flex;
  justify-content: space-between;
  background: var(--gray-bg);
}
.panel-body { padding: 0; }
.row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 13px 18px;
  border-bottom: 1px solid var(--border-soft);
}
.row:last-child { border-bottom: none; }
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--green);
  flex-shrink: 0;
}
.ip { color: var(--text); min-width: 118px; font-weight: 500; }
.empty { color: var(--muted); padding: 24px 18px; font-size: 13px; }
button {
  font-family: inherit;
  font-size: 12.5px;
  font-weight: 500;
  background: #fff;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 6px 13px;
  border-radius: 6px;
  cursor: pointer;
}
button:hover { border-color: #c9ccd1; background: var(--gray-bg); }
button.skip:hover {
  border-color: var(--red);
  color: var(--red);
  background: var(--red-bg);
}
button.run:hover { border-color: var(--blue); color: var(--blue); }
button.override-link {
  border-color: transparent;
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  text-decoration: underline;
  padding: 4px;
}
button.override-link:hover { color: var(--text); }
button.confirm {
  background: var(--text);
  border-color: var(--text);
  color: #fff;
}
button.cancel { border-color: transparent; color: var(--muted); }
button:disabled { opacity: 0.4; cursor: default; }
.spacer { flex: 1; }
.cred-form {
  display: none;
  gap: 8px;
  padding: 12px 18px 16px;
  border-bottom: 1px solid var(--border-soft);
  background: var(--gray-bg);
}
.cred-form.open { display: flex; align-items: center; flex-wrap: wrap; }
.cred-form input {
  font-family: inherit;
  background: #fff;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 7px 10px;
  border-radius: 6px;
  font-size: 13px;
}
.results .row { align-items: flex-start; }
.status-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 5px;
  min-width: 104px;
  text-align: center;
}
.status-COMPLIANT { background: var(--green-bg); color: var(--green); }
.status-NON-COMPLIANT,
.status-ERROR { background: var(--red-bg); color: var(--red); }
.status-SKIPPED { background: var(--gray-bg); color: var(--muted); }
.detail { color: var(--muted); font-size: 12.5px; }
.time { color: var(--muted); font-size: 12px; min-width: 56px; }
.mac {
  font-size: 11.5px;
  color: var(--text);
  background: var(--gray-bg);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 5px;
  white-space: nowrap;
}
footer {
  color: var(--muted);
  font-size: 11.5px;
  text-align: center;
  margin-top: 24px;
}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>ISE Posture Console</h1>
<div class="meta" id="server-label"></div>
</header>

<div class="search-bar">
<input type="text" id="search-input"
       class="mono"
       placeholder="Filter by IP, hostname, or MAC..."
       autocomplete="off">
</div>

<div class="panel">
<div class="panel-title">
<span>Needs attention</span>
<span id="pending-count">0</span>
</div>
<div class="panel-body" id="queue-list">
<div class="empty">
Nothing needs attention. New devices are checked automatically as they connect.
</div>
</div>
</div>

<div class="panel results">
<div class="panel-title">
<span>Results log</span>
<span id="results-count">0</span>
</div>
<div class="panel-body" id="results-list">
<div class="empty">Nothing checked yet.</div>
</div>
</div>

<footer>
Devices are checked automatically as they connect · polling every 4s
</footer>
</div>

<script>
const serverLabel = document.getElementById('server-label');
serverLabel.textContent =
  'posture server: ' + (window.__POSTURE_SERVER__ || '');

let formOpenFor = null;
let searchTerm = '';
let currentPending = [];
let currentResults = [];

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function applyPendingFilter(list) {
  if (!searchTerm) return list;
  return list.filter(ip =>
    ip.toLowerCase().includes(searchTerm)
  );
}

function applyResultsFilter(list) {
  if (!searchTerm) return list;

  return list.filter(r =>
    (r.ip || '').toLowerCase().includes(searchTerm) ||
    (r.computer || '').toLowerCase().includes(searchTerm) ||
    (r.mac || '').toLowerCase().includes(searchTerm)
  );
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function rowTemplate(ip) {
  const safeIp = esc(ip);
  const div = document.createElement('div');
  div.className = 'device';

  div.innerHTML = `
    <div class="row">
      <span class="dot"></span>
      <span class="ip mono">${safeIp}</span>
      <span class="spacer"></span>
      <button class="run" data-ip="${safeIp}">Retry</button>
      <button class="override-link" data-ip="${safeIp}">
        different creds?
      </button>
      <button class="skip" data-ip="${safeIp}">Skip</button>
    </div>
    <div class="cred-form" data-ip="${safeIp}">
      <input type="text"
             class="username"
             placeholder="Username (e.g. Administrator)">
      <input type="password"
             class="password"
             placeholder="Password">
      <button class="confirm" data-ip="${safeIp}">
        Confirm &#9656;
      </button>
      <button class="cancel" data-ip="${safeIp}">
        Cancel
      </button>
    </div>
  `;

  return div;
}

function renderQueue(pending) {
  const list = document.getElementById('queue-list');

  document.getElementById('pending-count').textContent =
    pending.length;

  if (pending.length === 0) {
    list.innerHTML =
      '<div class="empty">' +
      'Nothing needs attention. New devices are checked automatically as they connect.' +
      '</div>';
    return;
  }

  list.innerHTML = '';
  pending.forEach(ip =>
    list.appendChild(rowTemplate(ip))
  );
}

function renderResults(results) {
  const list = document.getElementById('results-list');

  document.getElementById('results-count').textContent =
    results.length;

  if (results.length === 0) {
    list.innerHTML =
      '<div class="empty">Nothing checked yet.</div>';
    return;
  }

  list.innerHTML = '';

  results.forEach(r => {
    const status = r.status || 'ERROR';
    const badgeClass = 'status-' + status;

    const detailBits = [];

    if (r.computer) detailBits.push(esc(r.computer));
    if (r.detail) detailBits.push(esc(r.detail));

    if (r.submitted === false) {
      detailBits.push(
        '(not submitted to ISE: ' +
        esc(r.submitError || 'unknown error') +
        ')'
      );
    }

    const macBadge = r.mac
      ? `<span class="mac mono">MAC: ${esc(r.mac)}</span>`
      : '';

    const row = document.createElement('div');
    row.className = 'row';

    row.innerHTML = `
      <span class="time">${esc(r.time)}</span>
      <span class="ip mono">${esc(r.ip)}</span>
      <span class="status-badge ${esc(badgeClass)}">
        ${esc(status)}
      </span>
      ${macBadge}
      <span class="detail">
        ${detailBits.join(' &middot; ')}
      </span>
    `;

    list.appendChild(row);
  });
}

async function refreshQueue() {
  try {
    const data = await fetchJSON('/api/needs_attention');

    currentPending = data.needs_attention || [];

    if (formOpenFor) return;

    renderQueue(
      applyPendingFilter(currentPending)
    );
  } catch (err) {
    console.error('Queue refresh failed:', err);
  }
}

async function refreshResults() {
  try {
    const data = await fetchJSON('/api/results');

    currentResults = data.results || [];

    renderResults(
      applyResultsFilter(currentResults)
    );
  } catch (err) {
    console.error('Results refresh failed:', err);
  }
}

document.addEventListener('click', async e => {
  const ip = e.target.dataset.ip;

  if (!ip) return;

  if (e.target.classList.contains('run')) {
    e.target.disabled = true;
    e.target.textContent = 'Retrying...';

    try {
      const data = await fetchJSON('/api/check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip})
      });

      currentPending = data.needs_attention || [];
      renderQueue(
        applyPendingFilter(currentPending)
      );
      await refreshResults();
    } catch (err) {
      console.error(err);
      e.target.disabled = false;
      e.target.textContent = 'Retry';
    }
  }

  if (e.target.classList.contains('override-link')) {
    document.querySelectorAll('.cred-form')
      .forEach(f => f.classList.remove('open'));

    const form = document.querySelector(
      `.cred-form[data-ip="${ip}"]`
    );

    if (form) {
      form.classList.add('open');
      form.querySelector('.username').focus();
      formOpenFor = ip;
    }
  }

  if (e.target.classList.contains('cancel')) {
    const form = document.querySelector(
      `.cred-form[data-ip="${ip}"]`
    );

    if (form) form.classList.remove('open');

    formOpenFor = null;
  }

  if (e.target.classList.contains('skip')) {
    e.target.disabled = true;

    try {
      const data = await fetchJSON('/api/skip', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip})
      });

      currentPending = data.needs_attention || [];

      renderQueue(
        applyPendingFilter(currentPending)
      );

      await refreshResults();
    } catch (err) {
      console.error(err);
      e.target.disabled = false;
    }
  }

  if (e.target.classList.contains('confirm')) {
    const form = document.querySelector(
      `.cred-form[data-ip="${ip}"]`
    );

    if (!form) return;

    const username =
      form.querySelector('.username').value.trim();

    const password =
      form.querySelector('.password').value;

    if (!username || !password) return;

    e.target.disabled = true;
    e.target.textContent = 'Running...';

    try {
      const data = await fetchJSON('/api/check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          ip,
          username,
          password
        })
      });

      formOpenFor = null;

      currentPending =
        data.needs_attention || [];

      renderQueue(
        applyPendingFilter(currentPending)
      );

      await refreshResults();
    } catch (err) {
      console.error(err);
      e.target.disabled = false;
      e.target.textContent = 'Confirm ▶';
    }
  }
});

document.getElementById('search-input')
  .addEventListener('input', e => {
    searchTerm =
      e.target.value.trim().toLowerCase();

    if (!formOpenFor) {
      renderQueue(
        applyPendingFilter(currentPending)
      );
    }

    renderResults(
      applyResultsFilter(currentResults)
    );
  });

refreshQueue();
refreshResults();

setInterval(refreshQueue, 4000);
setInterval(refreshResults, 4000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print(
        f"Posture Console at "
        f"http://127.0.0.1:{UI_PORT}"
    )
    print(f"Queue file: {QUEUE_FILE}")
    print(f"PS script:  {PS_SCRIPT}")
    print(f"Posture server: {POSTURE_SERVER}")
    print(f"SQLite DB: {DB_FILE}")

    load_state()

    print(
        f"Database contains "
        f"{len(get_assessments(100000))} assessment(s)."
    )
    print(
        f"Needs attention: "
        f"{len(get_needs_attention())}"
    )
    print(
        "Auto-worker running: new devices are "
        "checked automatically in the background."
    )

    threading.Thread(
        target=auto_worker,
        daemon=True,
        name="posture-auto-worker",
    ).start()

    app.run(
        host="127.0.0.1",
        port=UI_PORT,
        debug=False,
        threaded=True,
    )