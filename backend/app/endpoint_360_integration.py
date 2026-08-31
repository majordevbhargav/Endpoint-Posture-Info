"""
VE Compliance Engine - Endpoint 360 integration.

Endpoint 360 = Endpoint Experience (Wi-Fi / LAN / DNS / WAN / application
path, 0-100 experience score) + Security Indicators (lateral-movement /
beaconing / suspicious-connection signal, 0-100 security score) for the
machine this console is running on, shown side by side without mixing
them into a single "compliant/non-compliant" number - NAC posture stays
separate from both, same as the original Endpoint Experience module.

Two collectors are loaded and run in the background:
    endpoint_experience_dashboard.py   -> experience score + root cause
    endpoint_security_indicators.py    -> security score + risk level

Integration:
    from endpoint_360_integration import register_endpoint_360
    register_endpoint_360(app)

Env overrides:
    EXPERIENCE_AGENT_FILE          (default endpoint_experience_dashboard.py)
    EXPERIENCE_REFRESH_SECONDS     (default 15)
    EXPERIENCE_TARGET              (default outlook.office.com)
    EXPERIENCE_TRACE               (default true)

    SECURITY_AGENT_FILE            (default endpoint_security_indicators.py)
    SECURITY_OBSERVE_SECONDS       (default 30)  - length of each sampling window
    SECURITY_SAMPLE_INTERVAL       (default 5)   - seconds between samples in a window
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2.extras
from flask import Blueprint, jsonify, render_template_string, request

from posture_db import db, init_db

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

EXPERIENCE_AGENT_FILE = Path(
    os.getenv("EXPERIENCE_AGENT_FILE", "endpoint_experience_dashboard.py")
)
EXPERIENCE_REFRESH_SECONDS = max(5, int(os.getenv("EXPERIENCE_REFRESH_SECONDS", "15")))
EXPERIENCE_TARGET = os.getenv("EXPERIENCE_TARGET", "outlook.office.com")
EXPERIENCE_TRACE = os.getenv("EXPERIENCE_TRACE", "true").lower() == "true"

SECURITY_AGENT_FILE = Path(
    os.getenv("SECURITY_AGENT_FILE", "endpoint_security_indicators.py")
)
SECURITY_OBSERVE_SECONDS = max(10, int(os.getenv("SECURITY_OBSERVE_SECONDS", "30")))
SECURITY_SAMPLE_INTERVAL = max(2, int(os.getenv("SECURITY_SAMPLE_INTERVAL", "5")))

_STATE = {
    "experience": {"report": None, "error": None, "lock": threading.Lock()},
    "security": {"report": None, "error": None, "lock": threading.Lock()},
    "started": False,
    "start_lock": threading.Lock(),
}
_EXPERIENCE_AGENT = None
_SECURITY_AGENT = None


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except Exception:
        return None
    finally:
        sock.close()


def _load_module(path: Path, module_name: str):
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"Collector not found: {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load collector from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_experience_agent():
    global _EXPERIENCE_AGENT
    if _EXPERIENCE_AGENT is None:
        _EXPERIENCE_AGENT = _load_module(
            EXPERIENCE_AGENT_FILE, "ve_endpoint_experience_agent"
        )
    return _EXPERIENCE_AGENT


def _load_security_agent():
    global _SECURITY_AGENT
    if _SECURITY_AGENT is None:
        _SECURITY_AGENT = _load_module(
            SECURITY_AGENT_FILE, "ve_endpoint_security_agent"
        )
    return _SECURITY_AGENT


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def init_endpoint_360_db():
    """Additive migration: never alters existing posture tables."""
    init_db()
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS endpoint_experience_history (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                mac TEXT,
                ip TEXT,
                hostname TEXT,
                target TEXT,
                score REAL,
                status TEXT,
                root_cause TEXT,
                endpoint_status TEXT,
                wifi_status TEXT,
                gateway_status TEXT,
                dns_status TEXT,
                internet_status TEXT,
                application_status TEXT,
                gateway_latency_ms REAL,
                gateway_loss_percent REAL,
                wifi_signal_percent REAL,
                dns_latency_ms REAL,
                internet_latency_ms REAL,
                tcp_443_latency_ms REAL,
                https_latency_ms REAL,
                report_json JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_experience_time
                ON endpoint_experience_history(timestamp);

            CREATE INDEX IF NOT EXISTS idx_experience_mac_time
                ON endpoint_experience_history(mac, timestamp);

            CREATE TABLE IF NOT EXISTS endpoint_security_history (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                ip TEXT,
                hostname TEXT,
                security_score REAL,
                risk_level TEXT,
                overall_status TEXT,
                high_findings INTEGER,
                medium_findings INTEGER,
                total_findings INTEGER,
                report_json JSONB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_time
                ON endpoint_security_history(timestamp);
            """
        )

        # One-time migration for databases created before report_json was
        # switched from TEXT to JSONB (see the matching note/migration in
        # posture_db.py's init_db()). Safe to run on every startup - it's a
        # no-op once the column is already jsonb.
        con.executescript(
            """
            DO $$
            BEGIN
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
            END $$;
            """
        )


def _endpoint_identity(report):
    endpoint = report.get("endpoint") or {}
    return {
        "mac": endpoint.get("mac") or endpoint.get("MAC"),
        "ip": endpoint.get("local_ip"),
        "hostname": endpoint.get("hostname"),
    }


def _nac_status(mac):
    if not mac:
        return None
    try:
        with db() as con:
            row = con.execute(
                """
                SELECT status
                FROM assessments
                WHERE mac = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
                """,
                (str(mac).upper(),),
            ).fetchone()
            return row["status"] if row else None
    except Exception:
        return None


def save_experience_report(report):
    ident = _endpoint_identity(report)
    exp = report.get("experience") or {}
    wifi = report.get("wifi") or {}
    gateway = report.get("gateway_test") or {}
    dns = report.get("dns_test") or {}
    internet = report.get("internet_test") or {}
    tcp = report.get("tcp_443_test") or {}
    app = report.get("application_test") or {}

    timestamp = report.get("timestamp_utc") or _utc_now()

    with db() as con:
        con.execute(
            """
            INSERT INTO endpoint_experience_history(
                timestamp, mac, ip, hostname, target,
                score, status, root_cause,
                endpoint_status, wifi_status, gateway_status,
                dns_status, internet_status, application_status,
                gateway_latency_ms, gateway_loss_percent,
                wifi_signal_percent, dns_latency_ms,
                internet_latency_ms, tcp_443_latency_ms,
                https_latency_ms, report_json
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                timestamp,
                ident["mac"],
                ident["ip"],
                ident["hostname"],
                app.get("host") or EXPERIENCE_TARGET,
                exp.get("score"),
                exp.get("status"),
                exp.get("root_cause"),
                (report.get("endpoint_health") or {}).get("status"),
                wifi.get("status"),
                gateway.get("status"),
                dns.get("status"),
                internet.get("status"),
                app.get("status"),
                gateway.get("avg_ms"),
                gateway.get("loss_percent"),
                wifi.get("signal_percent"),
                dns.get("latency_ms"),
                internet.get("avg_ms"),
                tcp.get("latency_ms"),
                app.get("total_ms"),
                # report_json is JSONB - pass a native dict via Json(),
                # not a json.dumps() string (see posture_db.py note).
                psycopg2.extras.Json(report),
            ),
        )


def save_security_report(report):
    endpoint = report.get("endpoint") or {}
    summary = report.get("security_summary") or {}
    timestamp = report.get("timestamp_utc") or _utc_now()

    with db() as con:
        con.execute(
            """
            INSERT INTO endpoint_security_history(
                timestamp, ip, hostname,
                security_score, risk_level, overall_status,
                high_findings, medium_findings, total_findings,
                report_json
            )
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                timestamp,
                _local_ip(),
                endpoint.get("hostname"),
                summary.get("security_score"),
                summary.get("risk_level"),
                summary.get("overall_status"),
                summary.get("high_findings"),
                summary.get("medium_findings"),
                summary.get("total_findings"),
                psycopg2.extras.Json(report),
            ),
        )


# ---------------------------------------------------------------------------
# Collector loops
# ---------------------------------------------------------------------------

def _experience_loop():
    try:
        agent = _load_experience_agent()
        agent.CONFIG["target"] = EXPERIENCE_TARGET
        agent.CONFIG["trace_enabled"] = EXPERIENCE_TRACE
        agent.CONFIG["refresh"] = EXPERIENCE_REFRESH_SECONDS
    except Exception as exc:
        with _STATE["experience"]["lock"]:
            _STATE["experience"]["error"] = str(exc)
        return

    while True:
        try:
            report = agent.collect_report()
            save_experience_report(report)
            with _STATE["experience"]["lock"]:
                _STATE["experience"]["report"] = report
                _STATE["experience"]["error"] = None
        except Exception as exc:
            with _STATE["experience"]["lock"]:
                _STATE["experience"]["error"] = str(exc)
        time.sleep(EXPERIENCE_REFRESH_SECONDS)


def _security_loop():
    try:
        agent = _load_security_agent()
        agent.CONFIG["observe"] = SECURITY_OBSERVE_SECONDS
        agent.CONFIG["interval"] = SECURITY_SAMPLE_INTERVAL
        agent.CONFIG["dashboard"] = False
    except Exception as exc:
        with _STATE["security"]["lock"]:
            _STATE["security"]["error"] = str(exc)
        return

    while True:
        try:
            # agent.collect() blocks internally for CONFIG["observe"]
            # seconds while it samples active connections, so this loop
            # naturally paces itself - no extra sleep needed on success.
            report = agent.collect()
            save_security_report(report)
            with _STATE["security"]["lock"]:
                _STATE["security"]["report"] = report
                _STATE["security"]["error"] = None
        except Exception as exc:
            with _STATE["security"]["lock"]:
                _STATE["security"]["error"] = str(exc)
            time.sleep(SECURITY_OBSERVE_SECONDS)


def start_endpoint_360_collectors():
    init_endpoint_360_db()
    with _STATE["start_lock"]:
        if _STATE["started"]:
            return
        _STATE["started"] = True

    threading.Thread(
        target=_experience_loop,
        name="endpoint-experience-collector",
        daemon=True,
    ).start()

    threading.Thread(
        target=_security_loop,
        name="endpoint-security-collector",
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def _pearson(rows, x_key, y_key="score"):
    pairs = []
    for row in rows:
        x, y = row.get(x_key), row.get(y_key)
        if x is None or y is None:
            continue
        try:
            pairs.append((float(x), float(y)))
        except (TypeError, ValueError):
            continue
    if len(pairs) < 3:
        return None
    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in pairs)
    denx = sum((x - mx) ** 2 for x in xs) ** 0.5
    deny = sum((y - my) ** 2 for y in ys) ** 0.5
    if not denx or not deny:
        return None
    return round(num / (denx * deny), 3)


def _history(table, days=7, extra_where="", extra_params=(), limit=2000):
    days = max(1, min(int(days), 90))
    limit = max(1, min(int(limit), 10000))
    # Cutoff computed in Python (not via SQLite's datetime('now', ?), which
    # Postgres doesn't have) so this works against either backend and
    # against the TEXT/ISO-8601 timestamp columns used throughout this
    # schema.
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sql = f"""
        SELECT *
        FROM {table}
        WHERE timestamp >= ?
        {extra_where}
        ORDER BY timestamp ASC, id ASC
        LIMIT ?
    """
    params = [cutoff, *extra_params, limit]
    with db() as con:
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def _decode_row(row):
    """
    Pop report_json out of a row dict and return it as a parsed Python
    object under "report".

    report_json is a JSONB column, so psycopg2's RealDictCursor already
    hands it back as a native dict/list - no json.loads() needed or
    wanted (calling json.loads() on an already-decoded dict would raise).
    The str branch is kept only as a defensive fallback (e.g. a database
    that hasn't been migrated to JSONB yet, or a driver configuration that
    returns raw JSON text), so this keeps working either way.
    """
    item = dict(row)
    raw = item.pop("report_json", None)

    if isinstance(raw, str):
        try:
            report = json.loads(raw)
        except (TypeError, ValueError):
            report = {}
    elif isinstance(raw, (dict, list)):
        report = raw
    else:
        report = {}

    item["report"] = report
    return item


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

endpoint360_bp = Blueprint("endpoint_360", __name__)


@endpoint360_bp.get("/api/endpoint-experience/current")
def experience_current():
    with _STATE["experience"]["lock"]:
        report = _STATE["experience"]["report"]
        error = _STATE["experience"]["error"]

    if report is None:
        return jsonify({"status": "INITIALIZING", "error": error, "report": None})

    ident = _endpoint_identity(report)
    report = dict(report)
    report["nac_posture"] = _nac_status(ident.get("mac"))
    return jsonify({"status": "UP", "report": report})


@endpoint360_bp.get("/api/endpoint-experience/history")
def experience_history():
    rows = _history(
        "endpoint_experience_history",
        request.args.get("days", 7, type=int),
        " AND UPPER(mac) = UPPER(?)" if request.args.get("mac") else "",
        (request.args.get("mac"),) if request.args.get("mac") else (),
        request.args.get("limit", 2000, type=int),
    )
    return jsonify({"history": [_decode_row(r) for r in rows]})


@endpoint360_bp.get("/api/endpoint-experience/summary")
def experience_summary():
    rows = _history(
        "endpoint_experience_history",
        request.args.get("days", 7, type=int),
        " AND UPPER(mac) = UPPER(?)" if request.args.get("mac") else "",
        (request.args.get("mac"),) if request.args.get("mac") else (),
        10000,
    )
    if not rows:
        return jsonify({
            "samples": 0, "avg_score": None, "min_score": None,
            "max_score": None, "root_causes": {}, "statuses": {},
        })

    scores = [r["score"] for r in rows if r["score"] is not None]
    roots, statuses = {}, {}
    for r in rows:
        if r["root_cause"]:
            roots[r["root_cause"]] = roots.get(r["root_cause"], 0) + 1
        if r["status"]:
            statuses[r["status"]] = statuses.get(r["status"], 0) + 1

    return jsonify({
        "samples": len(rows),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
        "min_score": min(scores) if scores else None,
        "max_score": max(scores) if scores else None,
        "root_causes": roots,
        "statuses": statuses,
        "correlation": {
            "experience_vs_wifi_signal": _pearson(rows, "wifi_signal_percent"),
            "experience_vs_gateway_latency": _pearson(rows, "gateway_latency_ms"),
            "experience_vs_dns_latency": _pearson(rows, "dns_latency_ms"),
            "experience_vs_internet_latency": _pearson(rows, "internet_latency_ms"),
            "experience_vs_https_latency": _pearson(rows, "https_latency_ms"),
        },
    })


@endpoint360_bp.get("/api/endpoint-security/current")
def security_current():
    with _STATE["security"]["lock"]:
        report = _STATE["security"]["report"]
        error = _STATE["security"]["error"]

    if report is None:
        return jsonify({"status": "INITIALIZING", "error": error, "report": None})

    return jsonify({"status": "UP", "report": report})


@endpoint360_bp.get("/api/endpoint-security/history")
def security_history():
    rows = _history(
        "endpoint_security_history",
        request.args.get("days", 7, type=int),
        limit=request.args.get("limit", 2000, type=int),
    )
    return jsonify({"history": [_decode_row(r) for r in rows]})


@endpoint360_bp.get("/api/endpoint-security/summary")
def security_summary():
    rows = _history(
        "endpoint_security_history",
        request.args.get("days", 7, type=int),
        limit=10000,
    )
    if not rows:
        return jsonify({
            "samples": 0, "avg_score": None, "min_score": None,
            "max_score": None, "risk_levels": {}, "total_high": 0, "total_medium": 0,
        })

    scores = [r["security_score"] for r in rows if r["security_score"] is not None]
    risk_levels = {}
    for r in rows:
        if r["risk_level"]:
            risk_levels[r["risk_level"]] = risk_levels.get(r["risk_level"], 0) + 1

    return jsonify({
        "samples": len(rows),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
        "min_score": min(scores) if scores else None,
        "max_score": max(scores) if scores else None,
        "risk_levels": risk_levels,
        "total_high": sum(int(r["high_findings"] or 0) for r in rows),
        "total_medium": sum(int(r["medium_findings"] or 0) for r in rows),
    })


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Endpoint 360 | VE Compliance Engine</title>
<style>
:root{
  --bg:#0b1220; --panel:#111a2c; --panel2:#0e1626; --border:#1f2a3d; --border-soft:#182238;
  --text:#e7ecf5; --muted:#8a95ab;
  --green:#22c55e; --green-bg:rgba(34,197,94,.12);
  --orange:#f59e0b; --orange-bg:rgba(245,158,11,.12);
  --red:#ef4444; --red-bg:rgba(239,68,68,.14);
  --blue:#3b82f6; --blue-bg:rgba(59,130,246,.12);
  --purple:#a78bfa; --purple-bg:rgba(167,139,250,.12);
  --cyan:#22d3ee; --cyan-bg:rgba(34,211,238,.12);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px -apple-system,Segoe UI,Arial,sans-serif}
.wrap{max-width:1560px;margin:auto;padding:20px}
.header{display:flex;justify-content:space-between;gap:15px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
.title{display:flex;align-items:center;gap:10px;font-size:19px;font-weight:700}
.title .logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#22d3ee);display:grid;place-items:center;font-size:15px}
.sub{color:var(--muted);margin-top:3px;font-size:12.5px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
button,input,select{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:7px;padding:8px 10px;font:inherit}
button{cursor:pointer}
button:hover{border-color:#33415c}
button.primary{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:600}
.toggle{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12.5px}
.grid{display:grid;gap:14px}
.cards6{grid-template-columns:repeat(6,minmax(140px,1fr))}
.three{grid-template-columns:1.05fr 1fr 1.4fr}
.five{grid-template-columns:repeat(5,1fr)}
.two{grid-template-columns:1fr 1fr}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
.label{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;display:flex;align-items:center;gap:6px}
.value{font-size:24px;font-weight:700;margin-top:6px}
.status{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;margin-top:8px}
.healthy{background:var(--green-bg);color:var(--green)}
.degraded{background:var(--orange-bg);color:var(--orange)}
.poor{background:var(--red-bg);color:var(--red)}
.neutral{background:rgba(255,255,255,.06);color:var(--muted)}
.security-low{background:var(--green-bg);color:var(--green)}
.security-review{background:var(--orange-bg);color:var(--orange)}
.security-high{background:var(--red-bg);color:var(--red)}
.gauge-wrap{display:flex;align-items:center;gap:14px}
.gauge{width:74px;height:74px;border-radius:50%;display:grid;place-items:center;position:relative;flex:0 0 auto}
.gauge::before{content:"";position:absolute;inset:8px;border-radius:50%;background:var(--panel)}
.gauge span{position:relative;font-size:16px;font-weight:800}
.section-title{font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px;font-size:13.5px}
.kv{display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12.5px}
.kv div:nth-child(odd){color:var(--muted)}
.findings{display:flex;flex-direction:column;gap:7px;max-height:220px;overflow:auto}
.finding{padding:9px 10px;border-left:3px solid var(--orange);background:var(--orange-bg);border-radius:5px;font-size:12.5px}
.finding.high{border-left-color:var(--red);background:var(--red-bg)}
.finding.medium{border-left-color:var(--orange);background:var(--orange-bg)}
.finding.low{border-left-color:var(--blue);background:var(--blue-bg)}
.path{display:flex;align-items:center;gap:6px;overflow:auto;padding:6px 0}
.node{min-width:92px;text-align:center;flex:0 0 auto}
.circle{width:30px;height:30px;border-radius:50%;margin:auto;background:var(--blue-bg);color:var(--blue);display:grid;place-items:center;font-weight:700;font-size:11.5px}
.line{height:2px;background:var(--border);min-width:20px}
.node small{color:var(--muted);word-break:break-word;font-size:10.5px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:8px;border-bottom:1px solid var(--border-soft)}
th{color:var(--muted);font-weight:600}
.bottom-bar{margin-top:14px;background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}
.bottom-bar .rec{font-size:13px;color:var(--text)}
.pill-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.pill{font-size:11px;font-weight:700;padding:3px 9px;border-radius:20px}
@media(max-width:1200px){.cards6{grid-template-columns:repeat(3,1fr)}.three{grid-template-columns:1fr}.five{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.cards6{grid-template-columns:1fr 1fr}.wrap{padding:12px}}
</style>
</head>
<body><div class="wrap">

<div class="header">
  <div>
    <div class="title"><span class="logo">&#128737;</span> Endpoint 360</div>
    <div class="sub" id="identity">Collecting endpoint, network, application and security evidence...</div>
  </div>
  <div class="actions">
    <input id="target" value="outlook.office.com" title="Application target" style="width:150px">
    <button onclick="refresh()">Refresh</button>
    <button class="primary" onclick="refresh()">Run Full Diagnostic</button>
  </div>
</div>

<div class="grid cards6">
  <div class="card">
    <div class="label">Experience Score</div>
    <div class="gauge-wrap" style="margin-top:8px">
      <div class="gauge" id="gauge"><span id="score">--</span></div>
      <div><span id="overall" class="status neutral">--</span></div>
    </div>
  </div>
  <div class="card"><div class="label">Root Cause</div><div class="value" id="root" style="font-size:17px">--</div><span id="rootStatus" class="status neutral">--</span></div>
  <div class="card"><div class="label">Gateway</div><div class="value" id="gateway">--</div><span id="gatewayStatus" class="status neutral">--</span></div>
  <div class="card"><div class="label">Internet</div><div class="value" id="internet">--</div><span id="internetStatus" class="status neutral">--</span></div>
  <div class="card"><div class="label">Application</div><div class="value" id="app">--</div><span id="appStatus" class="status neutral">--</span></div>
  <div class="card">
    <div class="label">&#128737; Security Indicators</div>
    <div class="value" id="secScore">--</div>
    <span id="secRisk" class="status neutral">--</span>
    <div class="pill-row">
      <span class="pill" id="secHigh" style="background:var(--red-bg);color:var(--red)">-- high</span>
      <span class="pill" id="secMedium" style="background:var(--orange-bg);color:var(--orange)">-- medium</span>
    </div>
  </div>
</div>

<div class="grid three" style="margin-top:14px">
  <div class="card"><div class="section-title">Endpoint Health</div><div class="kv" id="endpoint"></div></div>
  <div class="card"><div class="section-title">Wi-Fi / LAN</div><div class="kv" id="wifi"></div></div>
  <div class="card"><div class="section-title">Network Path (Traceroute)</div><div class="path" id="path"></div></div>
</div>

<div class="grid five" style="margin-top:14px">
  <div class="card"><div class="section-title">DNS Performance</div><div class="kv" id="dnsPerf"></div></div>
  <div class="card"><div class="section-title">Internet Performance</div><div class="kv" id="netPerf"></div></div>
  <div class="card"><div class="section-title">Application Performance</div><div class="kv" id="appPerf"></div></div>
  <div class="card"><div class="section-title">Root Cause Evidence</div><div class="findings" id="findings"></div></div>
  <div class="card">
    <div class="section-title">Security Findings <span class="sub" id="secMeta" style="margin-left:auto;font-weight:400"></span></div>
    <div class="findings" id="secFindings"></div>
  </div>
</div>

<div class="bottom-bar">
  <div class="rec" id="recommendation">Collecting evidence...</div>
  <div class="actions">
    <button onclick="alert('Export is not wired up yet - the JSON report is at endpoint_experience_latest.json / endpoint_security_indicators.json on this machine.')">Export Report</button>
    <button class="primary" onclick="refresh()">Run Full Diagnostic</button>
  </div>
</div>

</div>
<script>
const $=id=>document.getElementById(id);
const esc=x=>String(x??'--').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
function cls(s){s=String(s||'').toUpperCase();return s==='HEALTHY'?'healthy':(s==='DEGRADED'||s==='REVIEW')?'degraded':(s==='POOR'||s==='FAILED'||s==='DOWN')?'poor':'neutral'}
function set(id,v,s){$(id).textContent=v??'--';$(id).className='status '+cls(s)}
function kv(items){return items.map(x=>'<div>'+esc(x[0])+'</div><div>'+esc(x[1])+'</div>').join('')}
function fmt(v,u=''){return v===null||v===undefined?'--':v+u}
async function get(url){const r=await fetch(url+(url.includes('?')?'&':'?')+'ts='+Date.now());return r.json()}

function paintGauge(score){
  const s=Math.max(0,Math.min(100,Number(score)||0));
  const color=s>=90?'#22c55e':s>=70?'#f59e0b':'#ef4444';
  $('gauge').style.background=`conic-gradient(${color} ${s*3.6}deg, rgba(255,255,255,.08) 0deg)`;
}

function securityClass(risk){
  risk=String(risk||'').toUpperCase();
  if(risk==='LOW_RISK') return 'security-low';
  if(risk==='REVIEW') return 'security-review';
  if(risk==='HIGH_RISK') return 'security-high';
  return 'neutral';
}

async function refreshExperience(){
  const cur=await get('/api/endpoint-experience/current');
  if(!cur.report){ $('identity').textContent=cur.error||'Experience collector initializing...'; return; }
  const r=cur.report,e=r.experience||{},en=r.endpoint||{},eh=r.endpoint_health||{},w=r.wifi||{},g=r.gateway_test||{},d=r.dns_test||{},i=r.internet_test||{},t=r.tcp_443_test||{},a=r.application_test||{};

  $('identity').textContent=(en.hostname||'Endpoint')+' | '+(en.local_ip||'--')+' | '+(r.timestamp_utc||'');
  $('score').textContent=fmt(e.score);
  paintGauge(e.score);
  set('overall',e.status,e.status);
  $('root').textContent=e.root_cause||'NONE';
  set('rootStatus',(e.possible_areas||[]).length?'Investigate':'No issue',(e.possible_areas||[]).length?'DEGRADED':'HEALTHY');
  $('gateway').textContent=fmt(g.avg_ms,' ms');set('gatewayStatus',g.status,g.status);
  $('internet').textContent=fmt(i.avg_ms,' ms');set('internetStatus',i.status,i.status);
  $('app').textContent=fmt(a.total_ms,' ms');set('appStatus',a.status,a.status);

  $('endpoint').innerHTML=kv([['CPU',fmt(eh.cpu_percent,'%')],['Memory',fmt(eh.memory_percent,'%')],['C: Free',fmt(eh.disk_free_percent,'%')],['Disk Free',fmt(eh.disk_free_gb,' GB')],['Status',eh.status],['NAC posture',cur.report.nac_posture||'--']]);
  $('wifi').innerHTML=kv([['SSID',w.ssid],['BSSID',w.bssid],['Signal',fmt(w.signal_percent,'%')],['Channel',w.channel],['Radio',w.radio_type],['Gateway loss',fmt(g.loss_percent,'%')]]);
  $('dnsPerf').innerHTML=kv([['DNS target',d.target],['DNS latency',fmt(d.latency_ms,' ms')],['Status',d.status]]);
  $('netPerf').innerHTML=kv([['Latency',fmt(i.avg_ms,' ms')],['Packet loss',fmt(i.loss_percent,'%')],['Status',i.status]]);
  $('appPerf').innerHTML=kv([['Target',a.host],['HTTP status',a.status_code],['TCP 443',fmt(t.latency_ms,' ms')],['Status',a.status]]);

  const nodes=[['Client',en.local_ip],['Gateway',en.gateway],...((r.traceroute||{}).hops||[]).filter(h=>h.ip).map(h=>['Hop '+h.hop,h.ip+(h.latency_ms!=null?' | '+h.latency_ms+' ms':'')]),[a.host,t.ip]];
  $('path').innerHTML=nodes.map((n,k)=>'<div class="node"><div class="circle">'+(k+1)+'</div><b>'+esc(n[0])+'</b><br><small>'+esc(n[1])+'</small></div>'+(k<nodes.length-1?'<div class="line"></div>':'')).join('');
  $('findings').innerHTML=(e.findings||[]).length?(e.findings||[]).map(x=>'<div class="finding">'+esc(x)+'</div>').join(''):'<div class="status healthy">No significant issue detected</div>';

  const rec=(e.findings||[])[0];
  $('recommendation').textContent = rec ? ('The issue is likely related to ' + (e.root_cause||'an unclear area') + '. ' + rec) : 'No significant experience issue detected right now.';
}

async function refreshSecurity(){
  const cur=await get('/api/endpoint-security/current');
  if(!cur.report){ return; }
  const r=cur.report, s=r.security_summary||{};

  $('secScore').textContent=fmt(s.security_score);
  set('secRisk', (s.risk_level||'--').replace('_',' '), s.risk_level);
  $('secRisk').className='status '+securityClass(s.risk_level);
  $('secHigh').textContent=(s.high_findings??0)+' high';
  $('secMedium').textContent=(s.medium_findings??0)+' medium';
  $('secMeta').textContent=(r.observation? r.observation.snapshot_count+' samples' : '');

  const findings=r.security_indicators||[];
  $('secFindings').innerHTML = findings.length
    ? findings.slice(0,12).map(f=>{
        const sev=(f.severity||'LOW').toLowerCase();
        return '<div class="finding '+sev+'"><b>['+esc(f.severity)+']</b> '+esc(f.type||'')+' &mdash; '+esc(f.indicator||f.detail||'')+'</div>';
      }).join('')
    : '<div class="status healthy">No security indicators in this window</div>';
}

async function refresh(){
  try{
    await Promise.all([refreshExperience(), refreshSecurity()]);
  }catch(x){
    $('identity').textContent='Unable to load Endpoint 360 data: '+x;
  }
}

refresh();
setInterval(refresh,15000);
</script></body></html>"""


@endpoint360_bp.get("/endpoint-360")
def page():
    return render_template_string(PAGE)


# Backward-compatible alias for anything still linking the old route name.
@endpoint360_bp.get("/endpoint-experience")
def page_alias():
    return render_template_string(PAGE)


def register_endpoint_360(app):
    """Register Endpoint 360 (experience + security) and start its collectors."""
    start_endpoint_360_collectors()
    app.register_blueprint(endpoint360_bp)
    return app


if __name__ == "__main__":
    print("Import this module from posture_ui.py and call register_endpoint_360(app).")