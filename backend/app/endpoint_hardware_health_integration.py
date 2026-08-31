"""
Endpoint Hardware Health integration (project plan Section 6.1 / Phase 3a).

Built on top of endpoint_hardware_warranty_collector.py's report shape
(identity, cpu_memory, storage, battery, hardware_events, warranty), but
receives that JSON over HTTP instead of writing a local file, so results
land in the shared database rather than scattered across machines.

Submission source: hardware_health_agent.ps1 (backend/agents/), a remote
sibling of posture_agent.ps1 that wraps the same PowerShell/CIM blocks the
original collector already used, run against a target IP over WinRM/CIM
instead of only locally.

Scoring thresholds (Section 15, question 11 - illustrative defaults,
pending confirmation): 85+ healthy, 70-84 warning, 50-69 degraded, <50 critical.

Integration:
    from endpoint_hardware_health_integration import register_hardware_health
    register_hardware_health(app)
"""

from __future__ import annotations

from datetime import datetime, timezone

import psycopg2.extras
from flask import Blueprint, jsonify, request

from posture_db import db, init_db

hardware_health_bp = Blueprint("hardware_health", __name__)

# Illustrative score bands, pending Section 15 question 11.
SCORE_BANDS = [(85, "HEALTHY"), (70, "WARNING"), (50, "DEGRADED"), (0, "CRITICAL")]


def _band(score):
    if score is None:
        return "UNKNOWN"
    for threshold, label in SCORE_BANDS:
        if score >= threshold:
            return label
    return "CRITICAL"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_cpu(cpu_memory):
    cpu = (cpu_memory or {}).get("cpu") or {}
    load = cpu.get("LoadPercentage")
    if load is None:
        return None
    load = float(load)
    return max(0, round(100 - load))


def _score_memory(cpu_memory):
    mem = (cpu_memory or {}).get("memory") or {}
    used = mem.get("UsedPercent")
    if used is None:
        return None
    return max(0, round(100 - float(used)))


def _score_storage(storage):
    disks = (storage or {}).get("physical_disks")
    if isinstance(disks, dict):
        disks = [disks]
    if not disks:
        return None
    healthy = sum(1 for d in disks if str(d.get("HealthStatus", "")).lower() in ("healthy", "0"))
    return round((healthy / len(disks)) * 100)


def _score_battery(battery):
    static = (battery or {}).get("battery_static")
    if isinstance(static, dict):
        static = [static]
    if not static:
        return None
    scores = []
    for b in static:
        try:
            design = float(b.get("DesignedCapacity") or 0)
            full = float(b.get("FullChargedCapacity") or 0)
            if design > 0:
                scores.append(round((full / design) * 100))
        except (TypeError, ValueError):
            continue
    return round(sum(scores) / len(scores)) if scores else None


def init_hardware_health_db():
    """Schema already created centrally by posture_db.init_db(); kept as a
    no-op entry point so registration mirrors endpoint_360_integration.py."""
    init_db()


def register_hardware_health(app):
    init_hardware_health_db()
    app.register_blueprint(hardware_health_bp)
    return app


@hardware_health_bp.post("/api/v1/hardware-health")
def submit_hardware_health():
    """
    Receives the JSON report shape produced by
    endpoint_hardware_warranty_collector.py / hardware_health_agent.ps1.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "ERROR", "message": "Invalid JSON"}), 400

    endpoint = data.get("endpoint") or {}
    mac = (endpoint.get("mac") or "").upper()
    if not mac:
        return jsonify({"status": "ERROR", "message": "endpoint.mac is required"}), 400

    cpu_memory = data.get("cpu_memory") or {}
    storage = data.get("storage") or {}
    battery = data.get("battery") or {}
    events = data.get("hardware_events") or {}
    warranty = data.get("warranty") or {}
    recommendations = data.get("proactive_recommendations") or []

    cpu_score = _score_cpu(cpu_memory)
    memory_score = _score_memory(cpu_memory)
    storage_score = _score_storage(storage)
    battery_score = _score_battery(battery)

    component_scores = [s for s in (cpu_score, memory_score, storage_score, battery_score) if s is not None]
    overall_score = round(sum(component_scores) / len(component_scores)) if component_scores else None

    timestamp = _now()

    with db() as con:
        con.execute(
            """
            INSERT INTO endpoint_hardware_health(
                mac, timestamp, manufacturer, model, serial_number, bios_version,
                cpu_score, memory_score, storage_score, battery_score, overall_score,
                hardware_event_count, warranty_status, warranty_days_remaining, report_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                mac, timestamp,
                endpoint.get("manufacturer"), endpoint.get("model"), endpoint.get("serial_number"),
                endpoint.get("bios_version"),
                cpu_score, memory_score, storage_score, battery_score, overall_score,
                events.get("event_count"), warranty.get("status"), warranty.get("days_remaining"),
                # report_json is JSONB - hand psycopg2 a native dict wrapped
                # in Json() rather than json.dumps()'ing it ourselves. This
                # also means readers get a real dict back from the DB
                # instead of a string that still needs json.loads().
                psycopg2.extras.Json(data),
            ),
        )
        for rec in recommendations:
            con.execute(
                """
                INSERT INTO endpoint_hardware_recommendations(mac, timestamp, priority, area, action)
                VALUES (?,?,?,?,?)
                """,
                (mac, timestamp, rec.get("priority"), rec.get("area"), rec.get("action")),
            )

    return jsonify({
        "status": "SUCCESS",
        "mac": mac,
        "overall_score": overall_score,
        "band": _band(overall_score),
    })


@hardware_health_bp.get("/api/endpoint-hardware-health/<mac>")
def get_hardware_health(mac):
    mac = mac.upper()
    with db() as con:
        row = con.execute(
            """
            SELECT * FROM endpoint_hardware_health
            WHERE mac = ? ORDER BY timestamp DESC LIMIT 1
            """,
            (mac,),
        ).fetchone()
        if not row:
            return jsonify({"mac": mac, "status": "NO_DATA"})

        recs = con.execute(
            """
            SELECT priority, area, action FROM endpoint_hardware_recommendations
            WHERE mac = ? ORDER BY timestamp DESC LIMIT 20
            """,
            (mac,),
        ).fetchall()

    result = dict(row)
    result["band"] = _band(result.get("overall_score"))
    result["recommendations"] = [dict(r) for r in recs]
    return jsonify(result)


@hardware_health_bp.get("/api/endpoint-hardware-health/<mac>/history")
def get_hardware_health_history(mac):
    mac = mac.upper()
    days = max(1, min(request.args.get("days", 30, type=int), 365))
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as con:
        rows = con.execute(
            """
            SELECT timestamp, cpu_score, memory_score, storage_score, battery_score, overall_score
            FROM endpoint_hardware_health
            WHERE mac = ? AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (mac, cutoff),
        ).fetchall()
    return jsonify({"mac": mac, "history": [dict(r) for r in rows]})