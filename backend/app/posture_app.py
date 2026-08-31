"""
Posture Application (Phase 1 - enforcement decoupled)

Receives Windows posture results and stores them. It no longer writes to
ISE or triggers CoA/ANC automatically - see the project plan Section 2.2
and Section 8.1. Those actions are now explicit, admin-triggered calls
made from posture_ui.py's /api/v1/endpoints/<mac>/share-posture,
/restrict and /clear-restriction routes, via ise_transport.get_transport().

Required environment variables:
    POSTGRES_HOST / POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD
       (or DATABASE_URL)
    ISE_HOST, ISE_USER, ISE_PASS   - only needed once an admin actually
       clicks Share/Restrict; receive_posture() itself never touches ISE.

Optional:
    ISE_VERIFY_TLS=false
    POSTURE_API_KEY=
    ENFORCEMENT_MODE=attribute   # attribute, or anc
    ENFORCEMENT_TRANSPORT=ers    # ers, or pxgrid (Phase 5)
    POSTURE_LISTEN_HOST=127.0.0.1
    POSTURE_LISTEN_PORT=8000
"""

from __future__ import annotations

import logging
import os
import time

from pathlib import Path
from dotenv import load_dotenv

# Explicit path, not just load_dotenv() - that only auto-finds .env by
# walking up from the current *working* directory, which breaks if this
# script is ever launched from somewhere other than backend/app.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from flask import Flask, jsonify, request

from posture_db import DB_FILE, init_db, log_ise_action, save_assessment
from ise_transport import get_transport

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("posture_app")

POSTURE_API_KEY = os.getenv("POSTURE_API_KEY", "")
LISTEN_HOST = os.getenv("POSTURE_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("POSTURE_LISTEN_PORT", "8000"))

STATUS_MAP = {"COMPLIANT": "Compliant", "NON-COMPLIANT": "NonCompliant"}

app = Flask(__name__)


def save_posture(
    *, mac, ip, hostname, os_name, os_version, status, detail, submitted,
    submit_error, checks, apps_count, listening_ports, installed_apps=None,
    hardware=None, resource_usage=None, top_processes=None,
) -> int:
    return save_assessment(
        mac=mac.upper(), ip=ip, hostname=hostname, os_name=os_name,
        os_version=os_version, timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        status=status, detail=detail, submitted=submitted, submit_error=submit_error,
        checks=checks or [], apps_count=int(apps_count or 0),
        listening_ports=listening_ports or [],
        # NOTE: preserved from the original - None means "leave inventory alone".
        installed_apps=installed_apps,
        hardware=hardware or {}, resource_usage=resource_usage or {},
        top_processes=top_processes or [],
    )


@app.get("/health")
def health():
    transport_ok = None
    try:
        transport_ok = get_transport().reachable()
    except Exception:
        transport_ok = False
    return jsonify({
        "application": "Posture Application",
        "status": "UP",
        "ise_configured": transport_ok,
        "database": {"status": "UP", "path": str(DB_FILE)},
    })


@app.post("/api/v1/posture")
def receive_posture():
    """
    Stores the posture result. Does NOT write to ISE and does NOT enforce.
    That is now a separate, admin-triggered step (see the /share-posture,
    /restrict routes in posture_ui.py).
    """
    if POSTURE_API_KEY and request.headers.get("X-API-Key") != POSTURE_API_KEY:
        return jsonify({"status": "ERROR", "message": "Invalid or missing API key"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "ERROR", "message": "Invalid JSON"}), 400

    endpoint = data.get("endpoint") or {}
    posture = data.get("posture") or {}

    mac = endpoint.get("mac")
    hostname = endpoint.get("hostname")
    os_name = endpoint.get("operating_system")
    os_version = endpoint.get("os_version")
    ip = endpoint.get("ip") or (endpoint.get("ips") or [None])[0]

    raw_status = posture.get("status")
    checks = posture.get("checks") or []
    apps_count = posture.get("appsCount") or 0
    listening_ports = posture.get("listening_ports") or []

    raw_installed_apps = posture.get("installed_apps") or []
    app_collection_error = posture.get("appCollectionError")
    installed_apps = raw_installed_apps if (raw_installed_apps or not app_collection_error) else None

    hardware = endpoint.get("hardware") or {}
    resource_usage = posture.get("resource_usage") or {}
    top_processes = posture.get("top_processes") or []

    if not mac:
        return jsonify({"status": "ERROR", "message": "endpoint.mac is required"}), 400
    if raw_status not in STATUS_MAP:
        return jsonify({
            "status": "ERROR",
            "message": f"posture.status must be one of {list(STATUS_MAP)}",
        }), 400

    failed = ", ".join(
        str(check.get("Check", "?")) for check in checks if check.get("Status") != "COMPLIANT"
    )
    detail = checks[0].get("Details", raw_status) if checks else raw_status

    log.info("Posture: %s (%s) -> %s | failed=%s", hostname or mac, mac, raw_status, failed or "none")

    try:
        assessment_id = save_posture(
            mac=mac, ip=ip, hostname=hostname, os_name=os_name, os_version=os_version,
            status=raw_status, detail=detail, submitted=True, submit_error=None,
            checks=checks, apps_count=apps_count, listening_ports=listening_ports,
            installed_apps=installed_apps, hardware=hardware, resource_usage=resource_usage,
            top_processes=top_processes,
        )
    except Exception as exc:
        log.exception("Postgres persistence failed for %s", mac)
        return jsonify({"status": "ERROR", "message": "Database persistence failed", "detail": str(exc)}), 500

    return jsonify({
        "status": "SUCCESS",
        "mac": mac,
        "posture": STATUS_MAP[raw_status],
        "assessment_id": assessment_id,
        "note": "Stored. Not shared with ISE and not enforced - use the dashboard to do that explicitly.",
    })


# ---------------------------------------------------------------------------
# Admin-triggered ISE actions (Section 8.2 of the project plan)
# ---------------------------------------------------------------------------

def _latest_assessment(mac: str):
    from posture_db import get_assessments
    for row in get_assessments(limit=5000):
        if (row.get("mac") or "").upper() == mac.upper():
            return row
    return None


@app.post("/api/v1/endpoints/<mac>/share-posture")
def share_posture(mac):
    mac = mac.upper()
    assessment = _latest_assessment(mac)
    if not assessment:
        return jsonify({"error": "No stored assessment for this endpoint"}), 404

    failed = ", ".join(c["Check"] for c in assessment.get("checks", []) if c.get("Status") != "COMPLIANT")
    try:
        result = get_transport().publish_posture(mac, assessment.get("status"), failed or "none")
    except Exception as exc:
        result = {"ok": False, "detail": str(exc)}

    log_ise_action(mac, "SHARE_POSTURE", operator=request.headers.get("X-Operator"),
                    result="SUCCESS" if result.get("ok") else "FAILED", detail=result.get("detail"))
    return jsonify(result), (200 if result.get("ok") else 502)


@app.post("/api/v1/endpoints/<mac>/restrict")
def restrict_endpoint(mac):
    mac = mac.upper()
    data = request.get_json(silent=True) or {}
    policy = data.get("policy")
    try:
        result = get_transport().publish_enforcement(mac, "RESTRICT", policy)
    except Exception as exc:
        result = {"ok": False, "detail": str(exc)}

    log_ise_action(mac, "RESTRICT", operator=request.headers.get("X-Operator"),
                    result="SUCCESS" if result.get("ok") else "FAILED", detail=result.get("detail"))
    return jsonify(result), (200 if result.get("ok") else 502)


@app.post("/api/v1/endpoints/<mac>/clear-restriction")
def clear_restriction(mac):
    mac = mac.upper()
    try:
        result = get_transport().publish_enforcement(mac, "CLEAR_RESTRICTION")
    except Exception as exc:
        result = {"ok": False, "detail": str(exc)}

    log_ise_action(mac, "CLEAR_RESTRICTION", operator=request.headers.get("X-Operator"),
                    result="SUCCESS" if result.get("ok") else "FAILED", detail=result.get("detail"))
    return jsonify(result), (200 if result.get("ok") else 502)


@app.get("/api/v1/endpoints/<mac>/ise-status")
def ise_status(mac):
    mac = mac.upper()
    try:
        reachable = get_transport().reachable()
    except Exception as exc:
        return jsonify({"reachable": False, "error": str(exc)})
    return jsonify({"reachable": reachable})


if __name__ == "__main__":
    init_db()
    log.info("Postgres database: %s", DB_FILE)
    log.info("Listening on http://%s:%s", LISTEN_HOST, LISTEN_PORT)
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
