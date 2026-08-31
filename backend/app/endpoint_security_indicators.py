#!/usr/bin/env python3
"""
Endpoint Security Indicators Sensor - Windows
==============================================

Purpose
-------
A lightweight, standalone Windows security-indicator collector focused ONLY
on endpoint network/security indicators.

It is NOT an EDR, antivirus, malware scanner, vulnerability scanner, or
automatic NAC enforcement engine.

It collects and scores indicators associated with:

1. Possible lateral movement
   - SMB 445
   - RPC 135
   - RDP 3389
   - WinRM 5985/5986
   - SSH 22
   - Multiple internal destinations
   - One process contacting many internal systems

2. Possible C2 / beaconing
   - Repeated outbound connections
   - Relatively regular connection intervals
   - Same process + destination repeatedly communicating

3. Suspicious outbound behavior
   - Unusual external destination ports
   - High external connection volume

4. Endpoint context
   - Process owning connection
   - Process executable path where available
   - Windows Firewall profile
   - Recent Security events (4624/4625/4648/4672)
   - DNS cache
   - Current active TCP connections

Output
------
- Console findings
- endpoint_security_indicators.json

Optional dashboard
------------------
The script can also expose a very small local dashboard:

    http://127.0.0.1:8766

Run
---
    python endpoint_security_indicators.py

Recommended:
    Run from an elevated Administrator PowerShell.

Longer observation:
    python endpoint_security_indicators.py --observe 300 --interval 5

Disable dashboard:
    python endpoint_security_indicators.py --no-dashboard

Important
---------
Indicators are NOT proof of compromise. Legitimate RMM, SCCM/Intune,
backup software, browsers, security agents and administrative tools can
generate similar patterns. Confirm high-risk findings with trusted EDR/NDR,
authentication logs, DNS/security telemetry and firewall logs before
automated quarantine.
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import statistics
import subprocess
import threading
import time
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

LATERAL_PORTS = {
    22: "SSH",
    135: "RPC",
    139: "NetBIOS/SMB",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}

UNUSUAL_EXTERNAL_PORTS = {
    23,       # Telnet
    2323,
    4444,
    5555,
    6666,
    6667,
    31337,
    9001,
    9050,
}

CONFIG = {
    "observe": 60,
    "interval": 5,
    "dashboard": True,
    "port": 8766,
    "output": "endpoint_security_indicators.json",
}

STATE = {
    "report": None,
    "lock": threading.Lock(),
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def run_cmd(command, timeout=30):
    try:
        p = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def split_endpoint(value):
    """
    Handles:
      10.1.1.1:443
      [::1]:443
      0.0.0.0:135
    """
    value = value.strip()

    if value.startswith("["):
        match = re.match(r"^\[(.*)\]:(\d+|\*)$", value)
        if match:
            ip = match.group(1)
            port = (
                int(match.group(2))
                if match.group(2).isdigit()
                else None
            )
            return ip, port

    if value.count(":") == 1:
        ip, port = value.rsplit(":", 1)
        return ip, int(port) if port.isdigit() else None

    return value, None


# ---------------------------------------------------------------------------
# Active network connections
# ---------------------------------------------------------------------------

def get_active_connections():
    """
    Prefer Get-NetTCPConnection because it provides OwningProcess directly.
    Fall back to netstat if necessary.
    """

    powershell = r"""
Get-NetTCPConnection -ErrorAction SilentlyContinue |
Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
ConvertTo-Json -Compress
"""

    rc, out, err = run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            powershell,
        ],
        timeout=30,
    )

    rows = []

    if rc == 0 and out.strip():
        try:
            data = json.loads(out)

            if isinstance(data, dict):
                data = [data]

            for item in data:
                remote_ip = item.get("RemoteAddress")

                if not remote_ip:
                    continue

                if remote_ip in (
                    "0.0.0.0",
                    "::",
                    "127.0.0.1",
                    "::1",
                ):
                    continue

                rows.append({
                    "local_ip": item.get("LocalAddress"),
                    "local_port": item.get("LocalPort"),
                    "remote_ip": remote_ip,
                    "remote_port": item.get("RemotePort"),
                    "state": item.get("State"),
                    "pid": item.get("OwningProcess"),
                })

            return rows

        except Exception:
            pass

    # Fallback to netstat.
    rc, out, err = run_cmd(
        ["netstat", "-ano"],
        timeout=30,
    )

    if rc != 0:
        return []

    for line in out.splitlines():
        parts = re.split(r"\s+", line.strip())

        if len(parts) >= 5 and parts[0].upper() == "TCP":
            lip, lp = split_endpoint(parts[1])
            rip, rp = split_endpoint(parts[2])

            if rip in (
                "0.0.0.0",
                "::",
                "127.0.0.1",
                "::1",
            ):
                continue

            rows.append({
                "local_ip": lip,
                "local_port": lp,
                "remote_ip": rip,
                "remote_port": rp,
                "state": parts[3],
                "pid": (
                    int(parts[4])
                    if parts[4].isdigit()
                    else None
                ),
            })

    return rows


# ---------------------------------------------------------------------------
# Process ownership
# ---------------------------------------------------------------------------

def enrich_processes(rows):
    pids = sorted({
        row.get("pid")
        for row in rows
        if row.get("pid") is not None
    })

    if not pids:
        return rows

    pids = pids[:500]

    powershell = f"""
$ids=@({",".join(map(str, pids))})
Get-Process -Id $ids -ErrorAction SilentlyContinue |
Select-Object Id,ProcessName,Path |
ConvertTo-Json -Compress
"""

    rc, out, err = run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            powershell,
        ],
        timeout=40,
    )

    process_map = {}

    if rc == 0 and out.strip():
        try:
            data = json.loads(out)

            if isinstance(data, dict):
                data = [data]

            for item in data:
                pid = item.get("Id")

                if pid is not None:
                    process_map[int(pid)] = {
                        "process": item.get("ProcessName"),
                        "process_path": item.get("Path"),
                    }

        except Exception:
            pass

    for row in rows:
        info = process_map.get(row.get("pid"), {})

        row["process"] = info.get("process")
        row["process_path"] = info.get("process_path")

    return rows


# ---------------------------------------------------------------------------
# Lateral movement detection
# ---------------------------------------------------------------------------

def detect_lateral_movement(rows):
    findings = []

    destinations_by_port = defaultdict(set)
    destinations_by_process = defaultdict(set)

    evidence = []

    for row in rows:
        remote_ip = row.get("remote_ip")
        remote_port = row.get("remote_port")

        if not remote_ip or not is_ip(remote_ip):
            continue

        # Only internal/private destinations.
        if not is_private_ip(remote_ip):
            continue

        if remote_port not in LATERAL_PORTS:
            continue

        destinations_by_port[remote_port].add(remote_ip)

        process = (
            row.get("process")
            or f"PID-{row.get('pid')}"
        )

        destinations_by_process[process].add(remote_ip)

        evidence.append(row)

    # Destination fan-out by administrative protocol.
    for port, destinations in destinations_by_port.items():

        if len(destinations) >= 5:
            severity = "HIGH"
        elif len(destinations) >= 2:
            severity = "MEDIUM"
        else:
            continue

        findings.append({
            "type": "POSSIBLE_LATERAL_MOVEMENT",
            "severity": severity,
            "confidence": "MEDIUM",
            "indicator": (
                f"Endpoint contacted {len(destinations)} internal hosts "
                f"using {port}/{LATERAL_PORTS[port]}."
            ),
            "port": port,
            "protocol": LATERAL_PORTS[port],
            "destinations": sorted(destinations),
        })

    # One process contacting many internal systems.
    for process, destinations in destinations_by_process.items():

        if len(destinations) >= 5:
            findings.append({
                "type": "PROCESS_INTERNAL_FANOUT",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "indicator": (
                    f"Process {process} contacted "
                    f"{len(destinations)} internal hosts "
                    f"using administrative ports."
                ),
                "process": process,
                "destinations": sorted(destinations),
            })

    return findings


# ---------------------------------------------------------------------------
# External connection detection
# ---------------------------------------------------------------------------

def detect_external_anomalies(rows):
    findings = []

    external_by_process = defaultdict(set)

    for row in rows:
        remote_ip = row.get("remote_ip")
        remote_port = row.get("remote_port")

        if not remote_ip or not is_ip(remote_ip):
            continue

        if is_private_ip(remote_ip):
            continue

        process = (
            row.get("process")
            or f"PID-{row.get('pid')}"
        )

        external_by_process[process].add(
            (
                remote_ip,
                remote_port,
            )
        )

        if remote_port in UNUSUAL_EXTERNAL_PORTS:

            findings.append({
                "type": "UNUSUAL_EXTERNAL_PORT",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "indicator": (
                    f"Outbound connection to "
                    f"{remote_ip}:{remote_port}."
                ),
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process": process,
            })

    # High external destination volume.
    for process, destinations in external_by_process.items():

        if len(destinations) >= 30:

            findings.append({
                "type": "HIGH_EXTERNAL_DESTINATION_VOLUME",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "indicator": (
                    f"Process {process} has "
                    f"{len(destinations)} unique external "
                    f"IP/port destinations."
                ),
                "process": process,
            })

    return findings


# ---------------------------------------------------------------------------
# Possible C2 beacon detection
# ---------------------------------------------------------------------------

def detect_possible_beaconing(snapshots):
    """
    Conservative periodicity detector.

    It looks for the same:
        external IP + port + process

    across multiple observation snapshots with reasonably regular intervals.

    This is only a behavioral indicator.
    """

    observations = defaultdict(list)

    for snapshot in snapshots:

        epoch = snapshot["epoch"]

        for row in snapshot["connections"]:

            remote_ip = row.get("remote_ip")
            remote_port = row.get("remote_port")

            if not remote_ip:
                continue

            if not is_ip(remote_ip):
                continue

            if is_private_ip(remote_ip):
                continue

            if not remote_port:
                continue

            process = (
                row.get("process")
                or f"PID-{row.get('pid')}"
            )

            key = (
                remote_ip,
                remote_port,
                process,
            )

            observations[key].append(epoch)

    findings = []

    for key, times in observations.items():

        if len(times) < 4:
            continue

        times.sort()

        intervals = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
        ]

        if not intervals:
            continue

        median_interval = statistics.median(intervals)

        # Ignore extremely fast or very long intervals.
        if median_interval < 3:
            continue

        if median_interval > 900:
            continue

        consistency = sum(
            1
            for interval in intervals
            if (
                abs(interval - median_interval)
                / median_interval
            ) <= 0.35
        ) / len(intervals)

        if consistency < 0.75:
            continue

        remote_ip, remote_port, process = key

        findings.append({
            "type": "POSSIBLE_C2_BEACON",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "indicator": (
                f"Process {process} repeatedly contacted "
                f"{remote_ip}:{remote_port} with a "
                f"relatively regular interval."
            ),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "process": process,
            "median_interval_seconds": round(
                median_interval,
                1,
            ),
            "interval_consistency": round(
                consistency,
                2,
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Windows Firewall
# ---------------------------------------------------------------------------

def get_firewall_state():
    powershell = r"""
Get-NetFirewallProfile |
Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
ConvertTo-Json -Compress
"""

    rc, out, err = run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            powershell,
        ],
        timeout=30,
    )

    if rc != 0 or not out.strip():
        return {
            "available": False,
            "profiles": [],
            "error": err,
        }

    try:
        data = json.loads(out)

        if isinstance(data, dict):
            data = [data]

        return {
            "available": True,
            "profiles": data,
            "error": None,
        }

    except Exception as exc:
        return {
            "available": False,
            "profiles": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Windows Security events
# ---------------------------------------------------------------------------

def get_security_events():
    """
    Best-effort context collection.

    Event IDs:
      4624 - successful logon
      4625 - failed logon
      4648 - explicit credential use
      4672 - special privileges assigned

    This is supporting evidence only.
    """

    powershell = r"""
Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 100 |
Where-Object {$_.Id -in @(4624,4625,4648,4672)} |
Select-Object Id,TimeCreated,ProviderName,Message |
ConvertTo-Json -Depth 4 -Compress
"""

    rc, out, err = run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            powershell,
        ],
        timeout=45,
    )

    if rc != 0 or not out.strip():
        return {
            "available": False,
            "events": [],
            "error": (
                err
                or "Security event log unavailable. "
                   "Run as Administrator."
            ),
        }

    try:
        data = json.loads(out)

        if isinstance(data, dict):
            data = [data]

        events = []

        for event in data:

            events.append({
                "event_id": event.get("Id"),
                "time": event.get("TimeCreated"),
                "provider": event.get("ProviderName"),
                "message": event.get("Message"),
            })

        return {
            "available": True,
            "events": events,
            "error": None,
        }

    except Exception as exc:
        return {
            "available": False,
            "events": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# DNS cache
# ---------------------------------------------------------------------------

def get_dns_cache():
    powershell = r"""
Get-DnsClientCache |
Select-Object Entry,RecordType,Status,Data,TimeToLive |
ConvertTo-Json -Compress
"""

    rc, out, err = run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            powershell,
        ],
        timeout=30,
    )

    if rc != 0 or not out.strip():
        return {
            "available": False,
            "entries": [],
        }

    try:
        data = json.loads(out)

        if isinstance(data, dict):
            data = [data]

        return {
            "available": True,
            "entries": data,
        }

    except Exception:
        return {
            "available": False,
            "entries": [],
        }


# ---------------------------------------------------------------------------
# Overall security score
# ---------------------------------------------------------------------------

def calculate_security_score(findings):

    score = 100

    for finding in findings:

        severity = finding.get("severity")

        if severity == "HIGH":
            score -= 30

        elif severity == "MEDIUM":
            score -= 12

        elif severity == "LOW":
            score -= 4

    score = max(
        0,
        min(100, score),
    )

    if score >= 90:
        status = "LOW_RISK"

    elif score >= 70:
        status = "REVIEW"

    else:
        status = "HIGH_RISK"

    return {
        "score": score,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Main report
# ---------------------------------------------------------------------------

def build_report(
    snapshots,
    latest_connections,
):

    all_findings = []

    all_findings.extend(
        detect_lateral_movement(
            latest_connections
        )
    )

    all_findings.extend(
        detect_external_anomalies(
            latest_connections
        )
    )

    all_findings.extend(
        detect_possible_beaconing(
            snapshots
        )
    )

    # Remove duplicate indicators based on type/process/destination.
    unique = {}
    for finding in all_findings:

        key = (
            finding.get("type"),
            finding.get("process"),
            finding.get("remote_ip"),
            finding.get("remote_port"),
            finding.get("port"),
        )

        unique[key] = finding

    findings = list(unique.values())

    security_score = calculate_security_score(
        findings
    )

    high = sum(
        1
        for finding in findings
        if finding["severity"] == "HIGH"
    )

    medium = sum(
        1
        for finding in findings
        if finding["severity"] == "MEDIUM"
    )

    if high:
        overall = "HIGH_RISK_INDICATOR"

    elif medium:
        overall = "REVIEW"

    else:
        overall = "NO_HIGH_CONFIDENCE_INDICATOR"

    return {
        "report_version": "1.0",
        "timestamp_utc": utc_now(),

        "endpoint": {
            "hostname": socket.gethostname(),
            "username": os.environ.get("USERNAME"),
        },

        "observation": {
            "duration_seconds": CONFIG["observe"],
            "interval_seconds": CONFIG["interval"],
            "snapshot_count": len(snapshots),
        },

        "security_summary": {
            "overall_status": overall,
            "security_score": security_score["score"],
            "risk_level": security_score["status"],
            "high_findings": high,
            "medium_findings": medium,
            "total_findings": len(findings),
        },

        "security_indicators": findings,

        "current_connections": latest_connections,

        "firewall": get_firewall_state(),

        "dns_cache": get_dns_cache(),

        "security_events": get_security_events(),

        "nac_context": {
            "security_status": overall,
            "security_score": security_score["score"],
            "recommended_action": (
                "INVESTIGATE"
                if high
                else "NORMAL_ACCESS"
            ),
            "automation_guidance": (
                "Do not quarantine solely on this script. "
                "Correlate high-risk indicators with trusted "
                "EDR/NDR/authentication telemetry."
            ),
        },

        "limitations": [
            "Indicators are not proof of compromise.",
            "Legitimate administrative and management software can "
            "generate similar traffic.",
            "Beacon periodicity alone cannot confirm C2.",
            "Use EDR/NDR, authentication, DNS and firewall telemetry "
            "for confirmation before automated enforcement.",
        ],
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Endpoint Security Indicators</title>

<style>

body {
    margin: 0;
    background: #f4f6f8;
    font-family: Segoe UI, Arial, sans-serif;
    color: #202124;
}

header {
    background: #17212b;
    color: white;
    padding: 20px 28px;
}

header h1 {
    margin: 0;
    font-size: 24px;
}

header p {
    opacity: .7;
    margin: 5px 0;
}

.container {
    max-width: 1400px;
    margin: auto;
    padding: 20px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
}

.card {
    background: white;
    border-radius: 10px;
    padding: 18px;
    box-shadow: 0 2px 9px rgba(0,0,0,.08);
}

.title {
    font-size: 11px;
    text-transform: uppercase;
    color: #6b7280;
}

.value {
    font-size: 28px;
    font-weight: 700;
    margin-top: 7px;
}

.badge {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    margin-top: 8px;
}

.green {
    background: #d9f7df;
    color: #176b2c;
}

.yellow {
    background: #fff0c7;
    color: #815d00;
}

.red {
    background: #ffd9d9;
    color: #a30000;
}

.gray {
    background: #e9ecef;
    color: #555;
}

.section {
    margin-top: 16px;
}

.finding {
    padding: 12px;
    margin-bottom: 8px;
    border-left: 5px solid #d97706;
    background: #fff8e8;
    border-radius: 5px;
}

.finding.high {
    border-left-color: #b91c1c;
    background: #fff0f0;
}

.finding-title {
    font-weight: 700;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

th, td {
    padding: 8px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
}

@media(max-width:900px) {
    .grid {
        grid-template-columns: 1fr 1fr;
    }
}

@media(max-width:550px) {
    .grid {
        grid-template-columns: 1fr;
    }
}

</style>
</head>

<body>

<header>
<h1>Endpoint Security Indicators</h1>
<p id="endpoint">Loading...</p>
</header>

<div class="container">

<div class="grid">

<div class="card">
<div class="title">Security Score</div>
<div class="value" id="score">--</div>
<span class="badge gray" id="risk">--</span>
</div>

<div class="card">
<div class="title">Overall Status</div>
<div class="value" style="font-size:20px" id="status">--</div>
<span class="badge gray" id="statusBadge">--</span>
</div>

<div class="card">
<div class="title">High Indicators</div>
<div class="value" id="high">--</div>
</div>

<div class="card">
<div class="title">Medium Indicators</div>
<div class="value" id="medium">--</div>
</div>

</div>


<div class="section card">

<h2>Security Indicators</h2>

<div id="findings">
Loading...
</div>

</div>


<div class="section card">

<h2>Network Connections</h2>

<table>

<thead>
<tr>
<th>Process</th>
<th>PID</th>
<th>Remote IP</th>
<th>Port</th>
<th>State</th>
</tr>
</thead>

<tbody id="connections">
</tbody>

</table>

</div>


<div class="section card">

<h2>NAC Context</h2>

<div id="nac"></div>

</div>

</div>

<script>

function esc(x) {
    if (x === null || x === undefined) return "--";

    return String(x).replace(/[&<>"']/g, function(c) {
        return {
            "&":"&amp;",
            "<":"&lt;",
            ">":"&gt;",
            '"':"&quot;",
            "'":"&#039;"
        }[c];
    });
}


function badgeClass(status) {

    status = (status || "").toUpperCase();

    if (
        status.includes("LOW") ||
        status.includes("NORMAL") ||
        status.includes("NO_HIGH")
    ) {
        return "green";
    }

    if (
        status.includes("REVIEW") ||
        status.includes("MEDIUM")
    ) {
        return "yellow";
    }

    if (
        status.includes("HIGH") ||
        status.includes("RISK")
    ) {
        return "red";
    }

    return "gray";
}


async function load() {

    try {

        const response =
            await fetch("/api/report?t=" + Date.now());

        const r =
            await response.json();

        document.getElementById("endpoint").textContent =
            r.endpoint.hostname +
            " | User: " +
            (r.endpoint.username || "--") +
            " | " +
            r.timestamp_utc;

        document.getElementById("score").textContent =
            r.security_summary.security_score +
            "/100";

        document.getElementById("risk").textContent =
            r.security_summary.risk_level;

        document.getElementById("risk").className =
            "badge " +
            badgeClass(
                r.security_summary.risk_level
            );

        document.getElementById("status").textContent =
            r.security_summary.overall_status;

        document.getElementById("statusBadge").textContent =
            r.security_summary.overall_status;

        document.getElementById("statusBadge").className =
            "badge " +
            badgeClass(
                r.security_summary.overall_status
            );

        document.getElementById("high").textContent =
            r.security_summary.high_findings;

        document.getElementById("medium").textContent =
            r.security_summary.medium_findings;


        const findings =
            document.getElementById("findings");

        if (!r.security_indicators.length) {

            findings.innerHTML =
                '<span class="badge green">' +
                'No high-confidence security indicator detected' +
                '</span>';

        } else {

            findings.innerHTML =
                r.security_indicators.map(function(x) {

                    const cls =
                        x.severity === "HIGH"
                        ? "finding high"
                        : "finding";

                    return (
                        '<div class="' + cls + '">' +
                        '<div class="finding-title">' +
                        esc(x.severity) +
                        " - " +
                        esc(x.type) +
                        '</div>' +
                        '<div>' +
                        esc(x.indicator) +
                        '</div>' +
                        '</div>'
                    );

                }).join("");
        }


        const tbody =
            document.getElementById("connections");

        tbody.innerHTML = "";

        (r.current_connections || [])
            .slice(0, 150)
            .forEach(function(x) {

                const tr =
                    document.createElement("tr");

                tr.innerHTML =
                    "<td>" +
                    esc(x.process) +
                    "</td>" +

                    "<td>" +
                    esc(x.pid) +
                    "</td>" +

                    "<td>" +
                    esc(x.remote_ip) +
                    "</td>" +

                    "<td>" +
                    esc(x.remote_port) +
                    "</td>" +

                    "<td>" +
                    esc(x.state) +
                    "</td>";

                tbody.appendChild(tr);
            });


        const n = r.nac_context;

        document.getElementById("nac").innerHTML =
            "<p><b>Security Status:</b> " +
            esc(n.security_status) +
            "</p>" +

            "<p><b>Security Score:</b> " +
            esc(n.security_score) +
            "/100</p>" +

            "<p><b>Recommended Action:</b> " +
            esc(n.recommended_action) +
            "</p>" +

            "<p><b>Guidance:</b> " +
            esc(n.automation_guidance) +
            "</p>";

    }

    catch (e) {

        document.getElementById("endpoint").textContent =
            "Dashboard error: " + e;

    }

}

load();

</script>

</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        return

    def do_GET(self):

        if self.path.startswith("/api/report"):

            with STATE["lock"]:
                report = STATE["report"]

            if report is None:
                report = {
                    "endpoint": {
                        "hostname": socket.gethostname(),
                        "username": os.environ.get("USERNAME"),
                    },
                    "security_summary": {
                        "security_score": 0,
                        "risk_level": "INITIALIZING",
                        "overall_status": "INITIALIZING",
                        "high_findings": 0,
                        "medium_findings": 0,
                        "total_findings": 0,
                    },
                    "security_indicators": [],
                    "current_connections": [],
                    "nac_context": {},
                    "timestamp_utc": utc_now(),
                }

            data = json.dumps(
                report,
                ensure_ascii=False,
            ).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json",
            )

            self.send_header(
                "Content-Length",
                str(len(data)),
            )

            self.send_header(
                "Cache-Control",
                "no-store",
            )

            self.end_headers()

            self.wfile.write(data)

            return


        if self.path == "/":

            data = DASHBOARD_HTML.encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(data)),
            )

            self.end_headers()

            self.wfile.write(data)

            return


        self.send_response(404)

        self.end_headers()


# ---------------------------------------------------------------------------
# Collection loop
# ---------------------------------------------------------------------------

def collect():

    print("Collecting active connections...")

    snapshots = []

    start = time.time()

    while (
        time.time() - start
        < CONFIG["observe"]
    ):

        rows = get_active_connections()

        rows = enrich_processes(rows)

        snapshot = {
            "epoch": time.time(),
            "timestamp_utc": utc_now(),
            "connections": rows,
        }

        snapshots.append(snapshot)

        print(
            f"[{snapshot['timestamp_utc']}] "
            f"{len(rows)} active TCP connections"
        )

        remaining = (
            CONFIG["observe"]
            - (time.time() - start)
        )

        if remaining <= 0:
            break

        time.sleep(
            min(
                CONFIG["interval"],
                remaining,
            )
        )


    latest = (
        snapshots[-1]["connections"]
        if snapshots
        else []
    )

    print("Collecting Windows security context...")

    report = build_report(
        snapshots,
        latest,
    )

    return report


def collector_thread():

    try:

        report = collect()

        with STATE["lock"]:
            STATE["report"] = report

        Path(
            CONFIG["output"]
        ).write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        print()
        print("=" * 70)
        print("SECURITY INDICATOR RESULT")
        print("=" * 70)

        print(
            "Status:",
            report["security_summary"]["overall_status"],
        )

        print(
            "Security Score:",
            report["security_summary"]["security_score"],
        )

        print(
            "High:",
            report["security_summary"]["high_findings"],
        )

        print(
            "Medium:",
            report["security_summary"]["medium_findings"],
        )

        for finding in report["security_indicators"]:

            print(
                f"[{finding['severity']}] "
                f"{finding['type']} - "
                f"{finding['indicator']}"
            )

        print()
        print(
            "JSON report:",
            Path(CONFIG["output"]).resolve(),
        )

    except Exception as exc:

        print(
            "Collection error:",
            exc,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Windows Endpoint Security Indicators Sensor"
        )
    )

    parser.add_argument(
        "--observe",
        type=int,
        default=60,
        help="Observation duration in seconds",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Connection sampling interval",
    )

    parser.add_argument(
        "--output",
        default="endpoint_security_indicators.json",
        help="JSON report file",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8766,
        help="Local dashboard port",
    )

    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable local dashboard",
    )

    args = parser.parse_args()

    CONFIG["observe"] = max(
        10,
        args.observe,
    )

    CONFIG["interval"] = max(
        2,
        args.interval,
    )

    CONFIG["output"] = args.output

    CONFIG["port"] = args.port

    CONFIG["dashboard"] = not args.no_dashboard

    print("=" * 70)
    print("ENDPOINT SECURITY INDICATORS SENSOR")
    print("=" * 70)

    print(
        "Endpoint:",
        socket.gethostname(),
    )

    print(
        "Observation:",
        CONFIG["observe"],
        "seconds",
    )

    print(
        "Interval:",
        CONFIG["interval"],
        "seconds",
    )

    if CONFIG["dashboard"]:

        print(
            "Dashboard:",
            f"http://127.0.0.1:{CONFIG['port']}",
        )

    print()
    print(
        "Recommended: run as Administrator."
    )

    print("=" * 70)


    # Start collection.
    thread = threading.Thread(
        target=collector_thread,
        daemon=True,
    )

    thread.start()


    if not CONFIG["dashboard"]:
        thread.join()
        return


    server = ThreadingHTTPServer(
        (
            "127.0.0.1",
            CONFIG["port"],
        ),
        DashboardHandler,
    )


    # Open browser.
    threading.Timer(
        1.5,
        lambda: webbrowser.open(
            f"http://127.0.0.1:{CONFIG['port']}"
        ),
    ).start()


    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "\nStopping..."
        )

    finally:

        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
