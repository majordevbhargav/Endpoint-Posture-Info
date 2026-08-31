"""
Endpoint Experience Dashboard - collector.

Standalone collector for the "Endpoint Experience" half of Endpoint 360:
Wi-Fi/LAN, gateway, DNS, internet path, and one application-response probe,
rolled up into a single 0-100 experience score with a best-guess root
cause. This mirrors the shape endpoint_360_integration.py expects:

    from endpoint_experience_dashboard import CONFIG, collect_report
    CONFIG["target"] = "outlook.office.com"
    report = collect_report()

Scope: like the rest of this project's local collectors, this only
inspects the machine the console/agent is running on (its own Wi-Fi,
gateway, DNS, path to the internet) - not the remote fleet devices
checked over WinRM by posture_agent.ps1.

Everything here is best-effort: any single probe failing degrades that
section's status rather than raising, so one broken command (e.g. no
Wi-Fi adapter, tracert blocked by a firewall) never blocks the rest of
the report.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard project dependency
    psutil = None

IS_WINDOWS = platform.system().lower().startswith("win")

CONFIG = {
    "target": "outlook.office.com",
    "trace_enabled": True,
    "refresh": 15,
    "ping_target": "8.8.8.8",
    "dns_target": "outlook.office.com",
    "gateway_ping_count": 4,
    "internet_ping_count": 4,
    "traceroute_max_hops": 12,
    "traceroute_timeout": 15,
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd, timeout=10):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -2, "", "timed out"
    except FileNotFoundError:
        return -3, "", "command not found"
    except Exception as exc:
        return -1, "", str(exc)


def _status_for_latency(ms, good, degraded):
    if ms is None:
        return "UNKNOWN"
    if ms <= good:
        return "HEALTHY"
    if ms <= degraded:
        return "DEGRADED"
    return "POOR"


def _local_ip_and_gateway():
    local_ip = None
    gateway = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            local_ip = sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        pass

    try:
        if IS_WINDOWS:
            rc, out, _ = _run(["ipconfig"], timeout=8)
            if rc == 0:
                for line in out.splitlines():
                    if "Default Gateway" in line and ":" in line:
                        value = line.split(":", 1)[1].strip()
                        if value:
                            gateway = value
                            break
        else:
            rc, out, _ = _run(["ip", "route"], timeout=8)
            if rc == 0:
                match = re.search(r"default via (\S+)", out)
                if match:
                    gateway = match.group(1)
    except Exception:
        pass

    return local_ip, gateway


def _mac_address():
    try:
        if psutil:
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    fam = str(getattr(addr, "family", ""))
                    if "AF_LINK" in fam or "PACKET" in fam:
                        mac = addr.address
                        if mac and mac not in ("00:00:00:00:00:00", ""):
                            return mac.upper()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# endpoint health
# ---------------------------------------------------------------------------

def collect_endpoint_health():
    health = {
        "cpu_percent": None,
        "memory_percent": None,
        "disk_free_percent": None,
        "disk_free_gb": None,
        "disk_total_gb": None,
        "uptime_seconds": None,
        "top_process": None,
        "status": "UNKNOWN",
    }

    if not psutil:
        return health

    try:
        health["cpu_percent"] = round(psutil.cpu_percent(interval=0.3), 1)
        mem = psutil.virtual_memory()
        health["memory_percent"] = round(mem.percent, 1)

        disk = psutil.disk_usage("C:\\" if IS_WINDOWS else "/")
        health["disk_free_percent"] = round(100 - disk.percent, 1)
        health["disk_free_gb"] = round(disk.free / (1024 ** 3), 1)
        health["disk_total_gb"] = round(disk.total / (1024 ** 3), 1)

        health["uptime_seconds"] = round(time.time() - psutil.boot_time())

        top = None
        top_cpu = -1
        for proc in psutil.process_iter(["name", "cpu_percent"]):
            try:
                cpu = proc.info.get("cpu_percent") or 0
                if cpu > top_cpu:
                    top_cpu = cpu
                    top = proc.info.get("name")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if top:
            health["top_process"] = f"{top} ({top_cpu:.1f}%)"
    except Exception:
        pass

    cpu = health["cpu_percent"]
    mem = health["memory_percent"]
    if cpu is None or mem is None:
        health["status"] = "UNKNOWN"
    elif cpu >= 90 or mem >= 90:
        health["status"] = "POOR"
    elif cpu >= 70 or mem >= 75:
        health["status"] = "DEGRADED"
    else:
        health["status"] = "HEALTHY"

    return health


# ---------------------------------------------------------------------------
# wifi
# ---------------------------------------------------------------------------

def collect_wifi():
    wifi = {
        "ssid": None, "bssid": None, "signal_percent": None,
        "channel": None, "radio_type": None, "status": "UNKNOWN",
    }

    if not IS_WINDOWS:
        wifi["status"] = "UNKNOWN"
        return wifi

    rc, out, _ = _run(["netsh", "wlan", "show", "interfaces"], timeout=8)
    if rc != 0 or not out.strip():
        wifi["status"] = "UNKNOWN"
        return wifi

    def _field(label):
        m = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", out, re.MULTILINE)
        return m.group(1).strip() if m else None

    wifi["ssid"] = _field("SSID")
    wifi["bssid"] = _field("BSSID")
    wifi["channel"] = _field("Channel")
    wifi["radio_type"] = _field("Radio type")

    signal_raw = _field("Signal")
    if signal_raw:
        m = re.search(r"(\d+)", signal_raw)
        if m:
            wifi["signal_percent"] = int(m.group(1))

    signal = wifi["signal_percent"]
    if signal is None:
        wifi["status"] = "UNKNOWN"
    elif signal >= 60:
        wifi["status"] = "HEALTHY"
    elif signal >= 35:
        wifi["status"] = "DEGRADED"
    else:
        wifi["status"] = "POOR"

    return wifi


# ---------------------------------------------------------------------------
# ping-based tests (gateway / internet)
# ---------------------------------------------------------------------------

def _ping(target, count):
    result = {"avg_ms": None, "loss_percent": None, "status": "UNKNOWN"}

    if not target:
        return result

    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "1000", target]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", target]

    rc, out, _ = _run(cmd, timeout=count * 2 + 5)

    if not out.strip():
        result["status"] = "POOR"
        result["loss_percent"] = 100.0
        return result

    loss_match = re.search(r"(\d+)%\s*(?:packet )?loss", out, re.IGNORECASE)
    if loss_match:
        result["loss_percent"] = float(loss_match.group(1))

    avg_match = re.search(
        r"Average\s*=\s*(\d+)\s*ms", out, re.IGNORECASE
    ) or re.search(
        r"(?:rtt|round-trip).*=\s*[\d.]+/([\d.]+)/", out, re.IGNORECASE
    )
    if avg_match:
        try:
            result["avg_ms"] = float(avg_match.group(1))
        except ValueError:
            pass

    if result["loss_percent"] is not None and result["loss_percent"] >= 50:
        result["status"] = "POOR"
    else:
        result["status"] = _status_for_latency(result["avg_ms"], 30, 100)

    return result


def collect_gateway_test(gateway_ip):
    return _ping(gateway_ip, CONFIG["gateway_ping_count"])


def collect_internet_test():
    return _ping(CONFIG.get("ping_target", "8.8.8.8"), CONFIG["internet_ping_count"])


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def collect_dns_test():
    target = CONFIG.get("dns_target") or CONFIG.get("target") or "outlook.office.com"
    result = {"target": target, "latency_ms": None, "status": "UNKNOWN"}

    start = time.perf_counter()
    try:
        socket.gethostbyname(target)
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        result["status"] = _status_for_latency(result["latency_ms"], 60, 200)
    except Exception:
        result["status"] = "POOR"

    return result


# ---------------------------------------------------------------------------
# TCP 443 + application (HTTPS) test
# ---------------------------------------------------------------------------

def collect_tcp_443_test(host):
    result = {"ip": None, "latency_ms": None, "status": "UNKNOWN"}
    if not host:
        return result

    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
        start = time.perf_counter()
        with socket.create_connection((ip, 443), timeout=5):
            pass
        result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        result["status"] = _status_for_latency(result["latency_ms"], 100, 300)
    except Exception:
        result["status"] = "POOR"

    return result


def collect_application_test(host):
    result = {
        "host": host, "status_code": None, "total_ms": None, "status": "UNKNOWN",
    }
    if not host:
        return result

    url = host if host.startswith("http") else f"https://{host}"
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "endpoint-360/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            result["status_code"] = resp.getcode()
    except urllib.error.HTTPError as exc:
        # A same-origin app that answers with e.g. 401/403 is still "up".
        result["status_code"] = exc.code
    except Exception:
        result["status"] = "POOR"
        return result
    finally:
        result["total_ms"] = round((time.perf_counter() - start) * 1000, 1)

    result["status"] = _status_for_latency(result["total_ms"], 400, 1200)
    return result


# ---------------------------------------------------------------------------
# traceroute
# ---------------------------------------------------------------------------

def collect_traceroute(target):
    hops = []
    if not target or not CONFIG.get("trace_enabled", True):
        return {"hops": hops}

    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", str(CONFIG["traceroute_max_hops"]), "-w", "800", target]
    else:
        cmd = ["traceroute", "-n", "-m", str(CONFIG["traceroute_max_hops"]), target]

    rc, out, _ = _run(cmd, timeout=CONFIG["traceroute_timeout"])
    if rc not in (0, -2) or not out.strip():
        return {"hops": hops}

    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\D", line)
        if not m:
            continue
        hop_num = int(m.group(1))

        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if not ip_match:
            continue
        ip = ip_match.group(1)

        latency_match = re.search(r"(\d+)\s*ms", line)
        latency_ms = int(latency_match.group(1)) if latency_match else None

        hops.append({"hop": hop_num, "ip": ip, "latency_ms": latency_ms})

    return {"hops": hops}


# ---------------------------------------------------------------------------
# scoring / root cause
# ---------------------------------------------------------------------------

def _score_and_root_cause(wifi, gateway, dns, internet, app):
    score = 100
    findings = []
    possible_areas = []
    deductions = {}

    def deduct(area, amount, message):
        nonlocal score
        if amount <= 0:
            return
        score -= amount
        deductions[area] = deductions.get(area, 0) + amount
        possible_areas.append(area)
        findings.append(message)

    signal = wifi.get("signal_percent")
    if signal is not None:
        if signal < 35:
            deduct("WIFI", 25, f"Wi-Fi signal is weak ({signal}%).")
        elif signal < 60:
            deduct("WIFI", 10, f"Wi-Fi signal is marginal ({signal}%).")

    if gateway.get("status") == "POOR":
        deduct("GATEWAY", 20, "Gateway latency/packet loss is high.")
    elif gateway.get("status") == "DEGRADED":
        deduct("GATEWAY", 8, "Gateway latency is slightly elevated.")

    if dns.get("status") == "POOR":
        deduct("DNS", 20, "DNS resolution is slow or failing.")
    elif dns.get("status") == "DEGRADED":
        deduct("DNS", 8, "DNS latency is mildly high.")

    if internet.get("status") == "POOR":
        deduct("INTERNET", 20, "Internet path latency/packet loss is high.")
    elif internet.get("status") == "DEGRADED":
        deduct("INTERNET", 8, "Internet latency is mildly high.")

    if app.get("status") == "POOR":
        deduct("APPLICATION", 25, f"{app.get('host') or 'The application'} is slow or unreachable.")
    elif app.get("status") == "DEGRADED":
        deduct("APPLICATION", 8, f"{app.get('host') or 'The application'} response is mildly slow.")

    score = max(0, min(100, score))

    if score >= 85:
        status = "HEALTHY"
    elif score >= 60:
        status = "DEGRADED"
    else:
        status = "POOR"

    root_cause = "NONE"
    if deductions:
        root_cause = max(deductions, key=deductions.get)

    if not findings:
        findings.append("No significant experience issue detected right now.")

    return {
        "score": score,
        "status": status,
        "root_cause": root_cause,
        "possible_areas": sorted(set(possible_areas)),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def collect_report():
    target = CONFIG.get("target") or "outlook.office.com"

    hostname = socket.gethostname()
    local_ip, gateway = _local_ip_and_gateway()
    mac = _mac_address()

    endpoint_health = collect_endpoint_health()
    wifi = collect_wifi()
    gateway_test = collect_gateway_test(gateway)
    dns_test = collect_dns_test()
    internet_test = collect_internet_test()
    tcp_443_test = collect_tcp_443_test(target)
    application_test = collect_application_test(target)
    traceroute = collect_traceroute(target)

    experience = _score_and_root_cause(
        wifi, gateway_test, dns_test, internet_test, application_test
    )

    return {
        "report_version": "1.0",
        "timestamp_utc": _utc_now(),
        "endpoint": {
            "hostname": hostname,
            "mac": mac,
            "local_ip": local_ip,
            "gateway": gateway,
        },
        "endpoint_health": endpoint_health,
        "wifi": wifi,
        "gateway_test": gateway_test,
        "dns_test": dns_test,
        "internet_test": internet_test,
        "tcp_443_test": tcp_443_test,
        "application_test": application_test,
        "traceroute": traceroute,
        "experience": experience,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(collect_report(), indent=2, default=str))
