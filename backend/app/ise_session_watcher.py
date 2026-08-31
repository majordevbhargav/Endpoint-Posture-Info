import os
import time
import msvcrt
import logging
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth
import urllib3
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from posture_db import mark_connected, mark_disconnected

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("ise_watcher")

# ---------------- CONFIG ----------------

ISE_HOST = os.getenv("ISE_HOST", "https://10.6.1.90").rstrip("/")
ISE_USER = os.getenv("ISE_USER", "Dev")
ISE_PASS = os.getenv("ISE_PASS", "Login@123")

VERIFY_TLS = os.getenv("ISE_VERIFY_TLS", "false").lower() == "true"
POLL_INTERVAL = int(os.getenv("WATCHER_POLL_SECONDS", "20"))

# Once a MAC's posture check has run, how long before it's due to be
# rechecked. Without this, a device that was checked once (compliant or
# not) would sit at that same status/app/port snapshot forever, since
# nothing else in this project ever re-queues an already-seen MAC.
# Default: 4 hours.
RECHECK_INTERVAL_SECONDS = int(
    os.getenv("RECHECK_INTERVAL_SECONDS", str(4 * 60 * 60))
)

QUEUE_FILE = os.getenv("PENDING_QUEUE_FILE", "pending_devices.txt")
SEEN_FILE = os.getenv("SEEN_MACS_FILE", "seen_macs.txt")
IP_MAC_FILE = os.getenv("IP_MAC_MAP_FILE", "ip_mac_map.txt")

URL = f"{ISE_HOST}/admin/API/mnt/Session/ActiveList"
AUTH = HTTPBasicAuth(ISE_USER, ISE_PASS)


# ---------------- FILE HELPERS ----------------

def load_seen():
    """
    Returns {MAC: last_queued_epoch_seconds}.

    SEEN_FILE historically stored a bare list of MACs with no
    timestamp, which is what made a MAC "seen forever" - once added,
    nothing ever re-queued it. Lines are now "MAC,epoch_seconds". Old
    bare-MAC lines (no comma) are treated as due for an immediate
    recheck rather than "seen forever" going forward, so upgrading
    doesn't require manually deleting the file - devices just get one
    recheck on the next poll and then fall onto the normal interval.
    """
    if not os.path.exists(SEEN_FILE):
        return {}

    seen = {}
    with open(SEEN_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "," in line:
                mac, ts = line.split(",", 1)
                try:
                    seen[mac.strip().upper()] = float(ts.strip())
                except ValueError:
                    seen[mac.strip().upper()] = 0.0
            else:
                seen[line.upper()] = 0.0
    return seen


def due_for_check(mac, seen):
    """True if this MAC has never been queued, or its last check is stale."""
    last = seen.get(mac)
    if last is None:
        return True
    return (time.time() - last) >= RECHECK_INTERVAL_SECONDS


def save_seen(seen):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        for mac in sorted(seen):
            f.write(f"{mac},{seen[mac]}\n")


def save_ip_mac(ip, mac):
    if not ip or ip == "unknown-ip" or not mac:
        return

    mapping = {}

    if os.path.exists(IP_MAC_FILE):
        with open(IP_MAC_FILE, encoding="utf-8") as f:
            for line in f:
                if "," in line:
                    k, v = line.strip().split(",", 1)
                    mapping[k] = v

    mapping[ip] = mac

    with open(IP_MAC_FILE, "w", encoding="utf-8") as f:
        for ip_addr, mac_addr in mapping.items():
            f.write(f"{ip_addr},{mac_addr}\n")


def enqueue(ip):
    if not ip or ip == "unknown-ip":
        log.warning("No IP yet - will retry on next poll.")
        return False

    if not os.path.exists(QUEUE_FILE):
        open(QUEUE_FILE, "a").close()

    with open(QUEUE_FILE, "r+", encoding="utf-8") as f:
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)

        try:
            existing = {
                line.strip()
                for line in f
                if line.strip()
            }

            if ip in existing:
                return True

            f.seek(0, os.SEEK_END)
            f.write(ip + "\n")
            log.info("QUEUED %s", ip)
            return True

        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


# ---------------- ISE ----------------

def fetch_sessions():
    response = requests.get(
        URL,
        auth=AUTH,
        verify=VERIFY_TLS,
        timeout=15
    )

    response.raise_for_status()

    if not response.text.strip():
        return {}

    root = ET.fromstring(response.text)
    sessions = {}

    for session in root:
        fields = {}

        for element in session.iter():
            if len(element) == 0 and element.text:
                tag = element.tag.split("}")[-1]
                fields[tag] = element.text.strip()

        mac = (
            fields.get("calling_station_id")
            or fields.get("mac_address")
            or fields.get("MACAddress")
        )

        if mac:
            sessions[mac.upper()] = fields

    return sessions


def get_info(fields):
    ip = (
        fields.get("framed_ip_address")
        or fields.get("ip_address")
        or "unknown-ip"
    )

    hostname = (
        fields.get("endpoint_id")
        or fields.get("host_name")
        or "?"
    )

    return ip, hostname


# ---------------- MAIN ----------------

def main():

    log.info(
        "Watching %s every %ss",
        ISE_HOST,
        POLL_INTERVAL
    )

    seen = load_seen()

    log.info(
        "Loaded %d previously seen MACs",
        len(seen)
    )

    # Initial snapshot
    try:
        current = fetch_sessions()

        log.info(
            "Initial sessions: %d",
            len(current)
        )

        for mac, fields in current.items():

            ip, hostname = get_info(fields)
            save_ip_mac(ip, mac)
            mark_connected(mac, ip)

            if not due_for_check(mac, seen):
                remaining = int(RECHECK_INTERVAL_SECONDS - (time.time() - seen[mac]))
                log.info(
                    "RECENTLY CHECKED MAC=%s IP=%s HOST=%s (next recheck in ~%ss)",
                    mac, ip, hostname, max(0, remaining)
                )
                continue

            log.info(
                "QUEUEING (new session or recheck due) MAC=%s IP=%s HOST=%s",
                mac, ip, hostname
            )

            if enqueue(ip):
                seen[mac] = time.time()

        save_seen(seen)

    except Exception as e:
        log.error("Initial ISE query failed: %s", e)

    # Continuous polling
    while True:

        time.sleep(POLL_INTERVAL)

        try:
            current = fetch_sessions()

        except Exception as e:
            log.error("ISE poll failed: %s", e)
            continue

        current_macs = set(current)

        for mac in current_macs:

            ip, hostname = get_info(current[mac])
            save_ip_mac(ip, mac)
            mark_connected(mac, ip)

            if not due_for_check(mac, seen):
                continue

            log.info(
                "NEW SESSION OR RECHECK DUE MAC=%s IP=%s HOST=%s",
                mac, ip, hostname
            )

            if enqueue(ip):
                seen[mac] = time.time()

        # Session ended: mark disconnected AND drop from `seen`, so
        # due_for_check() treats a reconnect as immediately due instead of
        # waiting out the rest of RECHECK_INTERVAL_SECONDS (Problem 2 /
        # project plan Section 8.4).
        for mac in set(seen) - current_macs:
            log.info("SESSION ENDED MAC=%s", mac)
            mark_disconnected(mac)
            seen.pop(mac, None)

        save_seen(seen)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")