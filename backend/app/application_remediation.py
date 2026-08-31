"""
Application Compliance & Remediation module for the VE Compliance Engine.

Adds a fleet-wide "Application Remediation" workflow on top of the
application inventory already collected by posture_agent.ps1 into
posture_db (the endpoint_apps table). It does not run its own discovery
against endpoints - it classifies and acts on whatever inventory the
existing posture checks have already gathered.

Workflow:
    Business Relevant / Business Irrelevant / Review classification
    Select-for-uninstall workflow
    Remote uninstall by endpoint IP (WinRM / PowerShell Remoting)
    Audit log of every classification / selection / uninstall action

Integration:
    from application_remediation import register_remediation
    register_remediation(app)
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request

from posture_db import db, init_db, get_all_applications

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Reuses the SAME encrypted credential file Save-PostureCredential.ps1
# already creates for posture_agent.ps1 (DPAPI-encrypted via
# Export-Clixml - decryptable only by the same Windows account, on the
# same machine, that saved it). Point REMEDIATION_COMMON_CRED_PATH at a
# different file if you want a separate credential for uninstalls.
#
# Default points at backend/agents/posture_common_cred.xml - the file
# actually lives next to posture_agent.ps1 and Save-PostureCredential.ps1
# (backend/agents/), not next to this module (backend/app/), per the
# frontend/backend folder split.
COMMON_CRED_PATH = Path(
    os.getenv(
        "REMEDIATION_COMMON_CRED_PATH",
        os.getenv(
            "POSTURE_COMMON_CRED_PATH",
            str(Path(__file__).resolve().parent.parent / "agents" / "posture_common_cred.xml"),
        ),
    )
)

PROTECTED_KEYWORDS = {
    "windows", "microsoft visual c++", "microsoft .net",
    "microsoft edge update", "intel", "nvidia", "realtek",
    "cisco secure client", "cisco anyconnect", "crowdstrike",
    "sentinelone", "trellix",
}

DEFAULT_RELEVANT = {
    "microsoft 365", "microsoft office", "microsoft teams",
    "google chrome", "microsoft edge", "cisco secure client",
    "cisco anyconnect", "adobe acrobat", "7-zip",
}

CATEGORIES = {"Business Relevant", "Business Irrelevant", "Review"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_ps_text(text):
    """
    Text that crosses a non-interactive `powershell.exe -EncodedCommand`
    invocation (our uninstall subprocess) or a remoting session gets
    serialized by PowerShell as CLIXML. That format encodes embedded
    control characters as "_xHHHH_" escapes instead of literal
    characters - e.g. a CR LF inside an error message becomes the
    literal text "_x000D__x000A_" - and wraps everything in XML tags.
    Left undecoded, error text in the UI/audit log shows those raw
    escape codes instead of a readable message. Decode both.
    """
    if not text:
        return text

    def _unescape(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    text = re.sub(r"_x([0-9A-Fa-f]{4})_", _unescape, text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]*\n[ \t]*", "\n", text).strip()
    return text


def _norm(value):
    return re.sub(r"\s+", " ", (value or "").strip().lower())


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def init_remediation_db():
    """Additive migration: never alters the existing posture tables."""
    init_db()
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_classification (
                app_key TEXT PRIMARY KEY,
                app_name TEXT NOT NULL,
                category TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_uninstall_selection (
                app_key TEXT PRIMARY KEY,
                app_name TEXT NOT NULL,
                selected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS remediation_audit (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                application TEXT,
                endpoint_ip TEXT,
                endpoint_mac TEXT,
                detail TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_remediation_audit_time
                ON remediation_audit(timestamp);
            """
        )

        existing = con.execute(
            "SELECT COUNT(*) AS n FROM app_classification"
        ).fetchone()["n"]

        # Seed default classification once on first run
        if existing == 0:
            now = _now()
            for name in sorted(DEFAULT_RELEVANT):
                con.execute(
                    """
                    INSERT INTO app_classification(
                        app_key, app_name, category, updated_at
                    ) VALUES (?,?,?,?)
                    ON CONFLICT(app_key) DO NOTHING
                    """,
                    (_norm(name), name, "Business Relevant", now),
                )


def _is_protected(name):
    n = _norm(name)
    return any(keyword in n for keyword in PROTECTED_KEYWORDS)


def _audit(action, application=None, endpoint_ip=None, endpoint_mac=None, detail=None):
    with db() as con:
        con.execute(
            """
            INSERT INTO remediation_audit(
                timestamp, action, application, endpoint_ip, endpoint_mac, detail
            ) VALUES (?,?,?,?,?,?)
            """,
            (_now(), action, application, endpoint_ip, endpoint_mac, detail),
        )


def _classification_map():
    with db() as con:
        rows = con.execute(
            "SELECT app_key, category FROM app_classification"
        ).fetchall()
    return {row["app_key"]: row["category"] for row in rows}


def _selection_set():
    with db() as con:
        rows = con.execute(
            "SELECT app_key FROM app_uninstall_selection"
        ).fetchall()
    return {row["app_key"] for row in rows}


def _remove_inventory_app(mac, app_name):
    """
    Remove a successfully uninstalled app from the local endpoint snapshot,
    and drop it from the uninstall-selection list if no instance of it
    remains anywhere in the fleet.

    BUGFIX: the "does any instance remain fleet-wide" check used to compare
    SQL's LOWER(TRIM(name)) against LOWER(TRIM(?)) - but TRIM() only strips
    leading/trailing whitespace, while _norm() (used everywhere else in this
    module, including the app_key primary key) also collapses *internal*
    whitespace runs down to a single space. An app name with irregular
    internal spacing (e.g. "Foo   Bar" vs "Foo Bar") would pass the initial
    DELETE (which only needs an exact TRIM match against this endpoint's
    own row) but then fail the "still present elsewhere" check for a
    differently-spaced instance on another endpoint - or vice versa -
    silently leaving a stale app_uninstall_selection row behind (or
    deleting one it shouldn't have). Now normalized the same way in Python
    on both sides, matching app_key exactly.
    """
    if not mac or not app_name:
        return 0

    key = _norm(app_name)

    with db() as con:
        cur = con.execute(
            "DELETE FROM endpoint_apps WHERE UPPER(mac)=UPPER(?) AND LOWER(TRIM(name))=LOWER(TRIM(?))",
            (str(mac), str(app_name)),
        )
        removed = cur.rowcount

        # Normalize every remaining distinct name in Python (same
        # normalization app_key already uses) instead of relying on a
        # SQL TRIM()-only comparison, so this decision matches _norm()
        # exactly rather than approximately.
        still_present = False
        for row in con.execute("SELECT DISTINCT name FROM endpoint_apps").fetchall():
            if _norm(row["name"]) == key:
                still_present = True
                break

        if not still_present:
            con.execute("DELETE FROM app_uninstall_selection WHERE app_key=?", (key,))

    return removed


def _endpoints_overview():
    with db() as con:
        rows = con.execute(
            """
            SELECT mac, ip, hostname, os, os_version, last_seen, apps_count
            FROM endpoints
            ORDER BY LOWER(hostname), ip
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _apps_for_endpoint(mac):
    with db() as con:
        rows = con.execute(
            """
            SELECT name, version, publisher
            FROM endpoint_apps
            WHERE mac = ?
            ORDER BY LOWER(name)
            """,
            (mac,),
        ).fetchall()

    classification = _classification_map()
    selected = _selection_set()

    apps = []
    for row in rows:
        name = row["name"] or "Unknown application"
        key = _norm(name)
        apps.append(
            {
                "app_key": key,
                "name": name,
                "version": row["version"],
                "publisher": row["publisher"],
                "category": classification.get(key, "Review"),
                "protected": _is_protected(name),
                "selected_for_uninstall": key in selected,
            }
        )
    return apps


def _grouped_inventory():
    """
    Group fleet-wide raw app rows by application identity so the remediation table
    shows one row per application with its target endpoint list.
    """
    raw = get_all_applications()
    classification = _classification_map()
    selected = _selection_set()

    grouped = {}
    for row in raw:
        name = row.get("name") or "Unknown application"
        key = _norm(name)

        entry = grouped.setdefault(
            key,
            {
                "app_key": key,
                "name": name,
                "version": row.get("version"),
                "publisher": row.get("publisher"),
                "endpoints": [],
            },
        )
        entry["endpoints"].append(
            {
                "mac": row.get("mac"),
                "hostname": row.get("hostname"),
                "ip": row.get("ip"),
            }
        )

    result = []
    for key, entry in grouped.items():
        result.append(
            {
                **entry,
                "category": classification.get(key, "Review"),
                "protected": _is_protected(entry["name"]),
                "selected_for_uninstall": key in selected,
                "endpoint_count": len(entry["endpoints"]),
            }
        )

    result.sort(key=lambda item: item["name"].lower())
    return result


# ---------------------------------------------------------------------------
# Remote Uninstall Execution Script
# ---------------------------------------------------------------------------

_REMOTE_UNINSTALL_SCRIPT = r'''
param($AppName)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
function Normalize-Name([string]$Value) { if ($null -eq $Value) { return "" }; return ([regex]::Replace($Value.Trim(), "\s+", " " )).ToLowerInvariant() }
function Get-UninstallEntries { $paths=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"); foreach($path in $paths){ Get-ItemProperty $path -ErrorAction SilentlyContinue } }
function Find-App([string]$Name) { $wanted=Normalize-Name $Name; return @(Get-UninstallEntries | Where-Object { $_.DisplayName -and (Normalize-Name ([string]$_.DisplayName)) -eq $wanted }) | Select-Object -First 1 }
function Parse-UninstallCommand([string]$Command) { $cmd=$Command.Trim(); if($cmd -match '^\s*"([^"]+)"\s*(.*)$'){return @{FilePath=$Matches[1];Arguments=$Matches[2].Trim()}}; if($cmd -match '^\s*(\S+)\s*(.*)$'){return @{FilePath=$Matches[1];Arguments=$Matches[2].Trim()}}; throw "Unable to parse uninstall command: $Command" }
function Add-SilentArguments([string]$FilePath,[string]$Arguments) { $args=$Arguments.Trim(); $leaf=[System.IO.Path]::GetFileName($FilePath).ToLowerInvariant(); if($leaf -eq "msiexec.exe" -and $args -notmatch '(?i)(^|\s)/(quiet|qn)(\s|$)'){$args=($args+" /quiet /norestart").Trim();return $args}; if($leaf -match '^unins\d*\.exe$' -and $args -notmatch '(?i)/verysilent|/silent'){$args=($args+" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART").Trim();return $args}; if($FilePath -match '(?i)\\Nmap\\uninstall\.exe$' -and $args -notmatch '(?i)(^|\s)/S(\s|$)'){$args=($args+" /S").Trim();return $args}; if($args -notmatch '(?i)(^|\s)/S(\s|$)|/silent|/verysilent|/quiet|/qn'){$args=($args+" /S").Trim()}; return $args }
$before=Find-App $AppName; if(-not $before){throw "APPLICATION_NOT_FOUND: $AppName"}; $cmd=$before.QuietUninstallString; $source="QuietUninstallString"; if([string]::IsNullOrWhiteSpace([string]$cmd)){$cmd=$before.UninstallString;$source="UninstallString"}; if([string]::IsNullOrWhiteSpace([string]$cmd)){throw "NO_UNINSTALL_COMMAND: $AppName"}; $parsed=Parse-UninstallCommand ([string]$cmd); $filePath=$parsed.FilePath; $arguments=Add-SilentArguments $filePath $parsed.Arguments; if(-not(Test-Path -LiteralPath $filePath)){throw "UNINSTALLER_NOT_FOUND: $filePath"}; $pinfo=New-Object System.Diagnostics.ProcessStartInfo; $pinfo.FileName=$filePath; $pinfo.Arguments=$arguments; $pinfo.UseShellExecute=$false; $pinfo.CreateNoWindow=$true; $pinfo.WorkingDirectory=Split-Path -Parent $filePath; $proc=[System.Diagnostics.Process]::Start($pinfo); if($null -eq $proc){throw "UNINSTALL_START_FAILED: $filePath"}; if(-not $proc.WaitForExit(120000)){try{$proc.Kill()}catch{};throw "UNINSTALL_TIMEOUT: $filePath"}; $exitCode=$proc.ExitCode; $stillRegistered=$true; for($i=0;$i -lt 5;$i++){Start-Sleep -Seconds 2; if($null -eq (Find-App $AppName)){$stillRegistered=$false;break}}; if(-not $stillRegistered){Write-Output "UNINSTALL_SUCCESS";Write-Output "APPLICATION=$AppName";Write-Output "COMMAND_SOURCE=$source";Write-Output "FILE=$filePath";Write-Output "ARGUMENTS=$arguments";Write-Output "EXIT_CODE=$exitCode";Write-Output "VERIFIED=TRUE";exit 0}; if($exitCode -eq 0){ $pending=$null; try{ $pending=(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations }catch{}; if($pending){ Write-Output "UNINSTALL_SUCCESS_PENDING_REBOOT";Write-Output "APPLICATION=$AppName";Write-Output "COMMAND_SOURCE=$source";Write-Output "FILE=$filePath";Write-Output "ARGUMENTS=$arguments";Write-Output "EXIT_CODE=$exitCode";Write-Output "VERIFIED=FALSE";exit 0 } }; throw "UNINSTALL_FAILED: Exit code $exitCode and application is still registered. This can happen for driver-based software (e.g. Npcap) that needs a reboot to finish removal, or if the driver is currently in use by another program."
'''


def _valid_ipv4(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except Exception:
        return False


def _ps_literal(value):
    """
    Build a PowerShell single-quoted string literal.

    json.dumps() was used here previously, which produces a
    double-quoted string. That is wrong on two counts inside a
    PowerShell script: double-quoted strings interpolate "$" as the
    start of a variable reference (so a password like "Admin$007"
    silently loses everything from the $ onward, becoming just
    "Admin"), and PowerShell does not treat backslash as an escape
    character the way JSON does, so JSON's "\\\\" for one backslash
    comes out as two literal backslashes (breaking "IP\\Administrator"
    style credentials). A single-quoted PowerShell literal has neither
    problem - the only special case is doubling embedded single quotes.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _remote_uninstall(ip, app_name, username=None, password=None):
    """
    Uninstall one application from one endpoint over PowerShell Remoting (WinRM).
    """
    if not _valid_ipv4(ip):
        return {
            "status": "FAILED",
            "reason": "Invalid or missing IPv4 address",
        }

    # Only attempt credential binding if BOTH username and password are provided and non-empty
    has_creds = bool(username and str(username).strip() and password and str(password).strip())

    # No explicit override in the request -> fall back to the stored
    # common credential (same file Save-PostureCredential.ps1 writes),
    # instead of silently running with no credentials at all (which is
    # almost always Access Denied on a real target). The password is
    # never read into Python at all in this branch - Import-Clixml
    # decrypts it entirely inside the PowerShell process.
    use_common_cred = (not has_creds) and COMMON_CRED_PATH.exists()

    if has_creds:
        # An unqualified local account name (e.g. "Administrator" typed
        # into the browser prompt, with no "IP\" or "HOST\" prefix) makes
        # Negotiate auth attempt a slower Kerberos-style lookup that
        # fails differently than a clean access-denied - it often shows
        # up as a WinRM timeout instead, even though the credentials
        # themselves are correct. posture_agent.ps1 already qualifies
        # usernames the same way; this mirrors that so the app does not
        # depend on the person typing "IP\Administrator" exactly right.
        qualified_username = str(username).strip()
        if "\\" not in qualified_username and "@" not in qualified_username:
            qualified_username = f"{ip}\\{qualified_username}"

        # Built as a raw System.Security.SecureString rather than via the
        # ConvertTo-SecureString cmdlet. That cmdlet lives in the
        # Microsoft.PowerShell.Security module and PowerShell has to
        # auto-load it on first use - if the console process (Flask,
        # often run as a service or under a stripped-down environment)
        # is missing PSModulePath, that auto-load fails with
        # CouldNotAutoloadMatchingModule and the whole uninstall aborts
        # before it ever reaches the remote endpoint. Building the
        # SecureString directly from the .NET class needs no module.
        ps_wrapper = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$sec = New-Object System.Security.SecureString
foreach ($ch in ({_ps_literal(password)}).ToCharArray()) {{ $sec.AppendChar($ch) }}
$sec.MakeReadOnly()
$cred = New-Object System.Management.Automation.PSCredential({_ps_literal(qualified_username)}, $sec)
Invoke-Command -ComputerName {_ps_literal(ip)} -Credential $cred -ScriptBlock {{ {_REMOTE_UNINSTALL_SCRIPT} }} -ArgumentList {_ps_literal(app_name)}
"""

    elif use_common_cred:
        # Built with plain string concatenation (not an f-string) on
        # purpose - the requalification regexes below contain literal
        # "{" "}" quantifiers that would otherwise have to be doubled
        # and would be easy to get wrong.
        cred_path_lit = _ps_literal(str(COMMON_CRED_PATH))
        target_lit = _ps_literal(ip)
        app_lit = _ps_literal(app_name)

        ps_wrapper = (
            "$ProgressPreference = 'SilentlyContinue'\n"
            "$ErrorActionPreference = 'Stop'\n"
            "$credPath = " + cred_path_lit + "\n"
            "if (-not (Test-Path $credPath)) { throw \"COMMON_CRED_NOT_FOUND: $credPath\" }\n"
            "$stored = Import-Clixml -Path $credPath\n"
            "$storedUser = $stored.UserName\n"
            "$bareUser = $storedUser\n"
            "$prefix = $null\n"
            "if ($storedUser -match '\\\\') {\n"
            "    $parts = $storedUser -split '\\\\', 2\n"
            "    $prefix = $parts[0]\n"
            "    $bareUser = $parts[1]\n"
            "}\n"
            # Same requalification rule as posture_agent.ps1's
            # Get-PostureCred: a credential saved with no prefix, a
            # bare ".", or scoped to a *different* target IP needs to
            # be re-qualified to THIS target; anything else (a domain
            # prefix, or already matching this IP) is used as-is.
            "$prefixIsIp = $prefix -and ($prefix -match '^\\d{1,3}(\\.\\d{1,3}){3}$')\n"
            "$needsRequalify = (-not $prefix) -or ($prefix -eq '.') -or ($prefixIsIp -and $prefix -ne " + target_lit + ")\n"
            "if ($needsRequalify) {\n"
            "    $qualifiedUser = " + target_lit + " + '\\' + $bareUser\n"
            "    $cred = New-Object System.Management.Automation.PSCredential($qualifiedUser, $stored.Password)\n"
            "} else {\n"
            "    $cred = $stored\n"
            "}\n"
            "Invoke-Command -ComputerName " + target_lit +
            " -Credential $cred -ScriptBlock { " + _REMOTE_UNINSTALL_SCRIPT + " } -ArgumentList " + app_lit + "\n"
        )

    else:
        ps_wrapper = f"""
$ProgressPreference = 'SilentlyContinue'
Invoke-Command -ComputerName {_ps_literal(ip)} -ScriptBlock {{ {_REMOTE_UNINSTALL_SCRIPT} }} -ArgumentList {_ps_literal(app_name)}
"""

    encoded_cmd = base64.b64encode(ps_wrapper.encode("utf-16le")).decode("utf-8")

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded_cmd,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        verified_removed = "UNINSTALL_SUCCESS" in stdout and "VERIFIED=TRUE" in stdout
        pending_reboot = "UNINSTALL_SUCCESS_PENDING_REBOOT" in stdout
        success = result.returncode == 0 and (verified_removed or pending_reboot)

        # Format human-readable error reasons
        reason = None
        if pending_reboot:
            # The uninstaller itself ran and exited cleanly, and Windows
            # has a pending file-rename operation scheduled for next
            # boot (the standard mechanism for removing files/drivers
            # that are in use) - this is expected for driver-based
            # software like Npcap, not a failure. It will finish
            # removing itself on the endpoint's next reboot.
            reason = (
                "Uninstaller ran successfully. Windows has scheduled the remaining "
                "driver files to be removed on next reboot - this is expected for "
                "driver-based software and is not a failure."
            )
        elif not success:
            # Order matters: TrustedHosts and Kerberos/SPN failures also
            # raise PSRemotingTransportException, the same exception type
            # a genuine timeout does, so check for the more specific
            # messages first or a TrustedHosts rejection gets reported
            # to the user as a network timeout, which sends them
            # troubleshooting the wrong layer entirely.
            if "COMMON_CRED_NOT_FOUND" in stdout or "COMMON_CRED_NOT_FOUND" in stderr:
                reason = (
                    f"No common credential is saved at {COMMON_CRED_PATH}. "
                    "Run Save-PostureCredential.ps1 once on this console to store one."
                )
            elif "Key not valid" in stderr or "Cryptographic" in stderr or "padding is invalid" in stderr:
                reason = (
                    "Could not decrypt the stored common credential - it was saved under a "
                    "different Windows account/session than this console is running under. "
                    "Re-run Save-PostureCredential.ps1 under this same account/session."
                )
            elif "TrustedHosts" in stderr or "trusted hosts" in stderr.lower():
                reason = (
                    f"{ip} is not in this console's WinRM TrustedHosts list. "
                    "Run on the console: Set-Item WSMan:\\localhost\\Client\\TrustedHosts "
                    f"-Value \"{ip}\" -Concatenate -Force"
                )
            elif "0x80070005" in stderr or "Access is denied" in stderr:
                reason = "Access denied. Verify administrative credentials."
            elif "0x8009030e" in stderr:
                reason = f"Logon session error. Qualify username as workgroup/domain prefix (e.g., {ip}\\Administrator)."
            elif "WinRMOperationTimeout" in stderr or "PSRemotingTransportException" in stderr:
                reason = f"WinRM connection timed out or host {ip} is unreachable on port 5985."
            else:
                # Fall back to the target's own error text rather than a
                # generic message - cleaned up so it reads as plain text
                # instead of raw CLIXML escape codes.
                fallback = _clean_ps_text(stderr) or _clean_ps_text(stdout)
                if fallback:
                    reason = fallback[-500:]

        status = "UNINSTALLED" if verified_removed else "PENDING_REBOOT" if pending_reboot else "FAILED"

        return {
            "status": status,
            "return_code": result.returncode,
            "reason": reason,
            "output": _clean_ps_text(stdout[-2000:]),
            "error": _clean_ps_text(stderr[-4000:]),
            "verified": verified_removed,
            "pending_reboot": pending_reboot,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "FAILED",
            "reason": f"Timed out waiting for WinRM connection to {ip}.",
        }

    except FileNotFoundError:
        return {
            "status": "FAILED",
            "reason": "powershell.exe was not found on this console host.",
        }

    except Exception as exc:
        return {
            "status": "FAILED",
            "reason": str(exc),
        }


# ---------------------------------------------------------------------------
# Blueprint & API Endpoints
# ---------------------------------------------------------------------------

remediation_bp = Blueprint("remediation", __name__)


@remediation_bp.get("/api/remediation/endpoints")
def api_remediation_endpoints():
    search = (request.args.get("q") or "").strip().lower()
    endpoints = _endpoints_overview()

    if search:
        endpoints = [
            e for e in endpoints
            if search in (e.get("hostname") or "").lower()
            or search in (e.get("ip") or "").lower()
            or search in (e.get("mac") or "").lower()
        ]

    return jsonify({"total": len(endpoints), "endpoints": endpoints})


@remediation_bp.get("/api/remediation/endpoints/<mac>/apps")
def api_remediation_endpoint_apps(mac):
    mac = mac.upper()
    search = (request.args.get("q") or "").strip().lower()

    apps = _apps_for_endpoint(mac)

    if search:
        apps = [
            a for a in apps
            if search in a["name"].lower() or search in (a.get("publisher") or "").lower()
        ]

    return jsonify({"mac": mac, "total": len(apps), "applications": apps})


@remediation_bp.get("/api/remediation/apps")
def api_remediation_apps():
    search = (request.args.get("q") or "").strip().lower()
    category = (request.args.get("category") or "").strip()

    apps = _grouped_inventory()

    if search:
        apps = [
            a for a in apps
            if search in a["name"].lower() or search in (a.get("publisher") or "").lower()
        ]

    if category:
        apps = [a for a in apps if a["category"] == category]

    return jsonify({"total": len(apps), "applications": apps})


@remediation_bp.get("/api/remediation/summary")
def api_remediation_summary():
    apps = _grouped_inventory()
    return jsonify(
        {
            "total": len(apps),
            "relevant": sum(1 for a in apps if a["category"] == "Business Relevant"),
            "irrelevant": sum(1 for a in apps if a["category"] == "Business Irrelevant"),
            "review": sum(1 for a in apps if a["category"] == "Review"),
            "selected": sum(1 for a in apps if a["selected_for_uninstall"]),
            "protected": sum(1 for a in apps if a["protected"]),
        }
    )


@remediation_bp.post("/api/remediation/classify")
def api_remediation_classify():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    category = str(data.get("category", "")).strip()

    if not name or category not in CATEGORIES:
        return jsonify({"error": "name and a valid category are required"}), 400

    key = _norm(name)
    with db() as con:
        con.execute(
            """
            INSERT INTO app_classification(app_key, app_name, category, updated_at)
            VALUES (?,?,?,?)
            ON CONFLICT(app_key) DO UPDATE SET
                category = excluded.category,
                updated_at = excluded.updated_at
            """,
            (key, name, category, _now()),
        )

    _audit("CLASSIFICATION_CHANGE", application=name, detail=f"Moved to {category}")
    return jsonify({"ok": True})


@remediation_bp.post("/api/remediation/select")
def api_remediation_select():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    selected = bool(data.get("selected", True))

    if not name:
        return jsonify({"error": "name is required"}), 400

    key = _norm(name)
    with db() as con:
        if selected:
            con.execute(
                """
                INSERT INTO app_uninstall_selection(app_key, app_name, selected_at)
                VALUES (?,?,?)
                ON CONFLICT(app_key) DO UPDATE SET selected_at = excluded.selected_at
                """,
                (key, name, _now()),
            )
        else:
            con.execute(
                "DELETE FROM app_uninstall_selection WHERE app_key = ?", (key,)
            )

    _audit("UNINSTALL_SELECTION", application=name, detail=f"selected={selected}")
    return jsonify({"ok": True})


@remediation_bp.post("/api/remediation/uninstall")
def api_remediation_uninstall():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    username = str(data.get("username", "")).strip() or None
    password = data.get("password")
    targets = data.get("targets")

    if not name:
        return jsonify({"error": "name is required"}), 400

    if username and (password is None or str(password).strip() == ""):
        return jsonify({"error": "Password is required when username is provided."}), 400

    if _is_protected(name):
        return jsonify(
            {"error": "This application is on the protected list and cannot be automatically removed."}
        ), 400

    if not targets:
        match = next((a for a in _grouped_inventory() if a["app_key"] == _norm(name)), None)
        targets = match["endpoints"] if match else []

    if not targets:
        return jsonify({"error": "No endpoints currently report this application installed."}), 400

    results = []
    for target in targets:
        ip = (target or {}).get("ip")
        mac = (target or {}).get("mac")
        outcome = _remote_uninstall(ip, name, username, password)
        outcome["ip"] = ip
        outcome["mac"] = mac
        results.append(outcome)

        if outcome.get("status") == "UNINSTALLED":
            outcome["inventory_removed"] = _remove_inventory_app(mac, name)

        # Build clean audit log string
        status = outcome.get("status")
        if status == "UNINSTALLED":
            detail_text = "UNINSTALLED and VERIFIED: application removed from endpoint inventory."
        elif status == "PENDING_REBOOT":
            # Not removed from local inventory yet - the endpoint still
            # reports it installed until the scheduled reboot actually
            # happens, so the next posture check will confirm removal.
            detail_text = (
                "UNINSTALL RAN, PENDING REBOOT: driver-based software - Windows will "
                "finish removing it on the endpoint's next reboot."
            )
        elif outcome.get("reason"):
            detail_text = f"FAILED: {outcome['reason']}"
        else:
            tail = _clean_ps_text(outcome.get("error") or outcome.get("output") or "")
            detail_text = f"FAILED: {tail[-500:]}" if tail else "FAILED: Unknown error"

        _audit(
            "REMOTE_UNINSTALL",
            application=name,
            endpoint_ip=ip,
            endpoint_mac=mac,
            detail=detail_text,
        )

    return jsonify({"application": name, "results": results})


@remediation_bp.get("/api/remediation/common-credential")
def api_remediation_common_credential():
    """
    Lets the dashboard know whether a common credential is already
    saved, so it can skip prompting for username/password on every
    single uninstall click.
    """
    return jsonify(
        {
            "configured": COMMON_CRED_PATH.exists(),
            "path": str(COMMON_CRED_PATH),
        }
    )


@remediation_bp.get("/api/remediation/audit")
def api_remediation_audit():
    limit = request.args.get("limit", 100, type=int)
    limit = max(1, min(limit, 1000))

    with db() as con:
        rows = con.execute(
            "SELECT * FROM remediation_audit ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return jsonify({"entries": [dict(row) for row in rows]})


def register_remediation(app):
    """Register the Application Remediation blueprint and prepare its tables."""
    init_remediation_db()
    app.register_blueprint(remediation_bp)
    return app


if __name__ == "__main__":
    print("Import this module from posture_ui.py and call register_remediation(app).")