<#
.SYNOPSIS
    Endpoint Hardware Health collector - Phase 3a (project plan Section 6.1).

.DESCRIPTION
    Wraps the same PowerShell/CIM collection approach already proven in
    endpoint_hardware_warranty_collector.py (identity, CPU/memory, storage
    health, battery, hardware events), but instead of writing a local JSON
    file, POSTs the report to posture_app.py's /api/v1/hardware-health
    endpoint so results land in the shared Postgres database.

    Currently implemented: LOCAL collection (run this on the endpoint
    itself, e.g. via a scheduled task, same as the original collector).

    TODO (Phase 3a completion): add a -ComputerName remote mode using the
    same New-CimSession DCOM-then-WSMan fallback pattern already
    implemented in posture_agent.ps1, so this can run centrally from the
    console the same way posture checks do, rather than needing to be
    deployed to every endpoint individually. Warranty CSV/API lookup
    (Section 15, question 10) is deferred until that question is answered.

.EXAMPLE
    .\hardware_health_agent.ps1 -PostureAppBase "http://127.0.0.1:8000"
#>

param(
    [string]$PostureAppBase = "http://127.0.0.1:8000",
    [string]$ComputerName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-Json($ScriptBlockText) {
    try {
        $raw = Invoke-Expression $ScriptBlockText | ConvertTo-Json -Depth 6 -Compress
        if (-not $raw) { return $null }
        return $raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

# --- Identity ---------------------------------------------------------
$cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$csp  = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$nic  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue | Select-Object -First 1

$identity = @{
    manufacturer   = $cs.Manufacturer
    model          = $cs.Model
    serial_number  = $csp.IdentifyingNumber
    bios_version   = $bios.SMBIOSBIOSVersion
    mac            = $nic.MACAddress
    hostname       = $env:COMPUTERNAME
    ip             = ($nic.IPAddress | Where-Object { $_ -and $_ -notmatch ':' } | Select-Object -First 1)
}

# --- CPU / Memory -------------------------------------------------------
$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
    Select-Object -First 1 Name, LoadPercentage
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$memUsedPct = $null
if ($os.TotalVisibleMemorySize) {
    $memUsedPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
}

$cpuMemory = @{
    cpu    = @{ LoadPercentage = $cpu.LoadPercentage }
    memory = @{ UsedPercent = $memUsedPct }
}

# --- Storage --------------------------------------------------------
$disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, HealthStatus, MediaType)
$storage = @{ physical_disks = $disks }

# --- Battery ----------------------------------------------------------
$batteryStatic = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue |
    Select-Object DesignedCapacity, FullChargedCapacity)
$battery = @{ battery_static = $batteryStatic }

# --- Hardware events (7 days) ------------------------------------------
$hwEvents = @(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'WHEA|disk|storport|stornvme|Ntfs|Kernel-Power|Display|USB' })
$events = @{ lookback_days = 7; event_count = $hwEvents.Count }

# --- Warranty (Section 15 question 10 pending; UNKNOWN until answered) --
$warranty = @{ status = "UNKNOWN"; days_remaining = $null; reason = "Warranty data source not yet configured (see project plan Section 15, question 10)." }

# --- Proactive recommendations (mirrors the original collector) -------
$recommendations = @()
foreach ($d in $disks) {
    if ($d.HealthStatus -and $d.HealthStatus -notin @("Healthy", "0")) {
        $recommendations += @{ priority = "HIGH"; area = "Storage"; action = "Investigate SSD/HDD health and schedule backup/replacement." }
    }
}
if ($events.event_count -ge 20) {
    $recommendations += @{ priority = "HIGH"; area = "Hardware Events"; action = "$($events.event_count) hardware-related events in 7 days; investigate before failure." }
} elseif ($events.event_count -ge 5) {
    $recommendations += @{ priority = "MEDIUM"; area = "Hardware Events"; action = "$($events.event_count) hardware-related events in 7 days; monitor trend." }
}

$report = @{
    endpoint                    = $identity
    cpu_memory                  = $cpuMemory
    storage                     = $storage
    battery                     = $battery
    hardware_events             = $events
    warranty                    = $warranty
    proactive_recommendations   = $recommendations
}

$payload = $report | ConvertTo-Json -Depth 8

try {
    $resp = Invoke-RestMethod -Uri "$PostureAppBase/api/v1/hardware-health" -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 20
    Write-Host "Submitted hardware health for $($identity.hostname): overall_score=$($resp.overall_score) band=$($resp.band)" -ForegroundColor Green
} catch {
    Write-Host "ERROR submitting hardware health: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
