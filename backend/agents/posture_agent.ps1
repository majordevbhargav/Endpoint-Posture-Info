<#
.SYNOPSIS
    Cisco ISE Posture Agent - Windows Firewall / Open Ports / Application
    Control check.

.DESCRIPTION
    Checks the local or remote Windows device, collects:
      - Windows OS information
      - Primary IP/MAC information
      - Windows Firewall profile state
      - TCP listening ports (+ evaluated against an allow/block list)
      - Installed applications (+ evaluated against required/blocked lists)

    Remote connections try CIM/DCOM first and automatically fall back
    to CIM/WSMan.

    Results are submitted to posture_app.py and a RESULT_JSON line is
    always emitted so posture_ui.py can reliably parse the result.

.EXAMPLE
    .\posture_agent.ps1

.EXAMPLE
    .\posture_agent.ps1 -ComputerName 10.66.1.12

.EXAMPLE
    .\posture_agent.ps1 -ComputerName 10.66.1.12 -AllowedPorts 80,443,3389 -BlockedApps "uTorrent","TeamViewer"
#>

param(
    [string]$PostureServer = "http://127.0.0.1:8000/api/v1/posture",
    [string]$ComputerName,
    [string]$QueueFile = "pending_devices.txt",
    [string]$Username,
    [securestring]$Password,
    [string]$PlainPassword,
    [string]$CommonCredPath = "$PSScriptRoot\posture_common_cred.xml",

    # ------------------------------------------------------------------
    # Policy inputs. These are simple defaults - move them to a shared
    # config/JSON file once you want per-org or per-group policy instead
    # of one policy for every device this agent checks.
    # ------------------------------------------------------------------
    # NOTE: no longer used to gate compliance - ports are now classified
    # by actual reachability (see "Open Ports" evaluation below) instead
    # of a static allow/block list. Kept only so existing callers that
    # still pass these flags don't break.
    [int[]]$AllowedPorts = @(80, 443, 3389, 445, 135, 5985),
    [int[]]$BlockedPorts = @(21, 23, 3306, 5900),

    # Max time to wait on each per-port reachability probe. Keep this
    # small - it runs once per listening port, sequentially, inside the
    # overall check.
    [int]$PortProbeTimeoutMs = 400,
    [string[]]$RequiredApps = @("Cisco Secure Client"),
    [string[]]$BlockedApps  = @("uTorrent", "TeamViewer")
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Cross-process queue locking
# ---------------------------------------------------------------------------

if (-not ("Win32FileLock" -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32FileLock {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool LockFile(
        IntPtr hFile,
        uint dwFileOffsetLow,
        uint dwFileOffsetHigh,
        uint nNumberOfBytesToLockLow,
        uint nNumberOfBytesToLockHigh
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnlockFile(
        IntPtr hFile,
        uint dwFileOffsetLow,
        uint dwFileOffsetHigh,
        uint nNumberOfBytesToUnlockLow,
        uint nNumberOfBytesToUnlockHigh
    );
}
"@
}

function Open-LockedQueueFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType File -Force | Out-Null
    }

    $fs = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::ReadWrite
    )

    $handle = $fs.SafeFileHandle.DangerousGetHandle()

    $locked = $false

    for ($i = 0; $i -lt 50 -and -not $locked; $i++) {
        $locked = [Win32FileLock]::LockFile(
            $handle,
            0,
            0,
            1,
            0
        )

        if (-not $locked) {
            Start-Sleep -Milliseconds 100
        }
    }

    if (-not $locked) {
        $fs.Close()
        throw "Could not lock $Path (another process held it for 5s straight) - try again."
    }

    return $fs
}

function Close-LockedQueueFile {
    param([System.IO.FileStream]$FileStream)

    if (-not $FileStream) {
        return
    }

    try {
        $handle = $FileStream.SafeFileHandle.DangerousGetHandle()

        [Win32FileLock]::UnlockFile(
            $handle,
            0,
            0,
            1,
            0
        ) | Out-Null
    }
    finally {
        $FileStream.Close()
    }
}

# ---------------------------------------------------------------------------
# Queue handling
# ---------------------------------------------------------------------------

if (-not $ComputerName) {
    if (-not (Test-Path $QueueFile)) {
        Write-Host "No queue file found at $QueueFile - nothing pending. (Is the watcher running?)"
        exit 0
    }

    while (-not $ComputerName) {
        $Fs = Open-LockedQueueFile -Path $QueueFile

        $Candidate = $null
        $RemainingCount = 0

        try {
            $Reader = New-Object System.IO.StreamReader(
                $Fs,
                [System.Text.Encoding]::UTF8,
                $true,
                1024,
                $true
            )

            $Content = $Reader.ReadToEnd()
            $Reader.Dispose()

            $Pending = @(
                $Content -split "`r?`n" |
                Where-Object { $_.Trim() -ne "" }
            )

            if ($Pending.Count -eq 0) {
                Write-Host "Queue is empty - no pending devices to check."
                Close-LockedQueueFile -FileStream $Fs
                exit 0
            }

            $Candidate = $Pending[0].Trim()

            $Remaining = if ($Pending.Count -gt 1) {
                $Pending[1..($Pending.Count - 1)]
            }
            else {
                @()
            }

            $RemainingCount = $Remaining.Count

            $NewContent = if ($Remaining.Count -gt 0) {
                ($Remaining -join "`n") + "`n"
            }
            else {
                ""
            }

            $Fs.Position = 0
            $Fs.SetLength(0)

            $Writer = New-Object System.IO.StreamWriter(
                $Fs,
                [System.Text.Encoding]::UTF8,
                1024,
                $true
            )

            $Writer.Write($NewContent)
            $Writer.Flush()
            $Writer.Dispose()
        }
        finally {
            Close-LockedQueueFile -FileStream $Fs
        }

        $Answer = Read-Host "Run posture check on $Candidate? (Y/N)"

        if ($Answer -match '^[Yy]') {
            $ComputerName = $Candidate
        }
        else {
            Write-Host "Skipped $Candidate. ($RemainingCount remaining in queue)"
        }
    }
}

# ---------------------------------------------------------------------------
# Connection setup
# ---------------------------------------------------------------------------

$IsRemote = $ComputerName -ne $env:COMPUTERNAME

$CimParams = @{}
$Session = $null
$Cred = $null

# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

function Get-PostureCred {
    $HasExplicitOverride = [bool](
        $Username -or
        $Password -or
        $PlainPassword
    )

    if (-not $HasExplicitOverride -and (Test-Path $CommonCredPath)) {
        try {
            $Stored = Import-Clixml -Path $CommonCredPath
            $StoredUser = $Stored.UserName

            $BareUser = $StoredUser
            $Prefix = $null

            if ($StoredUser -match '\\') {
                $Parts = $StoredUser -split '\\', 2
                $Prefix = $Parts[0]
                $BareUser = $Parts[1]
            }

            $PrefixIsIp = $Prefix -and (
                $Prefix -match '^\d{1,3}(\.\d{1,3}){3}$'
            )

            $NeedsRequalify =
                (-not $Prefix) -or
                ($Prefix -eq '.') -or
                ($Prefix -ieq $env:COMPUTERNAME) -or
                ($PrefixIsIp -and $Prefix -ne $ComputerName)

            if ($NeedsRequalify) {
                if ($PrefixIsIp -and $Prefix -ne $ComputerName) {
                    Write-Host `
                        "Stored credential was saved scoped to $Prefix, not $ComputerName - re-qualifying for this target." `
                        -ForegroundColor DarkYellow
                }

                $QualifiedStoredUser = "$ComputerName\$BareUser"

                $Stored = New-Object `
                    System.Management.Automation.PSCredential(
                        $QualifiedStoredUser,
                        $Stored.Password
                    )
            }

            Write-Host `
                "Using stored common credential ($($Stored.UserName)) for $ComputerName" `
                -ForegroundColor DarkGray

            return $Stored
        }
        catch {
            $ImportErr = $_.Exception.Message

            if (
                $ImportErr -match
                'Key not valid|invalid in the current context|padding is invalid|Cryptographic'
            ) {
                $script:CredLoadWarning =
                    "Could not decrypt the stored credential at $CommonCredPath. " +
                    "This almost always means it was saved under a different " +
                    "Windows user account/session. Re-run " +
                    "Save-PostureCredential.ps1 under the same account/session " +
                    "that runs posture_agent.ps1."
            }
            else {
                $script:CredLoadWarning =
                    "Could not load stored credential from $CommonCredPath : $ImportErr"
            }

            Write-Host `
                $script:CredLoadWarning `
                -ForegroundColor Yellow
        }
    }

    if (-not $Username) {
        try {
            $script:Username = Read-Host `
                "Username on $ComputerName (e.g. Administrator)"
        }
        catch {
            $Reason = if ($script:CredLoadWarning) {
                $script:CredLoadWarning
            }
            else {
                "No credential available, and this session cannot prompt interactively."
            }

            throw $Reason
        }
    }

    if ($PlainPassword) {
        $SecurePwd = New-Object System.Security.SecureString

        foreach ($ch in $PlainPassword.ToCharArray()) {
            $SecurePwd.AppendChar($ch)
        }

        $SecurePwd.MakeReadOnly()
    }
    elseif ($Password) {
        $SecurePwd = $Password
    }
    else {
        $SecurePwd = Read-Host `
            "Password for $Username" `
            -AsSecureString
    }

    $QualifiedUser = if ($Username -match '\\') {
        $Username
    }
    else {
        "$ComputerName\$Username"
    }

    return New-Object `
        System.Management.Automation.PSCredential(
            $QualifiedUser,
            $SecurePwd
        )
}

# ---------------------------------------------------------------------------
# Main posture collection
# ---------------------------------------------------------------------------

$CollectionSucceeded = $false
$OS = $null
$Nic = $null
$Compliant = $null
$Status = "ERROR"
$Detail = $null
$Ports = @()
$InstalledApps = @()

# Open Ports / Application Control evaluation results (populated below,
# defaulted here so the payload build never sees an undefined variable
# if collection fails before reaching those sections).
$OpenPortsStatus = "ERROR"
$OpenPortsDetail = "Not evaluated - collection did not complete."
$AppControlStatus = "ERROR"
$AppControlDetail = "Not evaluated - collection did not complete."

try {
    if ($IsRemote) {
        try {
            $Cred = Get-PostureCred
        }
        catch {
            Write-Host `
                "ERROR: $($_.Exception.Message)" `
                -ForegroundColor Red

            $FailResult = [ordered]@{
                computer  = $ComputerName
                compliant = $null
                status    = "ERROR"
                detail    = $_.Exception.Message
                submitted = $false
            }

            Write-Output (
                "RESULT_JSON:" +
                ($FailResult | ConvertTo-Json -Compress)
            )

            exit 1
        }

        # DCOM first.
        try {
            $Session = New-CimSession `
                -ComputerName $ComputerName `
                -Credential $Cred `
                -SessionOption (
                    New-CimSessionOption -Protocol Dcom
                ) `
                -ErrorAction Stop
        }
        catch {
            $DcomError = $_.Exception.Message

            Write-Host `
                "DCOM connection failed ($DcomError), trying WSMan/Kerberos instead..." `
                -ForegroundColor Yellow

            try {
                $Session = New-CimSession `
                    -ComputerName $ComputerName `
                    -Credential $Cred `
                    -ErrorAction Stop
            }
            catch {
                Write-Host ""
                Write-Host `
                    "ERROR: Could not connect to $ComputerName via DCOM or WSMan." `
                    -ForegroundColor Red

                Write-Host `
                    "Most likely causes:" `
                    -ForegroundColor Red

                Write-Host `
                    "  1. The account does not have real admin rights on $ComputerName." `
                    -ForegroundColor Red

                Write-Host `
                    "  2. Wrong password or account locked out." `
                    -ForegroundColor Red

                Write-Host `
                    "  3. WMI firewall rules are blocked on the target." `
                    -ForegroundColor Red

                Write-Host ""
                Write-Host `
                    "WSMan error detail: $($_.Exception.Message)" `
                    -ForegroundColor DarkGray

                $FailResult = [ordered]@{
                    computer  = $ComputerName
                    compliant = $null
                    status    = "ERROR"
                    detail    = "Could not connect via DCOM or WSMan: $($_.Exception.Message)"
                    submitted = $false
                }

                Write-Output (
                    "RESULT_JSON:" +
                    ($FailResult | ConvertTo-Json -Compress)
                )

                exit 1
            }
        }

        $CimParams = @{
            CimSession = $Session
        }
    }

    try {
        # ---------------------------------------------------------------
        # OS
        # ---------------------------------------------------------------

        $OS = Get-CimInstance `
            @CimParams `
            -ClassName Win32_OperatingSystem

        # ---------------------------------------------------------------
        # Network adapter
        # ---------------------------------------------------------------

        $Nic = Get-CimInstance `
            @CimParams `
            -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled=True" |
            Where-Object {
                $_.DefaultIPGateway
            } |
            Select-Object -First 1

        if (-not $Nic) {
            $Nic = Get-CimInstance `
                @CimParams `
                -ClassName Win32_NetworkAdapterConfiguration `
                -Filter "IPEnabled=True" |
                Select-Object -First 1
        }

        if (-not $Nic) {
            throw "No IP-enabled network adapter was found on $ComputerName."
        }

        # ---------------------------------------------------------------
        # Windows Firewall
        # ---------------------------------------------------------------

        $FwDisabled = Get-CimInstance `
            @CimParams `
            -Namespace ROOT\StandardCimv2 `
            -ClassName MSFT_NetFirewallProfile |
            Where-Object {
                -not $_.Enabled
            }

        $Compliant = $FwDisabled.Count -eq 0

        $Status = if ($Compliant) {
            "COMPLIANT"
        }
        else {
            "NON-COMPLIANT"
        }

        $Detail = if ($Compliant) {
            "All firewall profiles enabled"
        }
        else {
            $DisabledNames = @(
                $FwDisabled |
                Select-Object -ExpandProperty Name |
                Where-Object { $_ }
            )

            "Disabled: " + ($DisabledNames -join ", ")
        }

        # ---------------------------------------------------------------
        # Hardware inventory (manufacturer / model / serial number)
        # ---------------------------------------------------------------

        $HardwareInfo = @{
            manufacturer  = $null
            model         = $null
            serial_number = $null
        }

        try {
            $CS = Get-CimInstance `
                @CimParams `
                -ClassName Win32_ComputerSystem

            $BiosInfo = Get-CimInstance `
                @CimParams `
                -ClassName Win32_BIOS

            $HardwareInfo.manufacturer  = $CS.Manufacturer
            $HardwareInfo.model         = $CS.Model
            $HardwareInfo.serial_number = $BiosInfo.SerialNumber
        }
        catch {
            Write-Host `
                "WARNING: Failed to collect hardware info: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }

        # ---------------------------------------------------------------
        # CPU / memory utilization
        # ---------------------------------------------------------------
        #
        # $OS was already retrieved above with no -Property filter, so
        # its TotalVisibleMemorySize/FreePhysicalMemory (both in KB) are
        # already populated - no extra CIM round trip needed for those.

        $ResourceUsage = @{
            cpu_percent     = $null
            memory_percent  = $null
            memory_total_mb = $null
            memory_free_mb  = $null
        }

        try {
            $CpuLoad = (
                Get-CimInstance `
                    @CimParams `
                    -ClassName Win32_Processor |
                Measure-Object -Property LoadPercentage -Average
            ).Average

            if ($null -ne $CpuLoad) {
                $ResourceUsage.cpu_percent = [math]::Round($CpuLoad, 1)
            }

            $TotalMemKb = $OS.TotalVisibleMemorySize
            $FreeMemKb  = $OS.FreePhysicalMemory

            if ($TotalMemKb) {
                $ResourceUsage.memory_total_mb = [math]::Round($TotalMemKb / 1024, 1)
                $ResourceUsage.memory_free_mb  = [math]::Round($FreeMemKb / 1024, 1)
                $ResourceUsage.memory_percent  = [math]::Round(
                    (($TotalMemKb - $FreeMemKb) / $TotalMemKb) * 100,
                    1
                )
            }
        }
        catch {
            Write-Host `
                "WARNING: Failed to collect CPU/memory usage: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }

        # ---------------------------------------------------------------
        # Top processes by memory (CIM works remotely without WinRM;
        # Get-Process does not support -ComputerName on modern PowerShell)
        # ---------------------------------------------------------------

        $TopProcesses = @()

        try {
            # Only ask CIM for the 4 fields actually used below. Without
            # -Property, Win32_Process returns the FULL object (dozens
            # of fields, including things like CommandLine) for EVERY
            # process on the box, which then has to be serialized back
            # over DCOM/WSMan and sorted before being thrown away. That
            # is the single heaviest thing this agent does remotely, and
            # is almost certainly what pushed some checks over the 90s
            # timeout - trimming it to 4 fields cuts both the network
            # payload and the work on the target substantially.
            $TopProcesses = @(
                Get-CimInstance `
                    @CimParams `
                    -ClassName Win32_Process `
                    -Property Name, ProcessId, WorkingSetSize, UserModeTime, KernelModeTime |
                Sort-Object WorkingSetSize -Descending |
                Select-Object -First 10 |
                ForEach-Object {
                    @{
                        name      = $_.Name
                        pid       = $_.ProcessId
                        memory_mb = [math]::Round($_.WorkingSetSize / 1MB, 1)
                        cpu_time_seconds = if ($_.UserModeTime -and $_.KernelModeTime) {
                            [math]::Round((($_.UserModeTime + $_.KernelModeTime) / 1e7), 1)
                        } else {
                            $null
                        }
                    }
                }
            )
        }
        catch {
            Write-Host `
                "WARNING: Failed to collect process list: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }

        # ---------------------------------------------------------------
        # Listening TCP ports
        # ---------------------------------------------------------------

        try {
            $Connections = Get-CimInstance `
                @CimParams `
                -Namespace ROOT\StandardCimv2 `
                -ClassName MSFT_NetTCPConnection `
                -Filter "State=2" `
                -ErrorAction SilentlyContinue

            if ($Connections) {
                $Pids = $Connections |
                    Select-Object -ExpandProperty OwningProcess -Unique

                $ProcMap = @{}

                if ($Pids) {
                    $PidsFilter = (
                        $Pids |
                        ForEach-Object {
                            "ProcessId=$_"
                        }
                    ) -join " or "

                    $Processes = Get-CimInstance `
                        @CimParams `
                        -ClassName Win32_Process `
                        -Filter $PidsFilter `
                        -ErrorAction SilentlyContinue

                    foreach ($p in $Processes) {
                        $ProcMap[$p.ProcessId] = $p.Name
                    }
                }

                foreach ($c in $Connections) {
                    $ProcessId = $c.OwningProcess

                    $ProcessName = if (
                        $ProcMap.ContainsKey($ProcessId)
                    ) {
                        $ProcMap[$ProcessId]
                    }
                    else {
                        "Unknown"
                    }

                    $Ports += @{
                        port    = $c.LocalPort
                        process = $ProcessName
                        pid     = $ProcessId
                    }
                }
            }
        }
        catch {
            Write-Host `
                "WARNING: Failed to query listening ports: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }

        # ---------------------------------------------------------------
        # Installed applications (registry-based - see
        # Endpoint_Application_&Port.docx for the local-machine version
        # of this approach)
        # ---------------------------------------------------------------

        try {
            $AppCollectionMethod = $null
            $AppCollectionError  = $null

            if ($IsRemote) {
                # Get-ItemProperty doesn't traverse a CIM session, so for
                # remote targets we read the same uninstall keys through
                # StdRegProv over CIM instead.
                #
                # NOTE: StdRegProv's remote registry methods (EnumKey,
                # GetStringValue) depend on the target's "Remote Registry"
                # (RemoteRegistry) service. That service is Automatic on
                # Windows Server but DISABLED BY DEFAULT on Windows 10/11
                # client editions. When it's off, every call below fails
                # and - because each one used -ErrorAction SilentlyContinue
                # - $InstalledApps silently stays empty with no trace
                # anywhere. We now capture that failure explicitly instead
                # of swallowing it, and fall back to a method that doesn't
                # need Remote Registry at all (see below).
                $RegPaths = @(
                    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                )

                try {
                    $Reg = Get-CimInstance `
                        -CimSession $Session `
                        -Namespace root\default `
                        -ClassName StdRegProv `
                        -ErrorAction Stop

                    if ($Reg) {
                        $HKLM = [uint32]2147483650

                        foreach ($RegPath in $RegPaths) {
                            $SubKeys = Invoke-CimMethod `
                                -InputObject $Reg `
                                -MethodName EnumKey `
                                -Arguments @{ hDefKey = $HKLM; sSubKeyName = $RegPath } `
                                -ErrorAction Stop

                            if ($SubKeys.ReturnValue -ne 0) {
                                throw "StdRegProv.EnumKey returned code $($SubKeys.ReturnValue) for '$RegPath' - the Remote Registry service on $ComputerName is likely stopped/disabled."
                            }

                            foreach ($Key in $SubKeys.sNames) {
                                $FullKey = "$RegPath\$Key"

                                $NameResult = Invoke-CimMethod `
                                    -InputObject $Reg `
                                    -MethodName GetStringValue `
                                    -Arguments @{ hDefKey = $HKLM; sSubKeyName = $FullKey; sValueName = "DisplayName" } `
                                    -ErrorAction SilentlyContinue

                                $Name = $NameResult.sValue

                                if ($Name) {
                                    $VersionResult = Invoke-CimMethod `
                                        -InputObject $Reg `
                                        -MethodName GetStringValue `
                                        -Arguments @{ hDefKey = $HKLM; sSubKeyName = $FullKey; sValueName = "DisplayVersion" } `
                                        -ErrorAction SilentlyContinue

                                    $PublisherResult = Invoke-CimMethod `
                                        -InputObject $Reg `
                                        -MethodName GetStringValue `
                                        -Arguments @{ hDefKey = $HKLM; sSubKeyName = $FullKey; sValueName = "Publisher" } `
                                        -ErrorAction SilentlyContinue

                                    $InstalledApps += @{
                                        name      = $Name
                                        version   = $VersionResult.sValue
                                        publisher = $PublisherResult.sValue
                                    }
                                }
                            }
                        }

                        if ($InstalledApps.Count -gt 0) {
                            $AppCollectionMethod = "stdregprov"
                        }
                    }
                    else {
                        throw "Get-CimInstance for StdRegProv returned nothing."
                    }
                }
                catch {
                    $AppCollectionError = $_.Exception.Message

                    Write-Host `
                        "WARNING: StdRegProv application collection failed ($AppCollectionError). Falling back to WinRM/Invoke-Command..." `
                        -ForegroundColor Yellow

                    # Fallback: PowerShell remoting (WinRM) runs the exact
                    # same native Get-ItemProperty registry read directly
                    # ON the target, so it needs WinRM (already required
                    # for the WSMan CIM fallback above) but NOT the
                    # separate Remote Registry service that StdRegProv
                    # depends on.
                    try {
                        $RemoteApps = Invoke-Command `
                            -ComputerName $ComputerName `
                            -Credential $Cred `
                            -ErrorAction Stop `
                            -ScriptBlock {
                                @(
                                    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
                                    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
                                ) |
                                Where-Object { $_.DisplayName } |
                                ForEach-Object {
                                    [PSCustomObject]@{
                                        name      = $_.DisplayName
                                        version   = $_.DisplayVersion
                                        publisher = $_.Publisher
                                    }
                                }
                            }

                        $InstalledApps = @(
                            $RemoteApps | ForEach-Object {
                                @{ name = $_.name; version = $_.version; publisher = $_.publisher }
                            }
                        )

                        if ($InstalledApps.Count -gt 0) {
                            $AppCollectionMethod = "winrm"
                            $AppCollectionError = $null
                        }
                    }
                    catch {
                        $AppCollectionError = "$AppCollectionError | WinRM fallback also failed: $($_.Exception.Message)"

                        Write-Host `
                            "WARNING: WinRM application collection fallback also failed: $($_.Exception.Message)" `
                            -ForegroundColor Yellow
                    }
                }
            }
            else {
                $InstalledApps = @(
                    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
                    Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
                ) |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    @{
                        name      = $_.DisplayName
                        version   = $_.DisplayVersion
                        publisher = $_.Publisher
                    }
                }
            }

            $InstalledApps = @(
                $InstalledApps |
                Sort-Object { $_.name } -Unique
            )

            if (-not $IsRemote -and $InstalledApps.Count -gt 0) {
                $AppCollectionMethod = "local"
            }
        }
        catch {
            Write-Host `
                "WARNING: Failed to collect installed applications: $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }

        $AppNames = @($InstalledApps | ForEach-Object { $_.name })

        # ---------------------------------------------------------------
        # Evaluate "Open Ports" check
        #
        # Rather than judging each listening port against a static
        # allow/block list, each port is actively probed from the
        # machine running this script:
        #
        #   - Open ports   = listening AND the probe connected. These
        #                    are genuinely reachable/working.
        #   - Blocked ports = listening locally, but the probe could
        #                    not connect (firewall/ACL/network path is
        #                    dropping or rejecting it).
        #
        # This is informational (both categories are valid outcomes
        # depending on intent), so it does not by itself flip the
        # compliance status - it gives visibility into which of the
        # device's listening services are actually reachable.
        #
        # NOTE: Test-NetConnection was tried first here and reverted -
        # it has no configurable connect timeout, and a genuinely
        # filtered/dropped port can make it hang for 10-20+ seconds
        # EACH. With several listening ports on a device, that alone
        # blew past the 90s subprocess timeout in posture_ui.py and
        # made previously-fine devices show up as ERROR/timeout. A raw
        # TcpClient probe with an explicit short timeout below fixes
        # that: each probe is capped at $PortProbeTimeoutMs.
        # ---------------------------------------------------------------

        $ListeningPortNumbers = @(
            $Ports |
            ForEach-Object { [int]$_.port } |
            Sort-Object -Unique
        )

        $OpenPorts = @()
        $BlockedPortsUnreachable = @()

        foreach ($PortNum in $ListeningPortNumbers) {
            $Reachable = $false
            $TcpClient = New-Object System.Net.Sockets.TcpClient

            try {
                $ConnectTask = $TcpClient.ConnectAsync($ComputerName, $PortNum)

                if ($ConnectTask.Wait($PortProbeTimeoutMs)) {
                    $Reachable = $TcpClient.Connected
                }
                else {
                    $Reachable = $false
                }
            }
            catch {
                $Reachable = $false
            }
            finally {
                $TcpClient.Close()
                $TcpClient.Dispose()
            }

            if ($Reachable) {
                $OpenPorts += $PortNum
            }
            else {
                $BlockedPortsUnreachable += $PortNum
            }
        }

        # Attach reachability onto each already-collected port/process
        # record so the UI can show process + reachability together.
        foreach ($PortEntry in $Ports) {
            $PortEntry.reachable = $OpenPorts -contains [int]$PortEntry.port
        }

        $OpenPortsStatus = "COMPLIANT"

        $OpenPortsDetail = (
            "Open/working: " +
            $(if ($OpenPorts.Count) { $OpenPorts -join ", " } else { "none" }) +
            " | Blocked/unreachable: " +
            $(if ($BlockedPortsUnreachable.Count) { $BlockedPortsUnreachable -join ", " } else { "none" })
        )

        # ---------------------------------------------------------------
        # Evaluate "Application Control" check
        #
        # NON-COMPLIANT if a required app is missing, or a blocked app
        # is present. Matching is substring-based ("-like *term*") since
        # DisplayName strings vary by version/vendor formatting.
        # ---------------------------------------------------------------

        $MissingRequired = @(
            $RequiredApps | Where-Object {
                $Req = $_
                -not ($AppNames | Where-Object { $_ -like "*$Req*" })
            }
        )

        $FoundBlocked = @(
            $BlockedApps | Where-Object {
                $Blk = $_
                ($AppNames | Where-Object { $_ -like "*$Blk*" })
            }
        )

        if ($InstalledApps.Count -eq 0 -and $AppCollectionError) {
            # We genuinely could not read the application inventory (see
            # $AppCollectionError above) - this is a collection failure,
            # not evidence that required apps are missing. Reporting it
            # as NON-COMPLIANT here would be a false compliance finding,
            # so it gets its own ERROR state instead.
            $AppControlStatus = "ERROR"
            $AppControlDetail =
                "Could not read the installed-application inventory from " +
                "$ComputerName (StdRegProv and WinRM both failed) - Application " +
                "Control was not evaluated this run. Likely cause: the " +
                "'Remote Registry' service is stopped/disabled on the " +
                "target, or WinRM is unreachable. Detail: $AppCollectionError"
        }
        else {
            $AppControlStatus = if ($MissingRequired.Count -eq 0 -and $FoundBlocked.Count -eq 0) {
                "COMPLIANT"
            }
            else {
                "NON-COMPLIANT"
            }

            $AppControlDetailParts = @()

            if ($MissingRequired.Count -gt 0) {
                $AppControlDetailParts += "Missing required: " + ($MissingRequired -join ", ")
            }

            if ($FoundBlocked.Count -gt 0) {
                $AppControlDetailParts += "Blocked apps found: " + ($FoundBlocked -join ", ")
            }

            $AppControlDetail = if ($AppControlDetailParts.Count -gt 0) {
                $AppControlDetailParts -join " | "
            }
            else {
                "Policy satisfied."
            }
        }

        $CollectionSucceeded = $true
    }
    catch {
        Write-Host `
            "ERROR querying $ComputerName after connecting: $($_.Exception.Message)" `
            -ForegroundColor Red

        $FailResult = [ordered]@{
            computer  = if ($OS) {
                $OS.CSName
            }
            else {
                $ComputerName
            }
            compliant = $null
            status    = "ERROR"
            detail    = "Connected, but the posture query itself failed: $($_.Exception.Message)"
            submitted = $false
        }

        Write-Output (
            "RESULT_JSON:" +
            ($FailResult | ConvertTo-Json -Compress)
        )

        exit 1
    }
}
finally {
    if ($Session) {
        Remove-CimSession $Session
    }
}

# ---------------------------------------------------------------------------
# Result display
# ---------------------------------------------------------------------------

$DisplayColor = if ($Compliant) {
    "Green"
}
else {
    "Red"
}

Write-Host `
    "Host: $($OS.CSName)  MAC: $($Nic.MACAddress)  Firewall: $Status  Ports: $OpenPortsStatus  Apps: $AppControlStatus" `
    -ForegroundColor $DisplayColor

# ---------------------------------------------------------------------------
# Submit to posture_app.py
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Build payload for posture_app.py
# ---------------------------------------------------------------------------

$PrimaryIPv4 = $null

if ($Nic.IPAddress) {
    $PrimaryIPv4 = @(
        $Nic.IPAddress |
        Where-Object {
            $_ -and $_ -notmatch ':'
        }
    ) | Select-Object -First 1
}

$AllIPs = @()

if ($Nic.IPAddress) {
    $AllIPs = @(
        $Nic.IPAddress |
        Where-Object {
            $_
        }
    )
}

$AllChecks = @(
    @{ Check = "Windows Firewall"; Status = $Status; Details = $Detail }
    @{ Check = "Open Ports"; Status = $OpenPortsStatus; Details = $OpenPortsDetail }
    @{ Check = "Application Control"; Status = $AppControlStatus; Details = $AppControlDetail }
)

$PayloadObject = @{
    endpoint = @{
        hostname         = $OS.CSName
        mac              = $Nic.MACAddress
        operating_system = $OS.Caption
        os_version       = $OS.Version
        ip               = $PrimaryIPv4
        ips              = $AllIPs
        hardware         = $HardwareInfo
    }

    posture = @{
        status    = $Status
        timestamp = (Get-Date).ToUniversalTime().ToString("o")

        checks = $AllChecks

        appsCount = $InstalledApps.Count
        appCollectionMethod = $AppCollectionMethod
        appCollectionError  = $AppCollectionError

        resource_usage = $ResourceUsage
        top_processes  = @($TopProcesses)

        # Reachability-based port categorization (see "Open Ports"
        # evaluation above): "open" ports responded to a probe, "blocked"
        # ports were listening locally but did not respond.
        open_ports     = @($OpenPorts)
        blocked_ports  = @($BlockedPortsUnreachable)

        listening_ports = @(
            $Ports
        )

        installed_apps = @(
            $InstalledApps
        )
    }
}

$Payload = $PayloadObject |
    ConvertTo-Json -Depth 10

try {
    $Response = Invoke-RestMethod `
        -Uri $PostureServer `
        -Method Post `
        -Body $Payload `
        -ContentType "application/json" `
        -TimeoutSec 15

    Write-Host `
        "Submitted OK:" `
        ($Response | ConvertTo-Json -Depth 10)

    $SubmitOk = $true
    $SubmitError = $null
}
catch {
    Write-Host `
        "ERROR submitting to $PostureServer : $($_.Exception.Message)" `
        -ForegroundColor Red

    $SubmitOk = $false
    $SubmitError = $_.Exception.Message
}

# ---------------------------------------------------------------------------
# Machine-readable result for posture_ui.py
# ---------------------------------------------------------------------------

$FinalResult = [ordered]@{
    computer            = $OS.CSName
    mac                 = $Nic.MACAddress
    os                  = $OS.Caption
    osVersion           = $OS.Version
    compliant           = $Compliant
    status              = $Status
    detail              = $Detail
    submitted           = $SubmitOk
    submitError         = $SubmitError
    checks              = $AllChecks
    appsCount           = $InstalledApps.Count
    appCollectionMethod = $AppCollectionMethod
    appCollectionError  = $AppCollectionError
    listening_ports     = @($Ports)
    installed_apps      = @($InstalledApps)
    hardware            = $HardwareInfo
    resource_usage      = $ResourceUsage
    top_processes       = @($TopProcesses)
    open_ports          = @($OpenPorts)
    blocked_ports       = @($BlockedPortsUnreachable)
}

Write-Output (
    "RESULT_JSON:" +
    ($FinalResult | ConvertTo-Json -Compress -Depth 10)
)

# Return a non-zero process exit code only when the actual posture
# collection failed. A submission failure is already represented by
# submitted=false in RESULT_JSON and is handled by the caller.
if (-not $CollectionSucceeded) {
    exit 1
}

exit 0