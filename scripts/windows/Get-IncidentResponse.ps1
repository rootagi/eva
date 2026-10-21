<#
.SYNOPSIS
    Windows Incident Response Snapshot (EVA Sec compatible).
.DESCRIPTION
    Collects volatile endpoint evidence for first responders:
    - Host, boot and logged-on user information
    - Process inventory with parent lineage, suspicious paths, command lines,
      signatures and hashes for suspicious binaries
    - TCP/UDP listeners and established connections with owning processes
    - Services with suspicious or unquoted binary paths
    - Recently created executables and scripts in temporary directories
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
.PARAMETER MaxProcesses
    Maximum number of processes included in the report (default 250).
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "",
    [int]$MaxProcesses = 250
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-incident-response'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$processes = @()
$listeners = @()
$established = @()
$services = @()
$sessions = @()
$recentTemp = @()

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLower()
    } finally {
        $sha.Dispose()
    }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 1200)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $clean = ($Text -replace "[\r\n\t]+", " ").Trim()
    if ($clean.Length -gt $Max) { return $clean.Substring(0, $Max) }
    return $clean
}

function New-Finding {
    param(
        [string]$Id,
        [string]$RuleId,
        [string]$Title,
        [string]$Severity,
        [string]$Evidence,
        [string]$Remediation,
        [string]$File = "",
        [string]$Category = "host_anomaly",
        [string]$Confidence = "high"
    )
    [ordered]@{
        id = $Id
        tool = $script:ToolName
        rule_id = $RuleId
        title = $Title
        severity = $Severity
        confidence = $Confidence
        category = $Category
        target = $script:Hostname
        file = $File
        evidence = (Limit-Text $Evidence)
        remediation = (Limit-Text $Remediation)
        fingerprint = (Get-Sha256Hex "$Id|$RuleId|$Title|$File").Substring(0, 32)
    }
}

function Test-TrustedVendorPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '(?i)(\\ProgramData\\Microsoft\\Windows Defender\\|\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\|\\AppData\\Local\\Microsoft\\OneDrive\\)')
}

function Test-SuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (Test-TrustedVendorPath $Path) { return $false }
    return ($Path -match '(?i)(\\Temp\\|\\tmp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\Windows\\Temp\\|\\\$Recycle\.Bin\\|\\PerfLogs\\)')
}

function Test-PublicIP {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -match '^(10\.|127\.|169\.254\.|0\.0\.0\.0$|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fc|fd)') {
        return $false
    }
    return $true
}

function Get-SignatureStatus {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return "Unavailable" }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $sig) { return "Unknown" }
    return $sig.Status.ToString()
}

function Get-FileSha256 {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue
    if ($null -eq $hash) { return "" }
    return $hash.Hash.ToLower()
}

# ------------------------------------------------------------------------------
# 1. Host identity
# ------------------------------------------------------------------------------
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$uptime = ""
if ($os.LastBootUpTime) {
    $span = (Get-Date) - $os.LastBootUpTime
    $uptime = "{0}d {1}h {2}m" -f $span.Days, $span.Hours, $span.Minutes
}

$installedAt = ""
if ($os.InstallDate) { $installedAt = $os.InstallDate.ToUniversalTime().ToString("o") }
$lastBoot = ""
if ($os.LastBootUpTime) { $lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString("o") }

$currentUser = ""
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch { }

$hostInfo = [ordered]@{
    hostname = $script:Hostname
    os = $os.Caption
    version = $os.Version
    build = $os.BuildNumber
    architecture = $os.OSArchitecture
    domain = $cs.Domain
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    serial_number = $bios.SerialNumber
    installed_at = $installedAt
    last_boot = $lastBoot
    uptime = $uptime
    current_user = $currentUser
}

# ------------------------------------------------------------------------------
# 2. Process inventory and suspicious process findings
# ------------------------------------------------------------------------------
$allProcesses = @(Get-CimInstance -ClassName Win32_Process)
$processMap = @{}
foreach ($p in $allProcesses) {
    $processMap[[int]$p.ProcessId] = $p
}

$suspiciousProcessCount = 0
$index = 0
foreach ($p in ($allProcesses | Sort-Object ProcessId)) {
    $index++
    if ($index -gt $MaxProcesses) { break }
    $exe = [string]$p.ExecutablePath
    $cmd = [string]$p.CommandLine
    $parentPid = [int]$p.ParentProcessId
    $parent = $processMap[$parentPid]
    $parentName = ""
    if ($null -ne $parent) { $parentName = [string]$parent.Name }

    $isSuspiciousPath = Test-SuspiciousPath $exe
    $isSuspiciousCmd = $false
    $cmdReason = ""
    if ($cmd -match '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|\biex\b|invoke-expression|windowstyle\s+hidden)') {
        $isSuspiciousCmd = $true
        $cmdReason = "Encoded, hidden or download-and-execute PowerShell pattern"
    } elseif ($cmd -match '(?i)(mshta\s|rundll32\s+javascript|regsvr32[^\r\n]*/i:http|certutil[^\r\n]*-urlcache|bitsadmin[^\r\n]*/tr[a-z]{0,6}sfer)') {
        $isSuspiciousCmd = $true
        $cmdReason = "LOLBin download or script execution pattern"
    } elseif ($cmd -match '(?i)(vssadmin[^\r\n]*delete[^\r\n]*shadows|wbadmin[^\r\n]*delete|bcdedit[^\r\n]*/set|wevtutil[^\r\n]*cl\s|fsutil[^\r\n]*deletejournal)') {
        $isSuspiciousCmd = $true
        $cmdReason = "Defense evasion or anti-forensic command"
    } elseif ($cmd -match '(?i)(net\s+user[^\r\n]*/add|net\s+localgroup[^\r\n]*administrators[^\r\n]*/add|schtasks[^\r\n]*/create|wmic[^\r\n]*process[^\r\n]*call[^\r\n]*create)') {
        $isSuspiciousCmd = $true
        $cmdReason = "Account, task or process creation command"
    } elseif ($cmd -match '(?i)(mimi[a-z]{0,3}katz|procdump[^\r\n]*lsa[a-z]{0,2}s|comsvcs\.dll[^\r\n]*minidump)') {
        $isSuspiciousCmd = $true
        $cmdReason = "Credential dumping pattern"
    }

    if ($isSuspiciousPath -or $isSuspiciousCmd) {
        $suspiciousProcessCount++
    }

    $signature = "NotChecked"
    $hash = ""
    if ($isSuspiciousPath -or $isSuspiciousCmd) {
        $signature = Get-SignatureStatus $exe
        $hash = Get-FileSha256 $exe
    }

    if ($processes.Count -lt 200) {
        $processes += [ordered]@{
            pid = [int]$p.ProcessId
            ppid = $parentPid
            parent_name = $parentName
            name = [string]$p.Name
            executable = $exe
            command_line = (Limit-Text $cmd 500)
            signature = $signature
            sha256 = $hash
            suspicious_path = $isSuspiciousPath
            suspicious_command = $isSuspiciousCmd
        }
    }

    if ($isSuspiciousPath) {
        $findings += New-Finding -Id "triage-win-ir-proc-path-$($p.ProcessId)" `
            -RuleId "process.execution.user_writable_path" `
            -Title "Process executes from a user-writable or temporary path: $($p.Name)" `
            -Severity "high" -Category "process_anomaly" `
            -Evidence "PID $($p.ProcessId) executable: $exe CommandLine: $cmd" `
            -Remediation "Capture the binary, verify its signature and hash, and terminate it if unauthorized." `
            -File $exe
    }
    if ($isSuspiciousCmd) {
        $severity = "high"
        if ($cmdReason -eq "Credential dumping pattern") { $severity = "critical" }
        $findings += New-Finding -Id "triage-win-ir-proc-cmd-$($p.ProcessId)" `
            -RuleId "process.command_line.suspicious" `
            -Title "Suspicious process command line: $($p.Name)" `
            -Severity $severity -Category "command_and_control" `
            -Evidence "$cmdReason. PID $($p.ProcessId) CommandLine: $cmd" `
            -Remediation "Validate the parent process and user context, preserve command-line evidence, and contain the process if unauthorized." `
            -File $exe
    }
    if (($isSuspiciousPath -or $isSuspiciousCmd) -and $signature -notin @("Valid")) {
        $findings += New-Finding -Id "triage-win-ir-proc-sig-$($p.ProcessId)" `
            -RuleId "process.signature.invalid_or_missing" `
            -Title "Suspicious process is not validly signed: $($p.Name)" `
            -Severity "high" -Category "process_anomaly" -Confidence "medium" `
            -Evidence "PID $($p.ProcessId) signature: $signature executable: $exe" `
            -Remediation "Treat unsigned or invalidly signed binaries as untrusted until provenance is established." `
            -File $exe
    }
}

# ------------------------------------------------------------------------------
# 3. Network connections with process attribution
# ------------------------------------------------------------------------------
$tcpConnections = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $tcpConnections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
} else {
    $netstat = netstat -ano 2>$null | Select-String "TCP"
    foreach ($line in $netstat) {
        $parts = (($line.ToString() -split '\s+') | Where-Object { $_ -ne '' })
        if ($parts.Count -ge 5) {
            $tcpConnections += [pscustomobject]@{
                LocalAddress = $parts[1]
                LocalPort = [int]($parts[1] -replace '.*:', '')
                RemoteAddress = $parts[2]
                RemotePort = [int]($parts[2] -replace '.*:', '')
                State = $parts[3]
                OwningProcess = [int]$parts[4]
            }
        }
    }
}

foreach ($conn in $tcpConnections) {
    $ownerPid = [int]$conn.OwningProcess
    $owner = $processMap[$ownerPid]
    $ownerName = ""
    $ownerPath = ""
    if ($null -ne $owner) {
        $ownerName = [string]$owner.Name
        $ownerPath = [string]$owner.ExecutablePath
    }
    $state = [string]$conn.State
    if ($state -eq "LISTENING") { $state = "Listen" }
    if ($state -eq "ESTABLISHED") { $state = "Established" }
    $entry = [ordered]@{
        protocol = "TCP"
        local_address = [string]$conn.LocalAddress
        local_port = [int]$conn.LocalPort
        remote_address = [string]$conn.RemoteAddress
        remote_port = [int]$conn.RemotePort
        state = $state
        pid = $ownerPid
        process = $ownerName
        executable = $ownerPath
    }
    if ($state -eq "Listen") {
        if ($listeners.Count -lt 200) { $listeners += $entry }
        switch ([int]$conn.LocalPort) {
            23 { $findings += New-Finding -Id "triage-win-ir-port-23" -RuleId "network.service.telnet_exposed" -Title "Telnet listener exposed on port 23" -Severity "high" -Evidence "PID $ownerPid $ownerName" -Remediation "Disable the Telnet service and use SSH or WinRM over a protected management network." -Category "network_anomaly" }
            21 { $findings += New-Finding -Id "triage-win-ir-port-21" -RuleId "network.service.ftp_exposed" -Title "FTP listener exposed on port 21" -Severity "medium" -Evidence "PID $ownerPid $ownerName" -Remediation "Disable cleartext FTP or require FTPS/SFTP." -Category "network_anomaly" -Confidence "medium" }
            3389 { $findings += New-Finding -Id "triage-win-ir-port-3389" -RuleId "network.service.rdp_exposed" -Title "RDP listener exposed on port 3389" -Severity "medium" -Evidence "PID $ownerPid $ownerName" -Remediation "Restrict RDP to a management network or VPN with MFA and NLA." -Category "network_anomaly" -Confidence "medium" }
            5985 { $findings += New-Finding -Id "triage-win-ir-port-5985" -RuleId "network.service.winrm_exposed" -Title "WinRM listener exposed on port 5985" -Severity "medium" -Evidence "PID $ownerPid $ownerName" -Remediation "Disable WinRM or restrict it to trusted management networks with HTTPS." -Category "network_anomaly" -Confidence "medium" }
            5900 { $findings += New-Finding -Id "triage-win-ir-port-5900" -RuleId "network.service.vnc_exposed" -Title "VNC listener exposed on port 5900" -Severity "high" -Evidence "PID $ownerPid $ownerName" -Remediation "Disable VNC or place it behind an authenticated VPN." -Category "network_anomaly" }
            4444 { $findings += New-Finding -Id "triage-win-ir-port-4444" -RuleId "network.listener.suspicious_port" -Title "Common backdoor port listening on 4444" -Severity "high" -Evidence "PID $ownerPid $ownerName" -Remediation "Identify the owning process and remove unauthorized software." -Category "network_anomaly" }
            1337 { $findings += New-Finding -Id "triage-win-ir-port-1337" -RuleId "network.listener.suspicious_port" -Title "Common backdoor port listening on 1337" -Severity "high" -Evidence "PID $ownerPid $ownerName" -Remediation "Identify the owning process and remove unauthorized software." -Category "network_anomaly" }
            31337 { $findings += New-Finding -Id "triage-win-ir-port-31337" -RuleId "network.listener.suspicious_port" -Title "Common backdoor port listening on 31337" -Severity "high" -Evidence "PID $ownerPid $ownerName" -Remediation "Identify the owning process and remove unauthorized software." -Category "network_anomaly" }
        }
    } elseif ($state -eq "Established") {
        if ($established.Count -lt 200) { $established += $entry }
        if ((Test-PublicIP ([string]$conn.RemoteAddress)) -and (Test-SuspiciousPath $ownerPath)) {
            $findings += New-Finding -Id "triage-win-ir-external-conn-$ownerPid-$($conn.RemotePort)" `
                -RuleId "network.connection.suspicious_process_external" `
                -Title "Process in a user-writable path has an external connection: $ownerName" `
                -Severity "high" -Category "command_and_control" -Confidence "medium" `
                -Evidence "PID $ownerPid executable: $ownerPath remote: $($conn.RemoteAddress):$($conn.RemotePort)" `
                -Remediation "Block the remote endpoint, capture the process and network state, and investigate the binary." `
                -File $ownerPath
        }
    }
}

# ------------------------------------------------------------------------------
# 4. Services
# ------------------------------------------------------------------------------
$serviceList = @(Get-CimInstance -ClassName Win32_Service)
foreach ($svc in $serviceList) {
    $path = [string]$svc.PathName
    if ($services.Count -lt 300) {
        $services += [ordered]@{
            name = [string]$svc.Name
            display_name = [string]$svc.DisplayName
            state = [string]$svc.State
            start_mode = [string]$svc.StartMode
            start_name = [string]$svc.StartName
            path = (Limit-Text $path 500)
        }
    }
    if (Test-SuspiciousPath $path) {
        $findings += New-Finding -Id "triage-win-ir-svc-path-$(Get-Sha256Hex $svc.Name)" `
            -RuleId "service.binary.user_writable_path" `
            -Title "Service executes from a user-writable or temporary path: $($svc.Name)" `
            -Severity "high" -Category "persistence" `
            -Evidence "Service: $($svc.Name) path: $path" `
            -Remediation "Inspect the service binary and creation source; remove or reinstall the service if unauthorized." `
            -File $path
    }
    if ($svc.StartMode -eq "Auto" -and $path -notmatch '^\s*"' -and $path -match '^[^"]*\s+[^"]*\.exe(\s|$)') {
        $findings += New-Finding -Id "triage-win-ir-svc-unquoted-$(Get-Sha256Hex $svc.Name)" `
            -RuleId "service.path.unquoted" `
            -Title "Auto-start service has an unquoted path containing spaces: $($svc.Name)" `
            -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "Service: $($svc.Name) PathName: $path" `
            -Remediation "Quote the service binary path and verify directory permissions to prevent path interception." `
            -File $path
    }
}

# ------------------------------------------------------------------------------
# 5. Sessions and recent temporary executables
# ------------------------------------------------------------------------------
$queryUser = query user 2>$null
if ($queryUser) {
    foreach ($line in ($queryUser | Select-Object -Skip 1)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $sessions += (Limit-Text $line 300) }
    }
}

$tempPaths = @($env:TEMP, "$env:SystemRoot\Temp")
foreach ($tempPath in ($tempPaths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $tempPath)) { continue }
    $recent = Get-ChildItem -LiteralPath $tempPath -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match '(?i)\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|com)$' } |
        Select-Object -First 50
    foreach ($f in $recent) {
        if ($recentTemp.Count -ge 100) { break }
        $recentTemp += [ordered]@{
            path = $f.FullName
            size = $f.Length
            modified = $f.LastWriteTime.ToUniversalTime().ToString("o")
        }
        $findings += New-Finding -Id "triage-win-ir-temp-$((Get-Sha256Hex $f.FullName).Substring(0, 10))" `
            -RuleId "filesystem.temp.recent_executable" `
            -Title "Recent executable or script in a temporary directory: $($f.Name)" `
            -Severity "medium" -Category "malware" -Confidence "medium" `
            -Evidence "File: $($f.FullName) size: $($f.Length) modified: $($f.LastWriteTime.ToString('o'))" `
            -Remediation "Verify the file provenance, hash it for intelligence, and remove it if unauthorized." `
            -File $f.FullName
    }
}

# ------------------------------------------------------------------------------
# 6. Report assembly
# ------------------------------------------------------------------------------
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = $hostInfo
    metrics = [ordered]@{
        processes = $allProcesses.Count
        suspicious_processes = $suspiciousProcessCount
        listeners = $listeners.Count
        established_connections = $established.Count
        services = $serviceList.Count
        sessions = $sessions.Count
        recent_temp_executables = $recentTemp.Count
    }
    processes = @($processes)
    listeners = @($listeners)
    established_connections = @($established)
    services = @($services)
    sessions = @($sessions)
    recent_temp_executables = @($recentTemp)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Incident response report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
