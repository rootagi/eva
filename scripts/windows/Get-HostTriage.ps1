<#
.SYNOPSIS
    Endpoint Host Triage for Windows (EVA Sec compatible).
.DESCRIPTION
    Collects operating system information, active processes, listening sockets,
    scheduled tasks, and startup run keys via CIM/WMI.
    Outputs structured JSON directly ingestible by `eva sec ingest`.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'

$hostname = $env:COMPUTERNAME
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# 1. OS Information
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem

$osInfo = @{
    caption = $os.Caption
    version = $os.Version
    build = $os.BuildNumber
    arch = $os.OSArchitecture
    registered_user = $os.RegisteredUser
    last_boot = $os.LastBootUpTime.ToString("o")
    domain = $cs.Domain
    manufacturer = $cs.Manufacturer
    model = $cs.Model
}

# 2. Active Processes (sample top suspicious or all)
$processes = @()
$procList = Get-CimInstance -ClassName Win32_Process
foreach ($p in $procList) {
    $processes += @{
        pid = $p.ProcessId
        name = $p.Name
        command_line = $p.CommandLine
        executable_path = $p.ExecutablePath
        parent_pid = $p.ParentProcessId
        creation_date = $p.CreationDate.ToString("o")
    }
}

# 3. Listening Network Sockets
$listeners = @()
if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $tcp = Get-NetTCPConnection -State Listen
    foreach ($conn in $tcp) {
        $listeners += @{
            protocol = "TCP"
            local_address = $conn.LocalAddress
            local_port = $conn.LocalPort
            owning_process = $conn.OwningProcess
        }
    }
} else {
    $netstat = netstat -ano | Select-String "LISTENING"
    foreach ($line in $netstat) {
        $parts = ($line -split '\s+') | Where-Object { $_ -ne '' }
        if ($parts.Count -ge 5) {
            $listeners += @{
                protocol = $parts[1]
                local_address = $parts[2]
                state = $parts[3]
                owning_process = $parts[4]
            }
        }
    }
}

# 4. Scheduled Tasks
$tasks = @()
if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $schTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
    foreach ($t in $schTasks) {
        $tasks += @{
            task_name = $t.TaskName
            task_path = $t.TaskPath
            state = $t.State.ToString()
        }
    }
}

# 5. Startup Run Keys
$startup = @()
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $key = Get-ItemProperty -Path $rp
        foreach ($name in $key.PSObject.Properties.Name) {
            if ($name -notmatch '^PS.*') {
                $startup += @{
                    location = $rp
                    name = $name
                    command = $key.$name
                }
            }
        }
    }
}

# Findings Evaluation
$findings = @()

# Detect suspicious startup entries
foreach ($s in $startup) {
    $cmd = [string]$s.command
    if ($cmd -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)') {
        $findings += @{
            id = "triage-win-startup-$($s.name)"
            tool = "triage-windows"
            rule_id = "persistence.startup.script_interpreter"
            title = "Suspicious script interpreter in startup run key: $($s.name)"
            severity = "high"
            confidence = "high"
            category = "persistence"
            file = $s.location
            evidence = "Run Key: $($s.name) -> $($s.command)"
            remediation = "Inspect registry key value, verify binary provenance, and remove unauthorized autorun entries."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($s.location)|$($s.name)|$cmd"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

# Detect processes running from temporary paths
foreach ($p in $processes) {
    $exe = [string]$p.executable_path
    if ($exe -match '(?i)(\\AppData\\Local\\Temp|\\Windows\\Temp|\\Temporary Internet Files)') {
        $findings += @{
            id = "triage-win-proc-temp-$($p.pid)"
            tool = "triage-windows"
            rule_id = "process.execution.temp_directory"
            title = "Process running from temp directory: $($p.name) (PID $($p.pid))"
            severity = "medium"
            confidence = "high"
            category = "process_anomaly"
            evidence = "PID $($p.pid) ExecutablePath: $exe, CommandLine: $($p.command_line)"
            remediation = "Terminate suspicious process and capture memory and binary artifacts for forensic analysis."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($p.pid)|$exe"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows"
    collected_at = $now
    host = @{
        hostname = $hostname
        os = $osInfo
    }
    processes_count = $processes.Count
    listeners_count = $listeners.Count
    scheduled_tasks_count = $tasks.Count
    startup_entries_count = $startup.Count
    startup_entries = $startup
    processes = $processes | Select-Object -First 100
    listeners = $listeners
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5

if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Triage saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
