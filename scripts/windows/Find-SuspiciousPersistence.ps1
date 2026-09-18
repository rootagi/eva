<#
.SYNOPSIS
    Deep Persistence Audit for Windows (EVA Sec compatible).
.DESCRIPTION
    Inspects persistence mechanisms:
    - User/System Run & RunOnce keys
    - Startup folders
    - WMI Event Consumers & Subscriptions
    - BITS (Background Intelligent Transfer Service) active jobs
    - Winlogon helper DLLs & AppInit_DLLs
    Outputs structured findings compatible with `eva sec ingest`.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$hostname = $env:COMPUTERNAME
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$persistenceItems = @()

# 1. Startup Folders
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($sf in $startupFolders) {
    if (Test-Path $sf) {
        $files = Get-ChildItem -Path $sf -File
        foreach ($f in $files) {
            $persistenceItems += @{
                category = "StartupFolder"
                path = $f.FullName
                name = $f.Name
                size = $f.Length
                modified = $f.LastWriteTime.ToString("o")
            }
            if ($f.Extension -match '(?i)\.(bat|cmd|vbs|ps1|hta|js|exe|scr)') {
                $findings += @{
                    id = "triage-win-persist-startup-$($f.Name)"
                    tool = "triage-windows-persistence"
                    rule_id = "persistence.startup_folder.executable"
                    title = "Executable or script in Startup folder: $($f.Name)"
                    severity = "high"
                    confidence = "high"
                    category = "persistence"
                    file = $f.FullName
                    evidence = "File in startup folder: $($f.FullName)"
                    remediation = "Verify file origin and remove unauthorized startup items."
                    fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($f.FullName)"))).Replace("-", "").Substring(0, 32).ToLower()
                }
            }
        }
    }
}

# 2. AppInit DLLs & Winlogon Shell / Userinit
$winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$userinit = (Get-ItemProperty -Path $winlogonKey -Name Userinit -ErrorAction SilentlyContinue).Userinit
$shell = (Get-ItemProperty -Path $winlogonKey -Name Shell -ErrorAction SilentlyContinue).Shell

$persistenceItems += @{ category = "Winlogon"; name = "Userinit"; value = $userinit }
$persistenceItems += @{ category = "Winlogon"; name = "Shell"; value = $shell }

if ($shell -and $shell -ne "explorer.exe") {
    $findings += @{
        id = "triage-win-persist-shell-hijack"
        tool = "triage-windows-persistence"
        rule_id = "persistence.winlogon.shell_hijack"
        title = "Abnormal Winlogon Shell configured: $shell"
        severity = "critical"
        confidence = "high"
        category = "persistence"
        file = $winlogonKey
        evidence = "Winlogon Shell is set to '$shell' instead of 'explorer.exe'"
        remediation = "Reset HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon Shell to explorer.exe"
        fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("winlogon|$shell"))).Replace("-", "").Substring(0, 32).ToLower()
    }
}

# 3. WMI Event Consumers
try {
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $cName = $c.Name
        $persistenceItems += @{ category = "WMIEventConsumer"; name = $cName; type = $c.CimClass.CimClassName }
        $findings += @{
            id = "triage-win-wmi-consumer-$cName"
            tool = "triage-windows-persistence"
            rule_id = "persistence.wmi.event_consumer"
            title = "WMI Event Consumer persistence detected: $cName"
            severity = "high"
            confidence = "high"
            category = "persistence"
            evidence = "WMI Event Consumer: $cName ($($c.CimClass.CimClassName))"
            remediation = "Review WMI event bindings via Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding and remove unauthorized consumers."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("wmi|$cName"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
} catch {}

# 4. BITS Jobs
if (Get-Command -Name Get-BitsTransfer -ErrorAction SilentlyContinue) {
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        foreach ($bj in $bitsJobs) {
            $persistenceItems += @{
                category = "BITSJob"
                job_id = $bj.JobId.ToString()
                display_name = $bj.DisplayName
                file_list = ($bj.FileList | ForEach-Object { "$($_.RemoteName) -> $($_.LocalName)" })
            }
        }
    } catch {}
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows-persistence"
    collected_at = $now
    host = @{
        hostname = $hostname
    }
    persistence_items_count = $persistenceItems.Count
    items = $persistenceItems
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5
if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Persistence report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
