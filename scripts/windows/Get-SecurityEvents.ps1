<#
.SYNOPSIS
    Query Windows Security Event Logs for triage and threat detection (EVA Sec compatible).
.DESCRIPTION
    Queries recent security event logs:
    - Event ID 4624: Successful Logon
    - Event ID 4625: Failed Logon
    - Event ID 4672: Special Privileges Assigned (Admin Logon)
    - Event ID 4688: Process Creation
    - Event ID 7045: New Service Installed (System log)
    Outputs structured findings compatible with `eva sec ingest`.
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEventsPerType = 50,
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'

$hostname = $env:COMPUTERNAME
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$startTime = (Get-Date).AddHours(-$Hours)
$findings = @()
$events = @()

# Helper to fetch events safely
function Get-EventsSafe {
    param([string]$LogName, [int]$Id, [int]$Limit = 50)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Id = $Id
            StartTime = $startTime
        } -MaxEvents $Limit -ErrorAction SilentlyContinue
    } catch {
        @()
    }
}

# 1. Failed Logons (4625)
$failedLogons = Get-EventsSafe -LogName "Security" -Id 4625 -Limit $MaxEventsPerType
$failedCountsByUser = @{}
foreach ($evt in $failedLogons) {
    $xml = [xml]$evt.ToXml()
    $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $status = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' }).'#text'
    
    $events += @{
        event_id = 4625
        type = "FailedLogon"
        time = $evt.TimeCreated.ToString("o")
        target_user = $targetUser
        source_ip = $ip
        status = $status
    }
    if ($targetUser) {
        if (-not $failedCountsByUser.ContainsKey($targetUser)) { $failedCountsByUser[$targetUser] = 0 }
        $failedCountsByUser[$targetUser]++
    }
}

# Flag potential brute force if multiple failed logons
foreach ($u in $failedCountsByUser.Keys) {
    if ($failedCountsByUser[$u] -ge 5) {
        $findings += @{
            id = "triage-win-logon-bruteforce-$u"
            tool = "triage-windows-events"
            rule_id = "identity.logon.brute_force_detected"
            title = "Potential brute-force logon attempts for user: $u ($($failedCountsByUser[$u]) failures)"
            severity = "high"
            confidence = "high"
            category = "credential_access"
            evidence = "$($failedCountsByUser[$u]) failed logons in last $Hours hours for account $u"
            remediation = "Inspect source IP addresses, review account lockout status, and enforce MFA."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("4625|$u|$($failedCountsByUser[$u])"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

# 2. Admin Privileges Assigned (4672)
$adminLogons = Get-EventsSafe -LogName "Security" -Id 4672 -Limit $MaxEventsPerType
foreach ($evt in $adminLogons) {
    $xml = [xml]$evt.ToXml()
    $subjectUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    $events += @{
        event_id = 4672
        type = "AdminLogon"
        time = $evt.TimeCreated.ToString("o")
        subject_user = $subjectUser
    }
}

# 3. New Service Installed (7045 in System log)
$newServices = Get-EventsSafe -LogName "System" -Id 7045 -Limit $MaxEventsPerType
foreach ($evt in $newServices) {
    $xml = [xml]$evt.ToXml()
    $svcName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
    $img = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
    $svcType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceType' }).'#text'
    
    $events += @{
        event_id = 7045
        type = "ServiceInstalled"
        time = $evt.TimeCreated.ToString("o")
        service_name = $svcName
        image_path = $img
    }

    # Inspect for suspicious service binary path
    if ($img -match '(?i)(powershell|cmd\.exe|wscript|mshta|AppData|Temp|Users\\Public)') {
        $findings += @{
            id = "triage-win-service-$svcName"
            tool = "triage-windows-events"
            rule_id = "persistence.service.suspicious_path"
            title = "Suspicious new service created: $svcName"
            severity = "high"
            confidence = "high"
            category = "persistence"
            evidence = "Service $svcName created at $($evt.TimeCreated.ToString('o')) with image: $img"
            remediation = "Stop service immediately, verify legitimacy of binary, and audit parent process."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("7045|$svcName|$img"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

# 4. Process Creation (4688)
$procEvents = Get-EventsSafe -LogName "Security" -Id 4688 -Limit $MaxEventsPerType
foreach ($evt in $procEvents) {
    $xml = [xml]$evt.ToXml()
    $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
    $parentProc = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ParentProcessName' }).'#text'
    $newProc = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'

    $events += @{
        event_id = 4688
        type = "ProcessCreation"
        time = $evt.TimeCreated.ToString("o")
        process_name = $newProc
        command_line = $cmd
        parent_process = $parentProc
    }

    if ($cmd -match '(?i)(vssadmin\s+delete|mimikatz|Invoke-Mimikatz|sekurlsa|wdigest|nltest\s+/dclist)') {
        $findings += @{
            id = "triage-win-proc-threat-$($evt.RecordId)"
            tool = "triage-windows-events"
            rule_id = "process.threat.suspicious_command"
            title = "High-risk command line detected: $cmd"
            severity = "critical"
            confidence = "high"
            category = "threat_detection"
            evidence = "Process: $newProc (Parent: $parentProc), CommandLine: $cmd"
            remediation = "Isolate host from network, collect volatile memory, and begin incident response."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("4688|$cmd"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows-events"
    collected_at = $now
    host = @{
        hostname = $hostname
    }
    time_window_hours = $Hours
    events_collected = $events.Count
    events = $events
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5

if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Security events saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
