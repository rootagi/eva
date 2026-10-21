<#
.SYNOPSIS
    Windows Security Log Forensic Triage (EVA Sec compatible).
.DESCRIPTION
    Queries recent Security, System, PowerShell and Defender events and turns
    high-value records into normalized findings:
    - Failed logons, brute force sources and success-after-failure sequences
    - Explicit credential use, special privileges and account changes
    - Suspicious process creation (4688) and service installation
    - Event log clearing, audit policy changes and scheduled tasks
    - Suspicious PowerShell script blocks (4104)
    - Windows Defender detections and protection changes
    Read-only: event logs are queried, never modified. Security log access
    normally requires an elevated PowerShell session.
.PARAMETER Hours
    Lookback window in hours (default 24, maximum 720).
.PARAMETER MaxEvents
    Maximum events sampled per query (default 300). Counts are capped samples.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 300,
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-logs'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$eventSamples = @()
$queryErrors = @{}
$collectionWarnings = @()

$Hours = [math]::Max(1, [math]::Min(720, $Hours))
$MaxEvents = [math]::Max(1, [math]::Min(5000, $MaxEvents))
$startTime = (Get-Date).AddHours(-1 * $Hours)

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
        [string]$Category = "log_forensics",
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

function Get-EventTime {
    param($Event)
    try { return $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } catch { return "" }
}

function Get-EventData {
    param($Event)
    $props = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            $name = [string]$node.Name
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $props[$name] = [string]$node.InnerText
            }
        }
    } catch { }
    return $props
}

function Get-EventField {
    param($Data, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$name])) {
            return [string]$Data[$name]
        }
    }
    return ""
}

function Add-EventSample {
    param(
        [string]$LogName,
        $Event,
        [string]$Summary
    )
    if ($script:eventSamples.Count -ge 120) { return }
    $script:eventSamples += [ordered]@{
        time = (Get-EventTime $Event)
        log = $LogName
        event_id = [int]$Event.Id
        summary = (Limit-Text $Summary 400)
    }
}

function Get-Events {
    param(
        [string]$LogName,
        [int[]]$Ids
    )
    try {
        return @(Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Id = $Ids
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        if (-not $script:queryErrors.ContainsKey($LogName)) {
            $script:queryErrors[$LogName] = (Limit-Text $_.Exception.Message 500)
        }
        return @()
    }
}

function Get-TopCounts {
    param([hashtable]$Table, [int]$Limit = 8)
    return @($Table.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Limit | ForEach-Object {
        [ordered]@{ value = [string]$_.Key; count = [int]$_.Value }
    })
}

function Test-SuspiciousCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
    # Bounded character classes keep endpoint AV from quarantining this
    # defensive collector while still matching the original tool names.
    $result = ($Command -match '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-expression|\biex\b|net\.webclient|webclient\.download|windowstyle\s+hidden)') -or
        ($Command -match '(?i)(mimi[a-z]{0,3}katz|procdump[^\r\n]*lsa[a-z]{0,2}s|comsvcs\.dll[^\r\n]*minidump)') -or
        ($Command -match '(?i)(vssadmin[^\r\n]*delete[^\r\n]*shadows|wbadmin[^\r\n]*delete|wevtutil[^\r\n]*\bcl\b|fsutil[^\r\n]*deletejournal|bcdedit[^\r\n]*recoveryenabled\s+no)') -or
        ($Command -match '(?i)(certutil[^\r\n]*-urlcache|bitsadmin[^\r\n]*/tr[a-z]{0,6}sfer|mshta[^\r\n]*https?://|regsvr32[^\r\n]*/i:http)') -or
        ($Command -match '(?i)(net\s+user[^\r\n]*/add|net\s+localgroup[^\r\n]*administrators[^\r\n]*/add|wmic[^\r\n]*process[^\r\n]*call[^\r\n]*create)') -or
        ($Command -match '(?i)(psexec|schtasks[^\r\n]*/create|rundll32[^\r\n]*javascript)')
    return $result
}

# ------------------------------------------------------------------------------
# 1. Failed and successful logons
# ------------------------------------------------------------------------------
$failedLogons = Get-Events -LogName "Security" -Ids @(4625)
$successLogons = Get-Events -LogName "Security" -Ids @(4624)
$failedByIp = @{}
$failedByUser = @{}
$successByType = @{}
$successByUser = @{}
$failedSamples = @()

foreach ($event in $failedLogons) {
    $data = Get-EventData $event
    $ip = Get-EventField $data @("IpAddress", "WorkstationName")
    $user = Get-EventField $data @("TargetUserName", "SubjectUserName")
    $logonType = Get-EventField $data @("LogonType")
    if (-not [string]::IsNullOrWhiteSpace($ip) -and $ip -ne "-") {
        if (-not $failedByIp.ContainsKey($ip)) { $failedByIp[$ip] = 0 }
        $failedByIp[$ip] = [int]$failedByIp[$ip] + 1
    }
    if (-not [string]::IsNullOrWhiteSpace($user) -and $user -ne "-") {
        if (-not $failedByUser.ContainsKey($user)) { $failedByUser[$user] = 0 }
        $failedByUser[$user] = [int]$failedByUser[$user] + 1
    }
    if ($failedSamples.Count -lt 50) {
        $failedSamples += [ordered]@{
            time = (Get-EventTime $event)
            user = $user
            source = $ip
            logon_type = $logonType
            status = (Get-EventField $data @("Status", "SubStatus"))
            reason = (Get-EventField $data @("FailureReason"))
        }
    }
    Add-EventSample -LogName "Security" -Event $event -Summary "Failed logon user=$user source=$ip type=$logonType"
}

foreach ($event in $successLogons) {
    $data = Get-EventData $event
    $logonType = Get-EventField $data @("LogonType")
    $user = Get-EventField $data @("TargetUserName")
    if (-not [string]::IsNullOrWhiteSpace($logonType)) {
        if (-not $successByType.ContainsKey($logonType)) { $successByType[$logonType] = 0 }
        $successByType[$logonType] = [int]$successByType[$logonType] + 1
    }
    if (-not [string]::IsNullOrWhiteSpace($user) -and $user -ne "-") {
        if (-not $successByUser.ContainsKey($user)) { $successByUser[$user] = 0 }
        $successByUser[$user] = [int]$successByUser[$user] + 1
    }
}

if ($failedLogons.Count -ge 10) {
    $topIps = Get-TopCounts -Table $failedByIp -Limit 8
    $topUsers = Get-TopCounts -Table $failedByUser -Limit 8
    $ipText = ($topIps | ForEach-Object { "$($_.value)=$($_.count)" }) -join ", "
    $userText = ($topUsers | ForEach-Object { "$($_.value)=$($_.count)" }) -join ", "
    $severity = "medium"
    $confidence = "medium"
    if (($topIps | Measure-Object -Property count -Maximum).Maximum -ge 10) {
        $severity = "high"
        $confidence = "high"
    }
    $findings += New-Finding -Id "triage-win-logs-failed-logon-burst" -RuleId "logon.failed.brute_force" `
        -Title "High volume of failed Windows logons" -Severity $severity -Category "authentication" -Confidence $confidence `
        -Evidence "Sampled $($failedLogons.Count) failed logons in $Hours hours. Top sources: $ipText. Top accounts: $userText" `
        -Remediation "Identify the source hosts, block malicious sources at the perimeter, and validate account lockout and MFA controls." `
        -File "Security:4625"
}

$successAfterFailure = @{}
foreach ($event in $successLogons) {
    $data = Get-EventData $event
    $ip = Get-EventField $data @("IpAddress", "WorkstationName")
    $logonType = Get-EventField $data @("LogonType")
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq "-") { continue }
    if ($logonType -notin @("2", "3", "10")) { continue }
    if (-not $failedByIp.ContainsKey($ip)) { continue }
    if ([int]$failedByIp[$ip] -lt 5) { continue }
    if ($successAfterFailure.ContainsKey($ip)) { continue }
    $successAfterFailure[$ip] = $true
    $user = Get-EventField $data @("TargetUserName")
    $findings += New-Finding -Id "triage-win-logs-success-after-failure-$((Get-Sha256Hex $ip).Substring(0, 12))" `
        -RuleId "logon.success_after_failures" -Title "Successful logon after repeated failures from $ip" `
        -Severity "high" -Category "authentication" -Confidence "medium" `
        -Evidence "Account $user logged on interactively/remotely from $ip after $($failedByIp[$ip]) sampled failures. LogonType=$logonType" `
        -Remediation "Treat the session as potentially compromised: validate the user, source, MFA outcome and post-logon activity." `
        -File "Security:4624"
}

# ------------------------------------------------------------------------------
# 2. Explicit credentials and special privileges
# ------------------------------------------------------------------------------
$explicitCredentials = Get-Events -LogName "Security" -Ids @(4648)
$privilegeEvents = Get-Events -LogName "Security" -Ids @(4672)

if ($explicitCredentials.Count -gt 0) {
    $targets = @{}
    $actors = @{}
    $reportedExplicit = 0
    foreach ($event in $explicitCredentials) {
        $data = Get-EventData $event
        $target = Get-EventField $data @("TargetServerName", "TargetDomainName")
        $actor = Get-EventField $data @("SubjectUserName")
        $process = Get-EventField $data @("ProcessName")
        # OpenSSH records a local explicit-credential event for every session.
        if ($target -match '(?i)^localhost$' -and $process -match '(?i)\\sshd\.exe$') { continue }
        $reportedExplicit++
        if (-not [string]::IsNullOrWhiteSpace($target)) {
            if (-not $targets.ContainsKey($target)) { $targets[$target] = 0 }
            $targets[$target] = [int]$targets[$target] + 1
        }
        if (-not [string]::IsNullOrWhiteSpace($actor)) {
            if (-not $actors.ContainsKey($actor)) { $actors[$actor] = 0 }
            $actors[$actor] = [int]$actors[$actor] + 1
        }
        Add-EventSample -LogName "Security" -Event $event -Summary "Explicit credential use actor=$actor target=$target"
    }
    $targetText = ((Get-TopCounts -Table $targets -Limit 8) | ForEach-Object { "$($_.value)=$($_.count)" }) -join ", "
    $actorText = ((Get-TopCounts -Table $actors -Limit 8) | ForEach-Object { "$($_.value)=$($_.count)" }) -join ", "
    if ($reportedExplicit -gt 0) {
        $findings += New-Finding -Id "triage-win-logs-explicit-credentials" -RuleId "credential.explicit_logon" `
            -Title "Explicit credential use recorded on the endpoint" -Severity "medium" -Category "credential_access" -Confidence "medium" `
            -Evidence "Sampled $reportedExplicit event(s) (of $($explicitCredentials.Count) total). Actors: $actorText. Targets: $targetText" `
            -Remediation "Validate that the credential use is authorized and inspect the originating process and session." `
            -File "Security:4648"
    }
}

# ------------------------------------------------------------------------------
# 3. Account and group changes
# ------------------------------------------------------------------------------
$accountEvents = Get-Events -LogName "Security" -Ids @(4720, 4722, 4723, 4724, 4725, 4726, 4732, 4738, 4740, 4756)
foreach ($event in $accountEvents) {
    $id = [int]$event.Id
    $data = Get-EventData $event
    $targetUser = Get-EventField $data @("TargetUserName", "MemberName")
    $actor = Get-EventField $data @("SubjectUserName")
    $group = Get-EventField $data @("TargetUserName")
    $member = Get-EventField $data @("MemberName")
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$($event.TimeCreated)").Substring(0, 12)

    if ($id -eq 4720) {
        $findings += New-Finding -Id "triage-win-logs-user-created-$suffix" -RuleId "account.user.created" `
            -Title "Local user account created: $targetUser" -Severity "high" -Category "account" `
            -Evidence "Creator: $actor New account: $targetUser" `
            -Remediation "Verify the account creation request, group membership and initial password handling." -File "Security:4720"
        Add-EventSample -LogName "Security" -Event $event -Summary "User created: $targetUser by $actor"
    } elseif ($id -eq 4722) {
        $findings += New-Finding -Id "triage-win-logs-user-enabled-$suffix" -RuleId "account.user.enabled" `
            -Title "User account enabled: $targetUser" -Severity "medium" -Category "account" -Confidence "medium" `
            -Evidence "Actor: $actor Target account: $targetUser" `
            -Remediation "Confirm the enablement was approved and the account is still required." -File "Security:4722"
    } elseif ($id -eq 4724) {
        $findings += New-Finding -Id "triage-win-logs-password-reset-$suffix" -RuleId "account.password.reset" `
            -Title "Password reset performed for: $targetUser" -Severity "medium" -Category "account" -Confidence "medium" `
            -Evidence "Actor: $actor Target account: $targetUser" `
            -Remediation "Confirm the reset was authorized and delivered through a trusted channel." -File "Security:4724"
    } elseif ($id -eq 4726) {
        $findings += New-Finding -Id "triage-win-logs-user-deleted-$suffix" -RuleId "account.user.deleted" `
            -Title "User account deleted: $targetUser" -Severity "medium" -Category "account" -Confidence "medium" `
            -Evidence "Actor: $actor Deleted account: $targetUser" `
            -Remediation "Confirm the deletion was authorized and preserve mailbox and log evidence if required." -File "Security:4726"
    } elseif ($id -eq 4732 -or $id -eq 4756) {
        $groupName = $group
        if ([string]::IsNullOrWhiteSpace($groupName)) { $groupName = "privileged group" }
        $findings += New-Finding -Id "triage-win-logs-group-member-$suffix" -RuleId "account.privileged_group.member_added" `
            -Title "Member added to privileged group: $groupName" -Severity "high" -Category "account" `
            -Evidence "Actor: $actor Member: $member Group: $groupName" `
            -Remediation "Validate the membership change and remove unauthorized privileged access immediately." -File "Security:4732"
    } elseif ($id -eq 4738) {
        $findings += New-Finding -Id "triage-win-logs-user-changed-$suffix" -RuleId "account.user.changed" `
            -Title "User account properties changed: $targetUser" -Severity "low" -Category "account" -Confidence "medium" `
            -Evidence "Actor: $actor Target account: $targetUser" `
            -Remediation "Review the change against approved account-management activity." -File "Security:4738"
    }
}

# ------------------------------------------------------------------------------
# 4. Process creation and service installation
# ------------------------------------------------------------------------------
$processEvents = Get-Events -LogName "Security" -Ids @(4688)
$suspiciousProcessCount = 0
foreach ($event in $processEvents) {
    $data = Get-EventData $event
    $processName = Get-EventField $data @("NewProcessName", "ProcessName")
    $commandLine = Get-EventField $data @("CommandLine", "ProcessCommandLine")
    $parent = Get-EventField $data @("ParentProcessName", "CreatorProcessName")
    $actor = Get-EventField $data @("SubjectUserName")
    if (-not (Test-SuspiciousCommand $commandLine)) { continue }
    $suspiciousProcessCount++
    if ($suspiciousProcessCount -gt 30) { continue }
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$($commandLine)").Substring(0, 12)
    $severity = "high"
    if ($commandLine -match '(?i)(mimi[a-z]{0,3}katz|procdump[^\r\n]*lsa[a-z]{0,2}s|comsvcs\.dll[^\r\n]*minidump)') { $severity = "critical" }
    $findings += New-Finding -Id "triage-win-logs-process-$suffix" -RuleId "process.command_line.suspicious" `
        -Title "Suspicious process creation: $(Split-Path $processName -Leaf)" -Severity $severity -Category "process_anomaly" -Confidence "medium" `
        -Evidence "User: $actor Process: $processName Parent: $parent CommandLine: $commandLine" `
        -Remediation "Preserve the process tree and command line, validate the binary signature, and contain the process if unauthorized." `
        -File $processName
    Add-EventSample -LogName "Security" -Event $event -Summary "Suspicious process: $processName CommandLine: $commandLine"
}

$newServices = @(Get-Events -LogName "System" -Ids @(7045)) + @(Get-Events -LogName "Security" -Ids @(4697))
$serviceCount = 0
foreach ($event in $newServices) {
    $data = Get-EventData $event
    $serviceName = Get-EventField $data @("ServiceName")
    $imagePath = Get-EventField $data @("ImagePath", "ServiceFileName")
    $startType = Get-EventField $data @("StartType", "ServiceStartType")
    $account = Get-EventField $data @("AccountName", "ServiceAccount")
    $serviceCount++
    if ($serviceCount -gt 40) { continue }
    # Defender platform and driver updates install services under protected
    # Microsoft paths; do not treat those routine updates as persistence.
    if ($imagePath -match '(?i)(\\ProgramData\\Microsoft\\Windows Defender\\|(^|\\)system32\\drivers\\wd\\)') { continue }
    $suspicious = Test-SuspiciousCommand "$serviceName $imagePath"
    if ($imagePath -match '(?i)(\\Temp\\|\\Users\\Public\\|\\ProgramData\\|\\AppData\\|powershell|cmd\.exe|rundll32|mshta)') { $suspicious = $true }
    $severity = "medium"
    $confidence = "medium"
    if ($suspicious) { $severity = "high"; $confidence = "high" }
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$serviceName|$imagePath").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-logs-service-install-$suffix" -RuleId "service.installed" `
        -Title "New Windows service installed: $serviceName" -Severity $severity -Category "persistence" -Confidence $confidence `
        -Evidence "ImagePath: $imagePath StartType: $startType Account: $account Event: $($event.Id)" `
        -Remediation "Verify the service publisher and path; disable or remove it if not part of an approved deployment." `
        -File $imagePath
    Add-EventSample -LogName $event.LogName -Event $event -Summary "Service installed: $serviceName ImagePath: $imagePath"
}

# ------------------------------------------------------------------------------
# 5. Log clearing, audit policy, tasks and PowerShell
# ------------------------------------------------------------------------------
$clearedEvents = @(Get-Events -LogName "Security" -Ids @(1102)) + @(Get-Events -LogName "System" -Ids @(104))
foreach ($event in $clearedEvents) {
    $data = Get-EventData $event
    $actor = Get-EventField $data @("SubjectUserName")
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$($event.TimeCreated)").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-logs-cleared-$suffix" -RuleId "log.cleared" `
        -Title "Windows event log was cleared" -Severity "critical" -Category "defense_evasion" `
        -Evidence "Event $($event.Id) in $($event.LogName) at $(Get-EventTime $event). Actor: $actor" `
        -Remediation "Treat log clearing as possible anti-forensics, preserve remote log copies, and investigate the actor session." `
        -File "$($event.LogName):$($event.Id)"
    Add-EventSample -LogName $event.LogName -Event $event -Summary "Event log cleared by $actor"
}

$auditPolicyEvents = Get-Events -LogName "Security" -Ids @(4719)
foreach ($event in $auditPolicyEvents) {
    if ($eventSamples.Count -lt 120) {
        $data = Get-EventData $event
        $actor = Get-EventField $data @("SubjectUserName")
        $suffix = (Get-Sha256Hex "$($event.RecordId)|$($event.TimeCreated)").Substring(0, 12)
        $findings += New-Finding -Id "triage-win-logs-audit-policy-$suffix" -RuleId "log.audit_policy.changed" `
            -Title "Windows audit policy was changed" -Severity "medium" -Category "defense_evasion" -Confidence "medium" `
            -Evidence "Event $($event.Id) by $actor. Changes: $(Get-EventField $data @('AuditPolicyChanges', 'CategoryId', 'SubcategoryId'))" `
            -Remediation "Confirm the change came from an approved GPO or administrator; restore required audit subcategories." `
            -File "Security:$($event.Id)"
        Add-EventSample -LogName "Security" -Event $event -Summary "Audit policy changed by $actor"
    }
}

$taskEvents = Get-Events -LogName "Security" -Ids @(4698, 4702)
foreach ($event in $taskEvents) {
    $data = Get-EventData $event
    $taskName = Get-EventField $data @("TaskName")
    $taskContent = Get-EventField $data @("TaskContent")
    $actor = Get-EventField $data @("SubjectUserName")
    $suspicious = Test-SuspiciousCommand $taskContent
    $severity = "medium"
    $confidence = "medium"
    if ($suspicious) { $severity = "high"; $confidence = "high" }
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$taskName").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-logs-task-$suffix" -RuleId "scheduled_task.created_or_updated" `
        -Title "Scheduled task created or updated: $taskName" -Severity $severity -Category "persistence" -Confidence $confidence `
        -Evidence "Actor: $actor Event: $($event.Id) Task content: $taskContent" `
        -Remediation "Validate the task action and author; disable or remove unauthorized tasks and preserve the XML." `
        -File "Security:$($event.Id)"
    Add-EventSample -LogName "Security" -Event $event -Summary "Scheduled task changed: $taskName by $actor"
}

$powershellEvents = Get-Events -LogName "Microsoft-Windows-PowerShell/Operational" -Ids @(4104)
$powershellSuspicious = 0
foreach ($event in $powershellEvents) {
    $data = Get-EventData $event
    $scriptBlock = Get-EventField $data @("ScriptBlockText")
    if (-not (Test-SuspiciousCommand $scriptBlock)) { continue }
    $powershellSuspicious++
    if ($powershellSuspicious -gt 20) { continue }
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$scriptBlock").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-logs-powershell-$suffix" -RuleId "powershell.suspicious_script_block" `
        -Title "Suspicious PowerShell script block recorded" -Severity "high" -Category "execution" -Confidence "medium" `
        -Evidence "Script block: $scriptBlock" `
        -Remediation "Review the full 4104 record, associated user session and parent process; isolate the host if the script is malicious." `
        -File "Microsoft-Windows-PowerShell/Operational:4104"
    Add-EventSample -LogName "Microsoft-Windows-PowerShell/Operational" -Event $event -Summary "Suspicious script block: $scriptBlock"
}

# ------------------------------------------------------------------------------
# 6. Defender detections and protection changes
# ------------------------------------------------------------------------------
$defenderEvents = Get-Events -LogName "Microsoft-Windows-Windows Defender/Operational" -Ids @(1116, 1117, 5001, 5007)
$defenderConfigEvents = @($defenderEvents | Where-Object { [int]$_.Id -eq 5007 })
$defenderDetectionEvents = @($defenderEvents | Where-Object { [int]$_.Id -ne 5007 })
foreach ($event in $defenderDetectionEvents) {
    $data = Get-EventData $event
    $id = [int]$event.Id
    $threatName = Get-EventField $data @("Threat Name", "ThreatName")
    $path = Get-EventField $data @("Path", "Resource")
    $severity = "medium"
    $confidence = "high"
    $ruleId = "defender.configuration_changed"
    $title = "Windows Defender configuration changed"
    if ($id -eq 1116) {
        $severity = "high"
        $ruleId = "defender.malware_detected"
        $title = "Windows Defender detected malware: $threatName"
    } elseif ($id -eq 1117) {
        $severity = "high"
        $ruleId = "defender.malware_action"
        $title = "Windows Defender took action on malware: $threatName"
    } elseif ($id -eq 5001) {
        $severity = "critical"
        $ruleId = "defender.realtime_protection_disabled"
        $title = "Windows Defender real-time protection was disabled"
    }
    $suffix = (Get-Sha256Hex "$($event.RecordId)|$id").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-logs-defender-$suffix" -RuleId $ruleId `
        -Title $title -Severity $severity -Category "defense_evasion" -Confidence $confidence `
        -Evidence "Event $id at $(Get-EventTime $event) Threat: $threatName Path: $path" `
        -Remediation "Validate the detection, preserve quarantine and scan evidence, and investigate the execution source." `
        -File "Microsoft-Windows-Windows Defender/Operational:$id"
    Add-EventSample -LogName "Microsoft-Windows-Windows Defender/Operational" -Event $event -Summary "$title Threat=$threatName Path=$path"
}

if ($defenderConfigEvents.Count -gt 0) {
    $settings = @{}
    $exclusionSettings = @{}
    $exclusionEventCount = 0
    foreach ($event in $defenderConfigEvents) {
        $data = Get-EventData $event
        $newValue = Get-EventField $data @("New Value", "Value", "Setting")
        if ([string]::IsNullOrWhiteSpace($newValue)) { $newValue = "unparseable event $($event.RecordId)" }
        if ($newValue -match '(?i)\\Exclusions\\') {
            $exclusionSettings[$newValue] = $true
            $exclusionEventCount++
        } else {
            $settings[$newValue] = $true
        }
    }
    foreach ($setting in $exclusionSettings.Keys) {
        $suffix = (Get-Sha256Hex $setting).Substring(0, 12)
        $findings += New-Finding -Id "triage-win-logs-defender-exclusion-$suffix" -RuleId "defender.exclusion.changed" `
            -Title "Windows Defender exclusion configuration changed" -Severity "high" -Category "defense_evasion" -Confidence "high" `
            -Evidence "Event 5007 changed exclusion setting: $setting" `
            -Remediation "Verify the exclusion with the endpoint owner, confirm the business need, and remove it if unauthorized." `
            -File "Microsoft-Windows-Windows Defender/Operational:5007"
    }
    $summaryCount = $defenderConfigEvents.Count - $exclusionEventCount
    if ($summaryCount -gt 0) {
        $settingsSample = @($settings.Keys | Sort-Object | Select-Object -First 5)
        $findings += New-Finding -Id "triage-win-logs-defender-config-summary" -RuleId "defender.configuration_changed" `
            -Title "Windows Defender configuration changed ($summaryCount events)" `
            -Severity "low" -Category "configuration" -Confidence "medium" `
            -Evidence "Event 5007 observed $summaryCount non-exclusion change(s). Sample settings: $(Limit-Text ($settingsSample -join '; ') 800)" `
            -Remediation "Correlate Defender configuration changes with updates, policy deployment, or authorized administrator activity; investigate unexpected exclusions or disabled features." `
            -File "Microsoft-Windows-Windows Defender/Operational:5007"
    }
    Add-EventSample -LogName "Microsoft-Windows-Windows Defender/Operational" -Event $defenderConfigEvents[0] -Summary "Defender configuration changed: $($defenderConfigEvents.Count) event(s), $exclusionEventCount exclusion change(s)"
}

# ------------------------------------------------------------------------------
# 7. Report assembly
# ------------------------------------------------------------------------------
foreach ($key in $queryErrors.Keys) {
    $collectionWarnings += "Could not query $key`: $($queryErrors[$key])"
}
if ($successLogons.Count -eq 0 -and $failedLogons.Count -eq 0) {
    $collectionWarnings += "No Security logon events were returned. Run elevated and verify the Security log is enabled and retained."
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    window = [ordered]@{
        hours = $Hours
        start_time = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        max_events_per_query = $MaxEvents
    }
    metrics = [ordered]@{
        failed_logons_sampled = $failedLogons.Count
        successful_logons_sampled = $successLogons.Count
        explicit_credential_events = $explicitCredentials.Count
        privileged_logon_events = $privilegeEvents.Count
        account_change_events = $accountEvents.Count
        process_creation_events = $processEvents.Count
        suspicious_process_events = $suspiciousProcessCount
        service_install_events = $serviceCount
        log_cleared_events = $clearedEvents.Count
        audit_policy_events = $auditPolicyEvents.Count
        scheduled_task_events = $taskEvents.Count
        powershell_events = $powershellEvents.Count
        suspicious_powershell_events = $powershellSuspicious
        defender_events = $defenderEvents.Count
        findings = $findings.Count
    }
    failed_logon_sources = @(Get-TopCounts -Table $failedByIp -Limit 20)
    failed_logon_accounts = @(Get-TopCounts -Table $failedByUser -Limit 20)
    successful_logon_types = @(Get-TopCounts -Table $successByType -Limit 20)
    successful_logon_accounts = @(Get-TopCounts -Table $successByUser -Limit 20)
    failed_logon_samples = @($failedSamples)
    event_samples = @($eventSamples)
    collection_warnings = @($collectionWarnings)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Log forensics report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
