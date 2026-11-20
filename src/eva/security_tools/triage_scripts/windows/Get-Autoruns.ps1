<#
.SYNOPSIS
    Windows Autoruns and Persistence Audit (EVA Sec compatible).
.DESCRIPTION
    Enumerates persistence locations beyond basic Run keys:
    - HKLM/HKCU Run, RunOnce and Wow6432Node variants
    - Winlogon Shell/Userinit, AppInit_DLLs and IFEO Debugger entries
    - Auto-start services with suspicious or unquoted binary paths
    - Non-Microsoft scheduled tasks and their actions
    - User and common Startup folders
    - WMI event consumers, BITS jobs, logon scripts and Netsh helpers
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-autoruns'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$items = @()
$registryItems = @()
$serviceItems = @()
$taskItems = @()
$wmiItems = @()
$bitsItems = @()

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
        [string]$Category = "persistence",
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

function Test-SuspiciousCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
    if ($Command -match '(?i)(\\ProgramData\\Microsoft\\Windows Defender\\|\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\|\\AppData\\Local\\Microsoft\\OneDrive\\)') { return $false }
    return ($Command -match '(?i)(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|\\Temp\\|\\tmp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle\.Bin\\|\\PerfLogs\\)')
}

function Test-TrustedBitsJob {
    param($Job)
    $files = @($Job.FileList)
    if ($files.Count -eq 0) { return $false }
    foreach ($f in $files) {
        try { $uri = [Uri][string]$f.RemoteName } catch { return $false }
        if ($uri.Host -notmatch '(?i)(^|\.)(microsoft\.com|windowsupdate\.com|windows\.com)$') { return $false }
    }
    return $true
}

function Add-PersistenceItem {
    param(
        [string]$Category,
        [string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Source = ""
    )
    $item = [ordered]@{
        category = $Category
        location = $Location
        name = $Name
        command = (Limit-Text $Command 1000)
        source = $Source
        suspicious = (Test-SuspiciousCommand $Command)
    }
    $script:items += $item
    return $item
}

# ------------------------------------------------------------------------------
# 1. Registry autoruns
# ------------------------------------------------------------------------------
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($keyPath in $runKeys) {
    if (-not (Test-Path -LiteralPath $keyPath)) { continue }
    $key = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    if ($null -eq $key) { continue }
    foreach ($prop in $key.PSObject.Properties) {
        if ($prop.Name -match '^PS') { continue }
        $value = [string]$prop.Value
        $registryItems += [ordered]@{
            type = "RunKey"
            location = $keyPath
            name = $prop.Name
            command = (Limit-Text $value 1000)
        }
        $item = Add-PersistenceItem -Category "RunKey" -Location $keyPath -Name $prop.Name -Command $value
        if ($item.suspicious) {
            $findings += New-Finding -Id "triage-win-autorun-$((Get-Sha256Hex "$keyPath|$($prop.Name)").Substring(0, 16))" `
                -RuleId "persistence.run_key.suspicious_command" `
                -Title "Suspicious Run key entry: $($prop.Name)" `
                -Severity "high" -Category "persistence" `
                -Evidence "Location: $keyPath Name: $($prop.Name) Command: $value" `
                -Remediation "Verify the command and signer; remove the value or restore it from a known-good baseline if unauthorized." `
                -File $keyPath
        }
    }
}

$winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$userinit = [string](Get-ItemProperty -Path $winlogonKey -Name Userinit -ErrorAction SilentlyContinue).Userinit
$shellValue = [string](Get-ItemProperty -Path $winlogonKey -Name Shell -ErrorAction SilentlyContinue).Shell
if ($userinit) {
    $registryItems += [ordered]@{ type = "Winlogon"; location = $winlogonKey; name = "Userinit"; command = $userinit }
    if ($userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') {
        $findings += New-Finding -Id "triage-win-autorun-userinit" -RuleId "persistence.winlogon.userinit_hijack" `
            -Title "Abnormal Winlogon Userinit value" -Severity "critical" -Category "persistence" `
            -Evidence "Userinit = $userinit" `
            -Remediation "Restore Userinit to C:\Windows\system32\userinit.exe, and investigate the added command." -File $winlogonKey
    }
}
if ($shellValue -and $shellValue -notmatch '(?i)^explorer\.exe$') {
    $registryItems += [ordered]@{ type = "Winlogon"; location = $winlogonKey; name = "Shell"; command = $shellValue }
    $findings += New-Finding -Id "triage-win-autorun-shell" -RuleId "persistence.winlogon.shell_hijack" `
        -Title "Abnormal Winlogon Shell value" -Severity "critical" -Category "persistence" `
        -Evidence "Shell = $shellValue" `
        -Remediation "Restore the Winlogon Shell value to explorer.exe and remove unauthorized startup software." -File $winlogonKey
}

$appInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
$appInit = [string](Get-ItemProperty -Path $appInitKey -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
$loadAppInit = (Get-ItemProperty -Path $appInitKey -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs
if ($appInit) {
    $registryItems += [ordered]@{ type = "AppInit"; location = $appInitKey; name = "AppInit_DLLs"; command = $appInit }
    $severity = "medium"
    if ($loadAppInit -eq 1) { $severity = "critical" }
    $findings += New-Finding -Id "triage-win-autorun-appinit" -RuleId "persistence.appinit.dll" `
        -Title "AppInit_DLLs injection configured" -Severity $severity -Category "persistence" `
        -Evidence "AppInit_DLLs = $appInit LoadAppInit_DLLs = $loadAppInit" `
        -Remediation "Remove unapproved AppInit DLLs and set LoadAppInit_DLLs to 0 unless a signed enterprise hook is required." -File $appInitKey
}

$ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path -LiteralPath $ifeoRoot) {
    foreach ($sub in (Get-ChildItem -Path $ifeoRoot -ErrorAction SilentlyContinue)) {
        $debugger = (Get-ItemProperty -Path $sub.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            $registryItems += [ordered]@{ type = "IFEO"; location = $sub.PSPath; name = "Debugger"; command = $debugger }
            $findings += New-Finding -Id "triage-win-autorun-ifeo-$((Get-Sha256Hex $sub.PSPath).Substring(0, 12))" `
                -RuleId "persistence.ifeo.debugger" `
                -Title "Image File Execution Options debugger hijack: $($sub.PSChildName)" `
                -Severity "critical" -Category "persistence" `
                -Evidence "Key: $($sub.PSPath) Debugger: $debugger" `
                -Remediation "Remove the Debugger value after verifying it is not a sanctioned debugging configuration." `
                -File $sub.PSPath
        }
    }
}

$netshKey = "HKLM:\SOFTWARE\Microsoft\NetSh"
if (Test-Path -LiteralPath $netshKey) {
    $netsh = Get-ItemProperty -Path $netshKey -ErrorAction SilentlyContinue
    foreach ($prop in $netsh.PSObject.Properties) {
        if ($prop.Name -match '^PS') { continue }
        $value = [string]$prop.Value
        $registryItems += [ordered]@{ type = "NetshHelper"; location = $netshKey; name = $prop.Name; command = $value }
        if (Test-SuspiciousCommand $value) {
            $findings += New-Finding -Id "triage-win-autorun-netsh-$((Get-Sha256Hex $prop.Name).Substring(0, 12))" `
                -RuleId "persistence.netsh.helper_dll" `
                -Title "Suspicious Netsh helper DLL registration: $($prop.Name)" `
                -Severity "high" -Category "persistence" `
                -Evidence "Netsh helper: $($prop.Name) = $value" `
                -Remediation "Remove unapproved Netsh helper DLLs and investigate their origin." -File $netshKey
        }
    }
}

# ------------------------------------------------------------------------------
# 2. Services and scheduled tasks
# ------------------------------------------------------------------------------
$serviceList = @(Get-CimInstance -ClassName Win32_Service)
foreach ($svc in $serviceList) {
    $path = [string]$svc.PathName
    if ($serviceItems.Count -lt 300) {
        $serviceItems += [ordered]@{
            name = [string]$svc.Name
            display_name = [string]$svc.DisplayName
            state = [string]$svc.State
            start_mode = [string]$svc.StartMode
            start_name = [string]$svc.StartName
            path = (Limit-Text $path 500)
        }
    }
    if (Test-SuspiciousCommand $path) {
        $findings += New-Finding -Id "triage-win-autorun-svc-$((Get-Sha256Hex $svc.Name).Substring(0, 12))" `
            -RuleId "service.binary.suspicious_path" `
            -Title "Service binary uses a suspicious path or interpreter: $($svc.Name)" `
            -Severity "high" -Category "persistence" `
            -Evidence "Service: $($svc.Name) PathName: $path" `
            -Remediation "Validate the service binary signature and owner; remove or reinstall the service if unauthorized." `
            -File $path
    }
    if ($svc.StartMode -eq "Auto" -and $path -notmatch '^\s*"' -and $path -match '^[^"]*\s+[^"]*\.exe(\s|$)') {
        $findings += New-Finding -Id "triage-win-autorun-svc-unquoted-$((Get-Sha256Hex $svc.Name).Substring(0, 12))" `
            -RuleId "service.path.unquoted" `
            -Title "Auto-start service has an unquoted path containing spaces: $($svc.Name)" `
            -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "Service: $($svc.Name) PathName: $path" `
            -Remediation "Quote the service binary path and review directory permissions." -File $path
    }
}

$tasks = @(Get-ScheduledTask)
foreach ($task in $tasks) {
    if ($task.TaskPath -match '^\\Microsoft\\') { continue }
    $actions = @($task.Actions)
    $commands = @()
    foreach ($action in $actions) {
        $execute = [string]$action.Execute
        $arguments = [string]$action.Arguments
        if ($execute) {
            $commands += (Limit-Text "$execute $arguments" 800)
            if (Test-SuspiciousCommand "$execute $arguments") {
                $findings += New-Finding -Id "triage-win-autorun-task-$((Get-Sha256Hex "$($task.TaskPath)$($task.TaskName)").Substring(0, 12))" `
                    -RuleId "persistence.scheduled_task.suspicious_action" `
                    -Title "Scheduled task action uses a suspicious command: $($task.TaskName)" `
                    -Severity "high" -Category "persistence" `
                    -Evidence "Task: $($task.TaskPath)$($task.TaskName) Action: $execute $arguments" `
                    -Remediation "Verify the task creator and action; disable or remove unauthorized scheduled tasks." `
                    -File "$($task.TaskPath)$($task.TaskName)"
            }
        }
    }
    if ($taskItems.Count -lt 300) {
        $taskItems += [ordered]@{
            path = [string]$task.TaskPath
            name = [string]$task.TaskName
            state = [string]$task.State
            author = [string]$task.Author
            actions = @($commands)
        }
    }
}

# ------------------------------------------------------------------------------
# 3. Startup folders
# ------------------------------------------------------------------------------
$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    if (-not (Test-Path -LiteralPath $folder)) { continue }
    foreach ($file in (Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue)) {
        $item = Add-PersistenceItem -Category "StartupFolder" -Location $folder -Name $file.Name -Command $file.FullName -Source $file.FullName
        if ($file.Extension -match '(?i)\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|hta|lnk)$') {
            $findings += New-Finding -Id "triage-win-autorun-startup-$((Get-Sha256Hex $file.FullName).Substring(0, 12))" `
                -RuleId "persistence.startup_folder.executable" `
                -Title "Executable or script in Startup folder: $($file.Name)" `
                -Severity "high" -Category "persistence" `
                -Evidence "File: $($file.FullName) Modified: $($file.LastWriteTime.ToString('o'))" `
                -Remediation "Verify the file origin and remove unauthorized startup items." `
                -File $file.FullName
        }
    }
}

# ------------------------------------------------------------------------------
# 4. WMI subscriptions
# ------------------------------------------------------------------------------
$wmiFilters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
$wmiConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
$wmiBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
foreach ($filter in $wmiFilters) {
    $wmiItems += [ordered]@{ type = "EventFilter"; name = [string]$filter.Name; query = (Limit-Text ([string]$filter.Query) 800) }
}
foreach ($consumer in $wmiConsumers) {
    $wmiItems += [ordered]@{
        type = [string]$consumer.CimClass.CimClassName
        name = [string]$consumer.Name
        command = (Limit-Text ([string]$consumer.CommandLineTemplate) 800)
        script = (Limit-Text ([string]$consumer.ScriptText) 400)
    }
    if ([string]$consumer.Name -eq "SCM Event Log Consumer") { continue }
    $findings += New-Finding -Id "triage-win-autorun-wmi-$((Get-Sha256Hex $consumer.Name).Substring(0, 12))" `
        -RuleId "persistence.wmi.event_consumer" `
        -Title "WMI event consumer persistence: $($consumer.Name)" `
        -Severity "high" -Category "persistence" `
        -Evidence "Type: $($consumer.CimClass.CimClassName) Name: $($consumer.Name)" `
        -Remediation "Review WMI filter/consumer bindings and remove unauthorized subscriptions." `
        -File "root\subscription"
}
foreach ($binding in $wmiBindings) {
    $wmiItems += [ordered]@{ type = "Binding"; name = [string]$binding.Name; filter = [string]$binding.Filter; consumer = [string]$binding.Consumer }
}

# ------------------------------------------------------------------------------
# 5. BITS jobs and logon scripts
# ------------------------------------------------------------------------------
if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
    foreach ($job in @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue)) {
        $files = @()
        foreach ($f in @($job.FileList)) {
            $files += "$($f.RemoteName) -> $($f.LocalName)"
        }
        $bitsItems += [ordered]@{
            display_name = [string]$job.DisplayName
            state = [string]$job.JobState
            owner = [string]$job.OwnerAccount
            files = @($files)
        }
        if (Test-TrustedBitsJob $job) { continue }
        $findings += New-Finding -Id "triage-win-autorun-bits-$((Get-Sha256Hex $job.JobId.ToString()).Substring(0, 12))" `
            -RuleId "persistence.bits.job" `
            -Title "Active BITS transfer job: $($job.DisplayName)" `
            -Severity "high" -Category "persistence" `
            -Evidence "State: $($job.JobState) Owner: $($job.OwnerAccount) Files: $($files -join '; ')" `
            -Remediation "Inspect the BITS job source and destination; cancel unauthorized transfers and remove the job." `
            -File "BITS"
    }
}

$logonScripts = @(
    "HKCU:\Environment",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon"
)
foreach ($keyPath in $logonScripts) {
    if (-not (Test-Path -LiteralPath $keyPath)) { continue }
    $key = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    foreach ($prop in $key.PSObject.Properties) {
        if ($prop.Name -match '^PS') { continue }
        $value = [string]$prop.Value
        if ($prop.Name -match '(?i)logon|script' -or (Test-SuspiciousCommand $value)) {
            $registryItems += [ordered]@{ type = "LogonScript"; location = $keyPath; name = $prop.Name; command = $value }
            if ($prop.Name -eq "UserInitMprLogonScript") {
                $findings += New-Finding -Id "triage-win-autorun-logon-script" `
                    -RuleId "persistence.logon_script.user_init_mpr" `
                    -Title "UserInitMprLogonScript logon script configured" `
                    -Severity "high" -Category "persistence" `
                    -Evidence "Location: $keyPath Value: $value" `
                    -Remediation "Remove the logon script unless explicitly required and approved." -File $keyPath
            }
        }
    }
}

$gpoScriptFiles = @(
    "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts\scripts.ini",
    "$env:SystemRoot\System32\GroupPolicy\User\Scripts\scripts.ini"
)
foreach ($scriptFile in $gpoScriptFiles) {
    if (Test-Path -LiteralPath $scriptFile) {
        $registryItems += [ordered]@{ type = "GPOScript"; location = $scriptFile; name = (Split-Path $scriptFile -Leaf); command = "present" }
    }
}

# ------------------------------------------------------------------------------
# 6. Report assembly
# ------------------------------------------------------------------------------
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    metrics = [ordered]@{
        persistence_items = $items.Count
        run_key_entries = $registryItems.Count
        services = $serviceItems.Count
        scheduled_tasks = $taskItems.Count
        wmi_items = $wmiItems.Count
        bits_jobs = $bitsItems.Count
    }
    persistence_items = @($items)
    registry_autoruns = @($registryItems)
    services = @($serviceItems)
    scheduled_tasks = @($taskItems)
    wmi_subscriptions = @($wmiItems)
    bits_jobs = @($bitsItems)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Autoruns report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
