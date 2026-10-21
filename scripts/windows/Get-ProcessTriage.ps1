<#
.SYNOPSIS
    Windows Process Lineage and Execution Triage (EVA Sec compatible).
.DESCRIPTION
    Focused process analysis for intrusion investigation:
    - Parent/child process anomalies (Office, browser, IIS and service parents)
    - Suspicious command lines (encoded PowerShell, LOLBins, credential dumping)
    - Executables running from user-writable or temporary directories
    - Signature and SHA-256 enrichment for suspicious processes
    - LSASS protection and WDigest credential exposure checks
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-processes'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$results = @()
$chains = @()

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
        [string]$Category = "process_anomaly",
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

$processes = @(Get-CimInstance -ClassName Win32_Process)
$processMap = @{}
foreach ($p in $processes) {
    $processMap[[int]$p.ProcessId] = $p
}

$officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe', 'acrord32.exe', 'foxitreader.exe')
$browserParents = @('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'brave.exe', 'opera.exe')
$webParents = @('w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat.exe', 'java.exe')
$shellChildren = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'wmic.exe', 'schtasks.exe', 'net.exe', 'net1.exe', 'whoami.exe', 'nltest.exe', 'arp.exe', 'nslookup.exe', 'reg.exe', 'sc.exe')

$suspiciousCount = 0
foreach ($p in ($processes | Sort-Object ProcessId)) {
    $name = [string]$p.Name
    $nameLower = $name.ToLowerInvariant()
    $exe = [string]$p.ExecutablePath
    $cmd = [string]$p.CommandLine
    $parentPid = [int]$p.ParentProcessId
    $parent = $processMap[$parentPid]
    $parentName = ""
    $parentPath = ""
    if ($null -ne $parent) {
        $parentName = [string]$parent.Name
        $parentPath = [string]$parent.ExecutablePath
    }
    $parentLower = $parentName.ToLowerInvariant()

    $isSuspiciousPath = Test-SuspiciousPath $exe
    $chainReason = ""
    if (($officeParents -contains $parentLower) -and ($shellChildren -contains $nameLower)) {
        $chainReason = "Office application spawned a shell or LOLBin"
    } elseif (($browserParents -contains $parentLower) -and ($shellChildren -contains $nameLower)) {
        $chainReason = "Browser spawned a shell or LOLBin"
    } elseif (($webParents -contains $parentLower) -and ($shellChildren -contains $nameLower)) {
        $chainReason = "Web server worker spawned a shell or LOLBin"
    } elseif (($parentLower -eq 'services.exe') -and ($nameLower -match '^(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$')) {
        $chainReason = "Service Control Manager spawned an interactive shell"
    }

    $cmdReason = ""
    if ($cmd -match '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|\biex\b|invoke-expression|windowstyle\s+hidden)') {
        $cmdReason = "Encoded, hidden or download-and-execute PowerShell pattern"
    } elseif ($cmd -match '(?i)(mshta\s|rundll32\s+javascript|regsvr32[^\r\n]*/i:http|certutil[^\r\n]*-urlcache|bitsadmin[^\r\n]*/tr[a-z]{0,6}sfer)') {
        $cmdReason = "LOLBin download or script execution pattern"
    } elseif ($cmd -match '(?i)(vssadmin[^\r\n]*delete[^\r\n]*shadows|wbadmin[^\r\n]*delete|bcdedit[^\r\n]*/set|wevtutil[^\r\n]*cl\s|fsutil[^\r\n]*deletejournal)') {
        $cmdReason = "Defense evasion or anti-forensic command"
    } elseif ($cmd -match '(?i)(net\s+user[^\r\n]*/add|net\s+localgroup[^\r\n]*administrators[^\r\n]*/add|schtasks[^\r\n]*/create|wmic[^\r\n]*process[^\r\n]*call[^\r\n]*create)') {
        $cmdReason = "Account, task or process creation command"
    } elseif ($cmd -match '(?i)(mimi[a-z]{0,3}katz|procdump[^\r\n]*lsa[a-z]{0,2}s|comsvcs\.dll[^\r\n]*minidump)') {
        $cmdReason = "Credential dumping pattern"
    }

    $isSuspicious = $isSuspiciousPath -or ($chainReason -ne "") -or ($cmdReason -ne "")
    if ($isSuspicious) { $suspiciousCount++ }

    $signature = "NotChecked"
    $hash = ""
    if ($isSuspicious) {
        $signature = Get-SignatureStatus $exe
        $hash = Get-FileSha256 $exe
    }

    if ($results.Count -lt 300) {
        $results += [ordered]@{
            pid = [int]$p.ProcessId
            ppid = $parentPid
            name = $name
            parent_name = $parentName
            executable = $exe
            parent_executable = $parentPath
            command_line = (Limit-Text $cmd 500)
            suspicious = $isSuspicious
            signature = $signature
            sha256 = $hash
        }
    }

    if ($chainReason -ne "") {
        $chains += [ordered]@{
            pid = [int]$p.ProcessId
            name = $name
            ppid = $parentPid
            parent_name = $parentName
            reason = $chainReason
        }
        $findings += New-Finding -Id "triage-win-proc-chain-$($p.ProcessId)" `
            -RuleId "process.lineage.suspicious_parent_child" `
            -Title "$chainReason`: $parentName -> $name" `
            -Severity "high" -Category "process_anomaly" `
            -Evidence "PID $($p.ProcessId) parent PID $parentPid ($parentName) CommandLine: $cmd" `
            -Remediation "Capture the process tree, validate the user session, and contain the endpoint if the activity is not authorized." `
            -File $exe
    }
    if ($isSuspiciousPath) {
        $findings += New-Finding -Id "triage-win-proc-path-$($p.ProcessId)" `
            -RuleId "process.execution.user_writable_path" `
            -Title "Process executes from a user-writable or temporary path: $name" `
            -Severity "high" -Category "process_anomaly" `
            -Evidence "PID $($p.ProcessId) executable: $exe CommandLine: $cmd" `
            -Remediation "Hash and quarantine the binary, then determine how it was introduced." `
            -File $exe
    }
    if ($cmdReason -ne "") {
        $severity = "high"
        if ($cmdReason -eq "Credential dumping pattern") { $severity = "critical" }
        $findings += New-Finding -Id "triage-win-proc-cmd-$($p.ProcessId)" `
            -RuleId "process.command_line.suspicious" `
            -Title "Suspicious command line: $name" `
            -Severity $severity -Category "command_and_control" `
            -Evidence "$cmdReason. PID $($p.ProcessId) CommandLine: $cmd" `
            -Remediation "Preserve command-line evidence, inspect the parent process, and block associated network endpoints." `
            -File $exe
    }
    if ($isSuspicious -and $signature -ne "Valid") {
        $findings += New-Finding -Id "triage-win-proc-sig-$($p.ProcessId)" `
            -RuleId "process.signature.invalid_or_missing" `
            -Title "Suspicious process is not validly signed: $name" `
            -Severity "high" -Category "process_anomaly" -Confidence "medium" `
            -Evidence "PID $($p.ProcessId) signature: $signature executable: $exe" `
            -Remediation "Treat unsigned or invalidly signed binaries as untrusted until provenance is established." `
            -File $exe
    }
}

# Credential protection posture relevant to process memory attacks.
$lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPpl = (Get-ItemProperty -Path $lsaKey -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
$wdigest = (Get-ItemProperty -Path "$lsaKey\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
if ($runAsPpl -ne 1) {
    $findings += New-Finding -Id "triage-win-proc-lsass-protection" `
        -RuleId "credential.lsass.protection_disabled" `
        -Title "LSASS run-as-protected-process is not enabled" `
        -Severity "high" -Category "credential_access" -Confidence "high" `
        -Evidence "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL is not 1" `
        -Remediation "Enable LSA Protection (RunAsPPL=1) and Credential Guard where supported." `
        -File $lsaKey
}
if ($wdigest -eq 1) {
    $findings += New-Finding -Id "triage-win-proc-wdigest" `
        -RuleId "credential.wdigest.plaintext_logon" `
        -Title "WDigest plaintext credential caching is enabled" `
        -Severity "critical" -Category "credential_access" -Confidence "high" `
        -Evidence "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\WDigest\UseLogonCredential = 1" `
        -Remediation "Set UseLogonCredential to 0 and restart the endpoint to stop plaintext credential caching." `
        -File "$lsaKey\WDigest"
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    metrics = [ordered]@{
        processes = $processes.Count
        suspicious_processes = $suspiciousCount
        suspicious_chains = $chains.Count
        lsass_run_as_ppl = $runAsPpl
        wdigest_use_logon_credential = $wdigest
    }
    suspicious_chains = @($chains)
    processes = @($results)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Process triage report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
