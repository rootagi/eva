<#
.SYNOPSIS
    Web Root Webshell and Server-Side Script Hunt (EVA Sec compatible).
.DESCRIPTION
    Read-only content inspection of IIS, Apache, PHP and application web roots:
    - Server-side scripts with execution primitives and request-controlled input
    - Encoded/obfuscated PHP, ASP/ASPX, JSP and PowerShell patterns
    - Double-extension and hidden script files
    - SHA-256 enrichment for suspicious files
    Files are never executed and no content is sent off the endpoint.
.PARAMETER Path
    Web roots to scan. Defaults to common IIS/Apache/XAMPP locations.
.PARAMETER Days
    Recent-modification window for reporting recently changed web scripts (default 30).
.PARAMETER MaxFiles
    Maximum candidate script files inspected (default 3000).
.PARAMETER MaxFileSizeMB
    Skip content inspection of files larger than this size (default 4).
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
#>
[CmdletBinding()]
param(
    [string[]]$Path = @(),
    [int]$Days = 30,
    [int]$MaxFiles = 3000,
    [int]$MaxFileSizeMB = 4,
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-webshells'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$suspiciousFiles = @()
$recentScripts = @()
$collectionWarnings = @()
$suspiciousCount = 0
$totalCandidates = 0

$Days = [math]::Max(1, [math]::Min(3650, $Days))
$MaxFiles = [math]::Max(10, [math]::Min(100000, $MaxFiles))
$MaxBytes = [math]::Max(1024, $MaxFileSizeMB * 1024 * 1024)

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
        [string]$Category = "webshell",
        [string]$Confidence = "medium"
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

function Get-FileSha256 {
    param([string]$Path)
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue
    if ($null -eq $hash) { return "" }
    return $hash.Hash.ToLower()
}

function Get-ContentSnippet {
    param([string]$Content, [int]$Index, [int]$Length = 220)
    if ($Index -lt 0 -or $Content.Length -eq 0) { return "" }
    $start = [math]::Max(0, $Index - 60)
    $size = [math]::Min($Length, $Content.Length - $start)
    if ($size -le 0) { return "" }
    return (Limit-Text $Content.Substring($start, $size) 300)
}

function Get-LineNumber {
    param([string]$Content, [int]$Index)
    if ($Index -le 0) { return 1 }
    return ([regex]::Matches($Content.Substring(0, [math]::Min($Index, $Content.Length)), "`n").Count + 1)
}

function Get-CandidateFiles {
    param([string]$Root)
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    if ($null -eq $rootItem) { return }
    $stack = New-Object System.Collections.Stack
    $stack.Push($rootItem)
    $seen = @{}
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        if ($seen.ContainsKey($dir.FullName)) { continue }
        $seen[$dir.FullName] = $true
        foreach ($child in @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)) {
            try {
                if ($child.PSIsContainer) {
                    if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if ($child.Name -match '(?i)^(\.git|\.svn|node_modules|bower_components|__pycache__|\.cache|Cache)$') { continue }
                    $stack.Push($child)
                    continue
                }
                if ($child.Length -gt $MaxBytes) { continue }
                $isScriptExtension = $child.Name -match '(?i)\.(aspx?|php\d?|phtml|jspx?|jspf|ashx|asmx|cfm|cfml|cgi|pl|py|ps1|shtml)$'
                $isDoubleExtension = $child.Name -match '(?i)\.(php|asp|aspx|jsp|ashx|asmx|cfm)\.(jpg|jpeg|png|gif|txt|zip|rar|7z|doc|docx|pdf|bak)$'
                if ($isScriptExtension -or $isDoubleExtension) {
                    $child
                }
            } catch { }
        }
    }
}

# ------------------------------------------------------------------------------
# 1. Resolve web roots and candidate files
# ------------------------------------------------------------------------------
if ($Path.Count -eq 0) {
    $defaultRoots = @(
        (Join-Path $env:SystemDrive "inetpub\wwwroot"),
        (Join-Path $env:SystemDrive "xampp\htdocs"),
        (Join-Path $env:SystemDrive "Apache24\htdocs"),
        (Join-Path $env:SystemDrive "Apache\htdocs"),
        (Join-Path $env:SystemDrive "www"),
        (Join-Path $env:SystemDrive "sites")
    )
    $Path = @($defaultRoots | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | Select-Object -Unique)
}
if ($Path.Count -eq 0) {
    $collectionWarnings += "No web roots were found. Specify -Path to scan an application directory."
}

$candidateFiles = @()
$seenFiles = @{}
foreach ($root in $Path) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        $collectionWarnings += "Web root does not exist or is not a directory: $root"
        continue
    }
    foreach ($file in @(Get-CandidateFiles -Root $root)) {
        if ($seenFiles.ContainsKey($file.FullName)) { continue }
        $seenFiles[$file.FullName] = $true
        $candidateFiles += $file
        if ($candidateFiles.Count -ge $MaxFiles) { break }
    }
    if ($candidateFiles.Count -ge $MaxFiles) { break }
}

$rules = @(
    [ordered]@{ id = "php.eval"; label = "PHP eval execution"; pattern = '(?i)\beval\s*\('; weight = 3 },
    [ordered]@{ id = "php.assert"; label = "PHP assert/code execution"; pattern = '(?i)\bassert\s*\('; weight = 2 },
    [ordered]@{ id = "php.system"; label = "PHP system/command execution"; pattern = '(?i)\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\('; weight = 2 },
    [ordered]@{ id = "php.preg_e"; label = "PHP preg_replace /e code execution"; pattern = '(?i)preg_replace\s*\([^;]{0,200}/e'; weight = 3 },
    [ordered]@{ id = "php.create_function"; label = "PHP create_function"; pattern = '(?i)\bcreate_function\s*\('; weight = 2 },
    [ordered]@{ id = "php.base64"; label = "PHP base64 decoding"; pattern = '(?i)\bbase64_decode\s*\('; weight = 2 },
    [ordered]@{ id = "php.rot13"; label = "PHP str_rot13 obfuscation"; pattern = '(?i)\bstr_rot13\s*\('; weight = 1 },
    [ordered]@{ id = "asp.eval"; label = "ASP eval/execute request data"; pattern = '(?i)\b(eval|execute)\s*\(?\s*(request|eval)'; weight = 3 },
    [ordered]@{ id = "asp.wscript"; label = "ASP WScript.Shell execution"; pattern = '(?i)(WScript\.Shell|Shell\.Application|Server\.CreateObject\s*\(\s*"WScript\.Shell")'; weight = 3 },
    [ordered]@{ id = "aspx.process"; label = ".NET process execution"; pattern = '(?i)(ProcessStartInfo|Process\.Start\s*\(|System\.Diagnostics\.Process)'; weight = 2 },
    [ordered]@{ id = "aspx.assembly"; label = ".NET dynamic assembly load"; pattern = '(?i)(Assembly\.Load|FromBase64String|Invoke-Expression|\bIEX\b)'; weight = 2 },
    [ordered]@{ id = "jsp.runtime"; label = "JSP runtime command execution"; pattern = '(?i)Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec'; weight = 3 },
    [ordered]@{ id = "generic.shell"; label = "Shell command execution"; pattern = '(?i)(cmd\.exe\s+/c|powershell(\.exe)?\s+(-|/)|/bin/(sh|bash)\s+-c)'; weight = 2 },
    [ordered]@{ id = "generic.request"; label = "Direct request-controlled execution"; pattern = '(?i)(\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|Request\.Form|Request\.QueryString|Request\[|getParameter\s*\()'; weight = 1 },
    [ordered]@{ id = "generic.obfuscation"; label = "Encoder or obfuscation primitive"; pattern = '(?i)(gzinflate\s*\(\s*base64_decode|String\.fromCharCode|document\.write\s*\(\s*unescape|chr\s*\(\s*\d+\s*\)\s*\.)'; weight = 2 }
)

$quickPattern = '(?i)(eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|preg_replace\s*\([^;]{0,200}/e|create_function\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|WScript\.Shell|Shell\.Application|Server\.CreateObject|ProcessStartInfo|Assembly\.Load|FromBase64String|Invoke-Expression|Runtime\.getRuntime|Request\.Form|Request\.QueryString|\$_POST|\$_GET|\$_REQUEST|cmd\.exe\s+/c|powershell(\.exe)?\s+(-|/)|/bin/(sh|bash)\s+-c|String\.fromCharCode)'

$recentCutoff = (Get-Date).AddDays(-1 * $Days)
foreach ($file in $candidateFiles) {
    $totalCandidates++
    $isDoubleExtension = $file.Name -match '(?i)\.(php|asp|aspx|jsp|ashx|asmx|cfm)\.(jpg|jpeg|png|gif|txt|zip|rar|7z|doc|docx|pdf|bak)$'
    $isHidden = (($file.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0)
    $isRecent = $file.LastWriteTime -gt $recentCutoff

    if ($isRecent) {
        if ($recentScripts.Count -lt 100) {
            $recentScripts += [ordered]@{
                path = $file.FullName
                size = $file.Length
                modified = $file.LastWriteTime.ToUniversalTime().ToString("o")
            }
        }
    }

    if ($isDoubleExtension) {
        $hash = Get-FileSha256 $file.FullName
        $suspiciousCount++
        $findings += New-Finding -Id "triage-win-web-double-ext-$((Get-Sha256Hex $file.FullName).Substring(0, 16))" `
            -RuleId "webshell.file.double_extension" -Title "Web script uses a deceptive double extension: $($file.Name)" `
            -Severity "high" -Category "webshell" -Confidence "medium" `
            -Evidence "File: $($file.FullName) size: $($file.Length) modified: $($file.LastWriteTime.ToString('o')) sha256: $hash" `
            -Remediation "Preserve the file for analysis and remove it if it is not a deliberate, reviewed deployment." `
            -File $file.FullName
        $suspiciousFiles += [ordered]@{
            path = $file.FullName
            size = $file.Length
            modified = $file.LastWriteTime.ToUniversalTime().ToString("o")
            sha256 = $hash
            score = 10
            severity = "high"
            rules = @("double_extension")
        }
        if ($suspiciousFiles.Count -ge 200) { break }
    }

    if ($isHidden) {
        $findings += New-Finding -Id "triage-win-web-hidden-$((Get-Sha256Hex $file.FullName).Substring(0, 16))" `
            -RuleId "webshell.file.hidden_script" -Title "Hidden server-side script in a web root: $($file.Name)" `
            -Severity "medium" -Category "webshell" -Confidence "medium" `
            -Evidence "File: $($file.FullName) attributes: $($file.Attributes)" `
            -Remediation "Review the file purpose and remove it if it is not required by the application." `
            -File $file.FullName
    }

    $content = ""
    try { $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop } catch { continue }
    if ([string]::IsNullOrEmpty($content)) { continue }
    if ($content.IndexOf([char]0) -ge 0) { continue }
    if (-not [regex]::IsMatch($content, $quickPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { continue }

    $matchedRules = @()
    $matchEvidence = @()
    $score = 0
    $lineNumbers = @()
    foreach ($rule in $rules) {
        $match = [regex]::Match($content, $rule.pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $match.Success) { continue }
        $matchedRules += $rule.id
        $score += [int]$rule.weight
        $lineNumbers += (Get-LineNumber $content $match.Index)
        if ($matchEvidence.Count -lt 6) {
            $matchEvidence += "$($rule.label) at line $(Get-LineNumber $content $match.Index): $(Get-ContentSnippet $content $match.Index)"
        }
    }
    if ($matchedRules.Count -eq 0) { continue }

    $hasExecution = @($matchedRules | Where-Object { $_ -match 'eval|system|assert|wscript|process|assembly|runtime|shell|preg_e|create_function' }).Count -gt 0
    $hasRequest = $matchedRules -contains "generic.request"
    $hasObfuscation = @($matchedRules | Where-Object { $_ -match 'base64|rot13|obfuscation|assembly' }).Count -gt 0
    $severity = "low"
    $confidence = "medium"
    if ($hasExecution -and $hasRequest) {
        $severity = "high"
        $confidence = "high"
    } elseif ($hasExecution -and $hasObfuscation) {
        $severity = "high"
        $confidence = "medium"
    } elseif ($hasExecution -or $score -ge 4) {
        $severity = "medium"
    }
    if ($severity -eq "low" -and -not $isRecent) { continue }

    $hash = Get-FileSha256 $file.FullName
    $suspiciousCount++
    $ruleText = ($matchedRules | Select-Object -Unique) -join ', '
    $lineText = (($lineNumbers | Select-Object -Unique) | Select-Object -First 10) -join ', '
    $findings += New-Finding -Id "triage-win-web-content-$((Get-Sha256Hex $file.FullName).Substring(0, 16))" `
        -RuleId "webshell.script.suspicious_content" -Title "Potential server-side webshell: $($file.Name)" `
        -Severity $severity -Category "webshell" -Confidence $confidence `
        -Evidence "File: $($file.FullName) score: $score rules: $ruleText lines: $lineText sha256: $hash Matches: $($matchEvidence -join ' | ')" `
        -Remediation "Preserve the file and web logs, validate the deployment source, remove unauthorized code, and rotate application secrets." `
        -File $file.FullName
    $suspiciousFiles += [ordered]@{
        path = $file.FullName
        size = $file.Length
        modified = $file.LastWriteTime.ToUniversalTime().ToString("o")
        sha256 = $hash
        score = $score
        severity = $severity
        rules = @($matchedRules | Select-Object -Unique)
        lines = @($lineNumbers | Select-Object -Unique)
    }
    if ($suspiciousFiles.Count -ge 200) { break }
}

# ------------------------------------------------------------------------------
# 2. Report assembly
# ------------------------------------------------------------------------------
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    scan = [ordered]@{
        roots = @($Path)
        days = $Days
        max_files = $MaxFiles
        max_file_size_mb = $MaxFileSizeMB
    }
    metrics = [ordered]@{
        candidate_scripts = $totalCandidates
        recent_scripts = $recentScripts.Count
        suspicious_files = $suspiciousFiles.Count
        suspicious_findings = $suspiciousCount
        findings = $findings.Count
    }
    recent_web_scripts = @($recentScripts)
    suspicious_files = @($suspiciousFiles)
    collection_warnings = @($collectionWarnings)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Webshell hunt report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
