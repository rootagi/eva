<#
.SYNOPSIS
    Windows Defender and Antivirus Configuration Audit (EVA Sec compatible).
.DESCRIPTION
    Audits the endpoint protection posture and recent detections:
    - Defender service, real-time, behavior, IOAV and tamper protection state
    - Signature age/version and scan freshness
    - Cloud-delivered protection, PUA, network protection and ASR rules
    - Path, process, extension and IP exclusions (flags dangerous exclusions)
    - Recent Defender threat detections with associated resources
    - Registered antivirus products from the Security Center
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
.PARAMETER DetectionDays
    How many days of Defender detections to include (default 30).
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "",
    [int]$DetectionDays = 30
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-defender'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$detections = @()
$exclusionSummary = [ordered]@{}
$asrRules = @()

$DetectionDays = [math]::Max(1, [math]::Min(365, $DetectionDays))

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

function Get-ObjectValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function ConvertTo-UtcString {
    param($Value)
    if ($null -eq $Value) { return "" }
    try { return ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } catch { return "" }
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
        [string]$Category = "defense_evasion",
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

function Test-SuspiciousExclusionPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '(?i)^[A-Z]:\\?$|\\Temp\\|\\Windows\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle\.Bin\\|\\PerfLogs\\')
}

function Test-SuspiciousExclusionProcess {
    param([string]$Process)
    if ([string]::IsNullOrWhiteSpace($Process)) { return $false }
    return ($Process -match '(?i)(^|[\\/])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$|^\*$')
}

function Test-SuspiciousExclusionExtension {
    param([string]$Extension)
    if ([string]::IsNullOrWhiteSpace($Extension)) { return $false }
    return ($Extension -match '(?i)^\.(exe|dll|ps1|vbs|js|jse|hta|scr|bat|cmd|com|msi)$|^\.\*$')
}

function Test-PublicIp {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -match '^(10\.|127\.|169\.254\.|0\.0\.0\.0$|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fc|fd)') { return $false }
    return $true
}

# ------------------------------------------------------------------------------
# 1. Defender status and registered antivirus products
# ------------------------------------------------------------------------------
$defenderAvailable = $false
$status = $null
$preference = $null
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $defenderAvailable = $true
    } catch { $status = $null }
}
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    try { $preference = Get-MpPreference -ErrorAction Stop } catch { $preference = $null }
}

$avProducts = @()
try {
    $avProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            display_name = [string]$_.displayName
            path = [string]$_.pathToSignedProductExe
            product_state = [string]$_.productState
            timestamp = [string]$_.timestamp
        }
    })
} catch { $avProducts = @() }

$thirdPartyAv = @($avProducts | Where-Object { $_.display_name -notmatch '(?i)(Windows Defender|Microsoft Defender)' })
$hasThirdPartyAv = $thirdPartyAv.Count -gt 0

$realtime = [bool](Get-ObjectValue $status "RealTimeProtectionEnabled" $false)
$antivirus = [bool](Get-ObjectValue $status "AntivirusEnabled" $false)
$antispyware = [bool](Get-ObjectValue $status "AntispywareEnabled" $false)
$behavior = [bool](Get-ObjectValue $status "BehaviorMonitorEnabled" $false)
$ioav = [bool](Get-ObjectValue $status "IoavProtectionEnabled" $false)
$onAccess = [bool](Get-ObjectValue $status "OnAccessProtectionEnabled" $false)
$tamper = [bool](Get-ObjectValue $status "IsTamperProtected" $false)
$amService = [bool](Get-ObjectValue $status "AMServiceEnabled" $false)
$sigAge = [int](Get-ObjectValue $status "AntivirusSignatureAge" -1)
$sigVersion = [string](Get-ObjectValue $status "AntivirusSignatureVersion" "")
$sigUpdated = Get-ObjectValue $status "AntivirusSignatureLastUpdated" $null
$engineVersion = [string](Get-ObjectValue $status "AMEngineVersion" "")
$productVersion = [string](Get-ObjectValue $status "AMProductVersion" "")
$quickScanAge = [int](Get-ObjectValue $status "QuickScanAge" -1)
$fullScanAge = [int](Get-ObjectValue $status "FullScanAge" -1)

if (-not $defenderAvailable) {
    $findings += New-Finding -Id "triage-win-defender-unavailable" -RuleId "defender.unavailable" `
        -Title "Windows Defender status could not be collected" -Severity "low" -Category "configuration" -Confidence "medium" `
        -Evidence "Get-MpComputerStatus did not return data. A third-party antivirus product may be primary, or the Defender service is disabled." `
        -Remediation "Confirm which endpoint protection product is active and verify its health through the management console." `
        -File "Windows Defender"
} else {
    $rtpSeverity = "critical"
    $rtpConfidence = "high"
    $rtpNote = ""
    if ($hasThirdPartyAv) {
        $rtpSeverity = "medium"
        $rtpConfidence = "medium"
        $rtpNote = " Third-party antivirus products are registered: $(($thirdPartyAv | ForEach-Object { $_.display_name }) -join ', ')."
    }
    if (-not $realtime) {
        $findings += New-Finding -Id "triage-win-defender-rtp" -RuleId "defender.realtime_protection.disabled" `
            -Title "Windows Defender real-time protection is disabled" -Severity $rtpSeverity -Category "defense_evasion" -Confidence $rtpConfidence `
            -Evidence "RealTimeProtectionEnabled=false.$rtpNote" `
            -Remediation "Re-enable real-time protection, verify tamper protection, and investigate who or what disabled it." `
            -File "Windows Defender"
    }
    if (-not $antivirus -and -not $hasThirdPartyAv) {
        $findings += New-Finding -Id "triage-win-defender-av-disabled" -RuleId "defender.antivirus.disabled" `
            -Title "Windows Defender antivirus is disabled" -Severity "critical" -Category "defense_evasion" `
            -Evidence "AntivirusEnabled=false and no third-party antivirus product is registered." `
            -Remediation "Enable Defender or install and register an approved endpoint protection product." -File "Windows Defender"
    }
    if (-not $behavior -and -not $hasThirdPartyAv) {
        $findings += New-Finding -Id "triage-win-defender-behavior" -RuleId "defender.behavior_monitoring.disabled" `
            -Title "Windows Defender behavior monitoring is disabled" -Severity "high" -Category "defense_evasion" `
            -Evidence "BehaviorMonitorEnabled=false." `
            -Remediation "Enable behavior monitoring and validate related Group Policy or registry settings." -File "Windows Defender"
    }
    if (-not $ioav -and -not $hasThirdPartyAv) {
        $findings += New-Finding -Id "triage-win-defender-ioav" -RuleId "defender.ioav.disabled" `
            -Title "Windows Defender IOAV protection is disabled" -Severity "high" -Category "defense_evasion" `
            -Evidence "IoavProtectionEnabled=false." `
            -Remediation "Enable IOAV protection and investigate changes to Defender policy." -File "Windows Defender"
    }
    if (-not $tamper) {
        $findings += New-Finding -Id "triage-win-defender-tamper" -RuleId "defender.tamper_protection.disabled" `
            -Title "Windows Defender tamper protection is disabled" -Severity "high" -Category "defense_evasion" -Confidence "medium" `
            -Evidence "IsTamperProtected=false. Security settings can be changed by local administrators or malware." `
            -Remediation "Enable tamper protection through the Microsoft Defender portal or Intune where supported." -File "Windows Defender"
    }
    if (-not $amService) {
        $findings += New-Finding -Id "triage-win-defender-service" -RuleId "defender.service.disabled" `
            -Title "Windows Defender AM service is not running" -Severity "high" -Category "defense_evasion" `
            -Evidence "AMServiceEnabled=false. Check WinDefend, WdNisSvc and Sense service state." `
            -Remediation "Start the Defender services and investigate why the protection service stopped." -File "Windows Defender"
    }
    if ($sigAge -gt 7) {
        $findings += New-Finding -Id "triage-win-defender-signatures" -RuleId "defender.signatures.stale" `
            -Title "Windows Defender signatures are stale" -Severity "high" -Category "defense_evasion" `
            -Evidence "AntivirusSignatureAge=$sigAge days version=$sigVersion lastUpdated=$(ConvertTo-UtcString $sigUpdated)" `
            -Remediation "Restore signature updates, verify proxy and WSUS/Intune connectivity, and run an update scan." -File "Windows Defender"
    } elseif ($sigAge -gt 3) {
        $findings += New-Finding -Id "triage-win-defender-signatures" -RuleId "defender.signatures.stale" `
            -Title "Windows Defender signatures are aging" -Severity "medium" -Category "defense_evasion" -Confidence "medium" `
            -Evidence "AntivirusSignatureAge=$sigAge days version=$sigVersion" `
            -Remediation "Verify automatic signature updates and run an update scan." -File "Windows Defender"
    }
}

$winDefend = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if ($null -ne $winDefend -and $winDefend.StartType -eq 'Disabled') {
    $findings += New-Finding -Id "triage-win-defender-service-disabled" -RuleId "defender.service.startup_disabled" `
        -Title "Windows Defender service startup is disabled" -Severity "high" -Category "defense_evasion" `
        -Evidence "WinDefend StartType=Disabled Status=$($winDefend.Status)." `
        -Remediation "Set the WinDefend startup type to Automatic and investigate the change source." -File "WinDefend"
}

# ------------------------------------------------------------------------------
# 2. Preference hardening
# ------------------------------------------------------------------------------
$maps = [int](Get-ObjectValue $preference "MAPSReporting" -1)
$samples = [int](Get-ObjectValue $preference "SubmitSamplesConsent" -1)
$pua = [int](Get-ObjectValue $preference "PUAProtection" -1)
$networkProtection = [int](Get-ObjectValue $preference "EnableNetworkProtection" -1)
$controlledFolder = [int](Get-ObjectValue $preference "EnableControlledFolderAccess" -1)
$disableRealtime = [bool](Get-ObjectValue $preference "DisableRealtimeMonitoring" $false)
$disableBehavior = [bool](Get-ObjectValue $preference "DisableBehaviorMonitoring" $false)
$disableIoav = [bool](Get-ObjectValue $preference "DisableIOAVProtection" $false)
$disableScript = [bool](Get-ObjectValue $preference "DisableScriptScanning" $false)
$disableArchive = [bool](Get-ObjectValue $preference "DisableArchiveScanning" $false)
$disableIps = [bool](Get-ObjectValue $preference "DisableIntrusionPreventionSystem" $false)
$disableFirstSeen = [bool](Get-ObjectValue $preference "DisableBlockAtFirstSeen" $false)
$scanDay = [int](Get-ObjectValue $preference "ScanScheduleDay" -1)

if ($null -ne $preference) {
    if ($disableRealtime) {
        $findings += New-Finding -Id "triage-win-defender-pref-rtp" -RuleId "defender.preference.realtime_disabled" `
            -Title "Defender preference disables real-time monitoring" -Severity "high" -Category "defense_evasion" `
            -Evidence "Get-MpPreference DisableRealtimeMonitoring=true." `
            -Remediation "Remove the disabling policy and re-enable real-time protection." -File "Windows Defender"
    }
    if ($disableBehavior) {
        $findings += New-Finding -Id "triage-win-defender-pref-behavior" -RuleId "defender.preference.behavior_disabled" `
            -Title "Defender preference disables behavior monitoring" -Severity "high" -Category "defense_evasion" `
            -Evidence "Get-MpPreference DisableBehaviorMonitoring=true." `
            -Remediation "Remove the disabling policy and re-enable behavior monitoring." -File "Windows Defender"
    }
    if ($disableIoav) {
        $findings += New-Finding -Id "triage-win-defender-pref-ioav" -RuleId "defender.preference.ioav_disabled" `
            -Title "Defender preference disables IOAV scanning" -Severity "high" -Category "defense_evasion" `
            -Evidence "Get-MpPreference DisableIOAVProtection=true." `
            -Remediation "Remove the disabling policy and re-enable IOAV protection." -File "Windows Defender"
    }
    if ($disableScript) {
        $findings += New-Finding -Id "triage-win-defender-pref-script" -RuleId "defender.preference.script_scanning_disabled" `
            -Title "Defender script scanning is disabled" -Severity "high" -Category "defense_evasion" `
            -Evidence "Get-MpPreference DisableScriptScanning=true." `
            -Remediation "Re-enable script scanning and inspect recent script execution." -File "Windows Defender"
    }
    if ($disableArchive) {
        $findings += New-Finding -Id "triage-win-defender-pref-archive" -RuleId "defender.preference.archive_scanning_disabled" `
            -Title "Defender archive scanning is disabled" -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "Get-MpPreference DisableArchiveScanning=true." `
            -Remediation "Enable archive scanning unless a documented performance exception exists." -File "Windows Defender"
    }
    if ($disableIps -or $disableFirstSeen) {
        $findings += New-Finding -Id "triage-win-defender-pref-cloud" -RuleId "defender.preference.cloud_protection_disabled" `
            -Title "Defender cloud or intrusion-prevention features are disabled" -Severity "medium" -Category "configuration" `
            -Evidence "DisableIntrusionPreventionSystem=$disableIps DisableBlockAtFirstSeen=$disableFirstSeen." `
            -Remediation "Enable cloud-delivered and intrusion-prevention protection aligned with organizational policy." -File "Windows Defender"
    }
    if ($maps -eq 0) {
        $findings += New-Finding -Id "triage-win-defender-maps" -RuleId "defender.preference.cloud_lookup_disabled" `
            -Title "Defender cloud-delivered protection is disabled" -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "MAPSReporting=0." `
            -Remediation "Enable MAPS/cloud-delivered protection unless an approved offline policy requires otherwise." -File "Windows Defender"
    }
    if ($pua -eq 0) {
        $findings += New-Finding -Id "triage-win-defender-pua" -RuleId "defender.preference.pua_disabled" `
            -Title "Defender potentially unwanted application protection is disabled" -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "PUAProtection=0." `
            -Remediation "Enable PUA protection to block unwanted bundled software." -File "Windows Defender"
    }
    if ($networkProtection -eq 0) {
        $findings += New-Finding -Id "triage-win-defender-network" -RuleId "defender.preference.network_protection_disabled" `
            -Title "Defender network protection is disabled" -Severity "medium" -Category "configuration" -Confidence "medium" `
            -Evidence "EnableNetworkProtection=0." `
            -Remediation "Enable network protection in block or audit mode and review resulting events." -File "Windows Defender"
    }
    if ($controlledFolder -eq 0) {
        $findings += New-Finding -Id "triage-win-defender-cfa" -RuleId "defender.preference.controlled_folder_access_disabled" `
            -Title "Controlled Folder Access is disabled" -Severity "low" -Category "configuration" -Confidence "medium" `
            -Evidence "EnableControlledFolderAccess=0." `
            -Remediation "Evaluate Controlled Folder Access for ransomware protection on user endpoints." -File "Windows Defender"
    }
    if ($scanDay -eq 8) {
        $findings += New-Finding -Id "triage-win-defender-scan" -RuleId "defender.preference.scheduled_scan_never" `
            -Title "Scheduled Defender scan is disabled" -Severity "low" -Category "configuration" -Confidence "medium" `
            -Evidence "ScanScheduleDay=8 (Never). QuickScanAge=$quickScanAge FullScanAge=$fullScanAge." `
            -Remediation "Configure a recurring quick scan and periodic full scan." -File "Windows Defender"
    }
} elseif ($defenderAvailable) {
    $findings += New-Finding -Id "triage-win-defender-preference-unavailable" -RuleId "defender.preference.unavailable" `
        -Title "Defender preferences could not be collected" -Severity "low" -Category "configuration" -Confidence "medium" `
        -Evidence "Get-MpPreference returned no data while Get-MpComputerStatus succeeded." `
        -Remediation "Check Defender WMI health and permissions for the collecting account." -File "Windows Defender"
}

# ------------------------------------------------------------------------------
# 3. Exclusions and ASR rules
# ------------------------------------------------------------------------------
$exclusionPaths = @(Get-ObjectValue $preference "ExclusionPath" @())
$exclusionProcesses = @(Get-ObjectValue $preference "ExclusionProcess" @())
$exclusionExtensions = @(Get-ObjectValue $preference "ExclusionExtension" @())
$exclusionIps = @(Get-ObjectValue $preference "ExclusionIpAddress" @())

$suspiciousPaths = @($exclusionPaths | Where-Object { Test-SuspiciousExclusionPath $_ })
$suspiciousProcesses = @($exclusionProcesses | Where-Object { Test-SuspiciousExclusionProcess $_ })
$suspiciousExtensions = @($exclusionExtensions | Where-Object { Test-SuspiciousExclusionExtension $_ })
$publicExclusionIps = @($exclusionIps | Where-Object { Test-PublicIp $_ })

$exclusionSummary = [ordered]@{
    paths = @($exclusionPaths)
    processes = @($exclusionProcesses)
    extensions = @($exclusionExtensions)
    ip_addresses = @($exclusionIps)
    suspicious_paths = @($suspiciousPaths)
    suspicious_processes = @($suspiciousProcesses)
    suspicious_extensions = @($suspiciousExtensions)
    public_ip_exclusions = @($publicExclusionIps)
}

if ($exclusionPaths.Count -gt 0) {
    $severity = "medium"
    $confidence = "medium"
    if ($suspiciousPaths.Count -gt 0) { $severity = "high"; $confidence = "high" }
    $findings += New-Finding -Id "triage-win-defender-exclusion-path-$((Get-Sha256Hex ($exclusionPaths -join '|')).Substring(0, 12))" `
        -RuleId "defender.exclusion.suspicious_path" -Title "Defender path exclusions are configured" `
        -Severity $severity -Category "defense_evasion" -Confidence $confidence `
        -Evidence "Paths: $($exclusionPaths -join '; ')" `
        -Remediation "Remove broad or temporary-directory exclusions; document and tightly scope any legitimate exclusion." `
        -File "Windows Defender"
}
if ($exclusionProcesses.Count -gt 0) {
    $severity = "medium"
    $confidence = "medium"
    if ($suspiciousProcesses.Count -gt 0) { $severity = "high"; $confidence = "high" }
    $findings += New-Finding -Id "triage-win-defender-exclusion-process-$((Get-Sha256Hex ($exclusionProcesses -join '|')).Substring(0, 12))" `
        -RuleId "defender.exclusion.suspicious_process" -Title "Defender process exclusions are configured" `
        -Severity $severity -Category "defense_evasion" -Confidence $confidence `
        -Evidence "Processes: $($exclusionProcesses -join '; ')" `
        -Remediation "Remove exclusions for scripting engines and administrative utilities unless formally approved." `
        -File "Windows Defender"
}
if ($exclusionExtensions.Count -gt 0) {
    $severity = "medium"
    $confidence = "medium"
    if ($suspiciousExtensions.Count -gt 0) { $severity = "high"; $confidence = "high" }
    $findings += New-Finding -Id "triage-win-defender-exclusion-extension-$((Get-Sha256Hex ($exclusionExtensions -join '|')).Substring(0, 12))" `
        -RuleId "defender.exclusion.suspicious_extension" -Title "Defender extension exclusions are configured" `
        -Severity $severity -Category "defense_evasion" -Confidence $confidence `
        -Evidence "Extensions: $($exclusionExtensions -join '; ')" `
        -Remediation "Remove executable, script and wildcard extension exclusions." -File "Windows Defender"
}
if ($exclusionIps.Count -gt 0) {
    $severity = "medium"
    $confidence = "medium"
    if ($publicExclusionIps.Count -gt 0) { $severity = "high"; $confidence = "medium" }
    $findings += New-Finding -Id "triage-win-defender-exclusion-ip-$((Get-Sha256Hex ($exclusionIps -join '|')).Substring(0, 12))" `
        -RuleId "defender.exclusion.ip_address" -Title "Defender IP address exclusions are configured" `
        -Severity $severity -Category "defense_evasion" -Confidence $confidence `
        -Evidence "IP exclusions: $($exclusionIps -join '; ')" `
        -Remediation "Remove public IP exclusions and validate any internal exclusions against the network baseline." `
        -File "Windows Defender"
}

$asrIds = @(Get-ObjectValue $preference "AttackSurfaceReductionRules_Ids" @())
$asrActions = @(Get-ObjectValue $preference "AttackSurfaceReductionRules_Actions" @())
for ($i = 0; $i -lt $asrIds.Count; $i++) {
    $action = ""
    if ($i -lt $asrActions.Count) { $action = [string]$asrActions[$i] }
    $asrRules += [ordered]@{
        rule_id = [string]$asrIds[$i]
        action = $action
    }
}
if ($null -ne $preference -and $asrRules.Count -eq 0) {
    $findings += New-Finding -Id "triage-win-defender-asr-none" -RuleId "defender.asr.no_rules" `
        -Title "No attack surface reduction rules are configured" -Severity "medium" -Category "configuration" -Confidence "medium" `
        -Evidence "Get-MpPreference returned no AttackSurfaceReductionRules_Ids." `
        -Remediation "Enable ASR rules appropriate for the endpoint role, starting in audit mode where required." `
        -File "Windows Defender"
}

# ------------------------------------------------------------------------------
# 4. Recent Defender detections
# ------------------------------------------------------------------------------
$threats = @(Get-MpThreat -ErrorAction SilentlyContinue)
$threatNames = @{}
foreach ($threat in $threats) {
    $threatId = [string]$threat.ThreatID
    if (-not [string]::IsNullOrWhiteSpace($threatId)) {
        $threatNames[$threatId] = [string]$threat.ThreatName
    }
}
$detectionCutoff = (Get-Date).AddDays(-1 * $DetectionDays)
$rawDetections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
    $null -ne $_.InitialDetectionTime -and $_.InitialDetectionTime -gt $detectionCutoff
} | Sort-Object InitialDetectionTime -Descending)
$detectionCount = 0
foreach ($detection in $rawDetections) {
    $detectionCount++
    if ($detections.Count -ge 50) { continue }
    $threatId = [string]$detection.ThreatID
    $threatName = $threatNames[$threatId]
    if ([string]::IsNullOrWhiteSpace($threatName)) { $threatName = "ThreatID $threatId" }
    $resources = @($detection.Resources) -join '; '
    $detectedAt = ConvertTo-UtcString $detection.InitialDetectionTime
    $detections += [ordered]@{
        threat_id = $threatId
        threat_name = $threatName
        detected_at = $detectedAt
        status_id = [string]$detection.ThreatStatusID
        action_success = [string]$detection.ActionSuccess
        cleaning_action_id = [string]$detection.CleaningActionID
        resources = (Limit-Text $resources 800)
    }
    $suffix = (Get-Sha256Hex "$threatId|$detectedAt|$resources").Substring(0, 12)
    $findings += New-Finding -Id "triage-win-defender-detection-$suffix" -RuleId "defender.threat.detected" `
        -Title "Windows Defender detection: $threatName" -Severity "high" -Category "malware" -Confidence "high" `
        -Evidence "Detected $detectedAt. StatusID=$($detection.ThreatStatusID) ActionSuccess=$($detection.ActionSuccess) Resources: $resources" `
        -Remediation "Validate the detection and remediation status, preserve quarantined files, and investigate the execution vector." `
        -File $resources
}

# ------------------------------------------------------------------------------
# 5. Report assembly
# ------------------------------------------------------------------------------
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    available = $defenderAvailable
    products = @($avProducts)
    status = [ordered]@{
        realtime_protection = $realtime
        antivirus_enabled = $antivirus
        antispyware_enabled = $antispyware
        behavior_monitoring = $behavior
        ioav_protection = $ioav
        on_access_protection = $onAccess
        tamper_protected = $tamper
        am_service_enabled = $amService
        signature_age_days = $sigAge
        signature_version = $sigVersion
        signature_last_updated = (ConvertTo-UtcString $sigUpdated)
        engine_version = $engineVersion
        product_version = $productVersion
        quick_scan_age_days = $quickScanAge
        full_scan_age_days = $fullScanAge
    }
    preferences = [ordered]@{
        maps_reporting = $maps
        submit_samples_consent = $samples
        pua_protection = $pua
        network_protection = $networkProtection
        controlled_folder_access = $controlledFolder
        scan_schedule_day = $scanDay
    }
    exclusions = $exclusionSummary
    asr_rules = @($asrRules)
    metrics = [ordered]@{
        registered_antivirus_products = $avProducts.Count
        third_party_antivirus_products = $thirdPartyAv.Count
        asr_rules = $asrRules.Count
        exclusions = ($exclusionPaths.Count + $exclusionProcesses.Count + $exclusionExtensions.Count + $exclusionIps.Count)
        detections_in_window = $detectionCount
        findings = $findings.Count
    }
    detections = @($detections)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Defender audit report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
