<#
.SYNOPSIS
    Audit Windows System Hardening against CIS Baseline Controls (EVA Sec compatible).
.DESCRIPTION
    Audits local security policies against CIS benchmarks:
    - User Account Control (UAC) configuration
    - SMBv1 protocol status
    - Windows Firewall state across all profiles
    - PowerShell Script Block Logging policy
    - Windows Defender Credential Guard / LSA Protection
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
$audits = @()

function Add-AuditCheck {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Status, # PASS, FAIL, WARN
        [string]$Severity,
        [string]$Evidence,
        [string]$Remediation
    )
    $script:audits += @{
        control_id = $Id
        title = $Title
        status = $Status
        severity = $Severity
        evidence = $Evidence
        remediation = $Remediation
    }
    if ($Status -in @("FAIL", "WARN")) {
        $fp = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Id|$Title|$Evidence"))).Replace("-", "").Substring(0, 32).ToLower()
        $script:findings += @{
            id = "triage-win-$Id"
            tool = "triage-windows-hardening"
            rule_id = "hardening.$Id"
            title = $Title
            severity = $Severity
            confidence = "high"
            category = "hardening_audit"
            target = $env:COMPUTERNAME
            evidence = $Evidence
            remediation = $Remediation
            fingerprint = $fp
        }
    }
}

# 1. User Account Control (UAC) Check
$uacReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$enableLua = (Get-ItemProperty -Path $uacReg -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($enableLua -eq 1) {
    Add-AuditCheck -Id "uac.enabled" -Title "User Account Control (UAC) is enabled" -Status "PASS" -Severity "info" -Evidence "EnableLUA is set to 1" -Remediation ""
} else {
    Add-AuditCheck -Id "uac.disabled" -Title "UAC is disabled (EnableLUA = 0)" -Status "FAIL" -Severity "critical" -Evidence "EnableLUA registry value is 0" -Remediation "Enable UAC: Set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA to 1"
}

# 2. SMBv1 Protocol Status
$smb1Reg = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smb1Val = (Get-ItemProperty -Path $smb1Reg -Name SMB1 -ErrorAction SilentlyContinue).SMB1
if ($smb1Val -eq 0 -or (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State -ne 'Enabled') {
    Add-AuditCheck -Id "smb1.disabled" -Title "Legacy SMBv1 protocol is disabled" -Status "PASS" -Severity "info" -Evidence "SMBv1 is not active" -Remediation ""
} else {
    Add-AuditCheck -Id "smb1.enabled" -Title "Legacy SMBv1 protocol is enabled" -Status "FAIL" -Severity "high" -Evidence "SMBv1 feature or registry key is active" -Remediation "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
}

# 3. Windows Firewall Profiles
$fwProfiles = @("Domain", "Private", "Public")
$fwDisabled = @()
foreach ($p in $fwProfiles) {
    if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $state = (Get-NetFirewallProfile -Name $p).Enabled
        if ($state -ne $true -and $state -ne "True") {
            $fwDisabled += $p
        }
    } else {
        $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\${p}Profile"
        $enableFw = (Get-ItemProperty -Path $regKey -Name EnableFirewall -ErrorAction SilentlyContinue).EnableFirewall
        if ($enableFw -ne 1) {
            $fwDisabled += $p
        }
    }
}

if ($fwDisabled.Count -eq 0) {
    Add-AuditCheck -Id "firewall.all_profiles_enabled" -Title "Windows Firewall is active on all profiles" -Status "PASS" -Severity "info" -Evidence "Domain, Private, and Public profiles enabled" -Remediation ""
} else {
    Add-AuditCheck -Id "firewall.profiles_disabled" -Title "Windows Firewall disabled on: $($fwDisabled -join ', ')" -Status "FAIL" -Severity "high" -Evidence "Firewall profiles disabled: $($fwDisabled -join ', ')" -Remediation "Enable Windows Firewall: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
}

# 4. PowerShell Script Block Logging (EID 4104)
$psLogReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sbLog = (Get-ItemProperty -Path $psLogReg -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
if ($sbLog -eq 1) {
    Add-AuditCheck -Id "powershell.script_block_logging.enabled" -Title "PowerShell Script Block Logging is enabled" -Status "PASS" -Severity "info" -Evidence "EnableScriptBlockLogging = 1" -Remediation ""
} else {
    Add-AuditCheck -Id "powershell.script_block_logging.disabled" -Title "PowerShell Script Block Logging is not configured" -Status "FAIL" -Severity "medium" -Evidence "EnableScriptBlockLogging registry key is missing or set to 0" -Remediation "Enable Script Block Logging via GPO or set EnableScriptBlockLogging=1 under HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
}

# 5. Credential Guard / LSA Protection
$lsaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPpl = (Get-ItemProperty -Path $lsaReg -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
$lsaCfg = (Get-ItemProperty -Path $lsaReg -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
if ($runAsPpl -ge 1 -or $lsaCfg -ge 1) {
    Add-AuditCheck -Id "credential_guard.lsa_protection.enabled" -Title "LSA Protection / Credential Guard is active" -Status "PASS" -Severity "info" -Evidence "RunAsPPL: $runAsPpl, LsaCfgFlags: $lsaCfg" -Remediation ""
} else {
    Add-AuditCheck -Id "credential_guard.lsa_protection.disabled" -Title "LSA Protection (RunAsPPL) is not enabled (LSASS memory dump vulnerable)" -Status "FAIL" -Severity "high" -Evidence "RunAsPPL and LsaCfgFlags are disabled" -Remediation "Enable LSA Protection: Set RunAsPPL=1 under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa to protect LSASS memory."
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows-hardening"
    collected_at = $now
    host = @{
        hostname = $hostname
    }
    checks_total = $audits.Count
    checks_passed = ($audits | Where-Object { $_.status -eq 'PASS' }).Count
    checks_failed = ($audits | Where-Object { $_.status -in @('FAIL', 'WARN') }).Count
    audits = $audits
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5

if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Hardening audit saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
