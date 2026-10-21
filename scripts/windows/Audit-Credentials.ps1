<#
.SYNOPSIS
    Windows Credential Exposure and Account Audit (EVA Sec compatible).
.DESCRIPTION
    Read-only audit of credential attack surface and local account posture:
    - Local users, enabled accounts, built-in Administrator/Guest state
    - Local Administrators group membership and password-expiry flags
    - Autologon, cached logons, WDigest, LSA protection and Credential Guard
    - LSA anonymous/blank-password and LM compatibility settings
    - Unattend files, stored cmdkey entries, Git/netrc credential files
    - SSH private keys with overly broad read permissions
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
.PARAMETER StaleDays
    Reserved for future stale-account reporting. Accounts are never disabled by this script.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "",
    [int]$StaleDays = 90
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-credentials'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$users = @()
$adminMembers = @()
$credentialTargets = @()
$privateKeys = @()
$sensitiveFiles = @()

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
        [string]$Category = "credential_access",
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

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $null }
        return $item.$Name
    } catch { return $null }
}

# ------------------------------------------------------------------------------
# 1. Local users and Administrators group
# ------------------------------------------------------------------------------
$rawUsers = @()
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    try { $rawUsers = @(Get-LocalUser -ErrorAction SilentlyContinue) } catch { $rawUsers = @() }
}
if ($rawUsers.Count -eq 0) {
    try { $rawUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue) } catch { $rawUsers = @() }
}

if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
    try {
        $adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | ForEach-Object {
            $memberSid = ""
            if ($null -ne $_.SID -and $_.SID.PSObject.Properties.Name -contains 'Value') {
                $memberSid = [string]$_.SID.Value
            } else {
                $memberSid = [string]$_.SID
            }
            [ordered]@{
                name = [string]$_.Name
                object_class = [string]$_.ObjectClass
                principal_source = [string]$_.PrincipalSource
                sid = $memberSid
            }
        })
    } catch { $adminMembers = @() }
} else {
    $inMembers = $false
    $netOut = net localgroup Administrators 2>$null
    foreach ($line in @($netOut)) {
        $text = ([string]$line).Trim()
        if ($text -match '^-{3,}$') { $inMembers = $true; continue }
        if ($text -match '^The command completed') { break }
        if ($inMembers -and $text.Length -gt 0) {
            $adminMembers += [ordered]@{
                name = $text
                object_class = "Unknown"
                principal_source = "Unknown"
                sid = ""
            }
        }
    }
}

$adminNames = @($adminMembers | ForEach-Object { ([string]$_.name -split '\\')[-1] })
$enabledCount = 0
$adminUserCount = 0

foreach ($u in $rawUsers) {
    $name = [string]$u.Name
    if ([string]::IsNullOrWhiteSpace($name)) { continue }

    $enabled = $true
    if ($u.PSObject.Properties.Name -contains 'Enabled') {
        $enabled = [bool]$u.Enabled
    } elseif ($u.PSObject.Properties.Name -contains 'Disabled') {
        $enabled = -not [bool]$u.Disabled
    }

    $sid = ""
    if ($u.PSObject.Properties.Name -contains 'SID') {
        if ($null -ne $u.SID -and $u.SID.PSObject.Properties.Name -contains 'Value') {
            $sid = [string]$u.SID.Value
        } else {
            $sid = [string]$u.SID
        }
    }

    $lastLogon = $null
    if ($u.PSObject.Properties.Name -contains 'LastLogon') { $lastLogon = $u.LastLogon }
    $passwordLastSet = $null
    if ($u.PSObject.Properties.Name -contains 'PasswordLastSet') { $passwordLastSet = $u.PasswordLastSet }

    $passwordNeverExpires = $false
    if ($u.PSObject.Properties.Name -contains 'PasswordNeverExpires') {
        $passwordNeverExpires = [bool]$u.PasswordNeverExpires
    } elseif ($u.PSObject.Properties.Name -contains 'PasswordExpires') {
        $passwordNeverExpires = -not [bool]$u.PasswordExpires
    }

    $passwordRequired = $true
    if ($u.PSObject.Properties.Name -contains 'PasswordRequired') { $passwordRequired = [bool]$u.PasswordRequired }

    $isBuiltinAdmin = ($sid -match '-500$') -or ($name -ieq 'Administrator')
    $isBuiltinGuest = ($sid -match '-501$') -or ($name -ieq 'Guest')
    $isAdmin = $isBuiltinAdmin -or ($adminNames -contains $name) -or ($adminNames -contains "$($script:Hostname)\$name")
    if ($enabled) { $enabledCount++ }
    if ($enabled -and $isAdmin) { $adminUserCount++ }

    $users += [ordered]@{
        name = $name
        sid = $sid
        enabled = $enabled
        builtin_administrator = $isBuiltinAdmin
        builtin_guest = $isBuiltinGuest
        administrator = $isAdmin
        description = (Limit-Text ([string]$u.Description) 300)
        last_logon = (ConvertTo-UtcString $lastLogon)
        password_last_set = (ConvertTo-UtcString $passwordLastSet)
        password_never_expires = $passwordNeverExpires
        password_required = $passwordRequired
    }

    if ($enabled -and $isBuiltinGuest) {
        $findings += New-Finding -Id "triage-win-cred-guest-enabled" -RuleId "account.guest.enabled" `
            -Title "Built-in Guest account is enabled" -Severity "high" -Category "account" `
            -Evidence "Guest SID $sid is enabled on $($script:Hostname)." `
            -Remediation "Disable the built-in Guest account unless an approved exception exists." `
            -File "SAM"
    }
    if ($enabled -and $isBuiltinAdmin) {
        $findings += New-Finding -Id "triage-win-cred-builtin-admin-enabled" -RuleId "account.administrator.enabled" `
            -Title "Built-in Administrator account is enabled" -Severity "medium" -Category "account" -Confidence "medium" `
            -Evidence "Built-in Administrator SID $sid is enabled. Last logon: $(ConvertTo-UtcString $lastLogon)" `
            -Remediation "Disable the built-in Administrator account after validating a named break-glass process." `
            -File "SAM"
    }
    if ($enabled -and -not $passwordRequired) {
        $findings += New-Finding -Id "triage-win-cred-no-password-$((Get-Sha256Hex $sid).Substring(0, 12))" `
            -RuleId "account.password.not_required" -Title "Enabled account does not require a password: $name" `
            -Severity "high" -Category "account" `
            -Evidence "Account $name (SID $sid) is enabled with PasswordRequired=false." `
            -Remediation "Require a strong password or disable the account; investigate how a passwordless account was created." `
            -File "SAM"
    }
    if ($enabled -and $passwordNeverExpires -and -not $isBuiltinAdmin) {
        $severity = "low"
        if ($isAdmin) { $severity = "medium" }
        $findings += New-Finding -Id "triage-win-cred-password-never-expires-$((Get-Sha256Hex $sid).Substring(0, 12))" `
            -RuleId "account.password.never_expires" -Title "Password is set to never expire: $name" `
            -Severity $severity -Category "account" -Confidence "medium" `
            -Evidence "Account $name (SID $sid) is enabled with PasswordNeverExpires=true. Administrator=$isAdmin" `
            -Remediation "Use managed service accounts for service identities and enforce password rotation for interactive accounts." `
            -File "SAM"
    }
}

if ($adminUserCount -gt 1) {
    $adminList = ($users | Where-Object { $_.enabled -and $_.administrator } | ForEach-Object { $_.name }) -join ', '
    $findings += New-Finding -Id "triage-win-cred-multiple-admins" -RuleId "account.administrators.multiple_enabled" `
        -Title "Multiple enabled local administrator accounts" -Severity "medium" -Category "account" -Confidence "medium" `
        -Evidence "Enabled local administrators: $adminList" `
        -Remediation "Reduce standing local administrator access and require named, audited break-glass accounts." `
        -File "SAM"
}

# ------------------------------------------------------------------------------
# 2. Credential caching and logon policy
# ------------------------------------------------------------------------------
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$cachedLogons = Get-RegistryValue $winlogonPath "CachedLogonsCount"
if ($null -ne $cachedLogons -and [string]$cachedLogons -match '^\d+$') {
    $cachedCount = [int]$cachedLogons
    if ($cachedCount -gt 10) {
        $findings += New-Finding -Id "triage-win-cred-cached-logons" -RuleId "credential.cached_logons.excessive" `
            -Title "Excessive cached domain logons are configured" -Severity "medium" -Category "credential_access" -Confidence "medium" `
            -Evidence "CachedLogonsCount=$cachedCount. Cached verifier material increases offline cracking exposure." `
            -Remediation "Reduce CachedLogonsCount to 0-4 for domain workstations unless offline logon is operationally required." `
            -File $winlogonPath
    }
}

$autoAdminLogon = [string](Get-RegistryValue $winlogonPath "AutoAdminLogon")
$defaultPassword = Get-RegistryValue $winlogonPath "DefaultPassword"
$defaultUserName = [string](Get-RegistryValue $winlogonPath "DefaultUserName")
if (-not [string]::IsNullOrWhiteSpace([string]$defaultPassword)) {
    $findings += New-Finding -Id "triage-win-cred-autologon" -RuleId "credential.autologon.plaintext" `
        -Title "Automatic logon stores a plaintext credential" -Severity "critical" -Category "credential_access" `
        -Evidence "AutoAdminLogon=$autoAdminLogon DefaultUserName=$defaultUserName DefaultPassword is present (value intentionally not emitted)." `
        -Remediation "Remove the stored credential, disable automatic logon, and rotate the affected account password." `
        -File $winlogonPath
} elseif ($autoAdminLogon -eq '1') {
    $findings += New-Finding -Id "triage-win-cred-autologon-enabled" -RuleId "credential.autologon.enabled" `
        -Title "Automatic logon is enabled without a stored DefaultPassword" -Severity "medium" -Category "credential_access" -Confidence "medium" `
        -Evidence "AutoAdminLogon=1 DefaultUserName=$defaultUserName DefaultPassword is not set. Verify the configured logon mechanism and account exposure." `
        -Remediation "Disable automatic logon unless it is required for a kiosk, and confirm no credential is stored elsewhere." `
        -File $winlogonPath
}

$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$wdigest = Get-RegistryValue $wdigestPath "UseLogonCredential"
if ([string]$wdigest -eq '1') {
    $findings += New-Finding -Id "triage-win-cred-wdigest" -RuleId "credential.wdigest.plaintext_logon" `
        -Title "WDigest plaintext credential caching is enabled" -Severity "critical" -Category "credential_access" `
        -Evidence "UseLogonCredential=1 causes WDigest to retain reusable logon secrets in memory." `
        -Remediation "Set UseLogonCredential=0, reboot, and rotate credentials that may have been exposed." `
        -File $wdigestPath
}

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPpl = Get-RegistryValue $lsaPath "RunAsPPL"
if ($null -eq $runAsPpl -or [int]$runAsPpl -eq 0) {
    $findings += New-Finding -Id "triage-win-cred-lsa-ppl" -RuleId "credential.lsa_protection.disabled" `
        -Title "LSA protection (RunAsPPL) is not enabled" -Severity "medium" -Category "credential_access" -Confidence "medium" `
        -Evidence "RunAsPPL is missing or 0. LSASS is more exposed to credential-dumping tools." `
        -Remediation "Enable LSA protection with RunAsPPL=1 (or 2 for UEFI lock) after validating driver compatibility." `
        -File $lsaPath
}

$lmLevel = Get-RegistryValue $lsaPath "LmCompatibilityLevel"
if ($null -ne $lmLevel -and [int]$lmLevel -lt 3) {
    $findings += New-Finding -Id "triage-win-cred-lm-compat" -RuleId "credential.ntlm.lm_compatibility" `
        -Title "Legacy LAN Manager authentication is permitted" -Severity "high" -Category "credential_access" `
        -Evidence "LmCompatibilityLevel=$lmLevel. Values below 3 permit weaker LM/NTLM authentication." `
        -Remediation "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM and NTLM)." `
        -File $lsaPath
}

$limitBlank = Get-RegistryValue $lsaPath "LimitBlankPasswordUse"
if ($null -ne $limitBlank -and [int]$limitBlank -eq 0) {
    $findings += New-Finding -Id "triage-win-cred-blank-password" -RuleId "credential.blank_password_remote_logon" `
        -Title "Remote logon with blank passwords is allowed" -Severity "high" -Category "credential_access" `
        -Evidence "LimitBlankPasswordUse=0 permits blank-password accounts to authenticate remotely." `
        -Remediation "Set LimitBlankPasswordUse=1 and remove passwordless accounts." `
        -File $lsaPath
}

$deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$lsaCfgFlags = Get-RegistryValue $deviceGuardPath "LsaCfgFlags"
$vbsEnabled = Get-RegistryValue $deviceGuardPath "EnableVirtualizationBasedSecurity"
$credentialGuardOn = ($null -ne $lsaCfgFlags -and [int]$lsaCfgFlags -in @(1, 2))
if (-not $credentialGuardOn) {
    $findings += New-Finding -Id "triage-win-cred-credential-guard" -RuleId "credential.guard.disabled" `
        -Title "Credential Guard is not configured" -Severity "medium" -Category "credential_access" -Confidence "medium" `
        -Evidence "LsaCfgFlags=$lsaCfgFlags EnableVirtualizationBasedSecurity=$vbsEnabled. Credential Guard is not active." `
        -Remediation "Enable Virtualization-Based Security and Credential Guard on supported hardware and Windows editions." `
        -File $deviceGuardPath
}

# ------------------------------------------------------------------------------
# 3. Unattend files, stored credentials and sensitive credential files
# ------------------------------------------------------------------------------
$unattendPaths = @(
    "$env:SystemRoot\Panther\Unattend.xml",
    "$env:SystemRoot\Panther\Unattend\Unattend.xml",
    "$env:SystemRoot\System32\Sysprep\unattend.xml",
    "$env:SystemDrive\unattend.xml"
)
foreach ($path in ($unattendPaths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $content) { continue }
    $hasPassword = $content -match '(?i)<(Password|AutoLogon)>' -and $content -match '(?i)<Password>'
    if ($hasPassword) {
        $findings += New-Finding -Id "triage-win-cred-unattend-$((Get-Sha256Hex $path).Substring(0, 12))" `
            -RuleId "credential.unattend.embedded_password" `
            -Title "Unattend file contains an embedded credential" -Severity "high" -Category "credential_exposure" `
            -Evidence "Password element present in $path. File content is not emitted." `
            -Remediation "Remove or protect the unattend file, rotate any embedded credentials, and restrict file ACLs." `
            -File $path
    }
}

$cmdkeyOutput = cmdkey /list 2>$null
if ($cmdkeyOutput) {
    foreach ($line in @($cmdkeyOutput)) {
        if ([string]$line -match '^\s*Target:\s*(.+)$') {
            $credentialTargets += (Limit-Text $matches[1] 300)
        }
    }
    if ($credentialTargets.Count -gt 0) {
        $findings += New-Finding -Id "triage-win-cred-cmdkey" -RuleId "credential.cmdkey.stored" `
            -Title "Windows Credential Manager contains stored credentials" -Severity "low" -Category "credential_exposure" -Confidence "medium" `
            -Evidence "Stored targets: $($credentialTargets -join '; ')" `
            -Remediation "Remove obsolete saved credentials and migrate automation to a managed secret store." `
            -File "Credential Manager"
    }
}

$credentialFileCandidates = @(
    (Join-Path $env:USERPROFILE ".git-credentials"),
    (Join-Path $env:USERPROFILE ".netrc"),
    (Join-Path $env:USERPROFILE "_netrc")
)
foreach ($path in $credentialFileCandidates) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $sensitiveFiles += $path
    $findings += New-Finding -Id "triage-win-cred-file-$((Get-Sha256Hex $path).Substring(0, 12))" `
        -RuleId "credential.file.plaintext" -Title "Plaintext credential file is present: $(Split-Path $path -Leaf)" `
        -Severity "medium" -Category "credential_exposure" `
        -Evidence "Credential-bearing file exists at $path. File content is not read or emitted." `
        -Remediation "Remove the file after migrating to a credential manager, rotate exposed secrets, and restrict ACLs." `
        -File $path
}

$sshDirs = @(
    (Join-Path $env:USERPROFILE ".ssh"),
    "C:\ProgramData\ssh"
)
foreach ($dir in ($sshDirs | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    $keyFiles = @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$' -or $_.Extension -match '^\.(pem|ppk)$' })
    foreach ($key in $keyFiles) {
        $privateKeys += $key.FullName
        $weakAcl = $false
        try {
            $acl = Get-Acl -LiteralPath $key.FullName -ErrorAction SilentlyContinue
            foreach ($entry in @($acl.Access)) {
                if ($entry.AccessControlType -ne 'Allow') { continue }
                $identity = [string]$entry.IdentityReference
                $rights = [string]$entry.FileSystemRights
                if ($identity -match '(?i)(Everyone|BUILTIN\\Users|Authenticated Users)' -and $rights -match '(?i)(Read|Modify|FullControl)') {
                    $weakAcl = $true
                    break
                }
            }
        } catch { }
        if ($weakAcl) {
            $findings += New-Finding -Id "triage-win-cred-ssh-acl-$((Get-Sha256Hex $key.FullName).Substring(0, 12))" `
                -RuleId "credential.ssh_private_key.broad_acl" `
                -Title "SSH private key is readable by a broad Windows principal" -Severity "medium" -Category "credential_exposure" `
                -Evidence "Private key: $($key.FullName) has an Allow ACE for Everyone, Users or Authenticated Users with read access." `
                -Remediation "Restrict the key ACL to the owning service account and SYSTEM/Administrators only." `
                -File $key.FullName
        }
    }
}

# ------------------------------------------------------------------------------
# 4. Report assembly
# ------------------------------------------------------------------------------
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    metrics = [ordered]@{
        local_users = $users.Count
        enabled_users = $enabledCount
        enabled_administrators = $adminUserCount
        administrators_group_members = $adminMembers.Count
        stored_credentials = $credentialTargets.Count
        ssh_private_keys = $privateKeys.Count
        sensitive_credential_files = $sensitiveFiles.Count
    }
    policy = [ordered]@{
        cached_logons_count = [string]$cachedLogons
        auto_admin_logon = [string]$autoAdminLogon
        wdigest_use_logon_credential = [string]$wdigest
        lsass_run_as_ppl = [string]$runAsPpl
        lm_compatibility_level = [string]$lmLevel
        limit_blank_password_use = [string]$limitBlank
        credential_guard_lsa_cfg_flags = [string]$lsaCfgFlags
        virtualization_based_security = [string]$vbsEnabled
        stale_days_parameter = $StaleDays
    }
    users = @($users)
    administrators = @($adminMembers)
    stored_credentials = @($credentialTargets)
    ssh_private_keys = @($privateKeys)
    sensitive_files = @($sensitiveFiles)
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Credential audit report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
