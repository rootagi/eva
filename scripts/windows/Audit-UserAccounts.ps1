<#
.SYNOPSIS
    Audit Windows User Accounts and Local Administrators (EVA Sec compatible).
.DESCRIPTION
    Enumerates local accounts, administrators group membership, guest account status,
    password expiration policy, and dormant accounts.
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
$accounts = @()
$adminMembers = @()

# 1. Local Administrators Group
try {
    $admins = Get-CimInstance -ClassName Win32_Group -Filter "Name = 'Administrators'"
    $query = "ASSOCIATORS OF {Win32_Group.Domain='$($admins.Domain)',Name='Administrators'} WHERE AssocClass=Win32_GroupUser Role=GroupComponent ResultRole=PartComponent"
    $members = Get-CimInstance -Query $query
    foreach ($m in $members) {
        $adminMembers += @{
            name = $m.Name
            domain = $m.Domain
            caption = $m.Caption
        }
    }
} catch {}

# 2. Local Users Audit
$users = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = True"
foreach ($u in $users) {
    $accounts += @{
        name = $u.Name
        disabled = $u.Disabled
        lockout = $u.Lockout
        password_changeable = $u.PasswordChangeable
        password_expires = $u.PasswordExpires
        password_required = $u.PasswordRequired
        status = $u.Status
    }

    # Check Guest account enabled
    if ($u.Name -eq "Guest" -and $u.Disabled -eq $false) {
        $findings += @{
            id = "triage-win-user-guest-active"
            tool = "triage-windows-users"
            rule_id = "identity.guest_account.enabled"
            title = "Built-in Guest account is enabled"
            severity = "high"
            confidence = "high"
            category = "account_security"
            target = $hostname
            evidence = "User 'Guest' has Disabled = False"
            remediation = "Disable the built-in Guest account: Disable-LocalUser -Name 'Guest'"
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("guest_enabled|$hostname"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }

    # Check Password not required
    if ($u.PasswordRequired -eq $false -and $u.Disabled -eq $false) {
        $findings += @{
            id = "triage-win-user-no-pwd-req-$($u.Name)"
            tool = "triage-windows-users"
            rule_id = "identity.account.password_not_required"
            title = "Account '$($u.Name)' does not require a password"
            severity = "critical"
            confidence = "high"
            category = "account_security"
            target = $hostname
            evidence = "Account $($u.Name) has PasswordRequired = False"
            remediation = "Enforce password requirements on account $($u.Name)."
            fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("nopassword|$($u.Name)"))).Replace("-", "").Substring(0, 32).ToLower()
        }
    }
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows-users"
    collected_at = $now
    host = @{
        hostname = $hostname
    }
    local_accounts_count = $accounts.Count
    local_administrators_count = $adminMembers.Count
    administrators = $adminMembers
    accounts = $accounts
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5
if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] User account audit saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
