<#
.SYNOPSIS
    Endpoint Network Sockets and DNS Cache Triage for Windows (EVA Sec compatible).
.DESCRIPTION
    Collects active TCP/UDP connections, DNS client cache, routing table,
    and hosts file entries.
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

# 1. DNS Client Cache
$dnsEntries = @()
if (Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $cache = Get-DnsClientCache
    foreach ($entry in $cache) {
        if ($entry.Entry) {
            $dnsEntries += @{
                entry = $entry.Entry
                data = $entry.Data
                type = $entry.Type.ToString()
                status = $entry.Status.ToString()
            }
        }
    }
}

# 2. Hosts File Audit
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsEntries = @()
if (Test-Path $hostsPath) {
    $lines = Get-Content -Path $hostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
    foreach ($l in $lines) {
        $parts = ($l -split '\s+') | Where-Object { $_ -ne '' }
        if ($parts.Count -ge 2) {
            $hostsEntries += @{
                ip = $parts[0]
                host = $parts[1]
            }
            # Detect hosts file hijacking for security or update domains
            if ($parts[1] -match '(?i)(windowsupdate|microsoft|antivirus|virustotal|defender)') {
                $findings += @{
                    id = "triage-win-hosts-hijack-$($parts[1])"
                    tool = "triage-windows-network"
                    rule_id = "network.hosts.security_domain_hijacked"
                    title = "Potential security/update domain redirected in hosts file: $($parts[1])"
                    severity = "critical"
                    confidence = "high"
                    category = "network_tampering"
                    file = $hostsPath
                    evidence = "Hosts entry: $l"
                    remediation = "Remove unauthorized hosts file entry from $hostsPath"
                    fingerprint = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$l"))).Replace("-", "").Substring(0, 32).ToLower()
                }
            }
        }
    }
}

# 3. Active Connections
$activeConns = @()
if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection -State Established
    foreach ($c in $conns) {
        $activeConns += @{
            local_address = $c.LocalAddress
            local_port = $c.LocalPort
            remote_address = $c.RemoteAddress
            remote_port = $c.RemotePort
            owning_process = $c.OwningProcess
        }
    }
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = "triage-windows-network"
    collected_at = $now
    host = @{
        hostname = $hostname
    }
    dns_cache_count = $dnsEntries.Count
    active_established_connections = $activeConns.Count
    hosts_entries_count = $hostsEntries.Count
    hosts_entries = $hostsEntries
    dns_cache_sample = $dnsEntries | Select-Object -First 50
    active_connections = $activeConns | Select-Object -First 50
    findings = $findings
}

$jsonOutput = $report | ConvertTo-Json -Depth 5
if ($OutputFile) {
    $jsonOutput | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[+] Network triage report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
