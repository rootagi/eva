<#
.SYNOPSIS
    Windows Network and Remote-Access Forensics (EVA Sec compatible).
.DESCRIPTION
    Read-only network triage for intrusion investigation:
    - Interfaces, addresses, DNS servers/cache, routes and neighbor cache
    - TCP listeners and established connections with process attribution
    - Public connections and listeners on high-risk ports
    - Hosts file hijacking of security/update domains
    - Firewall profile state, SMB shares/sessions and SMBv1
    - RDP/NLA, WinRM authentication and netsh port-proxy rules
    - User proxy and WinHTTP proxy configuration
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
.PARAMETER MaxConnections
    Maximum connections/listeners retained in the report (default 300).
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "",
    [int]$MaxConnections = 300
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-network-forensics'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$listeners = @()
$established = @()
$connections = @()
$interfaces = @()
$dnsServers = @()
$dnsCache = @()
$routes = @()
$neighbors = @()
$hostsEntries = @()
$shares = @()
$smbSessions = @()
$fwProfiles = @()
$winrmConfig = [ordered]@{}
$portProxy = @()
$seenFindings = @{}

$MaxConnections = [math]::Max(20, [math]::Min(5000, $MaxConnections))

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
        [string]$Category = "network_anomaly",
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

function Test-PublicIp {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -match '^(10\.|127\.|169\.254\.|0\.0\.0\.0$|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|::|fe80:|fc|fd)') {
        return $false
    }
    return $true
}

function Test-SuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '(?i)(\\ProgramData\\Microsoft\\Windows Defender\\|\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\|\\AppData\\Local\\Microsoft\\OneDrive\\)') { return $false }
    return ($Path -match '(?i)(\\Temp\\|\\tmp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\Windows\\Temp\\|\\\$Recycle\.Bin\\|\\PerfLogs\\)')
}

function Split-Endpoint {
    param([string]$Endpoint)
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return @("", 0) }
    if ($Endpoint -match '^(.*):(\d+)$') {
        $address = $matches[1].Trim('[', ']')
        return @($address, [int]$matches[2])
    }
    return @($Endpoint, 0)
}

function Add-UniqueNetworkFinding {
    param(
        [string]$Key,
        [string]$Id,
        [string]$RuleId,
        [string]$Title,
        [string]$Severity,
        [string]$Evidence,
        [string]$Remediation,
        [string]$File = "",
        [string]$Category = "network_anomaly",
        [string]$Confidence = "high"
    )
    if ($script:seenFindings.ContainsKey($Key)) { return }
    $script:seenFindings[$Key] = $true
    if ($script:findings.Count -ge 200) { return }
    $script:findings += New-Finding -Id $Id -RuleId $RuleId -Title $Title -Severity $Severity `
        -Evidence $Evidence -Remediation $Remediation -File $File -Category $Category -Confidence $Confidence
}

# ------------------------------------------------------------------------------
# 1. Interfaces, addresses, DNS, routes and neighbors
# ------------------------------------------------------------------------------
if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
    $interfaces = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            alias = [string]$_.InterfaceAlias
            description = [string]$_.InterfaceDescription
            index = [string]$_.InterfaceIndex
            ipv4 = @($_.IPv4Address | ForEach-Object { [string]$_.IPAddress })
            ipv6 = @($_.IPv6Address | ForEach-Object { [string]$_.IPAddress })
            dns_servers = @($_.DNSServer | ForEach-Object { [string]$_.ServerAddresses })
            profile = [string]$_.NetProfile.Name
        }
    })
}
if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
    $dnsServers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object {
        [ordered]@{
            interface_index = $_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_family = [string]$_.AddressFamily
            servers = @($_.ServerAddresses)
        }
    })
}
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $dnsCache = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
        [ordered]@{
            entry = [string]$_.Entry
            record_type = [string]$_.Type
            data = (Limit-Text ([string]$_.Data) 300)
            status = [string]$_.Status
        }
    })
}
if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 300 | ForEach-Object {
        [ordered]@{
            destination = [string]$_.DestinationPrefix
            next_hop = [string]$_.NextHop
            interface_index = [string]$_.InterfaceIndex
            metric = $_.RouteMetric
        }
    })
}
if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
    $neighbors = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object -First 300 | ForEach-Object {
        [ordered]@{
            address = [string]$_.IPAddress
            link_layer = [string]$_.LinkLayerAddress
            state = [string]$_.State
            interface_index = [string]$_.InterfaceIndex
        }
    })
}

# ------------------------------------------------------------------------------
# 2. Socket inventory with process attribution
# ------------------------------------------------------------------------------
$processMap = @{}
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
    $processMap[[int]$p.Id] = $p
}

$rawTcp = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $rawTcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
} else {
    foreach ($line in @(netstat -ano 2>$null | Select-String -Pattern '^\s*TCP\s+')) {
        if ($line.Line -match '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
            $local = Split-Endpoint $matches[1]
            $remote = Split-Endpoint $matches[2]
            $rawTcp += [pscustomobject]@{
                LocalAddress = $local[0]
                LocalPort = $local[1]
                RemoteAddress = $remote[0]
                RemotePort = $remote[1]
                State = $matches[3]
                OwningProcess = [int]$matches[4]
                CreationTime = $null
            }
        }
    }
}

foreach ($c in $rawTcp) {
    $pidValue = [int]$c.OwningProcess
    $proc = $processMap[$pidValue]
    $processName = ""
    $processPath = ""
    if ($null -ne $proc) {
        $processName = [string]$proc.ProcessName
        try { $processPath = [string]$proc.Path } catch { $processPath = "" }
    }
    $state = [string]$c.State
    $remoteAddress = [string]$c.RemoteAddress
    $remotePort = [int]$c.RemotePort
    $localAddress = [string]$c.LocalAddress
    $localPort = [int]$c.LocalPort
    $item = [ordered]@{
        local_address = $localAddress
        local_port = $localPort
        remote_address = $remoteAddress
        remote_port = $remotePort
        state = $state
        pid = $pidValue
        process_name = $processName
        process_path = $processPath
        remote_public = (Test-PublicIp $remoteAddress)
    }
    $connections += $item
    if ($state -match '^(Listen|Listening)$') {
        if ($listeners.Count -lt $MaxConnections) { $listeners += $item }
    } elseif ($state -match '^(Established|SynSent|TimeWait|CloseWait)$') {
        if ($established.Count -lt $MaxConnections) { $established += $item }
    }
}

$highRiskPorts = @(4444, 4445, 5555, 6666, 6667, 1337, 31337, 9001, 9050, 1080)
$seenListenerRisk = @{}
foreach ($l in $listeners) {
    $isHighRiskPort = $highRiskPorts -contains [int]$l.local_port
    $isSuspiciousPath = Test-SuspiciousPath ([string]$l.process_path)
    if (-not $isHighRiskPort -and -not $isSuspiciousPath) { continue }
    $key = "listen-$($l.pid)-$($l.local_port)"
    if ($seenListenerRisk.ContainsKey($key)) { continue }
    $seenListenerRisk[$key] = $true
    $severity = "medium"
    $confidence = "medium"
    if ($isSuspiciousPath) { $severity = "high"; $confidence = "high" }
    if ($isHighRiskPort -and ([string]$l.local_address -in @("0.0.0.0", "::", "[::]"))) { $severity = "high" }
    Add-UniqueNetworkFinding -Key "listen-$key" -Id "triage-win-net-listener-$key" `
        -RuleId "network.listener.high_risk" -Title "Listener on a high-risk port or from a suspicious path" `
        -Severity $severity -Category "network_anomaly" -Confidence $confidence `
        -Evidence "Local $($l.local_address):$($l.local_port) PID $($l.pid) process $($l.process_name) path $($l.process_path)" `
        -Remediation "Identify the owning service, validate the binary signature and business need, and restrict the listener to trusted networks." `
        -File ([string]$l.process_path)
}

$seenEstablishedRisk = @{}
foreach ($e in $established) {
    $remotePort = [int]$e.remote_port
    $isHighRiskPort = $highRiskPorts -contains $remotePort
    $isPublic = [bool]$e.remote_public
    $isSuspiciousPath = Test-SuspiciousPath ([string]$e.process_path)
    if (-not (($isPublic -and $isHighRiskPort) -or $isSuspiciousPath)) { continue }
    $key = "conn-$($e.pid)-$($e.remote_address)-$($e.remote_port)"
    if ($seenEstablishedRisk.ContainsKey($key)) { continue }
    $seenEstablishedRisk[$key] = $true
    $severity = "high"
    $confidence = "medium"
    if ($isSuspiciousPath) { $confidence = "high" }
    Add-UniqueNetworkFinding -Key "conn-$key" -Id "triage-win-net-connection-$key" `
        -RuleId "network.connection.suspicious" -Title "Established connection to a high-risk endpoint or from a suspicious process" `
        -Severity $severity -Category "command_and_control" -Confidence $confidence `
        -Evidence "PID $($e.pid) $($e.process_name) ($($e.process_path)) -> $($e.remote_address):$($e.remote_port) state=$($e.state)" `
        -Remediation "Validate the remote endpoint and user intent, preserve flow evidence, and block the destination if unauthorized." `
        -File ([string]$e.process_path)
}

# ------------------------------------------------------------------------------
# 3. Hosts file tampering
# ------------------------------------------------------------------------------
$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
if (Test-Path -LiteralPath $hostsPath -PathType Leaf) {
    $lineNumber = 0
    foreach ($line in @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)) {
        $lineNumber++
        $clean = ($line -replace '#.*$', '').Trim()
        if ([string]::IsNullOrWhiteSpace($clean)) { continue }
        $parts = @($clean -split '\s+' | Where-Object { $_ -ne '' })
        if ($parts.Count -lt 2) { continue }
        $ip = [string]$parts[0]
        foreach ($hostName in $parts[1..($parts.Count - 1)]) {
            $hostsEntries += [ordered]@{
                line = $lineNumber
                ip = $ip
                host = $hostName
            }
            if ($hostName -match '(?i)(windowsupdate|update\.microsoft|microsoft\.com|defender|antivirus|virustotal|symantec|mcafee|crowdstrike|sentinelone|sophos|trendmicro|kaspersky|eset|bitdefender)') {
                $severity = "high"
                $confidence = "medium"
                if ($ip -in @("0.0.0.0", "127.0.0.1", "::1")) { $severity = "critical"; $confidence = "high" }
                Add-UniqueNetworkFinding -Key "hosts-$hostName-$ip" -Id "triage-win-net-hosts-$((Get-Sha256Hex "$hostName|$ip").Substring(0, 16))" `
                    -RuleId "network.hosts.security_domain_redirect" `
                    -Title "Security or update domain is redirected in the hosts file: $hostName" `
                    -Severity $severity -Category "network_tampering" -Confidence $confidence `
                    -Evidence "Line $lineNumber maps $hostName to $ip in $hostsPath." `
                    -Remediation "Remove the unauthorized hosts entry, restore DNS resolution, and investigate how the file was modified." `
                    -File $hostsPath
            }
        }
    }
}

# ------------------------------------------------------------------------------
# 4. Firewall, SMB and remote-access services
# ------------------------------------------------------------------------------
if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
    $fwProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            enabled = [bool]$_.Enabled
            default_inbound = [string]$_.DefaultInboundAction
            default_outbound = [string]$_.DefaultOutboundAction
            log_allowed = [bool]$_.LogAllowed
            log_blocked = [bool]$_.LogBlocked
        }
    })
    foreach ($profile in $fwProfiles) {
        if (-not $profile.enabled) {
            Add-UniqueNetworkFinding -Key "fw-$($profile.name)" -Id "triage-win-net-firewall-$($profile.name)" `
                -RuleId "network.firewall.profile_disabled" -Title "Windows Firewall profile is disabled: $($profile.name)" `
                -Severity "high" -Category "configuration" -Confidence "high" `
                -Evidence "Firewall profile $($profile.name) enabled=false defaultInbound=$($profile.default_inbound)." `
                -Remediation "Enable all firewall profiles and verify inbound exposure through the management console." `
                -File "Windows Firewall"
        }
    }
}

$smbConfig = $null
$smb1Enabled = $null
if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $smbConfig) {
        $smb1Enabled = [bool]$smbConfig.EnableSMB1Protocol
    }
    if ($null -ne $smbConfig -and [bool]$smbConfig.EnableSMB1Protocol) {
        $findings += New-Finding -Id "triage-win-net-smb1" -RuleId "network.smb1.enabled" `
            -Title "SMBv1 is enabled on the endpoint" -Severity "high" -Category "configuration" `
            -Evidence "Get-SmbServerConfiguration EnableSMB1Protocol=true." `
            -Remediation "Disable SMBv1 after validating legacy dependencies and apply the latest SMB hardening updates." `
            -File "SMB"
    }
}
if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            path = [string]$_.Path
            description = [string]$_.Description
            special = [bool]$_.Special
        }
    })
    foreach ($share in $shares) {
        if ([string]::IsNullOrWhiteSpace([string]$share.path)) { continue }
        if (Test-SuspiciousPath ([string]$share.path) -or [string]$share.path -match '^[A-Z]:\\?$') {
            $findings += New-Finding -Id "triage-win-net-share-$((Get-Sha256Hex ([string]$share.name).Substring(0, 12)))" `
                -RuleId "network.smb_share.sensitive_path" -Title "SMB share exposes a sensitive path: $($share.name)" `
                -Severity "high" -Category "network_anomaly" -Confidence "medium" `
                -Evidence "Share $($share.name) -> $($share.path) special=$($share.special)" `
                -Remediation "Remove or restrict the share and review SMB permissions for least privilege." -File ([string]$share.path)
        }
    }
}
if (Get-Command Get-SmbSession -ErrorAction SilentlyContinue) {
    $smbSessions = @(Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            client = [string]$_.ClientComputerName
            user = [string]$_.ClientUserName
            opens = [int]$_.NumOpens
            dialect = [string]$_.Dialect
        }
    })
}

$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpDeny = (Get-ItemProperty -Path $rdpPath -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
$rdpNla = (Get-ItemProperty -Path "$rdpPath\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
$rdpPort = (Get-ItemProperty -Path "$rdpPath\WinStations\RDP-Tcp" -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
$rdpEnabled = ([string]$rdpDeny -eq '0')
if ($rdpEnabled -and [string]$rdpNla -ne '1') {
    $findings += New-Finding -Id "triage-win-net-rdp-nla" -RuleId "network.rdp.nla_disabled" `
        -Title "Remote Desktop is enabled without Network Level Authentication" -Severity "high" -Category "configuration" `
        -Evidence "fDenyTSConnections=$rdpDeny UserAuthentication=$rdpNla PortNumber=$rdpPort." `
        -Remediation "Require NLA for RDP, restrict access through a gateway or VPN, and enforce MFA." `
        -File $rdpPath
}

$winrmAuth = [ordered]@{}
foreach ($name in @("Basic", "Kerberos", "Negotiate", "Certificate", "CredSSP")) {
    try {
        $item = Get-Item -Path "WSMan:\localhost\Service\Auth\$name" -ErrorAction Stop
        $winrmAuth[$name.ToLower()] = [string]$item.Value
    } catch { }
}
$winrmAllowUnencrypted = ""
try {
    $winrmAllowUnencrypted = [string](Get-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -ErrorAction Stop).Value
    $winrmAuth["allow_unencrypted"] = $winrmAllowUnencrypted
} catch { }
$winrmListeners = @()
try {
    $winrmListeners = @(Get-ChildItem -Path "WSMan:\localhost\Listener" -ErrorAction Stop | ForEach-Object {
        [ordered]@{ keys = [string]$_.Keys }
    })
} catch { }
if ([string]$winrmAuth["basic"] -eq 'true' -or $winrmAllowUnencrypted -eq 'true') {
    $findings += New-Finding -Id "triage-win-net-winrm-insecure" -RuleId "network.winrm.insecure_auth" `
        -Title "WinRM allows Basic authentication or unencrypted traffic" -Severity "high" -Category "configuration" `
        -Evidence "Basic=$($winrmAuth['basic']) AllowUnencrypted=$winrmAllowUnencrypted." `
        -Remediation "Disable Basic authentication and unencrypted WinRM; require Kerberos/Negotiate over HTTPS." `
        -File "WinRM"
}

$portProxyLines = @()
foreach ($family in @("v4tov4", "v6tov4", "v4tov6", "v6tov6")) {
    foreach ($line in @(netsh interface portproxy show $family 2>$null)) {
        $text = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($text -match '^(Listen|Address|-----|Listen on|Connect to)') { continue }
        if ($text -match '^\d') { $portProxyLines += "$family $text" }
    }
}
$portProxy = @($portProxyLines)
if ($portProxy.Count -gt 0) {
    $findings += New-Finding -Id "triage-win-net-portproxy" -RuleId "network.port_proxy.configured" `
        -Title "Netsh port proxy rules are configured" -Severity "high" -Category "network_anomaly" -Confidence "medium" `
        -Evidence "Rules: $($portProxy -join '; ')" `
        -Remediation "Remove unauthorized port-proxy rules and identify the process or administrator that created them." `
        -File "netsh portproxy"
}

# ------------------------------------------------------------------------------
# 5. Proxy configuration
# ------------------------------------------------------------------------------
$proxyKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$proxyEnable = (Get-ItemProperty -Path $proxyKey -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
$proxyServer = [string](Get-ItemProperty -Path $proxyKey -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
$autoConfigUrl = [string](Get-ItemProperty -Path $proxyKey -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
$winhttpProxy = @(netsh winhttp show proxy 2>$null | ForEach-Object { (Limit-Text ([string]$_) 300) })

# ------------------------------------------------------------------------------
# 6. Report assembly
# ------------------------------------------------------------------------------
$publicEstablished = @($established | Where-Object { $_.remote_public })
$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    metrics = [ordered]@{
        interfaces = $interfaces.Count
        dns_servers = $dnsServers.Count
        dns_cache_entries = $dnsCache.Count
        routes = $routes.Count
        neighbors = $neighbors.Count
        connections = $connections.Count
        listeners = $listeners.Count
        established = $established.Count
        public_established = $publicEstablished.Count
        hosts_entries = $hostsEntries.Count
        firewall_profiles = $fwProfiles.Count
        smb_shares = $shares.Count
        smb_sessions = $smbSessions.Count
        port_proxy_rules = $portProxy.Count
        findings = $findings.Count
    }
    interfaces = @($interfaces)
    dns_servers = @($dnsServers)
    dns_cache = @($dnsCache)
    routes = @($routes)
    neighbors = @($neighbors)
    listeners = @($listeners)
    established_connections = @($established)
    hosts_entries = @($hostsEntries)
    firewall_profiles = @($fwProfiles)
    smb = [ordered]@{
        smb1_enabled = $smb1Enabled
        shares = @($shares)
        sessions = @($smbSessions)
    }
    rdp = [ordered]@{
        enabled = $rdpEnabled
        nla_required = ([string]$rdpNla -eq '1')
        port = [string]$rdpPort
    }
    winrm = [ordered]@{
        auth = $winrmAuth
        listeners = @($winrmListeners)
    }
    port_proxy = @($portProxy)
    proxy = [ordered]@{
        enabled = [string]$proxyEnable
        server = $proxyServer
        auto_config_url = $autoConfigUrl
        winhttp = @($winhttpProxy)
    }
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Network forensics report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
