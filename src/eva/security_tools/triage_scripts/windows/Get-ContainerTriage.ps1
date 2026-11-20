<#
.SYNOPSIS
    Windows Container and WSL Security Triage (EVA Sec compatible).
.DESCRIPTION
    Read-only assessment of container and Linux subsystem exposure on Windows:
    - Docker CLI/daemon state, contexts and insecure remote API settings
    - Docker Desktop TCP API exposure and daemon.json configuration
    - Containers with privileged mode, host namespaces, added capabilities,
      Docker socket mounts, sensitive host mounts or unconfined profiles
    - WSL distro inventory, WSL1 isolation and .wslconfig settings
    - Windows container inventory and container-related services
    Outputs `eva.triage.v1` JSON ingestible by `eva sec ingest`.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
.PARAMETER MaxContainers
    Maximum containers inspected through Docker (default 100).
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "",
    [int]$MaxContainers = 100
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-containers'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$containers = @()
$contexts = @()
$networks = @()
$distros = @()
$wslConfig = @()
$windowsContainers = @()
$services = @()
$daemonConfigs = @()
$desktopSettings = @()
$dockerInfo = $null
$dockerVersion = $null
$dockerCliAvailable = $false
$dockerDaemonAvailable = $false
$wslAvailable = $false
$wslStatus = @()

$MaxContainers = [math]::Max(1, [math]::Min(1000, $MaxContainers))

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
        [string]$Category = "container",
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

function Invoke-NativeCommand {
    param([string]$FilePath, [string[]]$Arguments = @())
    try {
        $output = @(& $FilePath @Arguments 2>$null)
        if ($LASTEXITCODE -ne 0) { return @() }
        return $output
    } catch {
        return @()
    }
}

function Clean-NativeOutput {
    param($Lines)
    return @($Lines | ForEach-Object {
        (([string]$_) -replace "`0", "") -replace "`r", ""
    } | ForEach-Object { $_.TrimEnd() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function ConvertFrom-JsonSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Test-SensitiveMount {
    param([string]$Source)
    if ([string]::IsNullOrWhiteSpace($Source)) { return $false }
    $normalized = $Source.TrimEnd('\', '/')
    if ($normalized -match '(?i)^[A-Z]:$') { return $true }
    if ($normalized -match '(?i)^[A-Z]:\\(Windows|Users|Program Files|ProgramData)$') { return $true }
    return ($normalized -match '(?i)^(?:/|/etc|/var/run|/run|/proc|/sys|/dev|/root|/home|/boot)$')
}

# ------------------------------------------------------------------------------
# 1. Docker daemon, configuration and contexts
# ------------------------------------------------------------------------------
$dockerCliAvailable = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
if ($dockerCliAvailable) {
    $infoRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("info", "--format", "{{json .}}")
    if ($infoRaw.Count -gt 0) {
        $dockerInfo = ConvertFrom-JsonSafe (($infoRaw | ForEach-Object { [string]$_ }) -join "`n")
        $dockerDaemonAvailable = ($null -ne $dockerInfo)
    }
    $versionRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("version", "--format", "{{json .}}")
    if ($versionRaw.Count -gt 0) {
        $dockerVersion = ConvertFrom-JsonSafe (($versionRaw | ForEach-Object { [string]$_ }) -join "`n")
    }
    $contextRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("context", "ls", "--format", "{{json .}}")
    $currentContext = ""
    $currentContextRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("context", "show")
    if ($currentContextRaw.Count -gt 0) { $currentContext = ([string]$currentContextRaw[0]).Trim() }
    foreach ($line in $contextRaw) {
        $context = ConvertFrom-JsonSafe ([string]$line)
        if ($null -ne $context) {
            $contexts += [ordered]@{
                name = [string]$context.Name
                description = [string]$context.Description
                docker_endpoint = [string]$context.DockerEndpoint
                current = ([string]$context.Name -eq $currentContext)
            }
        }
    }
    $networkRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("network", "ls", "--format", "{{json .}}")
    foreach ($line in $networkRaw) {
        $network = ConvertFrom-JsonSafe ([string]$line)
        if ($null -ne $network) {
            $networks += [ordered]@{
                name = [string]$network.Name
                driver = [string]$network.Driver
                scope = [string]$network.Scope
            }
        }
    }
}

$daemonPaths = @(
    "$env:ProgramData\docker\config\daemon.json",
    (Join-Path $env:USERPROFILE ".docker\daemon.json")
)
foreach ($path in ($daemonPaths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
    $config = ConvertFrom-JsonSafe $raw
    $hosts = @()
    $insecureRegistries = @()
    $tlsVerify = $false
    if ($null -ne $config) {
        if ($null -ne $config.hosts) { $hosts = @($config.hosts) }
        if ($null -ne $config.'insecure-registries') { $insecureRegistries = @($config.'insecure-registries') }
        if ($null -ne $config.'tlsverify') { $tlsVerify = [bool]$config.'tlsverify' }
    }
    $daemonConfigs += [ordered]@{
        path = $path
        hosts = @($hosts)
        insecure_registries = @($insecureRegistries)
        tlsverify = $tlsVerify
        parsed = ($null -ne $config)
    }
    $remoteHosts = @($hosts | Where-Object { [string]$_ -match '(?i)tcp://' })
    if ($remoteHosts.Count -gt 0 -and -not $tlsVerify) {
        $findings += New-Finding -Id "triage-win-container-daemon-tcp-$((Get-Sha256Hex $path).Substring(0, 12))" `
            -RuleId "container.docker.remote_api_without_tls" `
            -Title "Docker daemon exposes a TCP API without TLS verification" -Severity "critical" -Category "container" `
            -Evidence "Config: $path Hosts: $($remoteHosts -join ', ') tlsverify=$tlsVerify" `
            -Remediation "Remove unauthenticated TCP listeners or require mutual TLS and restrict the API to trusted management networks." `
            -File $path
    }
    if ($insecureRegistries.Count -gt 0) {
        $findings += New-Finding -Id "triage-win-container-daemon-registry-$((Get-Sha256Hex $path).Substring(0, 12))" `
            -RuleId "container.docker.insecure_registry" `
            -Title "Docker is configured to trust insecure registries" -Severity "high" -Category "container" `
            -Evidence "Config: $path Insecure registries: $($insecureRegistries -join ', ')" `
            -Remediation "Use TLS-verified registries and remove insecure-registries entries." -File $path
    }
}

$desktopPaths = @(
    (Join-Path $env:APPDATA "Docker\settings-store.json"),
    (Join-Path $env:APPDATA "Docker\settings.json")
)
foreach ($path in ($desktopPaths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
    $settings = ConvertFrom-JsonSafe $raw
    if ($null -eq $settings) { continue }
    $exposeApi = $false
    if ($null -ne $settings.ExposeDockerAPIOnTCP2375) { $exposeApi = [bool]$settings.ExposeDockerAPIOnTCP2375 }
    $desktopSettings += [ordered]@{
        path = $path
        expose_docker_api_on_tcp2375 = $exposeApi
    }
    if ($exposeApi) {
        $findings += New-Finding -Id "triage-win-container-desktop-api" -RuleId "container.docker.desktop_api_exposed" `
            -Title "Docker Desktop exposes the Engine API on TCP 2375" -Severity "critical" -Category "container" `
            -Evidence "Setting ExposeDockerAPIOnTCP2375=true in $path. The API is unauthenticated by default." `
            -Remediation "Disable the TCP API in Docker Desktop settings and use the local named pipe or WSL integration." `
            -File $path
    }
}

$currentContextEndpoints = @($contexts | Where-Object { $_.current -and $_.docker_endpoint -match '(?i)tcp://' })
foreach ($context in $currentContextEndpoints) {
    $findings += New-Finding -Id "triage-win-container-context-$((Get-Sha256Hex ([string]$context.name)).Substring(0, 12))" `
        -RuleId "container.docker.remote_context" -Title "Docker context points to a remote TCP daemon" `
        -Severity "medium" -Category "container" -Confidence "medium" `
        -Evidence "Context $($context.name) endpoint $($context.docker_endpoint)." `
        -Remediation "Verify the remote daemon is TLS-protected and authorized; prefer local contexts for endpoint triage." `
        -File "Docker context"
}

# ------------------------------------------------------------------------------
# 2. Container configuration and escape risk
# ------------------------------------------------------------------------------
if ($dockerDaemonAvailable) {
    $containerIds = @(Invoke-NativeCommand -FilePath "docker" -Arguments @("ps", "-aq", "--no-trunc") | Select-Object -First $MaxContainers)
    foreach ($containerId in $containerIds) {
        $id = ([string]$containerId).Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $inspectRaw = Invoke-NativeCommand -FilePath "docker" -Arguments @("inspect", $id)
        $inspect = ConvertFrom-JsonSafe (($inspectRaw | ForEach-Object { [string]$_ }) -join "`n")
        if ($null -eq $inspect) { continue }
        $c = @($inspect)[0]
        if ($null -eq $c) { continue }

        $name = ([string]$c.Name).TrimStart('/')
        $image = [string]$c.Config.Image
        $running = [bool]$c.State.Running
        $privileged = [bool]$c.HostConfig.Privileged
        $networkMode = [string]$c.HostConfig.NetworkMode
        $pidMode = [string]$c.HostConfig.PidMode
        $ipcMode = [string]$c.HostConfig.IpcMode
        $user = [string]$c.Config.User
        $capAdd = @($c.HostConfig.CapAdd | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        $securityOpt = @($c.HostConfig.SecurityOpt | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        $mounts = @()
        foreach ($mount in @($c.Mounts)) {
            if ($null -eq $mount) { continue }
            $mounts += [ordered]@{
                type = [string]$mount.Type
                source = [string]$mount.Source
                destination = [string]$mount.Destination
                read_write = [bool]$mount.RW
            }
        }
        $binds = @($c.HostConfig.Binds | Where-Object { $null -ne $_ } | ForEach-Object { Limit-Text ([string]$_) 400 })

        $container = [ordered]@{
            id = $id.Substring(0, [math]::Min(12, $id.Length))
            name = $name
            image = $image
            running = $running
            user = $user
            privileged = $privileged
            network_mode = $networkMode
            pid_mode = $pidMode
            ipc_mode = $ipcMode
            cap_add = @($capAdd)
            security_opt = @($securityOpt)
            mounts = @($mounts)
            binds = @($binds)
            readonly_rootfs = [bool]$c.HostConfig.ReadonlyRootfs
        }
        $containers += $container

        $idSuffix = (Get-Sha256Hex "$id|$name").Substring(0, 12)
        if ($privileged) {
            $findings += New-Finding -Id "triage-win-container-privileged-$idSuffix" -RuleId "container.privileged" `
                -Title "Privileged container is present: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name ($id) runs with HostConfig.Privileged=true." `
                -Remediation "Remove privileged mode and grant only the specific capabilities the workload requires." `
                -File "docker:$name"
        }
        if ($networkMode -match '(?i)^host$') {
            $findings += New-Finding -Id "triage-win-container-hostnet-$idSuffix" -RuleId "container.host_network" `
                -Title "Container shares the host network namespace: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name network mode is host." `
                -Remediation "Use a dedicated bridge or overlay network and publish only required ports." -File "docker:$name"
        }
        if ($pidMode -match '(?i)^host$') {
            $findings += New-Finding -Id "triage-win-container-hostpid-$idSuffix" -RuleId "container.host_pid" `
                -Title "Container shares the host PID namespace: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name PID mode is host." `
                -Remediation "Remove host PID sharing and isolate process visibility." -File "docker:$name"
        }
        if ($ipcMode -match '(?i)^host$') {
            $findings += New-Finding -Id "triage-win-container-hostipc-$idSuffix" -RuleId "container.host_ipc" `
                -Title "Container shares the host IPC namespace: $name" -Severity "medium" -Category "container" `
                -Evidence "Container $name IPC mode is host." `
                -Remediation "Remove host IPC sharing unless a documented workload requirement exists." -File "docker:$name"
        }

        $socketMount = $false
        $sensitiveMount = $false
        $sensitiveSources = @()
        foreach ($mount in $mounts) {
            $source = [string]$mount.source
            if ($source -match '(?i)(docker\.sock|docker_engine|containerd\.sock)') {
                $socketMount = $true
            }
            if (Test-SensitiveMount $source) {
                $sensitiveMount = $true
                $sensitiveSources += "$source -> $($mount.destination)"
            }
        }
        if ($socketMount) {
            $findings += New-Finding -Id "triage-win-container-socket-$idSuffix" -RuleId "container.runtime_socket_mount" `
                -Title "Container mounts a container runtime socket: $name" -Severity "critical" -Category "container" `
                -Evidence "Container $name mounts a Docker/containerd socket. Mounts: $($mounts | ForEach-Object { "$($_.source) -> $($_.destination)" } | Select-Object -First 10)" `
                -Remediation "Remove runtime socket mounts; use a restricted API proxy or sidecar with least privilege." `
                -File "docker:$name"
        }
        if ($sensitiveMount) {
            $findings += New-Finding -Id "triage-win-container-mount-$idSuffix" -RuleId "container.sensitive_host_mount" `
                -Title "Container mounts a sensitive host path: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name mounts: $($sensitiveSources -join '; ')" `
                -Remediation "Remove broad host mounts and mount only the narrowest required directory read-only." `
                -File "docker:$name"
        }
        $dangerousCaps = @($capAdd | Where-Object { $_ -match '(?i)^(SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH|ALL)$' })
        if ($dangerousCaps.Count -gt 0) {
            $findings += New-Finding -Id "triage-win-container-caps-$idSuffix" -RuleId "container.dangerous_capability" `
                -Title "Container has dangerous Linux capabilities: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name CapAdd: $($dangerousCaps -join ', ')" `
                -Remediation "Drop all capabilities and add back only the minimum required set." -File "docker:$name"
        }
        if (($securityOpt -join ' ') -match '(?i)(seccomp=unconfined|apparmor=unconfined|label=disable)') {
            $findings += New-Finding -Id "triage-win-container-unconfined-$idSuffix" -RuleId "container.mac_unconfined" `
                -Title "Container disables a mandatory access control profile: $name" -Severity "high" -Category "container" `
                -Evidence "Container $name SecurityOpt: $($securityOpt -join ', ')" `
                -Remediation "Remove unconfined seccomp/AppArmor/SELinux options and use the default profiles." -File "docker:$name"
        }
    }
}

# ------------------------------------------------------------------------------
# 3. WSL inventory and configuration
# ------------------------------------------------------------------------------
$wslAvailable = $null -ne (Get-Command wsl.exe -ErrorAction SilentlyContinue)
$wslFeature = $null
try {
    $feature = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='Microsoft-Windows-Subsystem-Linux'" -ErrorAction SilentlyContinue
    if ($null -ne $feature) {
        $wslFeature = [ordered]@{
            name = [string]$feature.Name
            install_state = [int]$feature.InstallState
        }
    }
} catch { }

if ($wslAvailable) {
    $wslStatus = @(Clean-NativeOutput (Invoke-NativeCommand -FilePath "wsl.exe" -Arguments @("--status")))
    $verboseLines = @(Clean-NativeOutput (Invoke-NativeCommand -FilePath "wsl.exe" -Arguments @("--list", "--verbose")))
    foreach ($line in $verboseLines) {
        if ($line -match '^\s*(\*)?\s*(.+?)\s{2,}(Running|Stopped|Installing|Uninstalling)\s+(\d+)\s*$') {
            $distros += [ordered]@{
                name = $matches[2].Trim()
                state = $matches[3]
                version = [int]$matches[4]
                default = ($matches[1] -eq '*')
            }
        }
    }
    foreach ($distro in $distros) {
        if ([int]$distro.version -eq 1) {
            $findings += New-Finding -Id "triage-win-wsl1-$((Get-Sha256Hex $distro.name).Substring(0, 12))" `
                -RuleId "container.wsl.version1" -Title "WSL1 distribution has weaker isolation: $($distro.name)" `
                -Severity "medium" -Category "container" -Confidence "medium" `
                -Evidence "WSL distro $($distro.name) runs version 1, which uses a translation layer instead of a managed VM." `
                -Remediation "Migrate the distribution to WSL2 with wsl --set-version after validating compatibility." `
                -File "WSL"
        }
    }
    $wslConfigPath = Join-Path $env:USERPROFILE ".wslconfig"
    if (Test-Path -LiteralPath $wslConfigPath -PathType Leaf) {
        $wslConfig = @(Get-Content -LiteralPath $wslConfigPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#;]' } | ForEach-Object { Limit-Text ([string]$_) 300 })
    }
}

# ------------------------------------------------------------------------------
# 4. Windows containers and related services
# ------------------------------------------------------------------------------
if (Get-Command Get-Container -ErrorAction SilentlyContinue) {
    $windowsContainers = @(Get-Container -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            state = [string]$_.State
            image = [string]$_.ImageName
            owner = [string]$_.Owner
        }
    })
}
$serviceNames = @("docker", "com.docker.service", "containerd", "LxssManager", "vmcompute")
foreach ($serviceName in $serviceNames) {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $services += [ordered]@{
            name = [string]$svc.Name
            status = [string]$svc.Status
            display_name = [string]$svc.DisplayName
        }
    }
}

# ------------------------------------------------------------------------------
# 5. Report assembly
# ------------------------------------------------------------------------------
$dockerInfoReport = $null
if ($null -ne $dockerInfo) {
    $dockerInfoReport = [ordered]@{
        server_version = [string]$dockerInfo.ServerVersion
        operating_system = [string]$dockerInfo.OperatingSystem
        os_type = [string]$dockerInfo.OSType
        architecture = [string]$dockerInfo.Architecture
        docker_root_dir = [string]$dockerInfo.DockerRootDir
        security_options = @($dockerInfo.SecurityOptions)
        live_restore_enabled = [bool]$dockerInfo.LiveRestoreEnabled
    }
}
$dockerVersionReport = $null
if ($null -ne $dockerVersion) {
    $dockerVersionReport = $dockerVersion
}

$report = [ordered]@{
    schema = "eva.triage.v1"
    tool = $script:ToolName
    collected_at = $now
    host = [ordered]@{
        hostname = $script:Hostname
    }
    docker = [ordered]@{
        cli_available = $dockerCliAvailable
        daemon_available = $dockerDaemonAvailable
        info = $dockerInfoReport
        version = $dockerVersionReport
        daemon_configs = @($daemonConfigs)
        desktop_settings = @($desktopSettings)
        contexts = @($contexts)
        networks = @($networks)
    }
    containers = @($containers)
    wsl = [ordered]@{
        available = $wslAvailable
        feature = $wslFeature
        status = @($wslStatus)
        distros = @($distros)
        config = @($wslConfig)
    }
    windows_containers = @($windowsContainers)
    services = @($services)
    metrics = [ordered]@{
        containers = $containers.Count
        privileged_containers = @($containers | Where-Object { $_.privileged }).Count
        wsl_distros = $distros.Count
        windows_containers = $windowsContainers.Count
        findings = $findings.Count
    }
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 10
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Container/WSL report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
