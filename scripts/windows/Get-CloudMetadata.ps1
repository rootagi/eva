<#
.SYNOPSIS
    Cloud Instance Metadata Exposure Triage for Windows (EVA Sec compatible).
.DESCRIPTION
    Queries only link-local cloud metadata services and reports identity and
    exposure facts without retrieving secrets:
    - AWS EC2 IMDSv2 support and IMDSv1 fallback reachability
    - GCP compute metadata and attached service account identity
    - Azure instance metadata and user-data presence
    - User-data/startup-script SHA-256 only (content is never emitted)
    - Ambient credential environment variable names (values are never read)
    No public Internet requests are made and HTTP redirects are not followed.
.PARAMETER OutputFile
    Optional path to write the JSON report. When omitted, JSON is written to stdout.
#>
[CmdletBinding()]
param(
    [string]$OutputFile = ""
)

$ErrorActionPreference = 'SilentlyContinue'
$script:ToolName = 'triage-windows-cloud'
$script:Hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$findings = @()
$provider = "unknown"
$imdsv1Enabled = $false
$imdsv2Enabled = $false
$metadata = [ordered]@{}

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
        [string]$Category = "cloud",
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

function Invoke-MetadataRequest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [int]$TimeoutMs = 2000
    )
    $request = $null
    $response = $null
    $reader = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create($Uri)
        $request.Method = $Method
        $request.Proxy = $null
        $request.Timeout = $TimeoutMs
        $request.ReadWriteTimeout = $TimeoutMs
        $request.AllowAutoRedirect = $false
        $request.UserAgent = "eva-triage/1.0"
        foreach ($key in $Headers.Keys) {
            $request.Headers[[string]$key] = [string]$Headers[$key]
        }
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        return $body.Trim()
    } catch {
        return $null
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

function Get-MetadataValue {
    param([string]$Uri, [hashtable]$Headers = @{})
    $value = Invoke-MetadataRequest -Uri $Uri -Headers $Headers
    if ($null -eq $value) { return "" }
    return (Limit-Text $value 2000)
}

function Get-MetadataRaw {
    param([string]$Uri, [hashtable]$Headers = @{})
    $value = Invoke-MetadataRequest -Uri $Uri -Headers $Headers
    if ($null -eq $value) { return "" }
    return ([string]$value)
}

# ------------------------------------------------------------------------------
# 1. AWS EC2 metadata (IMDSv2 preferred, unauthenticated IMDSv1 detected)
# ------------------------------------------------------------------------------
$awsBase = "http://169.254.169.254/latest"
$awsToken = Invoke-MetadataRequest -Uri "$awsBase/api/token" -Method "PUT" -Headers @{
    "X-aws-ec2-metadata-token-ttl-seconds" = "60"
}
if (-not [string]::IsNullOrWhiteSpace([string]$awsToken)) {
    $imdsv2Enabled = $true
    $awsHeaders = @{ "X-aws-ec2-metadata-token" = [string]$awsToken }
    $awsInstanceId = Get-MetadataValue -Uri "$awsBase/meta-data/instance-id" -Headers $awsHeaders
} else {
    $awsHeaders = @{}
    $awsInstanceId = Get-MetadataValue -Uri "$awsBase/meta-data/instance-id"
}

if (-not [string]::IsNullOrWhiteSpace($awsInstanceId)) {
    $provider = "aws"
    $region = Get-MetadataValue -Uri "$awsBase/meta-data/placement/region" -Headers $awsHeaders
    $zone = Get-MetadataValue -Uri "$awsBase/meta-data/placement/availability-zone" -Headers $awsHeaders
    $machineType = Get-MetadataValue -Uri "$awsBase/meta-data/instance-type" -Headers $awsHeaders
    $privateIp = Get-MetadataValue -Uri "$awsBase/meta-data/local-ipv4" -Headers $awsHeaders
    $publicIp = Get-MetadataValue -Uri "$awsBase/meta-data/public-ipv4" -Headers $awsHeaders
    $role = Get-MetadataValue -Uri "$awsBase/meta-data/iam/security-credentials/" -Headers $awsHeaders
    $userData = Get-MetadataRaw -Uri "$awsBase/user-data" -Headers $awsHeaders
    $userDataBytes = 0
    $userDataSha256 = ""
    if (-not [string]::IsNullOrWhiteSpace($userData)) {
        $userDataBytes = [System.Text.Encoding]::UTF8.GetByteCount($userData)
        $userDataSha256 = Get-Sha256Hex $userData
    }

    $identityDocument = Invoke-MetadataRequest -Uri "$awsBase/dynamic/instance-identity/document" -Headers $awsHeaders
    $accountId = ""
    $imageId = ""
    $architecture = ""
    if (-not [string]::IsNullOrWhiteSpace([string]$identityDocument)) {
        try {
            $identity = $identityDocument | ConvertFrom-Json
            $accountId = [string]$identity.accountId
            $imageId = [string]$identity.imageId
            $architecture = [string]$identity.architecture
        } catch { }
    }

    $imdsV1Check = Invoke-MetadataRequest -Uri "$awsBase/meta-data/instance-id"
    if (-not [string]::IsNullOrWhiteSpace([string]$imdsV1Check)) {
        $imdsv1Enabled = $true
        $severity = "high"
        $confidence = "high"
        if ($imdsv2Enabled) {
            $severity = "medium"
            $confidence = "high"
        }
        $findings += New-Finding -Id "triage-win-cloud-aws-imdsv1" -RuleId "cloud.aws.imdsv1_enabled" `
            -Title "AWS IMDSv1 metadata is reachable without a session token" -Severity $severity -Category "cloud" -Confidence $confidence `
            -Evidence "The unauthenticated IMDSv1 endpoint returned instance metadata. IMDSv2 token support=$imdsv2Enabled." `
            -Remediation "Set EC2 instance metadata options to HttpTokens=required (IMDSv2 only) and HttpPutResponseHopLimit=1." `
            -File "AWS IMDS"
    }

    if ($userDataBytes -gt 0) {
        $findings += New-Finding -Id "triage-win-cloud-aws-userdata" -RuleId "cloud.instance.user_data_present" `
            -Title "AWS instance user-data is present" -Severity "low" -Category "cloud" -Confidence "medium" `
            -Evidence "User-data bytes=$userDataBytes sha256=$userDataSha256 (content intentionally not emitted)." `
            -Remediation "Review user-data for embedded credentials and move secrets to a managed secret store." `
            -File "AWS user-data"
    }

    $metadata = [ordered]@{
        instance_id = $awsInstanceId
        region = $region
        availability_zone = $zone
        instance_type = $machineType
        private_ip = $privateIp
        public_ip = $publicIp
        iam_role = $role
        account_id = $accountId
        image_id = $imageId
        architecture = $architecture
        user_data_bytes = $userDataBytes
        user_data_sha256 = $userDataSha256
    }
}

# ------------------------------------------------------------------------------
# 2. GCP compute metadata
# ------------------------------------------------------------------------------
if ($provider -eq "unknown") {
    $gcpHeaders = @{ "Metadata-Flavor" = "Google" }
    $gcpBase = "http://metadata.google.internal/computeMetadata/v1"
    $gcpInstanceId = Get-MetadataValue -Uri "$gcpBase/instance/id" -Headers $gcpHeaders
    if (-not [string]::IsNullOrWhiteSpace($gcpInstanceId)) {
        $provider = "gcp"
        $project = Get-MetadataValue -Uri "$gcpBase/project/project-id" -Headers $gcpHeaders
        $region = Get-MetadataValue -Uri "$gcpBase/instance/region" -Headers $gcpHeaders
        $zone = Get-MetadataValue -Uri "$gcpBase/instance/zone" -Headers $gcpHeaders
        $machineType = Get-MetadataValue -Uri "$gcpBase/instance/machine-type" -Headers $gcpHeaders
        $privateIp = Get-MetadataValue -Uri "$gcpBase/instance/network-interfaces/0/ip" -Headers $gcpHeaders
        $serviceAccounts = Get-MetadataValue -Uri "$gcpBase/instance/service-accounts/" -Headers $gcpHeaders
        $startupScript = Get-MetadataRaw -Uri "$gcpBase/instance/attributes/startup-script" -Headers $gcpHeaders
        $startupScriptBytes = 0
        $startupScriptSha256 = ""
        if (-not [string]::IsNullOrWhiteSpace($startupScript)) {
            $startupScriptBytes = [System.Text.Encoding]::UTF8.GetByteCount($startupScript)
            $startupScriptSha256 = Get-Sha256Hex $startupScript
        }
        $metadata = [ordered]@{
            instance_id = $gcpInstanceId
            project = $project
            region = ($region -replace '.*/', '')
            zone = ($zone -replace '.*/', '')
            machine_type = ($machineType -replace '.*/', '')
            private_ip = $privateIp
            service_accounts = $serviceAccounts
            startup_script_bytes = $startupScriptBytes
            startup_script_sha256 = $startupScriptSha256
        }
        if ($startupScriptBytes -gt 0) {
            $findings += New-Finding -Id "triage-win-cloud-gcp-startup" -RuleId "cloud.instance.user_data_present" `
                -Title "GCP instance startup script is present" -Severity "low" -Category "cloud" -Confidence "medium" `
                -Evidence "Startup script bytes=$startupScriptBytes sha256=$startupScriptSha256 (content intentionally not emitted)." `
                -Remediation "Review startup scripts for embedded credentials and restrict metadata access with network policy." `
                -File "GCP startup-script"
        }
    }
}

# ------------------------------------------------------------------------------
# 3. Azure instance metadata
# ------------------------------------------------------------------------------
if ($provider -eq "unknown") {
    $azureHeaders = @{ "Metadata" = "true" }
    $azureBase = "http://169.254.169.254/metadata/instance"
    $azureRaw = Invoke-MetadataRequest -Uri "$azureBase?api-version=2021-02-01" -Headers $azureHeaders
    if (-not [string]::IsNullOrWhiteSpace([string]$azureRaw)) {
        try {
            $azure = $azureRaw | ConvertFrom-Json
            if ($null -ne $azure.compute.vmId) {
                $provider = "azure"
                $privateIp = ""
                $publicIp = ""
                try {
                    $privateIp = [string]$azure.network.'interface'[0].ipv4.ipAddress[0].privateIpAddress
                    $publicIp = [string]$azure.network.'interface'[0].ipv4.ipAddress[0].publicIpAddress
                } catch { }
                $azureUserData = Invoke-MetadataRequest -Uri "$azureBase/compute/userData?api-version=2021-02-01&format=text" -Headers $azureHeaders
                $userDataBytes = 0
                $userDataSha256 = ""
                if (-not [string]::IsNullOrWhiteSpace([string]$azureUserData)) {
                    $userDataBytes = [System.Text.Encoding]::UTF8.GetByteCount([string]$azureUserData)
                    $userDataSha256 = Get-Sha256Hex ([string]$azureUserData)
                }
                $metadata = [ordered]@{
                    instance_id = [string]$azure.compute.vmId
                    name = [string]$azure.compute.name
                    location = [string]$azure.compute.location
                    zone = [string]$azure.compute.zone
                    vm_size = [string]$azure.compute.vmSize
                    resource_group = [string]$azure.compute.resourceGroupName
                    offer = [string]$azure.compute.offer
                    private_ip = $privateIp
                    public_ip = $publicIp
                    user_data_bytes = $userDataBytes
                    user_data_sha256 = $userDataSha256
                }
                if ($userDataBytes -gt 0) {
                    $findings += New-Finding -Id "triage-win-cloud-azure-userdata" -RuleId "cloud.instance.user_data_present" `
                        -Title "Azure instance user-data is present" -Severity "low" -Category "cloud" -Confidence "medium" `
                        -Evidence "User-data bytes=$userDataBytes sha256=$userDataSha256 (content intentionally not emitted)." `
                        -Remediation "Review user-data for embedded credentials and move secrets to Key Vault or a managed identity." `
                        -File "Azure user-data"
                }
            }
        } catch { }
    }
}

# ------------------------------------------------------------------------------
# 4. Ambient credential and managed-identity environment variables
# ------------------------------------------------------------------------------
$ambientNames = @()
foreach ($name in @("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS")) {
    $value = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        $ambientNames += $name
    }
}
$identityEnvironment = @()
foreach ($name in @("IDENTITY_ENDPOINT", "IDENTITY_HEADER", "MSI_ENDPOINT", "MSI_SECRET")) {
    $value = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        $identityEnvironment += $name
    }
}
if ($ambientNames.Count -gt 0) {
    $findings += New-Finding -Id "triage-win-cloud-ambient-credentials" -RuleId "cloud.credentials.process_environment" `
        -Title "Cloud credential environment variables are present" -Severity "medium" -Category "credential_exposure" -Confidence "medium" `
        -Evidence "Variable names present: $($ambientNames -join ', '). Values were not read or emitted." `
        -Remediation "Move long-lived cloud credentials to a managed identity or secret store and restart dependent services." `
        -File "Process environment"
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
    cloud = [ordered]@{
        provider = $provider
        imdsv2_supported = $imdsv2Enabled
        imdsv1_enabled = $imdsv1Enabled
        metadata = $metadata
    }
    ambient_credentials = @($ambientNames)
    identity_environment = @($identityEnvironment)
    metrics = [ordered]@{
        provider_detected = ($provider -ne "unknown")
        ambient_credential_variables = $ambientNames.Count
        managed_identity_variables = $identityEnvironment.Count
        findings = $findings.Count
    }
    findings = @($findings)
}

$jsonOutput = $report | ConvertTo-Json -Depth 8
if ($OutputFile) {
    [System.IO.File]::WriteAllText($OutputFile, $jsonOutput, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[+] Cloud metadata report saved to $OutputFile"
} else {
    Write-Output $jsonOutput
}
