#!/bin/sh
# ==============================================================================
# Linux Cloud Instance Metadata Triage (EVA Sec compatible)
# Queries only the local cloud metadata service (link-local address) and
# reports identity, placement and exposure facts:
#   - AWS EC2 IMDSv2 support and IMDSv1 fallback status
#   - GCP compute metadata and attached service account
#   - Azure instance metadata
#   - User-data presence and hash (raw user-data is never emitted)
#
# No public Internet requests are made. Emits `eva.triage.v1` JSON.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-cloud"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")
DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "unknown")
DMI_PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "unknown")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-cloud.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
: > "$TMP_FINDINGS"

cleanup() {
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

json_escape() {
    printf '%s' "${1:-}" | tr '\n\r\t' '   ' | sed -e 's/[[:cntrl:]]/ /g' -e 's/\\/\\\\/g' -e 's/"/\\"/g' | cut -c1-4000
}

snippet() {
    json_escape "$1" | cut -c1-1200
}

hash_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum 2>/dev/null | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 2>/dev/null | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        printf '%s' "$1" | openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
    else
        printf '%s' "$1" | cksum 2>/dev/null | tr -d ' '
    fi
}

add_finding() {
    _id=$1
    _rule=$2
    _title=$3
    _sev=$4
    _ev=$5
    _rem=$6
    _file=${7:-}
    _cat=${8:-cloud}
    _conf=${9:-high}
    _fp=$(hash_text "$_id|$_rule|$_title|$_file" | cut -c1-32)
    printf '{"id":"%s","tool":"%s","rule_id":"%s","title":"%s","severity":"%s","confidence":"%s","category":"%s","target":"%s","file":"%s","evidence":"%s","remediation":"%s","fingerprint":"%s"},\n' \
        "$(json_escape "$_id")" "$TOOL" "$(json_escape "$_rule")" "$(json_escape "$_title")" "$_sev" "$_conf" "$(json_escape "$_cat")" \
        "$(json_escape "$HOSTNAME")" "$(json_escape "$_file")" "$(snippet "$_ev")" "$(snippet "$_rem")" "$_fp" >> "$TMP_FINDINGS"
}

json_array_from() {
    if [ -s "$1" ]; then
        printf '[%s]' "$(sed '$ s/,$//' "$1")"
    else
        printf '[]'
    fi
}

http_get() {
    _url=$1
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --noproxy '*' --connect-timeout 1 --max-time 2 "$_url" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        no_proxy="169.254.169.254,metadata.google.internal" wget -q -T 2 -t 1 -O - "$_url" 2>/dev/null || true
    fi
}

http_get_header() {
    _url=$1
    _header=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --noproxy '*' --connect-timeout 1 --max-time 2 -H "$_header" "$_url" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        no_proxy="169.254.169.254,metadata.google.internal" wget -q -T 2 -t 1 --header="$_header" -O - "$_url" 2>/dev/null || true
    fi
}

http_put_header() {
    _url=$1
    _header=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --noproxy '*' --connect-timeout 1 --max-time 2 -X PUT -H "$_header" "$_url" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        no_proxy="169.254.169.254" wget -q -T 2 -t 1 --method=PUT --header="$_header" -O - "$_url" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------------------
# 1. AWS EC2 metadata (IMDSv2 preferred, IMDSv1 fallback detection)
# ------------------------------------------------------------------------------
PROVIDER="unknown"
INSTANCE_ID=""
REGION=""
ZONE=""
MACHINE_TYPE=""
PRIVATE_IP=""
PUBLIC_IP=""
ROLE=""
PROJECT=""
RESOURCE_NAME=""
USER_DATA_BYTES=0
USER_DATA_SHA256=""
IMDSV1_ENABLED="false"
IMDSV2_ENABLED="false"

AWS_BASE="http://169.254.169.254/latest"
AWS_TOKEN=$(http_put_header "$AWS_BASE/api/token" "X-aws-ec2-metadata-token-ttl-seconds: 60")
if [ -n "$AWS_TOKEN" ]; then
    IMDSV2_ENABLED="true"
    aws_get() {
        http_get_header "$AWS_BASE/$1" "X-aws-ec2-metadata-token: $AWS_TOKEN"
    }
else
    aws_get() {
        http_get "$AWS_BASE/$1"
    }
fi

INSTANCE_ID=$(aws_get "meta-data/instance-id" | head -n 1)
if [ -n "$INSTANCE_ID" ]; then
    PROVIDER="aws"
    REGION=$(aws_get "meta-data/placement/region" | head -n 1)
    ZONE=$(aws_get "meta-data/placement/availability-zone" | head -n 1)
    MACHINE_TYPE=$(aws_get "meta-data/instance-type" | head -n 1)
    PRIVATE_IP=$(aws_get "meta-data/local-ipv4" | head -n 1)
    PUBLIC_IP=$(aws_get "meta-data/public-ipv4" | head -n 1)
    ROLE=$(aws_get "meta-data/iam/security-credentials/" | head -n 1)
    USER_DATA=$(aws_get "user-data")
    USER_DATA_BYTES=$(printf '%s' "$USER_DATA" | wc -c | tr -d ' ' || echo 0)
    [ -n "${USER_DATA_BYTES:-}" ] || USER_DATA_BYTES=0
    if [ "$USER_DATA_BYTES" -gt 0 ]; then
        USER_DATA_SHA256=$(hash_text "$USER_DATA")
    fi

    IMDSV1_ID=$(http_get "$AWS_BASE/meta-data/instance-id" | head -n 1)
    if [ -n "$IMDSV1_ID" ]; then
        IMDSV1_ENABLED="true"
        if [ "$IMDSV2_ENABLED" = "true" ]; then
            add_finding "triage-linux-cloud-aws-imdsv1" "cloud.aws.imdsv1_enabled" \
                "AWS IMDSv1 is still reachable while IMDSv2 is supported" "medium" \
                "Both the unauthenticated IMDSv1 endpoint and the token-based IMDSv2 endpoint returned instance metadata." \
                "Set the instance metadata options to HttpTokens=required (IMDSv2 only) and HttpPutResponseHopLimit=1." "" "cloud" "high"
        else
            add_finding "triage-linux-cloud-aws-imdsv1" "cloud.aws.imdsv1_enabled" \
                "AWS instance metadata is accessible without a session token (IMDSv1)" "high" \
                "The unauthenticated IMDSv1 endpoint returned instance metadata." \
                "Enforce IMDSv2 with HttpTokens=required and restrict hop limits for containers." "" "cloud" "high"
        fi
    fi
    if [ "$USER_DATA_BYTES" -gt 0 ]; then
        add_finding "triage-linux-cloud-user-data" "cloud.instance.user_data_present" \
            "Instance user-data is present ($USER_DATA_BYTES bytes)" "low" \
            "SHA-256 of user-data: $USER_DATA_SHA256 (content intentionally not emitted)" \
            "Review user-data for embedded credentials and move secrets to a managed secret store." "" "cloud" "medium"
    fi
fi

# ------------------------------------------------------------------------------
# 2. GCP compute metadata
# ------------------------------------------------------------------------------
if [ "$PROVIDER" = "unknown" ]; then
    GCP_ID=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/id" "Metadata-Flavor: Google" | head -n 1)
    if [ -n "$GCP_ID" ]; then
        PROVIDER="gcp"
        INSTANCE_ID="$GCP_ID"
        PROJECT=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/project/project-id" "Metadata-Flavor: Google" | head -n 1)
        REGION=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/region" "Metadata-Flavor: Google" | head -n 1 | sed 's|.*/||')
        ZONE=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/zone" "Metadata-Flavor: Google" | head -n 1 | sed 's|.*/||')
        MACHINE_TYPE=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/machine-type" "Metadata-Flavor: Google" | head -n 1 | sed 's|.*/||')
        PRIVATE_IP=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip" "Metadata-Flavor: Google" | head -n 1)
        ROLE=$(http_get_header "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" "Metadata-Flavor: Google" | head -n 1)
    fi
fi

# ------------------------------------------------------------------------------
# 3. Azure instance metadata
# ------------------------------------------------------------------------------
if [ "$PROVIDER" = "unknown" ]; then
    AZURE_JSON=$(http_get_header "http://169.254.169.254/metadata/instance?api-version=2021-02-01" "Metadata: true")
    if [ -n "$AZURE_JSON" ]; then
        PROVIDER="azure"
        INSTANCE_ID=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"vmId":"\([^"]*\)".*/\1/p' | head -n 1)
        REGION=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"location":"\([^"]*\)".*/\1/p' | head -n 1)
        ZONE=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"zone":"\([^"]*\)".*/\1/p' | head -n 1)
        MACHINE_TYPE=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"vmSize":"\([^"]*\)".*/\1/p' | head -n 1)
        PRIVATE_IP=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"privateIpAddress":"\([^"]*\)".*/\1/p' | head -n 1)
        PUBLIC_IP=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"publicIpAddress":"\([^"]*\)".*/\1/p' | head -n 1)
        RESOURCE_NAME=$(printf '%s' "$AZURE_JSON" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | head -n 1)
    fi
fi

# ------------------------------------------------------------------------------
# 4. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")",
    "dmi_vendor": "$(json_escape "$DMI_VENDOR")",
    "dmi_product": "$(json_escape "$DMI_PRODUCT")"
  },
  "cloud": {
    "provider": "$(json_escape "$PROVIDER")",
    "instance_id": "$(json_escape "$INSTANCE_ID")",
    "region": "$(json_escape "$REGION")",
    "zone": "$(json_escape "$ZONE")",
    "machine_type": "$(json_escape "$MACHINE_TYPE")",
    "private_ip": "$(json_escape "$PRIVATE_IP")",
    "public_ip": "$(json_escape "$PUBLIC_IP")",
    "iam_role": "$(json_escape "$ROLE")",
    "project": "$(json_escape "$PROJECT")",
    "resource_name": "$(json_escape "$RESOURCE_NAME")",
    "imdsv2_enabled": $IMDSV2_ENABLED,
    "imdsv1_enabled": $IMDSV1_ENABLED,
    "user_data_bytes": $USER_DATA_BYTES,
    "user_data_sha256": "$(json_escape "$USER_DATA_SHA256")"
  },
  "findings": $FINDINGS_JSON
}
EOF
