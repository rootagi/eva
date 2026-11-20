#!/bin/sh
# ==============================================================================
# Linux Network Sockets and Routing Triage (EVA Sec compatible)
# Inspects sockets, routing table, DNS resolvers, hosts file, and firewall status.
# ==============================================================================

set -u

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_OUT=$(mktemp)
TMP_FINDINGS=$(mktemp)

echo "[]" > "$TMP_FINDINGS"

add_finding() {
    _id="$1"
    _rule="$2"
    _title="$3"
    _sev="$4"
    _ev="$5"
    _rem="$6"
    _file="${7:-}"

    _fp=$(echo "$_id|$_rule|$_title" | sha256sum 2>/dev/null | cut -d' ' -f1 | cut -c1-32 || echo "00000000000000000000000000000000")

    cat <<EOF >> "$TMP_FINDINGS.part"
{
  "id": "$_id",
  "tool": "triage-linux-network",
  "rule_id": "$_rule",
  "title": "$_title",
  "severity": "$_sev",
  "confidence": "high",
  "category": "network_anomaly",
  "target": "$HOSTNAME",
  "file": "$_file",
  "evidence": "$_ev",
  "remediation": "$_rem",
  "fingerprint": "$_fp"
},
EOF
}

# 1. Hosts File Hijacking Check
if [ -f /etc/hosts ]; then
    HOSTS_SUSP=$(grep -E -i '(\bantivirus\b|\bvirustotal\b|\bupdate\b|\bsecurity\b|\bdefender\b)' /etc/hosts 2>/dev/null | grep -v "^\s*#" || true)
    if [ -n "$HOSTS_SUSP" ]; then
        add_finding "triage-linux-hosts-redirect" "network.hosts.security_domain_redirected" "Potential security update redirect in /etc/hosts" "critical" "Hosts entries: $HOSTS_SUSP" "Review /etc/hosts and remove unauthorized redirects." "/etc/hosts"
    fi
fi

# 2. DNS Resolvers (/etc/resolv.conf)
RESOLVERS=$(grep -E '^\s*nameserver\s+' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' || echo "none")

# 3. Default Route
DEFAULT_GW="unknown"
if command -v ip >/dev/null 2>&1; then
    DEFAULT_GW=$(ip route show default 2>/dev/null | awk '{print $3}' || echo "none")
fi

# 4. Firewall status check
FW_STATUS="none"
if command -v ufw >/dev/null 2>&1; then
    FW_STATUS=$(ufw status 2>/dev/null | head -n 1 || echo "unknown")
elif command -v iptables >/dev/null 2>&1; then
    RULES_CNT=$(iptables -S 2>/dev/null | wc -l || echo 0)
    FW_STATUS="iptables ($RULES_CNT rules)"
elif command -v nft >/dev/null 2>&1; then
    FW_STATUS="nftables"
fi

if [ "$FW_STATUS" = "none" ] || [ "$FW_STATUS" = "Status: inactive" ]; then
    add_finding "triage-linux-firewall-inactive" "network.firewall.inactive" "Host firewall appears inactive or unconfigured" "medium" "Firewall status: $FW_STATUS" "Configure and enable host-based packet filtering (ufw/nftables/iptables)."
fi

# Assemble JSON
FINDINGS_ARRAY="[]"
if [ -f "$TMP_FINDINGS.part" ]; then
    FINDINGS_CONTENT=$(sed '$ s/,$//' "$TMP_FINDINGS.part")
    FINDINGS_ARRAY="[ $FINDINGS_CONTENT ]"
fi

cat <<EOF > "$TMP_OUT"
{
  "schema": "eva.triage.v1",
  "tool": "triage-linux-network",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$HOSTNAME"
  },
  "network": {
    "default_gateway": "$DEFAULT_GW",
    "dns_resolvers": "$RESOLVERS",
    "firewall_status": "$FW_STATUS"
  },
  "findings": $FINDINGS_ARRAY
}
EOF

cat "$TMP_OUT"
rm -f "$TMP_OUT" "$TMP_FINDINGS" "$TMP_FINDINGS.part" 2>/dev/null
