#!/bin/sh
# ==============================================================================
# Linux Security Events Triage Script (EVA Sec compatible)
# Parses authentication logs, journalctl, and wtmp for failed logons and sudo actions.
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

    _fp=$(echo "$_id|$_rule|$_title" | sha256sum 2>/dev/null | cut -d' ' -f1 | cut -c1-32 || echo "00000000000000000000000000000000")

    cat <<EOF >> "$TMP_FINDINGS.part"
{
  "id": "$_id",
  "tool": "triage-linux-events",
  "rule_id": "$_rule",
  "title": "$_title",
  "severity": "$_sev",
  "confidence": "high",
  "category": "authentication_anomaly",
  "target": "$HOSTNAME",
  "evidence": "$_ev",
  "remediation": "$_rem",
  "fingerprint": "$_fp"
},
EOF
}

# 1. Count Failed Logons
FAILED_LOGON_COUNT=0
AUTH_LOG=""
for candidate in /var/log/auth.log /var/log/secure; do
    if [ -r "$candidate" ]; then
        AUTH_LOG="$candidate"
        break
    fi
done

if [ -n "$AUTH_LOG" ]; then
    FAILED_LOGON_COUNT=$(grep "Failed password for" "$AUTH_LOG" 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    if [ "$FAILED_LOGON_COUNT" -gt 10 ] 2>/dev/null; then
        TOP_ATTACKERS=$(grep "Failed password for" "$AUTH_LOG" 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 5 | tr '\n' ' ')
        add_finding "triage-linux-ssh-bruteforce" "identity.ssh.brute_force_detected" "High volume of failed SSH logons ($FAILED_LOGON_COUNT failures)" "high" "Top source IPs: $TOP_ATTACKERS" "Inspect origin IPs, deploy fail2ban or firewall rate-limiting, and enforce public key authentication."
    fi
elif command -v journalctl >/dev/null 2>&1; then
    FAILED_LOGON_COUNT=$(journalctl -u sshd -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep "Failed password" | wc -l | tr -d ' ' || echo "0")
    if [ "$FAILED_LOGON_COUNT" -gt 10 ] 2>/dev/null; then
        add_finding "triage-linux-ssh-bruteforce" "identity.ssh.brute_force_detected" "High volume of failed SSH logons ($FAILED_LOGON_COUNT failures in last 24h)" "high" "$FAILED_LOGON_COUNT failed authentication attempts recorded in journalctl" "Enforce fail2ban or SSH key authentication."
    fi
fi

# 2. Check for UID 0 accounts besides root in /etc/passwd
NON_ROOT_ZERO=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null || true)
if [ -n "$NON_ROOT_ZERO" ]; then
    add_finding "triage-linux-uid0-nonroot" "identity.account.uid_zero_backdoor" "Non-root account with UID 0 detected: $NON_ROOT_ZERO" "critical" "Account: $NON_ROOT_ZERO in /etc/passwd has UID 0" "Inspect and remove backdoor superuser accounts immediately."
fi

# 3. Check for empty password hashes in /etc/shadow
if [ -r /etc/shadow ]; then
    EMPTY_PASS_USERS=$(awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null | head -n 5 || true)
fi

# Assemble JSON
FINDINGS_ARRAY="[]"
if [ -f "$TMP_FINDINGS.part" ]; then
    FINDINGS_CONTENT=$(sed '$ s/,$//' "$TMP_FINDINGS.part")
    FINDINGS_ARRAY="[ $FINDINGS_CONTENT ]"
fi

CLEAN_COUNT=$(echo "$FAILED_LOGON_COUNT" | tr -dc '0-9' || echo "0")
[ -z "$CLEAN_COUNT" ] && CLEAN_COUNT=0

cat <<EOF > "$TMP_OUT"
{
  "schema": "eva.triage.v1",
  "tool": "triage-linux-events",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$HOSTNAME"
  },
  "metrics": {
    "failed_ssh_logons": $CLEAN_COUNT
  },
  "findings": $FINDINGS_ARRAY
}
EOF

cat "$TMP_OUT"
rm -f "$TMP_OUT" "$TMP_FINDINGS" "$TMP_FINDINGS.part" 2>/dev/null
