#!/bin/sh
# ==============================================================================
# Linux Host Triage Script (EVA Sec compatible)
# Zero-dependency POSIX shell script collecting host facts and security anomalies.
# ==============================================================================

set -u

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")
KERNEL=$(uname -r 2>/dev/null || echo "unknown-kernel")
ARCH=$(uname -m 2>/dev/null || echo "unknown-arch")
UPTIME=$(uptime 2>/dev/null | tr -d '\n' | sed 's/"/\\"/g')

# Temporary file for JSON building
TMP_OUT=$(mktemp)
TMP_FINDINGS=$(mktemp)

echo "[]" > "$TMP_FINDINGS"

# Helper to append a finding
add_finding() {
    _id="$1"
    _rule="$2"
    _title="$3"
    _sev="$4"
    _ev="$5"
    _rem="$6"
    _file="${7:-}"
    
    # Simple SHA256 simulation or hash
    _fp=$(echo "$_id|$_rule|$_title" | sha256sum 2>/dev/null | cut -d' ' -f1 | cut -c1-32 || echo "00000000000000000000000000000000")
    
    # Format finding json
    cat <<EOF >> "$TMP_FINDINGS.part"
{
  "id": "$_id",
  "tool": "triage-linux",
  "rule_id": "$_rule",
  "title": "$_title",
  "severity": "$_sev",
  "confidence": "high",
  "category": "host_anomaly",
  "target": "$HOSTNAME",
  "file": "$_file",
  "evidence": "$_ev",
  "remediation": "$_rem",
  "fingerprint": "$_fp"
},
EOF
}

# 1. Check Listening Ports with ss or netstat
LISTENERS_JSON=""
if command -v ss >/dev/null 2>&1; then
    LISTENERS_RAW=$(ss -tlpn 2>/dev/null | awk 'NR>1 {print $4}' | sed 's/.*://' | sort -un)
elif command -v netstat >/dev/null 2>&1; then
    LISTENERS_RAW=$(netstat -tlpn 2>/dev/null | awk 'NR>2 {print $4}' | sed 's/.*://' | sort -un)
else
    LISTENERS_RAW=""
fi

for port in $LISTENERS_RAW; do
    if [ "$port" = "23" ]; then
        add_finding "triage-linux-telnet-listener" "network.listener.insecure_protocol" "Insecure Telnet service listening on port 23" "high" "Port 23 is open in listening state" "Disable telnet daemon and use SSH."
    fi
done

# 2. Check Mounted Filesystems with noexec/nosuid on /tmp
if [ -f /etc/fstab ]; then
    TMP_FSTAB=$(grep -E '\s+/tmp\s+' /etc/fstab 2>/dev/null || true)
    if [ -n "$TMP_FSTAB" ]; then
        echo "$TMP_FSTAB" | grep -q "noexec" || add_finding "triage-linux-tmp-exec" "filesystem.mount.tmp_executable" "/tmp filesystem is mounted without noexec flag" "low" "Fstab entry: $TMP_FSTAB" "Add noexec,nosuid,nodev options to /tmp in /etc/fstab." "/etc/fstab"
    fi
fi

# 3. Check for Suspicious Cron Jobs in /etc/cron*
CRON_COUNT=0
if [ -d /etc/cron.d ]; then
    CRON_COUNT=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null | wc -l)
    SUSPICIOUS_CRON=$(grep -E -rn '(\bcurl\b|\bwget\b|\bsh\s+-i\b|\bbash\s+-i\b|\bpython.*socket\b|\bnc\s+-e\b)' /etc/cron* /var/spool/cron 2>/dev/null || true)
    if [ -n "$SUSPICIOUS_CRON" ]; then
        add_finding "triage-linux-suspicious-cron" "persistence.cron.suspicious_command" "Suspicious download cradle or shell in cron" "high" "$(echo "$SUSPICIOUS_CRON" | head -n 3 | tr '\n' ' ' | sed 's/"/\\"/g')" "Review and remove unauthorized cron entries."
    fi
fi

# 4. Check for Active Systemd Timers
TIMERS_COUNT=0
if command -v systemctl >/dev/null 2>&1; then
    TIMERS_COUNT=$(systemctl list-timers --all --no-pager 2>/dev/null | grep -c "timer" || echo 0)
fi

# 5. Check Recent Sudo Invocations in auth logs
SUDO_CALLS=""
if [ -r /var/log/auth.log ]; then
    SUDO_CALLS=$(grep "sudo:" /var/log/auth.log 2>/dev/null | tail -n 10 | sed 's/"/\\"/g' | tr '\n' ' ')
elif [ -r /var/log/secure ]; then
    SUDO_CALLS=$(grep "sudo:" /var/log/secure 2>/dev/null | tail -n 10 | sed 's/"/\\"/g' | tr '\n' ' ')
fi

# Assemble Findings JSON
FINDINGS_ARRAY="[]"
if [ -f "$TMP_FINDINGS.part" ]; then
    FINDINGS_CONTENT=$(sed '$ s/,$//' "$TMP_FINDINGS.part")
    FINDINGS_ARRAY="[ $FINDINGS_CONTENT ]"
fi

cat <<EOF > "$TMP_OUT"
{
  "schema": "eva.triage.v1",
  "tool": "triage-linux",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$HOSTNAME",
    "kernel": "$KERNEL",
    "arch": "$ARCH",
    "uptime": "$UPTIME"
  },
  "metrics": {
    "listening_ports_sample": "$(echo "$LISTENERS_RAW" | tr '\n' ' ' | sed 's/[[:space:]]*$//')",
    "cron_files_count": $CRON_COUNT,
    "systemd_timers_count": $TIMERS_COUNT
  },
  "findings": $FINDINGS_ARRAY
}
EOF

cat "$TMP_OUT"
rm -f "$TMP_OUT" "$TMP_FINDINGS" "$TMP_FINDINGS.part" 2>/dev/null
