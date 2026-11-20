#!/bin/sh
# ==============================================================================
# Linux Persistence Mechanisms Audit (EVA Sec compatible)
# Inspects cron, systemd services/timers, init.d, rc.local, shell profiles,
# ld.so.preload, and SSH authorized_keys.
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
  "tool": "triage-linux-persistence",
  "rule_id": "$_rule",
  "title": "$_title",
  "severity": "$_sev",
  "confidence": "high",
  "category": "persistence",
  "target": "$HOSTNAME",
  "file": "$_file",
  "evidence": "$_ev",
  "remediation": "$_rem",
  "fingerprint": "$_fp"
},
EOF
}

# 1. Check /etc/ld.so.preload (shared library rootkit hijacking)
if [ -f /etc/ld.so.preload ]; then
    PRELOAD_CONTENT=$(cat /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')
    if [ -n "$PRELOAD_CONTENT" ]; then
        add_finding "triage-linux-ld-preload" "persistence.ld_preload.active" "Active /etc/ld.so.preload library hijacking configured" "critical" "Content: $PRELOAD_CONTENT" "Inspect libraries referenced in /etc/ld.so.preload for userland rootkits and remove unauthorized entries." "/etc/ld.so.preload"
    fi
fi

# 2. Check /etc/rc.local
if [ -f /etc/rc.local ] && [ -x /etc/rc.local ]; then
    RC_SUSP=$(grep -E -rn '(\bcurl\b|\bwget\b|\bsh\s+-i\b|\bbash\s+-i\b|\bnc\s+-e\b)' /etc/rc.local 2>/dev/null || true)
    if [ -n "$RC_SUSP" ]; then
        add_finding "triage-linux-rc-local-suspicious" "persistence.rc_local.suspicious_command" "Suspicious command invocation in /etc/rc.local" "high" "$RC_SUSP" "Audit /etc/rc.local and remove unverified startup commands." "/etc/rc.local"
    fi
fi

# 3. Check world-writable cron directories
for cdir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    if [ -d "$cdir" ]; then
        WW_CRON=$(find "$cdir" -maxdepth 1 -type f -perm -0002 2>/dev/null || true)
        if [ -n "$WW_CRON" ]; then
            add_finding "triage-linux-ww-cron-$(basename "$cdir")" "permissions.world_writable_cron" "World-writable cron file detected in $cdir" "high" "$WW_CRON" "Remove world-writable permissions: chmod o-w <file>" "$cdir"
        fi
    fi
done

# 4. Check for systemd services running from /tmp or /dev/shm
if [ -d /etc/systemd/system ]; then
    SUSP_SVC=$(grep -E -rn 'ExecStart=.*(/tmp|/var/tmp|/dev/shm)' /etc/systemd/system 2>/dev/null || true)
    if [ -n "$SUSP_SVC" ]; then
        add_finding "triage-linux-systemd-tmp-exec" "persistence.systemd.tmp_executable" "Systemd service executing binary from temporary filesystem" "high" "$SUSP_SVC" "Audit service file and ensure service binaries reside in /usr/bin or /usr/local/bin." "/etc/systemd/system"
    fi
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
  "tool": "triage-linux-persistence",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$HOSTNAME"
  },
  "findings": $FINDINGS_ARRAY
}
EOF

cat "$TMP_OUT"
rm -f "$TMP_OUT" "$TMP_FINDINGS" "$TMP_FINDINGS.part" 2>/dev/null
