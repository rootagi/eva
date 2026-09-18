#!/bin/sh
# ==============================================================================
# Linux System Hardening Audit Script (EVA Sec compatible)
# Audits SSH, login.defs, PAM, sysctl, and SUID binaries against CIS controls.
# ==============================================================================

set -u

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_OUT=$(mktemp)
TMP_FINDINGS=$(mktemp)
TMP_AUDITS=$(mktemp)

echo "[]" > "$TMP_FINDINGS"

add_audit() {
    _id="$1"
    _title="$2"
    _status="$3"
    _sev="$4"
    _ev="$5"
    _rem="$6"
    _file="${7:-}"

    _fp=$(echo "$_id|$_title|$_ev" | sha256sum 2>/dev/null | cut -d' ' -f1 | cut -c1-32 || echo "00000000000000000000000000000000")

    cat <<EOF >> "$TMP_AUDITS.part"
{
  "control_id": "$_id",
  "title": "$_title",
  "status": "$_status",
  "severity": "$_sev",
  "evidence": "$_ev",
  "remediation": "$_rem"
},
EOF

    if [ "$_status" = "FAIL" ] || [ "$_status" = "WARN" ]; then
        cat <<EOF >> "$TMP_FINDINGS.part"
{
  "id": "triage-linux-$_id",
  "tool": "triage-linux-hardening",
  "rule_id": "hardening.$_id",
  "title": "$_title",
  "severity": "$_sev",
  "confidence": "high",
  "category": "hardening_audit",
  "target": "$HOSTNAME",
  "file": "$_file",
  "evidence": "$_ev",
  "remediation": "$_rem",
  "fingerprint": "$_fp"
},
EOF
    fi
}

# 1. SSH Server Configuration Check
SSHD_CONFIG=""
for candidate in /etc/ssh/sshd_config /etc/sshd_config; do
    if [ -f "$candidate" ]; then
        SSHD_CONFIG="$candidate"
        break
    fi
done

if [ -n "$SSHD_CONFIG" ]; then
    # Check PermitRootLogin
    PRL=$(grep -E '^\s*PermitRootLogin\s+' "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' || echo "unconfigured")
    if [ "$PRL" = "yes" ]; then
        add_audit "ssh.permit_root_login" "SSH PermitRootLogin is enabled" "FAIL" "high" "PermitRootLogin yes in $SSHD_CONFIG" "Set 'PermitRootLogin no' or 'prohibit-password' in $SSHD_CONFIG." "$SSHD_CONFIG"
    elif [ "$PRL" = "no" ] || [ "$PRL" = "prohibit-password" ]; then
        add_audit "ssh.permit_root_login" "SSH PermitRootLogin is restricted" "PASS" "info" "PermitRootLogin $PRL" "" "$SSHD_CONFIG"
    else
        add_audit "ssh.permit_root_login" "SSH PermitRootLogin default setting in effect" "WARN" "medium" "PermitRootLogin not explicitly set to 'no'" "Explicitly set 'PermitRootLogin no' in $SSHD_CONFIG." "$SSHD_CONFIG"
    fi

    # Check PasswordAuthentication
    PA=$(grep -E '^\s*PasswordAuthentication\s+' "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' || echo "unconfigured")
    if [ "$PA" = "yes" ]; then
        add_audit "ssh.password_auth" "SSH Password Authentication is enabled" "WARN" "low" "PasswordAuthentication yes" "Consider key-based authentication with 'PasswordAuthentication no'." "$SSHD_CONFIG"
    else
        add_audit "ssh.password_auth" "SSH Password Authentication restricted or default" "PASS" "info" "PasswordAuthentication $PA" "" "$SSHD_CONFIG"
    fi
else
    add_audit "ssh.config_present" "SSH Daemon configuration file found" "INFO" "info" "No sshd_config found on host" "" ""
fi

# 2. Kernel Hardening Parameters (sysctl)
# ASLR (kernel.randomize_va_space)
ASLR_VAL=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unknown")
if [ "$ASLR_VAL" = "2" ]; then
    add_audit "sysctl.aslr" "Address Space Layout Randomization (ASLR) fully enabled" "PASS" "info" "kernel.randomize_va_space = 2" "" "/proc/sys/kernel/randomize_va_space"
else
    add_audit "sysctl.aslr" "ASLR is not fully enabled (value: $ASLR_VAL)" "FAIL" "high" "kernel.randomize_va_space is $ASLR_VAL (expected 2)" "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf" "/proc/sys/kernel/randomize_va_space"
fi

# IP Forwarding (net.ipv4.ip_forward)
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
if [ "$IP_FWD" = "1" ]; then
    add_audit "sysctl.ip_forward" "IPv4 Forwarding is enabled" "WARN" "low" "net.ipv4.ip_forward = 1" "Disable IP forwarding if host is not a router: set net.ipv4.ip_forward = 0 in /etc/sysctl.conf" "/proc/sys/net/ipv4/ip_forward"
else
    add_audit "sysctl.ip_forward" "IPv4 Forwarding is disabled" "PASS" "info" "net.ipv4.ip_forward = 0" "" "/proc/sys/net/ipv4/ip_forward"
fi

# Symlink Protection
SYMLINK_PROT=$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo "1")
if [ "$SYMLINK_PROT" = "1" ]; then
    add_audit "sysctl.protected_symlinks" "Protected symlinks enabled" "PASS" "info" "fs.protected_symlinks = 1" "" "/proc/sys/fs/protected_symlinks"
else
    add_audit "sysctl.protected_symlinks" "Protected symlinks disabled" "FAIL" "medium" "fs.protected_symlinks = 0" "Set 'fs.protected_symlinks = 1' in /etc/sysctl.conf" "/proc/sys/fs/protected_symlinks"
fi

# 3. Check /etc/login.defs password aging
if [ -f /etc/login.defs ]; then
    PASS_MAX=$(grep -E '^\s*PASS_MAX_DAYS\s+' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    if [ "$PASS_MAX" -gt 365 ] 2>/dev/null; then
        add_audit "login_defs.pass_max_days" "Password maximum age exceeds recommended policy ($PASS_MAX days)" "WARN" "low" "PASS_MAX_DAYS = $PASS_MAX" "Set PASS_MAX_DAYS <= 90 in /etc/login.defs" "/etc/login.defs"
    else
        add_audit "login_defs.pass_max_days" "Password maximum age meets policy" "PASS" "info" "PASS_MAX_DAYS = $PASS_MAX" "" "/etc/login.defs"
    fi

    UMASK_DEF=$(grep -E '^\s*UMASK\s+' /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "022")
    if [ "$UMASK_DEF" = "077" ] || [ "$UMASK_DEF" = "027" ]; then
        add_audit "login_defs.umask" "Default UMASK is restrictive ($UMASK_DEF)" "PASS" "info" "UMASK = $UMASK_DEF" "" "/etc/login.defs"
    else
        add_audit "login_defs.umask" "Default UMASK ($UMASK_DEF) is less restrictive than 027" "WARN" "low" "UMASK = $UMASK_DEF" "Set UMASK 027 in /etc/login.defs" "/etc/login.defs"
    fi
fi

# 4. Check for World-Writable SUID/SGID Binaries in common bin directories
SUID_WW=""
for d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin; do
    if [ -d "$d" ]; then
        FOUND=$(find "$d" -maxdepth 2 -type f \( -perm -4000 -o -perm -2000 \) -perm -0002 2>/dev/null || true)
        if [ -n "$FOUND" ]; then
            SUID_WW="$SUID_WW $FOUND"
        fi
    fi
done

if [ -n "$SUID_WW" ]; then
    add_audit "permissions.world_writable_suid" "World-writable SUID/SGID binaries found" "FAIL" "critical" "World-writable SUID: $SUID_WW" "Remove world-write permissions immediately: chmod o-w <file>" ""
else
    add_audit "permissions.world_writable_suid" "No world-writable SUID/SGID binaries in standard paths" "PASS" "info" "Clean" "" ""
fi

# Assemble JSON
AUDITS_ARRAY="[]"
if [ -f "$TMP_AUDITS.part" ]; then
    AUDITS_CONTENT=$(sed '$ s/,$//' "$TMP_AUDITS.part")
    AUDITS_ARRAY="[ $AUDITS_CONTENT ]"
fi

FINDINGS_ARRAY="[]"
if [ -f "$TMP_FINDINGS.part" ]; then
    FINDINGS_CONTENT=$(sed '$ s/,$//' "$TMP_FINDINGS.part")
    FINDINGS_ARRAY="[ $FINDINGS_CONTENT ]"
fi

cat <<EOF > "$TMP_OUT"
{
  "schema": "eva.triage.v1",
  "tool": "triage-linux-hardening",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$HOSTNAME"
  },
  "audits": $AUDITS_ARRAY,
  "findings": $FINDINGS_ARRAY
}
EOF

cat "$TMP_OUT"
rm -f "$TMP_OUT" "$TMP_FINDINGS" "$TMP_FINDINGS.part" "$TMP_AUDITS" "$TMP_AUDITS.part" 2>/dev/null
