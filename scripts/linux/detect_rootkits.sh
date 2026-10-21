#!/bin/sh
# ==============================================================================
# Linux Rootkit and Binary Integrity Auditor (EVA Sec compatible)
# Performs local, defensive checks for userland and kernel rootkit indicators:
#   - /etc/ld.so.preload and loader configuration hijacking
#   - Kernel taint flags, suspicious module names, hidden /proc processes
#   - Unexpected regular files in /dev and hidden files in /etc
#   - SUID/SGID, Linux capabilities and world-writable privileged binaries
#   - Package integrity verification (rpm/dpkg/debsums) and recent binary changes
#
# Read-only. Emits `eva.triage.v1` JSON on stdout.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-rootkit"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")
KERNEL=$(uname -r 2>/dev/null || echo "unknown-kernel")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-rk.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_SUID="$TMP_DIR/suid.txt"
TMP_CAPS="$TMP_DIR/caps.txt"
TMP_MODULES="$TMP_DIR/modules.txt"
TMP_PIDS="$TMP_DIR/pids.txt"
TMP_HIDDEN_PROC="$TMP_DIR/hidden_proc.txt"
TMP_DEV_FILES="$TMP_DIR/dev_files.txt"
TMP_HIDDEN_ETC="$TMP_DIR/hidden_etc.txt"
TMP_MODIFIED="$TMP_DIR/modified.txt"
TMP_PKG_OUT="$TMP_DIR/pkg_verify.txt"
: > "$TMP_FINDINGS"
: > "$TMP_SUID"
: > "$TMP_CAPS"
: > "$TMP_MODULES"
: > "$TMP_PIDS"
: > "$TMP_HIDDEN_PROC"
: > "$TMP_DEV_FILES"
: > "$TMP_HIDDEN_ETC"
: > "$TMP_MODIFIED"
: > "$TMP_PKG_OUT"

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
    _cat=${8:-rootkit}
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

raw_array_from() {
    if [ -s "$1" ]; then
        _first=1
        printf '['
        while IFS= read -r _line; do
            [ -n "$_line" ] || continue
            if [ "$_first" -eq 0 ]; then printf ','; fi
            printf '"%s"' "$(json_escape "$_line")"
            _first=0
        done < "$1"
        printf ']'
    else
        printf '[]'
    fi
}

count_lines() {
    wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0
}

# ------------------------------------------------------------------------------
# 1. Dynamic loader hijacking indicators
# ------------------------------------------------------------------------------
LD_PRELOAD_ACTIVE="false"
if [ -f /etc/ld.so.preload ]; then
    LD_PRELOAD_ACTIVE="true"
    PRELOAD_CONTENT=$(tr '\n' ' ' < /etc/ld.so.preload 2>/dev/null | cut -c1-800)
    if [ -n "$PRELOAD_CONTENT" ]; then
        add_finding "triage-linux-rk-ld-preload" "persistence.ld_preload.active" \
            "Active /etc/ld.so.preload library injection" "critical" \
            "Content: $PRELOAD_CONTENT" \
            "Hash each listed library, compare it with package contents, and remove unauthorized entries." "/etc/ld.so.preload"
    fi
fi

LD_CONF_SUSPICIOUS=$(grep -RhsE '^[[:space:]]*(include[[:space:]]+)?/(tmp|var/tmp|dev/shm|home|root)/' \
    /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null | head -n 20)
if [ -n "$LD_CONF_SUSPICIOUS" ]; then
    add_finding "triage-linux-rk-ld-conf" "persistence.ld_conf.untrusted_path" \
        "Dynamic loader configuration references an untrusted path" "high" \
        "$LD_CONF_SUSPICIOUS" \
        "Remove untrusted loader paths and restore the loader configuration from the package manager." "/etc/ld.so.conf"
fi

# ------------------------------------------------------------------------------
# 2. Kernel taint, loaded modules and hidden processes
# ------------------------------------------------------------------------------
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
[ -n "${TAINT:-}" ] || TAINT=0
TAINT_DESC=""
for _bit in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
    if [ $((TAINT & (1 << _bit))) -ne 0 ] 2>/dev/null; then
        case "$_bit" in
            0) _name="proprietary-module" ;;
            1) _name="forced-module-load" ;;
            2) _name="forced-module-unload" ;;
            3) _name="forced-version" ;;
            4) _name="machine-check" ;;
            5) _name="bad-page" ;;
            6) _name="user-requested" ;;
            7) _name="kernel-died" ;;
            8) _name="acpi-override" ;;
            9) _name="softlockup" ;;
            10) _name="livepatch" ;;
            11) _name="aux" ;;
            12) _name="staging-driver" ;;
            13) _name="tech-preview" ;;
            14) _name="out-of-tree-module" ;;
            15) _name="unsigned-module" ;;
            16) _name="softlockup" ;;
            17) _name="firmware-workaround" ;;
            *) _name="flag-$_bit" ;;
        esac
        TAINT_DESC="${TAINT_DESC}${TAINT_DESC:+, }$_name"
    fi
done
if [ "$TAINT" != "0" ]; then
    add_finding "triage-linux-rk-kernel-taint" "kernel.tainted" \
        "Kernel taint flags are set: $TAINT" "medium" \
        "Decoded flags: ${TAINT_DESC:-unknown}" \
        "Investigate unsigned or out-of-tree modules and remove any that are not explicitly approved." "/proc/sys/kernel/tainted"
fi

lsmod 2>/dev/null | head -n 300 > "$TMP_MODULES" || true
MODULE_COUNT=$(count_lines "$TMP_MODULES")
[ -n "${MODULE_COUNT:-}" ] || MODULE_COUNT=0
while read -r _mod _rest; do
    [ -n "${_mod:-}" ] || continue
    case "$_mod" in
        *diamorphine*|*reptile*|*knark*|*adore*|*suterusu*|*rootkit*|*hideproc*|*azazel*|*bdvl*)
            add_finding "triage-linux-rk-module-$_mod" "kernel.module.known_rootkit_name" \
                "Loaded kernel module matches a known rootkit name: $_mod" "critical" \
                "Module present in lsmod: $_mod" \
                "Isolate the host, capture module metadata, and remove the module after forensic review." "/proc/modules"
            ;;
    esac
done < "$TMP_MODULES"

ps -e -o pid= 2>/dev/null | tr -d ' ' | grep -E '^[0-9]+$' | sort -n > "$TMP_PIDS" || true
HIDDEN_PROC_COUNT=0
for _pdir in /proc/[0-9]*; do
    [ -d "$_pdir" ] || continue
    _pid=${_pdir#/proc/}
    [ -r "$_pdir/stat" ] || continue
    if ! grep -qx "$_pid" "$TMP_PIDS" 2>/dev/null; then
        _cmd=$(tr '\0' ' ' < "$_pdir/cmdline" 2>/dev/null | cut -c1-300)
        printf '%s|%s\n' "$_pid" "$_cmd" >> "$TMP_HIDDEN_PROC"
        HIDDEN_PROC_COUNT=$((HIDDEN_PROC_COUNT + 1))
        if [ "$HIDDEN_PROC_COUNT" -le 10 ]; then
            add_finding "triage-linux-rk-hidden-proc-$_pid" "process.hidden_pid" \
                "Process present in /proc but absent from ps output (PID $_pid)" "high" \
                "Command line: ${_cmd:-unreadable}" \
                "Capture /proc/$_pid details immediately; hidden processes can indicate a kernel rootkit or PID namespace artifact." "/proc/$_pid" "rootkit" "medium"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 3. /dev and /etc anomalies
# ------------------------------------------------------------------------------
find /dev -maxdepth 2 -type f 2>/dev/null | head -n 50 > "$TMP_DEV_FILES" || true
DEV_FILE_COUNT=$(count_lines "$TMP_DEV_FILES")
[ -n "${DEV_FILE_COUNT:-}" ] || DEV_FILE_COUNT=0
if [ "$DEV_FILE_COUNT" -gt 0 ]; then
    add_finding "triage-linux-rk-dev-regular-files" "filesystem.dev.regular_file" \
        "Regular files found under /dev" "medium" \
        "$(head -n 5 "$TMP_DEV_FILES" | tr '\n' ' ')" \
        "Inspect the files and remove any that are not required by device management software." "/dev" "rootkit" "medium"
fi

find /etc -maxdepth 1 -type f -name '.*' 2>/dev/null | head -n 50 > "$TMP_HIDDEN_ETC" || true
HIDDEN_ETC_COUNT=$(count_lines "$TMP_HIDDEN_ETC")
[ -n "${HIDDEN_ETC_COUNT:-}" ] || HIDDEN_ETC_COUNT=0

# ------------------------------------------------------------------------------
# 4. SUID/SGID and capabilities inventory
# ------------------------------------------------------------------------------
for _dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp; do
    [ -d "$_dir" ] || continue
    find "$_dir" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null >> "$TMP_SUID" || true
done
sort -u "$TMP_SUID" -o "$TMP_SUID" 2>/dev/null || true
SUID_COUNT=$(count_lines "$TMP_SUID")
[ -n "${SUID_COUNT:-}" ] || SUID_COUNT=0
SUID_WORLD_WRITABLE=""
SUID_UNUSUAL=""
while IFS= read -r _f; do
    [ -n "$_f" ] || continue
    _mode=$(stat -c '%a' "$_f" 2>/dev/null || true)
    case "$_mode" in
        *2|*3|*6|*7) SUID_WORLD_WRITABLE="${SUID_WORLD_WRITABLE} $_f" ;;
    esac
    case "$_f" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/opt/*) SUID_UNUSUAL="${SUID_UNUSUAL} $_f" ;;
    esac
done < "$TMP_SUID"
if [ -n "$SUID_WORLD_WRITABLE" ]; then
    add_finding "triage-linux-rk-suid-world-writable" "permissions.suid_world_writable" \
        "World-writable SUID/SGID binary detected" "critical" \
        "$SUID_WORLD_WRITABLE" \
        "Immediately remove world-write permission (chmod o-w) and investigate how the file was modified." "" "permissions"
fi
if [ -n "$SUID_UNUSUAL" ]; then
    add_finding "triage-linux-rk-suid-unusual-path" "permissions.suid_unusual_path" \
        "SUID/SGID binary found outside standard system directories" "high" \
        "$SUID_UNUSUAL" \
        "Verify the binary hash and package ownership; remove it if unauthorized." "" "permissions" "medium"
fi

if command -v getcap >/dev/null 2>&1; then
    for _dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp; do
        [ -d "$_dir" ] || continue
        getcap -r "$_dir" 2>/dev/null >> "$TMP_CAPS" || true
    done
    sort -u "$TMP_CAPS" -o "$TMP_CAPS" 2>/dev/null || true
fi
CAP_COUNT=$(count_lines "$TMP_CAPS")
[ -n "${CAP_COUNT:-}" ] || CAP_COUNT=0
RISKY_CAPS=""
while IFS= read -r _line; do
    [ -n "$_line" ] || continue
    case "$_line" in
        *cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_dac_read_search*|*cap_setuid*|*cap_setgid*)
            RISKY_CAPS="${RISKY_CAPS} $_line" ;;
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*)
            RISKY_CAPS="${RISKY_CAPS} $_line" ;;
    esac
done < "$TMP_CAPS"
if [ -n "$RISKY_CAPS" ]; then
    add_finding "triage-linux-rk-risky-capabilities" "permissions.file_capabilities" \
        "Risky Linux file capabilities assigned to binaries" "high" \
        "$(printf '%s' "$RISKY_CAPS" | cut -c1-1000)" \
        "Review each capability assignment against an approved baseline and remove unnecessary privileges with setcap -r." "" "permissions" "medium"
fi

# ------------------------------------------------------------------------------
# 5. Package integrity verification
# ------------------------------------------------------------------------------
PKG_MANAGER="unknown"
PKG_VERIFY_STATUS="not-run"
PKG_VERIFY_COUNT=0
if command -v rpm >/dev/null 2>&1; then
    PKG_MANAGER="rpm"
    if command -v timeout >/dev/null 2>&1; then
        timeout 60 rpm -Va 2>/dev/null | head -n 200 > "$TMP_PKG_OUT" || true
    else
        rpm -Va 2>/dev/null | head -n 200 > "$TMP_PKG_OUT" || true
    fi
    PKG_VERIFY_STATUS="completed"
    PKG_VERIFY_COUNT=$(count_lines "$TMP_PKG_OUT")
    [ -n "${PKG_VERIFY_COUNT:-}" ] || PKG_VERIFY_COUNT=0
    if [ "$PKG_VERIFY_COUNT" -gt 0 ]; then
        _digest=$(awk 'substr($1,3,1)=="5" {print $NF}' "$TMP_PKG_OUT" | head -n 10 | tr '\n' ' ')
        _mode=$(awk 'substr($1,2,1)=="M" {print $NF}' "$TMP_PKG_OUT" | head -n 10 | tr '\n' ' ')
        if [ -n "$_digest" ]; then
            add_finding "triage-linux-rk-rpm-digest" "integrity.package.digest_mismatch" \
                "RPM package files with digest mismatches" "high" \
                "$(awk 'substr($1,3,1)=="5" {print $NF}' "$TMP_PKG_OUT" | head -n 20 | tr '\n' ' ')" \
                "Reinstall or restore the affected packages and compare the binaries with a known-good image." "" "integrity"
        fi
        if [ -n "$_mode" ]; then
            add_finding "triage-linux-rk-rpm-mode" "integrity.package.mode_mismatch" \
                "RPM package files with permission mode mismatches" "medium" \
                "$(awk 'substr($1,2,1)=="M" {print $NF}' "$TMP_PKG_OUT" | head -n 20 | tr '\n' ' ')" \
                "Review package permissions and restore them with the package manager." "" "integrity" "medium"
        fi
    fi
elif command -v dpkg >/dev/null 2>&1; then
    PKG_MANAGER="dpkg"
    if command -v debsums >/dev/null 2>&1; then
        PKG_VERIFY_STATUS="debsums"
        if command -v timeout >/dev/null 2>&1; then
            timeout 60 debsums -c 2>/dev/null | head -n 200 > "$TMP_PKG_OUT" || true
        else
            debsums -c 2>/dev/null | head -n 200 > "$TMP_PKG_OUT" || true
        fi
    else
        PKG_VERIFY_STATUS="dpkg-verify"
        if command -v timeout >/dev/null 2>&1; then
            timeout 60 dpkg --verify 2>/dev/null | grep -v '^?????????' | grep -v 'Permission denied' | head -n 200 > "$TMP_PKG_OUT" || true
        else
            dpkg --verify 2>/dev/null | grep -v '^?????????' | grep -v 'Permission denied' | head -n 200 > "$TMP_PKG_OUT" || true
        fi
    fi
    PKG_VERIFY_COUNT=$(count_lines "$TMP_PKG_OUT")
    [ -n "${PKG_VERIFY_COUNT:-}" ] || PKG_VERIFY_COUNT=0
    if [ "$PKG_VERIFY_COUNT" -gt 0 ]; then
        add_finding "triage-linux-rk-dpkg-verify" "integrity.package.modified_files" \
            "Package-managed files failed integrity verification" "high" \
            "$(head -n 20 "$TMP_PKG_OUT" | tr '\n' ' ')" \
            "Reinstall affected packages, compare against a known-good image, and investigate the modification source." "" "integrity"
    fi
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    PKG_VERIFY_STATUS="not-supported"
fi

# Recently modified system binaries are unusual outside package upgrades.
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -mtime -7 2>/dev/null \
    | head -n 100 > "$TMP_MODIFIED" || true
MODIFIED_COUNT=$(count_lines "$TMP_MODIFIED")
[ -n "${MODIFIED_COUNT:-}" ] || MODIFIED_COUNT=0
if [ "$MODIFIED_COUNT" -gt 0 ]; then
    add_finding "triage-linux-rk-recent-system-binaries" "integrity.system_binary.recent_modification" \
        "System binaries modified within the last 7 days" "medium" \
        "$(head -n 20 "$TMP_MODIFIED" | tr '\n' ' ')" \
        "Correlate the modification times with package manager history and change tickets." "" "integrity" "medium"
fi

# ------------------------------------------------------------------------------
# 6. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
SUID_JSON=$(raw_array_from "$TMP_SUID")
CAPS_JSON=$(raw_array_from "$TMP_CAPS")
MODULES_JSON=$(raw_array_from "$TMP_MODULES")
HIDDEN_JSON=$(raw_array_from "$TMP_HIDDEN_PROC")
DEV_JSON=$(raw_array_from "$TMP_DEV_FILES")
HIDDEN_ETC_JSON=$(raw_array_from "$TMP_HIDDEN_ETC")
MODIFIED_JSON=$(raw_array_from "$TMP_MODIFIED")
PKG_OUT_JSON=$(raw_array_from "$TMP_PKG_OUT")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")",
    "kernel": "$(json_escape "$KERNEL")"
  },
  "metrics": {
    "kernel_taint": $TAINT,
    "loaded_modules": $MODULE_COUNT,
    "hidden_processes": $HIDDEN_PROC_COUNT,
    "suid_sgid_files": $SUID_COUNT,
    "file_capabilities": $CAP_COUNT,
    "package_verification_findings": $PKG_VERIFY_COUNT,
    "recent_system_binaries": $MODIFIED_COUNT,
    "dev_regular_files": $DEV_FILE_COUNT,
    "hidden_etc_files": $HIDDEN_ETC_COUNT
  },
  "taint": {
    "value": $TAINT,
    "flags": "$(json_escape "$TAINT_DESC")",
    "ld_preload_active": $LD_PRELOAD_ACTIVE
  },
  "kernel_modules": $MODULES_JSON,
  "hidden_processes": $HIDDEN_JSON,
  "suid_sgid_inventory": $SUID_JSON,
  "file_capabilities": $CAPS_JSON,
  "dev_regular_files": $DEV_JSON,
  "hidden_etc_files": $HIDDEN_ETC_JSON,
  "recent_system_binaries": $MODIFIED_JSON,
  "package_verification": {
    "manager": "$(json_escape "$PKG_MANAGER")",
    "status": "$(json_escape "$PKG_VERIFY_STATUS")",
    "records": $PKG_OUT_JSON
  },
  "findings": $FINDINGS_JSON
}
EOF
