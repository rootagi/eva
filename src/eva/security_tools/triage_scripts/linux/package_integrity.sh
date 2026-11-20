#!/bin/sh
# ==============================================================================
# Linux Package and Filesystem Integrity Audit (EVA Sec compatible)
# Verifies that trusted software has not been modified outside the package
# manager and inventories high-risk file permissions:
#   - rpm/dpkg/apk package verification (digest, mode, ownership, capabilities)
#   - Unpackaged SUID/SGID binaries
#   - World-writable files in /etc and system binary directories
#   - Broken package states and recently modified system binaries
#
# Read-only. Emits `eva.triage.v1` JSON on stdout.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-package-integrity"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")
KERNEL=$(uname -r 2>/dev/null || echo "unknown-kernel")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-pkg.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_VERIFY="$TMP_DIR/verify.txt"
TMP_SUID="$TMP_DIR/suid.txt"
TMP_UNPACKAGED="$TMP_DIR/unpackaged_suid.txt"
TMP_WORLD_WRITABLE="$TMP_DIR/world_writable.txt"
TMP_MODIFIED="$TMP_DIR/modified.txt"
TMP_AUDIT="$TMP_DIR/package_audit.txt"
: > "$TMP_FINDINGS"
: > "$TMP_VERIFY"
: > "$TMP_SUID"
: > "$TMP_UNPACKAGED"
: > "$TMP_WORLD_WRITABLE"
: > "$TMP_MODIFIED"
: > "$TMP_AUDIT"

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
    _cat=${8:-integrity}
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

run_limited() {
    _secs=$1
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$_secs" "$@"
    else
        "$@"
    fi
}

count_lines() {
    wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0
}

# ------------------------------------------------------------------------------
# 1. Package database verification
# ------------------------------------------------------------------------------
PKG_MANAGER="unknown"
PKG_COUNT=0
VERIFY_STATUS="not-run"
VERIFY_RECORDS=0
DIGEST_COUNT=0
MODE_COUNT=0
MISSING_COUNT=0
CAP_COUNT=0

if command -v rpm >/dev/null 2>&1; then
    PKG_MANAGER="rpm"
    PKG_COUNT=$(rpm -qa 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    [ -n "${PKG_COUNT:-}" ] || PKG_COUNT=0
    run_limited 90 rpm -Va 2>/dev/null | head -n 300 > "$TMP_VERIFY" || true
    VERIFY_STATUS="completed"
    VERIFY_RECORDS=$(count_lines "$TMP_VERIFY")
    [ -n "${VERIFY_RECORDS:-}" ] || VERIFY_RECORDS=0
    DIGEST_COUNT=$(awk 'substr($1,3,1)=="5" {c++} END {print c+0}' "$TMP_VERIFY" 2>/dev/null || echo 0)
    MODE_COUNT=$(awk 'substr($1,2,1)=="M" {c++} END {print c+0}' "$TMP_VERIFY" 2>/dev/null || echo 0)
    MISSING_COUNT=$(awk 'substr($1,1,7)=="missing" {c++} END {print c+0}' "$TMP_VERIFY" 2>/dev/null || echo 0)
    CAP_COUNT=$(awk 'substr($1,9,1)=="P" {c++} END {print c+0}' "$TMP_VERIFY" 2>/dev/null || echo 0)
    if [ "$DIGEST_COUNT" -gt 0 ] 2>/dev/null; then
        add_finding "triage-linux-pkg-rpm-digest" "integrity.package.digest_mismatch" \
            "RPM files with digest mismatch ($DIGEST_COUNT)" "high" \
            "$(awk 'substr($1,3,1)=="5" {print $NF}' "$TMP_VERIFY" | head -n 20 | tr '\n' ' ')" \
            "Reinstall affected packages and compare the host against a known-good image." ""
    fi
    if [ "$MISSING_COUNT" -gt 0 ] 2>/dev/null; then
        add_finding "triage-linux-pkg-rpm-missing" "integrity.package.missing_files" \
            "RPM-managed files are missing ($MISSING_COUNT)" "high" \
            "$(awk 'substr($1,1,7)=="missing" {print $NF}' "$TMP_VERIFY" | head -n 20 | tr '\n' ' ')" \
            "Reinstall the affected packages and investigate whether files were deleted by an attacker or a failed update." ""
    fi
    if [ "$MODE_COUNT" -gt 0 ] 2>/dev/null; then
        add_finding "triage-linux-pkg-rpm-mode" "integrity.package.mode_mismatch" \
            "RPM files with permission mode mismatch ($MODE_COUNT)" "medium" \
            "$(awk 'substr($1,2,1)=="M" {print $NF}' "$TMP_VERIFY" | head -n 20 | tr '\n' ' ')" \
            "Restore package permissions and review whether the change granted additional access." "" "integrity" "medium"
    fi
    if [ "$CAP_COUNT" -gt 0 ] 2>/dev/null; then
        add_finding "triage-linux-pkg-rpm-capabilities" "integrity.package.capability_mismatch" \
            "RPM files with capability mismatch ($CAP_COUNT)" "high" \
            "$(awk 'substr($1,9,1)=="P" {print $NF}' "$TMP_VERIFY" | head -n 20 | tr '\n' ' ')" \
            "Review Linux capabilities on affected binaries and restore them with the package manager." ""
    fi
elif command -v dpkg >/dev/null 2>&1; then
    PKG_MANAGER="dpkg"
    PKG_COUNT=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    [ -n "${PKG_COUNT:-}" ] || PKG_COUNT=0
    if command -v debsums >/dev/null 2>&1; then
        VERIFY_STATUS="debsums"
        run_limited 90 debsums -c 2>/dev/null | head -n 300 > "$TMP_VERIFY" || true
    else
        VERIFY_STATUS="dpkg-verify"
        run_limited 90 dpkg --verify 2>/dev/null | grep -v '^?????????' | grep -v 'Permission denied' | head -n 300 > "$TMP_VERIFY" || true
    fi
    VERIFY_RECORDS=$(count_lines "$TMP_VERIFY")
    [ -n "${VERIFY_RECORDS:-}" ] || VERIFY_RECORDS=0
    if [ "$VERIFY_RECORDS" -gt 0 ]; then
        add_finding "triage-linux-pkg-dpkg-verify" "integrity.package.modified_files" \
            "Package-managed files failed integrity verification ($VERIFY_RECORDS records)" "high" \
            "$(head -n 20 "$TMP_VERIFY" | tr '\n' ' ')" \
            "Reinstall affected packages and compare the host against a known-good image." ""
    fi
    dpkg --audit 2>/dev/null | head -n 100 > "$TMP_AUDIT" || true
    if [ -s "$TMP_AUDIT" ]; then
        add_finding "triage-linux-pkg-dpkg-audit" "integrity.package.broken_state" \
            "dpkg reports packages in an inconsistent state" "medium" \
            "$(head -n 10 "$TMP_AUDIT" | tr '\n' ' ')" \
            "Complete or repair the interrupted package operation and re-run the audit." "" "integrity" "medium"
    fi
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
    PKG_COUNT=$(apk info 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    [ -n "${PKG_COUNT:-}" ] || PKG_COUNT=0
    if apk audit --help >/dev/null 2>&1; then
        VERIFY_STATUS="apk-audit"
        run_limited 90 apk audit --system 2>/dev/null | head -n 300 > "$TMP_VERIFY" || true
        VERIFY_RECORDS=$(count_lines "$TMP_VERIFY")
        [ -n "${VERIFY_RECORDS:-}" ] || VERIFY_RECORDS=0
        if [ "$VERIFY_RECORDS" -gt 0 ]; then
            add_finding "triage-linux-pkg-apk-verify" "integrity.package.modified_files" \
                "APK-managed files failed integrity verification" "high" \
                "$(head -n 20 "$TMP_VERIFY" | tr '\n' ' ')" \
                "Reinstall affected packages and compare with a known-good image." ""
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 2. Unpackaged SUID/SGID binaries
# ------------------------------------------------------------------------------
for _dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp; do
    [ -d "$_dir" ] || continue
    find "$_dir" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null >> "$TMP_SUID" || true
done
sort -u "$TMP_SUID" -o "$TMP_SUID" 2>/dev/null || true
SUID_COUNT=$(count_lines "$TMP_SUID")
[ -n "${SUID_COUNT:-}" ] || SUID_COUNT=0

if [ "$PKG_MANAGER" = "rpm" ]; then
    while IFS= read -r _file; do
        [ -n "$_file" ] || continue
        if ! rpm -qf "$_file" >/dev/null 2>&1; then
            printf '%s\n' "$_file" >> "$TMP_UNPACKAGED"
        fi
    done < "$TMP_SUID"
elif [ "$PKG_MANAGER" = "dpkg" ]; then
    while IFS= read -r _file; do
        [ -n "$_file" ] || continue
        if ! dpkg -S "$_file" >/dev/null 2>&1; then
            printf '%s\n' "$_file" >> "$TMP_UNPACKAGED"
        fi
    done < "$TMP_SUID"
fi
UNPACKAGED_COUNT=$(count_lines "$TMP_UNPACKAGED")
[ -n "${UNPACKAGED_COUNT:-}" ] || UNPACKAGED_COUNT=0
if [ "$UNPACKAGED_COUNT" -gt 0 ]; then
    add_finding "triage-linux-pkg-unpackaged-suid" "integrity.suid.unpackaged" \
        "SUID/SGID binaries not owned by any package ($UNPACKAGED_COUNT)" "high" \
        "$(head -n 20 "$TMP_UNPACKAGED" | tr '\n' ' ')" \
        "Treat unpackaged privileged binaries as suspicious; hash them, identify their origin, and remove unauthorized files." "" "permissions"
fi

# ------------------------------------------------------------------------------
# 3. World-writable system configuration and binaries
# ------------------------------------------------------------------------------
for _dir in /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    [ -d "$_dir" ] || continue
    find "$_dir" -xdev -type f -perm -0002 2>/dev/null >> "$TMP_WORLD_WRITABLE" || true
done
sort -u "$TMP_WORLD_WRITABLE" -o "$TMP_WORLD_WRITABLE" 2>/dev/null || true
WORLD_WRITABLE_COUNT=$(count_lines "$TMP_WORLD_WRITABLE")
[ -n "${WORLD_WRITABLE_COUNT:-}" ] || WORLD_WRITABLE_COUNT=0
if [ "$WORLD_WRITABLE_COUNT" -gt 0 ]; then
    add_finding "triage-linux-pkg-world-writable" "permissions.world_writable_system_file" \
        "World-writable system configuration or binary files ($WORLD_WRITABLE_COUNT)" "high" \
        "$(head -n 20 "$TMP_WORLD_WRITABLE" | tr '\n' ' ')" \
        "Remove world-write permission and investigate how the file was modified." "" "permissions"
fi

# ------------------------------------------------------------------------------
# 4. Recently modified system binaries and kernel package ownership
# ------------------------------------------------------------------------------
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -mtime -7 2>/dev/null \
    | head -n 100 > "$TMP_MODIFIED" || true
MODIFIED_COUNT=$(count_lines "$TMP_MODIFIED")
[ -n "${MODIFIED_COUNT:-}" ] || MODIFIED_COUNT=0
if [ "$MODIFIED_COUNT" -gt 0 ]; then
    add_finding "triage-linux-pkg-recent-binaries" "integrity.system_binary.recent_modification" \
        "System binaries modified within 7 days" "medium" \
        "$(head -n 20 "$TMP_MODIFIED" | tr '\n' ' ')" \
        "Correlate modifications with package history and change records; reinstall anything unexplained." "" "integrity" "medium"
fi

KERNEL_OWNED="unknown"
if [ "$PKG_MANAGER" = "rpm" ] && [ -e "/boot/vmlinuz-$KERNEL" ]; then
    if rpm -qf "/boot/vmlinuz-$KERNEL" >/dev/null 2>&1; then
        KERNEL_OWNED="true"
    else
        KERNEL_OWNED="false"
        add_finding "triage-linux-pkg-kernel-unowned" "integrity.kernel.unpackaged" \
            "Running kernel image is not owned by an installed RPM package" "high" \
            "Kernel: $KERNEL Path: /boot/vmlinuz-$KERNEL" \
            "Verify the kernel origin, boot configuration, and secure boot measurements; reinstall a trusted kernel." "/boot/vmlinuz-$KERNEL"
    fi
elif [ "$PKG_MANAGER" = "dpkg" ] && [ -e "/boot/vmlinuz-$KERNEL" ]; then
    if dpkg -S "/boot/vmlinuz-$KERNEL" >/dev/null 2>&1; then
        KERNEL_OWNED="true"
    else
        KERNEL_OWNED="false"
        add_finding "triage-linux-pkg-kernel-unowned" "integrity.kernel.unpackaged" \
            "Running kernel image is not owned by an installed Debian package" "high" \
            "Kernel: $KERNEL Path: /boot/vmlinuz-$KERNEL" \
            "Verify the kernel origin, boot configuration, and secure boot measurements; reinstall a trusted kernel." "/boot/vmlinuz-$KERNEL"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
VERIFY_JSON=$(raw_array_from "$TMP_VERIFY")
SUID_JSON=$(raw_array_from "$TMP_SUID")
UNPACKAGED_JSON=$(raw_array_from "$TMP_UNPACKAGED")
WORLD_JSON=$(raw_array_from "$TMP_WORLD_WRITABLE")
MODIFIED_JSON=$(raw_array_from "$TMP_MODIFIED")
AUDIT_JSON=$(raw_array_from "$TMP_AUDIT")

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
    "package_manager": "$(json_escape "$PKG_MANAGER")",
    "packages": $PKG_COUNT,
    "verification_status": "$(json_escape "$VERIFY_STATUS")",
    "verification_records": $VERIFY_RECORDS,
    "digest_mismatches": $DIGEST_COUNT,
    "mode_mismatches": $MODE_COUNT,
    "missing_files": $MISSING_COUNT,
    "capability_mismatches": $CAP_COUNT,
    "suid_sgid_files": $SUID_COUNT,
    "unpackaged_suid_sgid": $UNPACKAGED_COUNT,
    "world_writable_system_files": $WORLD_WRITABLE_COUNT,
    "recent_system_binaries": $MODIFIED_COUNT,
    "kernel_package_owned": "$(json_escape "$KERNEL_OWNED")"
  },
  "verification_records": $VERIFY_JSON,
  "suid_sgid_inventory": $SUID_JSON,
  "unpackaged_suid_sgid": $UNPACKAGED_JSON,
  "world_writable_system_files": $WORLD_JSON,
  "recent_system_binaries": $MODIFIED_JSON,
  "package_audit": $AUDIT_JSON,
  "findings": $FINDINGS_JSON
}
EOF
