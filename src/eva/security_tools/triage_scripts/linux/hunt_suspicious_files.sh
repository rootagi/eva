#!/bin/sh
# ==============================================================================
# Linux Suspicious File and Webshell Hunter (EVA Sec compatible)
# Read-only content hunting across high-value paths:
#   - Download cradles, reverse shells, miners and anti-forensic commands
#   - Server-side webshell indicators and double-extension uploads
#   - Executable files in volatile/user-writable directories
#   - Hidden executables and recently modified security configuration
#   - Cron entries containing remote-download or shell payloads
#
# Optional arguments: one or more roots to scan. Defaults cover /etc, /tmp,
# /home, /opt, /usr/local and common web roots. Emits `eva.triage.v1` JSON.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-file-hunt"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-hunt.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_PATTERNS="$TMP_DIR/patterns.txt"
TMP_SCAN_LIST="$TMP_DIR/scan.list"
TMP_PATTERN_HITS="$TMP_DIR/pattern_hits.txt"
TMP_WEB_FILES="$TMP_DIR/web_files.txt"
TMP_WEB_SUSPICIOUS="$TMP_DIR/web_suspicious.txt"
TMP_TEMP_EXEC="$TMP_DIR/temp_exec.txt"
TMP_HIDDEN_EXEC="$TMP_DIR/hidden_exec.txt"
TMP_RECENT_ETC="$TMP_DIR/recent_etc.txt"
TMP_CRON_HITS="$TMP_DIR/cron_hits.txt"
TMP_ROOTS="$TMP_DIR/roots.txt"
: > "$TMP_FINDINGS"
: > "$TMP_PATTERN_HITS"
: > "$TMP_WEB_FILES"
: > "$TMP_WEB_SUSPICIOUS"
: > "$TMP_TEMP_EXEC"
: > "$TMP_HIDDEN_EXEC"
: > "$TMP_RECENT_ETC"
: > "$TMP_CRON_HITS"
: > "$TMP_ROOTS"

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
    _cat=${8:-malware}
    _conf=${9:-medium}
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

# ------------------------------------------------------------------------------
# 1. Resolve roots
# ------------------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
    for _root in "$@"; do
        [ -d "$_root" ] || continue
        printf '%s\n' "$_root" >> "$TMP_ROOTS"
    done
else
    for _root in /etc /tmp /var/tmp /dev/shm /home /opt /usr/local /var/www /srv/www /usr/share/nginx/html; do
        [ -d "$_root" ] && printf '%s\n' "$_root" >> "$TMP_ROOTS"
    done
    if [ -n "${EVA_WEB_ROOTS:-}" ]; then
        old_ifs=$IFS
        IFS=':'
        for _root in $EVA_WEB_ROOTS; do
            [ -d "$_root" ] && printf '%s\n' "$_root" >> "$TMP_ROOTS"
        done
        IFS=$old_ifs
    fi
fi
sort -u "$TMP_ROOTS" -o "$TMP_ROOTS" 2>/dev/null || true
ROOT_COUNT=$(wc -l < "$TMP_ROOTS" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${ROOT_COUNT:-}" ] || ROOT_COUNT=0

# ------------------------------------------------------------------------------
# 2. Content pattern hunting
# ------------------------------------------------------------------------------
cat > "$TMP_PATTERNS" <<'PATTERNS'
(curl|wget)[^|]{0,200}\|[[:space:]]*(ba|z|da)?sh([[:space:]]|$)
base64[[:space:]]+(-d|--decode)[^|]{0,100}\|[[:space:]]*(ba|z|da)?sh
eval[[:space:]]*\(?.*base64(_decode)?[[:space:]]*\(
(nc|ncat|netcat)[[:space:]]+[^#]{0,120}-e[[:space:]]
(socat)[[:space:]].*exec:
bash[[:space:]]+-i[[:space:]]*>&[[:space:]]*/dev/tcp/
/dev/tcp/[0-9A-Fa-f:.]+/[0-9]+
python[0-9.]*[[:space:]]+-c[[:space:]]+.*(socket|subprocess|pty)
chattr[[:space:]]+\+i[[:space:]]
history[[:space:]]+-c
LD_PRELOAD=
(stratum\+tcp|xmrig|minerd|cpuminer)
crontab[[:space:]]+-r
(powershell|pwsh)[^#]{0,120}-(enc|encodedcommand)[[:space:]]
PATTERNS
PATTERN_COUNT=$(grep -c . "$TMP_PATTERNS" 2>/dev/null || echo 0)
[ -n "${PATTERN_COUNT:-}" ] || PATTERN_COUNT=0

: > "$TMP_SCAN_LIST"
while IFS= read -r _root; do
    [ -n "$_root" ] || continue
    case "$_root" in
        /etc|/usr/local|/opt) _depth=6 ;;
        /home) _depth=5 ;;
        *) _depth=8 ;;
    esac
    find "$_root" -maxdepth "$_depth" -type f -size -2M \
        \( -name '*.sh' -o -name '*.bash' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' -o -name '*.php' -o -name '*.jsp' -o -name '*.aspx' -o -name '*.asp' -o -name '*.js' -o -name '*.ps1' -o -name '*.service' -o -name '*.timer' -o -name '*.conf' -o -name 'authorized_keys' -o -perm /111 \) \
        -print0 2>/dev/null >> "$TMP_SCAN_LIST" || true
done < "$TMP_ROOTS"
SCAN_LIST_COUNT=$(tr -cd '\0' < "$TMP_SCAN_LIST" 2>/dev/null | wc -c | tr -d ' ' || echo 0)
[ -n "${SCAN_LIST_COUNT:-}" ] || SCAN_LIST_COUNT=0
if [ "$SCAN_LIST_COUNT" -gt 4000 ] 2>/dev/null; then
    : # The find limits and per-root depth keep typical scans bounded; no truncation needed.
fi

PATTERN_HIT_FILES=0
if [ -s "$TMP_SCAN_LIST" ]; then
    run_limited 20 xargs -0 -r grep -IlE -f "$TMP_PATTERNS" -- < "$TMP_SCAN_LIST" 2>/dev/null \
        | head -n 80 > "$TMP_DIR/pattern_files.txt" || true
    while IFS= read -r _file; do
        [ -n "$_file" ] || continue
        PATTERN_HIT_FILES=$((PATTERN_HIT_FILES + 1))
        _hits=$(grep -nE -f "$TMP_PATTERNS" "$_file" 2>/dev/null | head -n 2 | cut -c1-400)
        [ -n "$_hits" ] || _hits="Pattern matched in $_file"
        printf '%s: %s\n' "$_file" "$_hits" >> "$TMP_PATTERN_HITS"
        add_finding "triage-linux-hunt-pattern-$(hash_text "$_file" | cut -c1-10)" "malware.file.suspicious_content" \
            "Suspicious execution pattern found in file" "high" \
            "$_hits" \
            "Quarantine the file, determine how it was created, and review the parent process and recent commands." "$_file" "malware"
    done < "$TMP_DIR/pattern_files.txt"
fi

# ------------------------------------------------------------------------------
# 3. Web root webshell indicators
# ------------------------------------------------------------------------------
WEB_ROOT_COUNT=0
for _root in /var/www /srv/www /usr/share/nginx/html; do
    [ -d "$_root" ] && WEB_ROOT_COUNT=$((WEB_ROOT_COUNT + 1))
done
if [ -n "${EVA_WEB_ROOTS:-}" ]; then
    old_ifs=$IFS
    IFS=':'
    for _root in $EVA_WEB_ROOTS; do
        [ -d "$_root" ] && WEB_ROOT_COUNT=$((WEB_ROOT_COUNT + 1))
    done
    IFS=$old_ifs
fi

while IFS= read -r _root; do
    case "$_root" in
        /var/www*|/srv/www*|/usr/share/nginx/html*|*www*|*html*|*public_html*) ;;
        *) continue ;;
    esac
    find "$_root" -maxdepth 8 -type f \
        \( -name '*.php' -o -name '*.php5' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' -o -name '*.ashx' -o -name '*.cgi' -o -name '*.pl' \) \
        -print0 2>/dev/null >> "$TMP_WEB_FILES" || true
done < "$TMP_ROOTS"

WEB_FILE_COUNT=0
if [ -s "$TMP_WEB_FILES" ]; then
    WEB_FILE_COUNT=$(tr -cd '\0' < "$TMP_WEB_FILES" 2>/dev/null | wc -c | tr -d ' ' || echo 0)
    [ -n "${WEB_FILE_COUNT:-}" ] || WEB_FILE_COUNT=0
    tr '\0' '\n' < "$TMP_WEB_FILES" 2>/dev/null | head -n 100 > "$TMP_DIR/web_files_plain.txt" || true
    while IFS= read -r _file; do
        [ -n "$_file" ] || continue
        _base=$(basename "$_file")
        _reason=""
        case "$_base" in
            *.*.php|*.*.asp|*.*.aspx|*.*.jsp|*.*.cgi|*.*.pl) _reason="Double extension on server-side script" ;;
            .*.php|.*.jsp|.*.aspx|.*.asp) _reason="Hidden server-side script" ;;
            *shell*|*cmd*|*c99*|*r57*|*backdoor*|*uploader*|*wso*|*b374k*|*webshell*) _reason="High-risk webshell filename" ;;
        esac
        if [ -n "$_reason" ]; then
            printf '%s: %s\n' "$_file" "$_reason" >> "$TMP_WEB_SUSPICIOUS"
            add_finding "triage-linux-hunt-web-name-$(hash_text "$_file" | cut -c1-10)" "web.webshell.suspicious_filename" \
                "Suspicious server-side script name: $_base" "high" \
                "$_reason File: $_file" \
                "Quarantine the file, review web server access logs, and verify application deployment history." "$_file" "web_attack"
        fi
        _mode=$(stat -c '%a' "$_file" 2>/dev/null || true)
        case "$_mode" in
            *2|*3|*6|*7)
                printf '%s: world-writable mode %s\n' "$_file" "$_mode" >> "$TMP_WEB_SUSPICIOUS"
                add_finding "triage-linux-hunt-web-writable-$(hash_text "$_file" | cut -c1-10)" "web.file.world_writable" \
                    "Web-accessible file is world-writable" "medium" \
                    "File: $_file mode: $_mode" \
                    "Remove world-write permission and review the upload or deployment process that created the file." "$_file" "web_attack"
                ;;
        esac
    done < "$TMP_DIR/web_files_plain.txt"
fi

# ------------------------------------------------------------------------------
# 4. Volatile and hidden executables, recent /etc changes, cron payloads
# ------------------------------------------------------------------------------
find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mtime -14 \( -perm /111 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' \) \
    2>/dev/null | head -n 100 > "$TMP_TEMP_EXEC" || true
TEMP_EXEC_COUNT=$(wc -l < "$TMP_TEMP_EXEC" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${TEMP_EXEC_COUNT:-}" ] || TEMP_EXEC_COUNT=0
while IFS= read -r _file; do
    [ -n "$_file" ] || continue
    _kind="executable or script"
    file -b "$_file" 2>/dev/null | grep -qi 'ELF' && _kind="ELF binary"
    add_finding "triage-linux-hunt-temp-$(hash_text "$_file" | cut -c1-10)" "filesystem.temp.executable" \
        "Recently created $_kind in a volatile directory" "medium" \
        "File: $_file" \
        "Verify provenance, hash the file for intelligence, and remove it if not part of an approved package." "$_file" "malware"
done < "$TMP_TEMP_EXEC"

find /home /opt /usr/local -maxdepth 5 -type f -name '.*' -perm /111 2>/dev/null | head -n 50 > "$TMP_HIDDEN_EXEC" || true
HIDDEN_EXEC_COUNT=$(wc -l < "$TMP_HIDDEN_EXEC" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${HIDDEN_EXEC_COUNT:-}" ] || HIDDEN_EXEC_COUNT=0
while IFS= read -r _file; do
    [ -n "$_file" ] || continue
    add_finding "triage-linux-hunt-hidden-$(hash_text "$_file" | cut -c1-10)" "filesystem.hidden_executable" \
        "Hidden executable file detected" "medium" \
        "File: $_file" \
        "Inspect the file, its owner and creation time; hidden executables are frequently used for persistence." "$_file" "malware"
done < "$TMP_HIDDEN_EXEC"

find /etc -maxdepth 4 -type f -mtime -7 \( -path '/etc/sudoers*' -o -path '/etc/ssh/*' -o -path '/etc/pam.d/*' -o -path '/etc/cron*' -o -name 'ld.so.preload' -o -path '/etc/systemd/*' \) \
    2>/dev/null | head -n 80 > "$TMP_RECENT_ETC" || true
RECENT_ETC_COUNT=$(wc -l < "$TMP_RECENT_ETC" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${RECENT_ETC_COUNT:-}" ] || RECENT_ETC_COUNT=0
if [ "$RECENT_ETC_COUNT" -gt 0 ]; then
    add_finding "triage-linux-hunt-recent-etc" "persistence.configuration.recent_change" \
        "Security-sensitive configuration files changed within 7 days" "medium" \
        "$(head -n 10 "$TMP_RECENT_ETC" | tr '\n' ' ')" \
        "Correlate the modifications with approved changes and review the file contents for unauthorized persistence." "/etc" "persistence" "medium"
fi

if [ -d /etc/cron.d ] || [ -d /var/spool/cron ] || [ -d /etc/cron.daily ]; then
    grep -RhsE '(curl|wget)[^|]*\|[[:space:]]*(ba|z|da)?sh|base64[^|]*\|[[:space:]]*(ba|z|da)?sh|nc[[:space:]].*-e[[:space:]]' \
        /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron 2>/dev/null | head -n 20 > "$TMP_CRON_HITS" || true
    if [ -s "$TMP_CRON_HITS" ]; then
        add_finding "triage-linux-hunt-cron-payload" "persistence.cron.download_cradle" \
            "Cron entry contains a download cradle or reverse shell pattern" "critical" \
            "$(head -n 5 "$TMP_CRON_HITS" | tr '\n' ' ')" \
            "Remove the unauthorized cron entry, preserve it as evidence, and identify the writer through audit logs." "/etc/cron.d" "persistence"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
ROOTS_JSON=$(raw_array_from "$TMP_ROOTS")
PATTERN_HITS_JSON=$(raw_array_from "$TMP_PATTERN_HITS")
WEB_SUSPICIOUS_JSON=$(raw_array_from "$TMP_WEB_SUSPICIOUS")
TEMP_EXEC_JSON=$(raw_array_from "$TMP_TEMP_EXEC")
HIDDEN_EXEC_JSON=$(raw_array_from "$TMP_HIDDEN_EXEC")
RECENT_ETC_JSON=$(raw_array_from "$TMP_RECENT_ETC")
CRON_HITS_JSON=$(raw_array_from "$TMP_CRON_HITS")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")"
  },
  "metrics": {
    "roots": $ROOT_COUNT,
    "content_patterns": $PATTERN_COUNT,
    "files_selected": $SCAN_LIST_COUNT,
    "pattern_hit_files": $PATTERN_HIT_FILES,
    "web_roots": $WEB_ROOT_COUNT,
    "web_server_files": $WEB_FILE_COUNT,
    "temp_executables": $TEMP_EXEC_COUNT,
    "hidden_executables": $HIDDEN_EXEC_COUNT,
    "recent_sensitive_configs": $RECENT_ETC_COUNT
  },
  "roots": $ROOTS_JSON,
  "pattern_hits": $PATTERN_HITS_JSON,
  "web_suspicious_files": $WEB_SUSPICIOUS_JSON,
  "temp_executables": $TEMP_EXEC_JSON,
  "hidden_executables": $HIDDEN_EXEC_JSON,
  "recent_sensitive_configs": $RECENT_ETC_JSON,
  "cron_payload_hits": $CRON_HITS_JSON,
  "findings": $FINDINGS_JSON
}
EOF
