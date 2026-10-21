#!/bin/sh
# ==============================================================================
# Linux Authentication and Web Log Forensics (EVA Sec compatible)
# Correlates local log sources for incident triage:
#   - SSH failed/successful logons, brute-force sources and success-after-failure
#   - sudo activity, account modifications and privilege changes
#   - Journal errors and indicators of log clearing/tampering
#   - Web server access logs with attack-pattern and error-rate analysis
#
# Read-only. Emits `eva.triage.v1` JSON on stdout.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-logs"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-logs.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_AUTH="$TMP_DIR/auth.log"
TMP_FAILED_IPS="$TMP_DIR/failed_ips.txt"
TMP_SUCCESS_IPS="$TMP_DIR/success_ips.txt"
TMP_SUDO="$TMP_DIR/sudo.txt"
TMP_ACCOUNT_CHANGES="$TMP_DIR/account_changes.txt"
TMP_SUSPICIOUS_REQUESTS="$TMP_DIR/suspicious_requests.txt"
TMP_WEB_IPS="$TMP_DIR/web_ips.txt"
TMP_WEB_LOGS="$TMP_DIR/web_logs.txt"
TMP_JOURNAL_ERRORS="$TMP_DIR/journal_errors.txt"
TMP_FAILED_SAMPLE="$TMP_DIR/failed_sample.txt"
TMP_SUCCESS_SAMPLE="$TMP_DIR/success_sample.txt"
TMP_TAMPER="$TMP_DIR/tamper.txt"
: > "$TMP_FINDINGS"
: > "$TMP_AUTH"
: > "$TMP_FAILED_IPS"
: > "$TMP_SUCCESS_IPS"
: > "$TMP_SUDO"
: > "$TMP_ACCOUNT_CHANGES"
: > "$TMP_SUSPICIOUS_REQUESTS"
: > "$TMP_WEB_IPS"
: > "$TMP_WEB_LOGS"
: > "$TMP_JOURNAL_ERRORS"
: > "$TMP_FAILED_SAMPLE"
: > "$TMP_SUCCESS_SAMPLE"
: > "$TMP_TAMPER"

cleanup() {
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

json_escape() {
    printf '%s' "${1:-}" | tr '\n\r\t' '   ' | sed -e 's/[[:cntrl:]]/ /g' -e 's/\\/\\\\/g' -e 's/"/\\"/g' | cut -c1-4000
}

snippet() {
    json_escape "$1" | cut -c1-1000
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
    _cat=${8:-authentication_anomaly}
    _conf=${9:-high}
    _fp=$(hash_text "$_id|$_rule|$_title|$_file" | cut -c1-32)
    printf '{"id":"%s","tool":"%s","rule_id":"%s","title":"%s","severity":"%s","confidence":"%s","category":"%s","target":"%s","file":"%s","evidence":"%s","remediation":"%s","fingerprint":"%s"},\n' \
        "$(json_escape "$_id")" "$TOOL" "$(json_escape "$_rule")" "$(json_escape "$_title")" "$_sev" "$_conf" "$(json_escape "$_cat")" \
        "$(json_escape "$HOSTNAME")" "$(json_escape "$_file")" "$(snippet "$_ev")" "$(snippet "$_rem")" "$_fp" >> "$TMP_FINDINGS"
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

json_array_from() {
    if [ -s "$1" ]; then
        printf '[%s]' "$(sed '$ s/,$//' "$1")"
    else
        printf '[]'
    fi
}

count_nonempty() {
    grep -c . "$1" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# 1. Select authentication source
# ------------------------------------------------------------------------------
AUTH_SOURCE="none"
for _candidate in /var/log/auth.log /var/log/secure; do
    if [ -r "$_candidate" ]; then
        AUTH_SOURCE="$_candidate"
        tail -n 20000 "$_candidate" 2>/dev/null > "$TMP_AUTH" || true
        break
    fi
done
if [ ! -s "$TMP_AUTH" ] && command -v journalctl >/dev/null 2>&1; then
    AUTH_SOURCE="journalctl"
    journalctl -q --since "-24 hours" -o short-iso 2>/dev/null | tail -n 20000 > "$TMP_AUTH" || true
fi

FAILED_COUNT=0
SUCCESS_COUNT=0
BRUTE_FORCE_SUCCESS=0
if [ -s "$TMP_AUTH" ]; then
    grep -E 'Failed password for|Invalid user|authentication failure' "$TMP_AUTH" 2>/dev/null > "$TMP_FAILED_SAMPLE" || true
    FAILED_COUNT=$(count_nonempty "$TMP_FAILED_SAMPLE")
    [ -n "${FAILED_COUNT:-}" ] || FAILED_COUNT=0

    grep -Eo 'from [0-9a-fA-F:.]+' "$TMP_FAILED_SAMPLE" 2>/dev/null | awk '{print $2}' \
        | sort | uniq -c | sort -nr | head -n 20 > "$TMP_FAILED_IPS" || true

    grep -E 'Accepted (password|publickey|keyboard-interactive)' "$TMP_AUTH" 2>/dev/null > "$TMP_SUCCESS_SAMPLE" || true
    SUCCESS_COUNT=$(count_nonempty "$TMP_SUCCESS_SAMPLE")
    [ -n "${SUCCESS_COUNT:-}" ] || SUCCESS_COUNT=0

    grep -Eo 'from [0-9a-fA-F:.]+' "$TMP_SUCCESS_SAMPLE" 2>/dev/null | awk '{print $2}' \
        | sort -u > "$TMP_SUCCESS_IPS" || true

    if [ -s "$TMP_FAILED_IPS" ] && [ -s "$TMP_SUCCESS_IPS" ]; then
        awk '{print $2}' "$TMP_FAILED_IPS" | sort -u > "$TMP_DIR/failed_unique.txt"
        comm -12 "$TMP_DIR/failed_unique.txt" "$TMP_SUCCESS_IPS" > "$TMP_DIR/brute_success.txt" 2>/dev/null || true
        BRUTE_FORCE_SUCCESS=$(count_nonempty "$TMP_DIR/brute_success.txt")
        [ -n "${BRUTE_FORCE_SUCCESS:-}" ] || BRUTE_FORCE_SUCCESS=0
        if [ "$BRUTE_FORCE_SUCCESS" -gt 0 ]; then
            add_finding "triage-linux-logs-bruteforce-success" "identity.ssh.brute_force_success" \
                "Successful SSH login from a source that also failed authentication" "critical" \
                "Source IPs: $(tr '\n' ' ' < "$TMP_DIR/brute_success.txt")" \
                "Treat the session as compromised, review executed commands, rotate credentials, and block the source." "$AUTH_SOURCE" "authentication_anomaly"
        fi
    fi

    if [ "$FAILED_COUNT" -ge 10 ] 2>/dev/null; then
        _sev="high"
        _title="High volume of failed authentication attempts ($FAILED_COUNT)"
    elif [ "$FAILED_COUNT" -ge 5 ] 2>/dev/null; then
        _sev="medium"
        _title="Repeated failed authentication attempts ($FAILED_COUNT)"
    else
        _sev=""
        _title=""
    fi
    if [ -n "$_sev" ]; then
        add_finding "triage-linux-logs-bruteforce" "identity.auth.repeated_failures" "$_title" "$_sev" \
            "Top sources (count IP): $(tr '\n' ' ' < "$TMP_FAILED_IPS")" \
            "Rate-limit or block abusive sources, enforce key-based SSH authentication, and enable fail2ban where appropriate." "$AUTH_SOURCE" "authentication_anomaly"
    fi

    # Account and group modification events
    grep -Ei 'useradd|usermod|userdel|groupadd|groupmod|groupdel|new user|new group|password changed' "$TMP_AUTH" 2>/dev/null \
        | tail -n 30 > "$TMP_ACCOUNT_CHANGES" || true
    if [ -s "$TMP_ACCOUNT_CHANGES" ]; then
        add_finding "triage-linux-logs-account-change" "identity.account.modification" \
            "Local account or group modification events recorded" "medium" \
            "$(head -n 5 "$TMP_ACCOUNT_CHANGES" | tr '\n' ' ')" \
            "Correlate the changes with an approved change request and verify the resulting account state." "$AUTH_SOURCE" "authentication_anomaly" "medium"
    fi

    # sudo activity
    grep -E 'sudo:.*COMMAND=' "$TMP_AUTH" 2>/dev/null | tail -n 30 > "$TMP_SUDO" || true
    SUDO_COUNT=$(count_nonempty "$TMP_SUDO")
    [ -n "${SUDO_COUNT:-}" ] || SUDO_COUNT=0
    if [ "$SUDO_COUNT" -gt 0 ]; then
        _sudo_shell=$(grep -E 'COMMAND=.*(bash|/bin/sh|/bin/zsh|/bin/dash)([[:space:]]|$)' "$TMP_SUDO" 2>/dev/null | head -n 5)
        if [ -n "$_sudo_shell" ]; then
            add_finding "triage-linux-logs-sudo-shell" "identity.sudo.shell_spawn" \
                "Interactive shell spawned through sudo" "medium" \
                "$_sudo_shell" \
                "Verify the administrative session and review subsequent commands in the audit log." "$AUTH_SOURCE" "authentication_anomaly" "medium"
        fi
    fi

    # Log clearing and tamper indicators
    grep -Ei 'journalctl.*vacuum|logrotate.*(fail|error)|logs? (cleared|truncated|rotated)|rsyslog.*(stopped|failed)' "$TMP_AUTH" 2>/dev/null \
        | tail -n 20 > "$TMP_TAMPER" || true
fi

# ------------------------------------------------------------------------------
# 2. Journal errors and boot history
# ------------------------------------------------------------------------------
JOURNAL_ERROR_COUNT=0
if command -v journalctl >/dev/null 2>&1; then
    journalctl -q -p err --since "-24 hours" --no-pager 2>/dev/null | tail -n 50 > "$TMP_JOURNAL_ERRORS" || true
    JOURNAL_ERROR_COUNT=$(count_nonempty "$TMP_JOURNAL_ERRORS")
    [ -n "${JOURNAL_ERROR_COUNT:-}" ] || JOURNAL_ERROR_COUNT=0
fi
if [ -s "$TMP_TAMPER" ]; then
    add_finding "triage-linux-logs-tamper" "log.tampering.indicator" \
        "Potential log tampering or logging disruption indicators" "high" \
        "$(head -n 5 "$TMP_TAMPER" | tr '\n' ' ')" \
        "Preserve the current logs, forward them to a remote collector, and verify logging configuration integrity." "/var/log" "anti_forensics"
fi

# ------------------------------------------------------------------------------
# 3. Web server access log analysis
# ------------------------------------------------------------------------------
for _log in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
    [ -r "$_log" ] || continue
    printf '%s\n' "$_log" >> "$TMP_WEB_LOGS"
    tail -n 10000 "$_log" 2>/dev/null >> "$TMP_DIR/web_tail.log" || true
done

WEB_REQUESTS=0
WEB_4XX=0
WEB_5XX=0
if [ -s "$TMP_WEB_LOGS" ]; then
    WEB_REQUESTS=$(wc -l < "$TMP_DIR/web_tail.log" 2>/dev/null | tr -d ' ' || echo 0)
    [ -n "${WEB_REQUESTS:-}" ] || WEB_REQUESTS=0
    awk '{print $1}' "$TMP_DIR/web_tail.log" 2>/dev/null | sort | uniq -c | sort -nr | head -n 15 > "$TMP_WEB_IPS" || true
    WEB_4XX=$(awk '$9 ~ /^4[0-9][0-9]$/ {c++} END {print c+0}' "$TMP_DIR/web_tail.log" 2>/dev/null || echo 0)
    WEB_5XX=$(awk '$9 ~ /^5[0-9][0-9]$/ {c++} END {print c+0}' "$TMP_DIR/web_tail.log" 2>/dev/null || echo 0)
    [ -n "${WEB_4XX:-}" ] || WEB_4XX=0
    [ -n "${WEB_5XX:-}" ] || WEB_5XX=0

    grep -Ei '(\.\./|/etc/passwd|/proc/self/environ|/\.env|/\.git/|wp-login\.php|xmlrpc\.php|/shell|/cmd|/c99|/r57|union([[:space:]]+all)?[[:space:]]+select|base64_|eval\(|/phpmyadmin|/adminer|/vendor/phpunit|/actuator|/console|/\.aws/|/config\.php)' \
        "$TMP_DIR/web_tail.log" 2>/dev/null | tail -n 30 > "$TMP_SUSPICIOUS_REQUESTS" || true
    if [ -s "$TMP_SUSPICIOUS_REQUESTS" ]; then
        add_finding "triage-linux-logs-web-attack" "web.request.attack_pattern" \
            "Web attack patterns observed in access logs" "high" \
            "$(head -n 5 "$TMP_SUSPICIOUS_REQUESTS" | tr '\n' ' ')" \
            "Review the affected application, block abusive clients, and verify whether any request succeeded." "/var/log" "web_attack"
    fi
    if [ "$WEB_4XX" -ge 200 ] 2>/dev/null; then
        add_finding "triage-linux-logs-web-4xx" "web.request.error_burst" \
            "High volume of web client errors (4xx: $WEB_4XX in sampled log)" "medium" \
            "Source counts: $(head -n 5 "$TMP_WEB_IPS" | tr '\n' ' ')" \
            "Correlate with application logs and rate-limit or block sources generating abusive traffic." "/var/log" "web_attack" "medium"
    fi
fi

# ------------------------------------------------------------------------------
# 4. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
FAILED_IPS_JSON=$(raw_array_from "$TMP_FAILED_IPS")
FAILED_SAMPLE_JSON=$(raw_array_from "$TMP_FAILED_SAMPLE")
SUCCESS_SAMPLE_JSON=$(raw_array_from "$TMP_SUCCESS_SAMPLE")
SUDO_JSON=$(raw_array_from "$TMP_SUDO")
ACCOUNT_JSON=$(raw_array_from "$TMP_ACCOUNT_CHANGES")
WEB_LOGS_JSON=$(raw_array_from "$TMP_WEB_LOGS")
WEB_IPS_JSON=$(raw_array_from "$TMP_WEB_IPS")
SUSPICIOUS_JSON=$(raw_array_from "$TMP_SUSPICIOUS_REQUESTS")
JOURNAL_JSON=$(raw_array_from "$TMP_JOURNAL_ERRORS")
TAMPER_JSON=$(raw_array_from "$TMP_TAMPER")
BRUTE_SUCCESS_JSON=$(raw_array_from "$TMP_DIR/brute_success.txt")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")"
  },
  "metrics": {
    "auth_source": "$(json_escape "$AUTH_SOURCE")",
    "failed_logons": $FAILED_COUNT,
    "successful_logons": $SUCCESS_COUNT,
    "brute_force_success_sources": $BRUTE_FORCE_SUCCESS,
    "sudo_events_sampled": ${SUDO_COUNT:-0},
    "web_requests_sampled": $WEB_REQUESTS,
    "web_4xx": $WEB_4XX,
    "web_5xx": $WEB_5XX,
    "journal_errors": $JOURNAL_ERROR_COUNT
  },
  "auth": {
    "failed_source_counts": $FAILED_IPS_JSON,
    "failed_samples": $FAILED_SAMPLE_JSON,
    "successful_samples": $SUCCESS_SAMPLE_JSON,
    "brute_force_success_sources": $BRUTE_SUCCESS_JSON
  },
  "sudo": {
    "samples": $SUDO_JSON
  },
  "account_changes": $ACCOUNT_JSON,
  "web": {
    "logs": $WEB_LOGS_JSON,
    "top_client_ips": $WEB_IPS_JSON,
    "suspicious_requests": $SUSPICIOUS_JSON
  },
  "journal_errors": $JOURNAL_JSON,
  "log_tampering_indicators": $TAMPER_JSON,
  "findings": $FINDINGS_JSON
}
EOF
