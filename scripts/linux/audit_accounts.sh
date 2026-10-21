#!/bin/sh
# ==============================================================================
# Linux Account and Privilege Audit (EVA Sec compatible)
# Reviews local identity and privilege boundaries:
#   - /etc/passwd, /etc/shadow, duplicate UIDs and UID 0 accounts
#   - Login shells, home directory permissions and password aging policy
#   - sudoers entries, NOPASSWD rules and privileged group membership
#   - SSH authorized_keys permissions and forced-command restrictions
#   - Recent interactive logins
#
# Read-only. Secret material is never written to output. Emits `eva.triage.v1`.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-accounts"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-acct.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_USERS="$TMP_DIR/users.jsonl"
TMP_AUDITS="$TMP_DIR/audits.jsonl"
TMP_KEYS="$TMP_DIR/keys.jsonl"
TMP_SUDOERS="$TMP_DIR/sudoers.txt"
TMP_NOPASSWD="$TMP_DIR/nopasswd.txt"
TMP_LOGINS="$TMP_DIR/logins.txt"
: > "$TMP_FINDINGS"
: > "$TMP_USERS"
: > "$TMP_AUDITS"
: > "$TMP_KEYS"
: > "$TMP_SUDOERS"
: > "$TMP_NOPASSWD"
: > "$TMP_LOGINS"

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
    _cat=${8:-identity}
    _conf=${9:-high}
    _fp=$(hash_text "$_id|$_rule|$_title|$_file" | cut -c1-32)
    printf '{"id":"%s","tool":"%s","rule_id":"%s","title":"%s","severity":"%s","confidence":"%s","category":"%s","target":"%s","file":"%s","evidence":"%s","remediation":"%s","fingerprint":"%s"},\n' \
        "$(json_escape "$_id")" "$TOOL" "$(json_escape "$_rule")" "$(json_escape "$_title")" "$_sev" "$_conf" "$(json_escape "$_cat")" \
        "$(json_escape "$HOSTNAME")" "$(json_escape "$_file")" "$(snippet "$_ev")" "$(snippet "$_rem")" "$_fp" >> "$TMP_FINDINGS"
}

add_audit() {
    _id=$1
    _title=$2
    _status=$3
    _sev=$4
    _ev=$5
    _rem=$6
    _fp=$(hash_text "$_id|$_title|$_ev" | cut -c1-32)
    printf '{"control_id":"%s","title":"%s","status":"%s","severity":"%s","evidence":"%s","remediation":"%s","fingerprint":"%s"},\n' \
        "$(json_escape "$_id")" "$(json_escape "$_title")" "$_status" "$_sev" "$(snippet "$_ev")" "$(snippet "$_rem")" "$_fp" >> "$TMP_AUDITS"
    if [ "$_status" = "FAIL" ] || [ "$_status" = "WARN" ]; then
        add_finding "triage-linux-accounts-$_id" "hardening.$_id" "$_title" "$_sev" "$_ev" "$_rem" "" "hardening_audit"
    fi
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

is_login_shell() {
    case "${1:-}" in
        ""|*/nologin|*/false|*/sync|*/shutdown|*/halt|*/sbin/nologin|*/bin/false) return 1 ;;
        *) return 0 ;;
    esac
}

is_world_writable() {
    _m=$(stat -c '%a' "$1" 2>/dev/null || true)
    case "$_m" in
        *2|*3|*6|*7) return 0 ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------------------
# 1. User inventory and high-risk identity conditions
# ------------------------------------------------------------------------------
USER_COUNT=0
UID0_COUNT=0
LOGIN_SHELL_COUNT=0
while IFS='|' read -r name uid gid home shell; do
    [ -n "${name:-}" ] || continue
    USER_COUNT=$((USER_COUNT + 1))
    uid_zero="false"
    login_shell="false"
    [ "${uid:-0}" = "0" ] && uid_zero="true"
    is_login_shell "$shell" && login_shell="true"
    [ "$login_shell" = "true" ] && LOGIN_SHELL_COUNT=$((LOGIN_SHELL_COUNT + 1))

    printf '{"name":"%s","uid":%s,"gid":%s,"home":"%s","shell":"%s","uid_zero":%s,"login_shell":%s},\n' \
        "$(json_escape "$name")" "${uid:-0}" "${gid:-0}" "$(json_escape "$home")" "$(json_escape "$shell")" \
        "$uid_zero" "$login_shell" >> "$TMP_USERS"

    if [ "$uid_zero" = "true" ] && [ "$name" != "root" ]; then
        UID0_COUNT=$((UID0_COUNT + 1))
        add_finding "triage-linux-accounts-uid0-$name" "identity.account.uid_zero_backdoor" \
            "Non-root account with UID 0: $name" "critical" \
            "User $name has UID 0 in /etc/passwd (home: $home, shell: $shell)" \
            "Disable the account immediately and investigate how it was created. Preserve audit logs and shell history." "/etc/passwd"
    fi

    if [ "$login_shell" = "true" ] && [ "${uid:-0}" -lt 1000 ] 2>/dev/null && [ "$name" != "root" ]; then
        add_finding "triage-linux-accounts-system-shell-$name" "identity.account.system_user_login_shell" \
            "System account has an interactive login shell: $name" "medium" \
            "UID $uid shell $shell" \
            "Set the account shell to /usr/sbin/nologin unless interactive access is explicitly required." "/etc/passwd" "identity" "medium"
    fi

    if [ -n "${home:-}" ] && [ -d "$home" ] && { [ "${uid:-0}" -ge 1000 ] 2>/dev/null || [ "$name" = "root" ]; } && is_world_writable "$home"; then
        add_finding "triage-linux-accounts-home-ww-$name" "permissions.home.world_writable" \
            "World-writable home directory for $name" "medium" \
            "Home directory: $home (mode $(stat -c '%a' "$home" 2>/dev/null || echo unknown))" \
            "Remove world-write permission from the home directory and review startup files for tampering." "$home" "permissions"
    fi
done <<EOF
$(awk -F: '{print $1"|"$3"|"$4"|"$6"|"$7}' /etc/passwd 2>/dev/null)
EOF

DUPLICATE_UIDS=$(awk -F: '{count[$3]++} END {for (u in count) if (count[u] > 1) print u}' /etc/passwd 2>/dev/null | sort -n | tr '\n' ' ')
if [ -n "$DUPLICATE_UIDS" ]; then
    add_finding "triage-linux-accounts-duplicate-uids" "identity.account.duplicate_uid" \
        "Duplicate UID assignments detected in /etc/passwd" "medium" \
        "Duplicate UIDs: $DUPLICATE_UIDS" \
        "Assign unique UIDs and review file ownership for the affected identities." "/etc/passwd" "identity" "medium"
fi

# ------------------------------------------------------------------------------
# 2. Password and shadow policy
# ------------------------------------------------------------------------------
SHADOW_READABLE="false"
EMPTY_PASSWORD_USERS=""
if [ -r /etc/shadow ]; then
    SHADOW_READABLE="true"
    EMPTY_PASSWORD_USERS=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | head -n 20 | tr '\n' ' ')
    _shadow_mode=$(stat -c '%a' /etc/shadow 2>/dev/null || true)
    case "$_shadow_mode" in
        600|640|000) add_audit "accounts.shadow_permissions" "Shadow file permissions are restrictive" "PASS" "info" "/etc/shadow mode $_shadow_mode" "" ;;
        *) add_audit "accounts.shadow_permissions" "Shadow file permissions are too permissive" "FAIL" "high" "/etc/shadow mode ${_shadow_mode:-unknown}" "Set /etc/shadow ownership to root:shadow and mode 640 or 600." ;;
    esac
else
    add_audit "accounts.shadow_readable" "Shadow file is not readable by the current user" "INFO" "info" "Run the audit as root to evaluate password hashes and aging." "" 
fi
if [ -n "$EMPTY_PASSWORD_USERS" ]; then
    add_finding "triage-linux-accounts-empty-password" "identity.account.empty_password" \
        "Accounts with empty password fields detected: $EMPTY_PASSWORD_USERS" "critical" \
        "Empty hash in /etc/shadow for: $EMPTY_PASSWORD_USERS" \
        "Lock the affected accounts immediately with passwd -l and investigate unauthorized access." "/etc/shadow"
fi

PASS_MAX=$(awk '$1=="PASS_MAX_DAYS" {print $2}' /etc/login.defs 2>/dev/null | head -n 1 || echo "")
PASS_MIN=$(awk '$1=="PASS_MIN_DAYS" {print $2}' /etc/login.defs 2>/dev/null | head -n 1 || echo "")
PASS_WARN=$(awk '$1=="PASS_WARN_AGE" {print $2}' /etc/login.defs 2>/dev/null | head -n 1 || echo "")
UMASK_DEF=$(awk '$1=="UMASK" {print $2}' /etc/login.defs 2>/dev/null | head -n 1 || echo "")
if [ -n "$PASS_MAX" ] && [ "$PASS_MAX" -gt 365 ] 2>/dev/null; then
    add_audit "accounts.password_max_age" "Password maximum age exceeds 365 days ($PASS_MAX)" "WARN" "low" "PASS_MAX_DAYS=$PASS_MAX" "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs."
elif [ -n "$PASS_MAX" ]; then
    add_audit "accounts.password_max_age" "Password maximum age is configured" "PASS" "info" "PASS_MAX_DAYS=$PASS_MAX" ""
fi
if [ -n "$PASS_MIN" ] && [ "$PASS_MIN" -lt 1 ] 2>/dev/null; then
    add_audit "accounts.password_min_age" "Password minimum age allows immediate password changes" "WARN" "low" "PASS_MIN_DAYS=$PASS_MIN" "Set PASS_MIN_DAYS to at least 1."
fi
if [ -n "$UMASK_DEF" ]; then
    case "$UMASK_DEF" in
        027|077|037) add_audit "accounts.umask" "Default UMASK is restrictive" "PASS" "info" "UMASK=$UMASK_DEF" "" ;;
        *) add_audit "accounts.umask" "Default UMASK is permissive" "WARN" "low" "UMASK=$UMASK_DEF" "Set UMASK to 027 in /etc/login.defs." ;;
    esac
fi

# ------------------------------------------------------------------------------
# 3. sudoers and privileged groups
# ------------------------------------------------------------------------------
SUDOERS_FILES=""
for _f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$_f" ] || continue
    SUDOERS_FILES="${SUDOERS_FILES} $_f"
    if is_world_writable "$_f"; then
        add_finding "triage-linux-accounts-sudoers-ww-$(hash_text "$_f" | cut -c1-8)" "permissions.sudoers.world_writable" \
            "World-writable sudoers file: $_f" "critical" \
            "Mode: $(stat -c '%a' "$_f" 2>/dev/null || echo unknown)" \
            "Remove world-write permission immediately and inspect the file for unauthorized privilege grants." "$_f" "permissions"
    fi
    grep -Ev '^[[:space:]]*(#|$)' "$_f" 2>/dev/null | head -n 200 >> "$TMP_SUDOERS" || true
done
NOPASSWD_ENTRIES=$(grep -RhsE 'NOPASSWD[[:space:]]*:' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -Ev '^[[:space:]]*#' | head -n 50)
if [ -n "$NOPASSWD_ENTRIES" ]; then
    printf '%s\n' "$NOPASSWD_ENTRIES" > "$TMP_NOPASSWD"
    add_finding "triage-linux-accounts-nopasswd" "identity.sudo.nopasswd" \
        "Passwordless sudo rules are configured" "medium" \
        "$(printf '%s' "$NOPASSWD_ENTRIES" | cut -c1-1000)" \
        "Require authentication for privileged commands and review each NOPASSWD rule against policy." "/etc/sudoers" "identity" "medium"
fi
if grep -RhsE '^[^#]*NOPASSWD[[:space:]]*:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q .; then
    add_finding "triage-linux-accounts-nopasswd-all" "identity.sudo.nopasswd_all" \
        "Passwordless unrestricted sudo access granted" "critical" \
        "A sudoers rule grants NOPASSWD: ALL" \
        "Remove the unrestricted passwordless rule and require re-authentication for administrative actions." "/etc/sudoers"
fi

PRIV_GROUPS=""
for _g in sudo wheel admin; do
    _members=$(getent group "$_g" 2>/dev/null | cut -d: -f4 || true)
    if [ -n "$_members" ]; then
        PRIV_GROUPS="${PRIV_GROUPS}${_g}=${_members}; "
    fi
done
if [ -z "$PRIV_GROUPS" ]; then
    PRIV_GROUPS="none"
fi

# ------------------------------------------------------------------------------
# 4. SSH authorized_keys review
# ------------------------------------------------------------------------------
AUTH_KEY_FILES=0
for _home in /root /home/*; do
    [ -d "$_home" ] || continue
    for _keyfile in "$_home/.ssh/authorized_keys" "$_home/.ssh/authorized_keys2"; do
        [ -f "$_keyfile" ] || continue
        AUTH_KEY_FILES=$((AUTH_KEY_FILES + 1))
        _owner=$(stat -c '%U' "$_keyfile" 2>/dev/null || echo unknown)
        _mode=$(stat -c '%a' "$_keyfile" 2>/dev/null || echo unknown)
        _count=$(grep -Evc '^[[:space:]]*(#|$)' "$_keyfile" 2>/dev/null || true)
        [ -n "${_count:-}" ] || _count=0
        printf '{"file":"%s","owner":"%s","mode":"%s","keys":%s},\n' \
            "$(json_escape "$_keyfile")" "$(json_escape "$_owner")" "$(json_escape "$_mode")" "$_count" >> "$TMP_KEYS"

        case "$_mode" in
            *2|*3|*6|*7)
                add_finding "triage-linux-accounts-ssh-key-perms-$(hash_text "$_keyfile" | cut -c1-8)" "identity.ssh.authorized_keys_world_writable" \
                    "SSH authorized_keys file is group/world writable" "high" \
                    "File: $_keyfile mode $_mode owner $_owner" \
                    "Run chmod 600 and chown <user>:<user> on the authorized_keys file, then review its contents." "$_keyfile" "identity"
                ;;
        esac

        if [ "$_owner" != "root" ] && [ "$_owner" != "$(basename "$_home")" ]; then
            add_finding "triage-linux-accounts-ssh-key-owner-$(hash_text "$_keyfile" | cut -c1-8)" "identity.ssh.authorized_keys_owner" \
                "SSH authorized_keys owner does not match the home directory user" "medium" \
                "File: $_keyfile owner $_owner home user $(basename "$_home")" \
                "Restore correct ownership so that only the account owner can manage their keys." "$_keyfile" "identity" "medium"
        fi

        while IFS= read -r _keyline; do
            case "$_keyline" in
                ''|'#'*) continue ;;
            esac
            if printf '%s' "$_keyline" | grep -Eq '(^|[[:space:]])(command|environment|permitopen|tunnel)='; then
                _kfp=$(hash_text "$_keyline" | cut -c1-16)
                add_finding "triage-linux-accounts-ssh-restricted-$_kfp" "identity.ssh.key_restriction" \
                    "SSH authorized key uses forced-command or environment restrictions" "low" \
                    "File: $_keyfile key fingerprint: sha256:$_kfp" \
                    "Verify the forced command or environment override was intentionally deployed and is still required." "$_keyfile" "identity" "medium"
            fi
        done < "$_keyfile"
    done
done

# ------------------------------------------------------------------------------
# 5. Recent logins and report assembly
# ------------------------------------------------------------------------------
last -n 15 2>/dev/null | head -n 15 > "$TMP_LOGINS" || true
LOGIN_COUNT=$(who 2>/dev/null | wc -l | tr -d ' ' || echo 0)
[ -n "${LOGIN_COUNT:-}" ] || LOGIN_COUNT=0

USERS_JSON=$(json_array_from "$TMP_USERS")
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
AUDITS_JSON=$(json_array_from "$TMP_AUDITS")
KEYS_JSON=$(json_array_from "$TMP_KEYS")
SUDOERS_JSON=$(raw_array_from "$TMP_SUDOERS")
NOPASSWD_JSON=$(raw_array_from "$TMP_NOPASSWD")
LOGINS_JSON=$(raw_array_from "$TMP_LOGINS")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")"
  },
  "metrics": {
    "users": $USER_COUNT,
    "uid_zero_accounts": $UID0_COUNT,
    "login_shell_accounts": $LOGIN_SHELL_COUNT,
    "authorized_keys_files": $AUTH_KEY_FILES,
    "active_sessions": $LOGIN_COUNT,
    "shadow_readable": $SHADOW_READABLE
  },
  "policy": {
    "pass_max_days": "$(json_escape "$PASS_MAX")",
    "pass_min_days": "$(json_escape "$PASS_MIN")",
    "pass_warn_age": "$(json_escape "$PASS_WARN")",
    "umask": "$(json_escape "$UMASK_DEF")"
  },
  "users": $USERS_JSON,
  "sudo": {
    "sudoers_files": "$(json_escape "$SUDOERS_FILES")",
    "privileged_groups": "$(json_escape "$PRIV_GROUPS")",
    "sudoers_rules": $SUDOERS_JSON,
    "nopasswd_rules": $NOPASSWD_JSON
  },
  "ssh_authorized_keys": $KEYS_JSON,
  "recent_logins": $LOGINS_JSON,
  "audits": $AUDITS_JSON,
  "findings": $FINDINGS_JSON
}
EOF
