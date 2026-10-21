#!/bin/sh
# ==============================================================================
# Linux Incident Response Snapshot (EVA Sec compatible)
# Collects volatile host evidence for first responders:
#   - Host identity, boot time, kernel and virtualization facts
#   - Process inventory with executable paths and suspicious-process findings
#   - Listening sockets, established connections and suspicious service ports
#   - Logged-in users, mounts, kernel modules, recent temporary files
#   - LD_PRELOAD hijacking and systemd units executing from temporary paths
#
# The script is read-only, zero-dependency, uses private temporary files, and
# emits `eva.triage.v1` JSON on stdout. No evidence leaves the endpoint.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-incident-response"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")
KERNEL=$(uname -r 2>/dev/null || echo "unknown-kernel")
ARCH=$(uname -m 2>/dev/null || echo "unknown-arch")
BOOT_TIME=$(uptime -s 2>/dev/null || who -b 2>/dev/null | awk '{print $3" "$4}' || echo "unknown")
UPTIME=$(uptime 2>/dev/null | sed 's/^ *//' | tr -d '\n')
CURRENT_USER=$(id 2>/dev/null | sed 's/"/\\"/g' || echo "unknown")
OS_RELEASE=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"' || echo "unknown")
VIRT=$(systemd-detect-virt 2>/dev/null || echo "unknown")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-ir.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_PROCESSES="$TMP_DIR/processes.jsonl"
TMP_SOCKETS="$TMP_DIR/sockets.txt"
TMP_ESTABLISHED="$TMP_DIR/established.txt"
TMP_TEMP_FILES="$TMP_DIR/tempfiles.txt"
TMP_USERS="$TMP_DIR/users.txt"
TMP_MOUNTS="$TMP_DIR/mounts.txt"
TMP_MODULES="$TMP_DIR/modules.txt"
TMP_SUSPECT_PORTS="$TMP_DIR/ports.txt"
: > "$TMP_FINDINGS"
: > "$TMP_PROCESSES"
: > "$TMP_SOCKETS"
: > "$TMP_ESTABLISHED"
: > "$TMP_TEMP_FILES"
: > "$TMP_USERS"
: > "$TMP_MOUNTS"
: > "$TMP_MODULES"
: > "$TMP_SUSPECT_PORTS"

cleanup() {
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

json_escape() {
    printf '%s' "${1:-}" | tr '\n\r\t' '   ' | sed -e 's/[[:cntrl:]]/ /g' -e 's/\\/\\\\/g' -e 's/"/\\"/g' | cut -c1-4000
}

snippet() {
    json_escape "$1" | cut -c1-800
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
    _cat=${8:-host_anomaly}
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

# ------------------------------------------------------------------------------
# 1. Process inventory and suspicious process indicators
# ------------------------------------------------------------------------------
PROCESS_COUNT=0
if ps -eo pid=,ppid=,user=,etimes=,comm=,args= > "$TMP_DIR/ps.txt" 2>/dev/null; then
    cp "$TMP_DIR/ps.txt" "$TMP_DIR/ps.norm"
else
    ps auxww > "$TMP_DIR/ps.txt" 2>/dev/null || true
    : > "$TMP_DIR/ps.norm"
fi

SUSPECT_PROC_FINDINGS=0
if [ -s "$TMP_DIR/ps.norm" ]; then
    while read -r pid ppid user etimes comm args; do
        [ -n "${pid:-}" ] || continue
        PROCESS_COUNT=$((PROCESS_COUNT + 1))
        [ "$PROCESS_COUNT" -le 400 ] || continue

        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
        [ -n "${args:-}" ] || args="$comm"
        args_snip=$(printf '%s' "$args" | cut -c1-500)

        if [ "$PROCESS_COUNT" -le 300 ]; then
            printf '{"pid":%s,"ppid":%s,"user":"%s","elapsed_seconds":%s,"name":"%s","executable":"%s","command":"%s"},\n' \
                "$pid" "${ppid:-0}" "$(json_escape "$user")" "${etimes:-0}" "$(json_escape "$comm")" "$(json_escape "$exe")" \
                "$(json_escape "$args_snip")" >> "$TMP_PROCESSES"
        fi

        case "$exe" in
            *" (deleted)")
                add_finding "triage-linux-ir-deleted-exe-$pid" "process.execution.deleted_binary" \
                    "Process $comm (PID $pid) is running from a deleted executable" "high" \
                    "PID $pid executable: $exe Command: $args_snip" \
                    "Capture process memory and the deleted binary for forensics, then terminate the process after containment." "" "process_anomaly"
                SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
                ;;
        esac

        case "$exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                add_finding "triage-linux-ir-temp-exe-$pid" "process.execution.temp_directory" \
                    "Process $comm (PID $pid) executes from a temporary directory" "high" \
                    "PID $pid executable: $exe Command: $args_snip" \
                    "Treat the binary as untrusted, capture it and compare its hash against known software." "$exe" "process_anomaly"
                SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
                ;;
        esac

        case "$comm" in
            .*)
                add_finding "triage-linux-ir-hidden-proc-$pid" "process.execution.hidden_name" \
                    "Process with hidden name detected: $comm (PID $pid)" "medium" \
                    "PID $pid executable: $exe Command: $args_snip" \
                    "Inspect the binary provenance and parent process; malware commonly hides executable names." "$exe" "process_anomaly"
                SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
                ;;
        esac

        if printf '%s' "$args_snip" | grep -Eqi '(^|[[:space:]])(xmrig|minerd|cpuminer|stratum\+tcp|xmr-stak|kawpow)([[:space:]]|$)'; then
            add_finding "triage-linux-ir-miner-$pid" "process.execution.cryptominer" \
                "Potential cryptominer process: $comm (PID $pid)" "high" \
                "PID $pid command: $args_snip" \
                "Isolate the host, capture the binary, and audit scheduled tasks and container workloads for miner deployment." "$exe" "process_anomaly"
            SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
        fi

        if printf '%s' "$args_snip" | grep -Eqi '(nc|ncat|netcat|socat)[[:space:]].*(-e[[:space:]]|exec:)'; then
            add_finding "triage-linux-ir-reverse-shell-$pid" "process.execution.reverse_shell" \
                "Potential reverse shell process: $comm (PID $pid)" "critical" \
                "PID $pid command: $args_snip" \
                "Terminate the process, block the remote peer at the firewall, and collect shell history and parent process details." "$exe" "command_and_control"
            SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
        fi

        if printf '%s' "$args_snip" | grep -Eqi '(curl|wget)[^|]{0,200}\|[[:space:]]*(ba|z|da)?sh([[:space:]]|$)'; then
            add_finding "triage-linux-ir-download-cradle-$pid" "execution.download_cradle" \
                "Download-and-execute shell pipeline observed: $comm (PID $pid)" "high" \
                "PID $pid command: $args_snip" \
                "Block the remote URL, inspect fetched payloads, and review shell history for follow-on commands." "$exe" "command_and_control"
            SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
        fi

        if printf '%s' "$args_snip" | grep -Eqi 'bash[[:space:]]+-i.*(/dev/tcp/|>&[[:space:]]*/dev/tcp/)'; then
            add_finding "triage-linux-ir-bash-tcp-$pid" "process.execution.bash_dev_tcp" \
                "Bash /dev/tcp interactive shell observed: $comm (PID $pid)" "critical" \
                "PID $pid command: $args_snip" \
                "Terminate the process and investigate the remote endpoint and parent process immediately." "$exe" "command_and_control"
            SUSPECT_PROC_FINDINGS=$((SUSPECT_PROC_FINDINGS + 1))
        fi
    done < "$TMP_DIR/ps.norm"
fi

# ------------------------------------------------------------------------------
# 2. Sockets and suspicious service ports
# ------------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
    ss -H -tulpn 2>/dev/null | head -n 300 > "$TMP_SOCKETS" || ss -tulpn 2>/dev/null | sed 1d | head -n 300 > "$TMP_SOCKETS"
    ss -H -tunp state established 2>/dev/null | head -n 200 > "$TMP_ESTABLISHED" || \
        ss -tunp 2>/dev/null | grep -E 'ESTAB|ESTABLISHED' | head -n 200 > "$TMP_ESTABLISHED"
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn 2>/dev/null | sed 1,2d | head -n 300 > "$TMP_SOCKETS"
    netstat -tunp 2>/dev/null | grep -E 'ESTABLISHED' | head -n 200 > "$TMP_ESTABLISHED"
fi

LISTENER_COUNT=$(wc -l < "$TMP_SOCKETS" 2>/dev/null | tr -d ' ' || echo 0)
ESTABLISHED_COUNT=$(wc -l < "$TMP_ESTABLISHED" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${LISTENER_COUNT:-}" ] || LISTENER_COUNT=0
[ -n "${ESTABLISHED_COUNT:-}" ] || ESTABLISHED_COUNT=0

if [ -s "$TMP_SOCKETS" ]; then
    awk '{for (i=1; i<=NF; i++) { if ($i ~ /:[0-9]+$/) { n=split($i,a,":"); print a[n]; break } }}' "$TMP_SOCKETS" \
        | sort -un > "$TMP_SUSPECT_PORTS"
fi

while IFS= read -r port; do
    [ -n "$port" ] || continue
    case "$port" in
        23)   _sev="high";   _title="Telnet service listening on port 23"; _rule="network.service.telnet_exposed"; _rem="Disable telnet and migrate to SSH." ;;
        21)   _sev="medium"; _title="FTP service listening on port 21"; _rule="network.service.ftp_exposed"; _rem="Disable cleartext FTP or require FTPS/SFTP." ;;
        69)   _sev="medium"; _title="TFTP service listening on port 69"; _rule="network.service.tftp_exposed"; _rem="Disable TFTP unless required for controlled provisioning." ;;
        111)  _sev="medium"; _title="rpcbind service listening on port 111"; _rule="network.service.rpcbind_exposed"; _rem="Restrict rpcbind to localhost or disable unused RPC services." ;;
        512|513|514) _sev="high"; _title="Legacy r-services listening on port $port"; _rule="network.service.legacy_rsh_exposed"; _rem="Disable rexec/rlogin/rsh and use SSH." ;;
        2049) _sev="medium"; _title="NFS service listening on port 2049"; _rule="network.service.nfs_exposed"; _rem="Restrict NFS exports to trusted networks and use Kerberos." ;;
        2375) _sev="critical"; _title="Docker API exposed without TLS on port 2375"; _rule="container.docker.api_unauthenticated"; _rem="Disable the unauthenticated Docker TCP socket and use a protected local socket." ;;
        2376) _sev="medium"; _title="Docker TLS API listening on port 2376"; _rule="container.docker.api_exposed"; _rem="Restrict Docker API access to trusted management networks." ;;
        4444|1337|31337|5555) _sev="high"; _title="Common backdoor port listening on $port"; _rule="network.listener.suspicious_port"; _rem="Identify the owning process and remove unauthorized software." ;;
        6667) _sev="medium"; _title="IRC service listening on port 6667"; _rule="network.listener.irc_port"; _rem="Block IRC egress and inspect the owning process for botnet activity." ;;
        9001|9050|1080) _sev="medium"; _title="Proxy or Tor-related listener on port $port"; _rule="network.listener.proxy_port"; _rem="Verify whether the proxy is authorized and inspect the owning process." ;;
        *) continue ;;
    esac
    _match=$(grep -E "[:.]$port([[:space:]]|$)" "$TMP_SOCKETS" 2>/dev/null | head -n 1)
    [ -n "$_match" ] || _match="Port $port detected in listening socket table"
    add_finding "triage-linux-ir-port-$port" "$_rule" "$_title" "$_sev" "$_match" "$_rem" "" "network_anomaly"
done < "$TMP_SUSPECT_PORTS"

# ------------------------------------------------------------------------------
# 3. Logged-in users, mounts, kernel modules
# ------------------------------------------------------------------------------
who -a 2>/dev/null | head -n 50 > "$TMP_USERS" || true
LOGGED_IN_COUNT=$(who 2>/dev/null | wc -l | tr -d ' ' || echo 0)
[ -n "${LOGGED_IN_COUNT:-}" ] || LOGGED_IN_COUNT=0

if who 2>/dev/null | awk '$1=="root" && NF >= 5 && $5 !~ /^\(:/ {found=1} END {exit found?0:1}'; then
    add_finding "triage-linux-ir-root-remote-login" "identity.session.root_remote" \
        "Root account has an interactive remote session" "medium" \
        "$(who 2>/dev/null | awk '$1=="root" {print}' | head -n 3 | tr '\n' ' ')" \
        "Confirm the session owner, prefer named sudo accounts, and restrict direct root SSH login." "" "authentication_anomaly" "medium"
fi

mount 2>/dev/null | head -n 100 > "$TMP_MOUNTS" || true
TMP_MOUNT_OPTIONS=""
if command -v findmnt >/dev/null 2>&1; then
    TMP_MOUNT_OPTIONS=$(findmnt -no OPTIONS /tmp 2>/dev/null || true)
    if [ -n "$TMP_MOUNT_OPTIONS" ] && ! printf '%s' "$TMP_MOUNT_OPTIONS" | grep -q 'noexec'; then
        add_finding "triage-linux-ir-tmp-noexec" "filesystem.tmp.executable" \
            "/tmp is mounted without the noexec option" "low" \
            "Mount options for /tmp: $TMP_MOUNT_OPTIONS" \
            "Add noexec,nosuid,nodev to the /tmp mount options where application compatibility permits." "" "hardening_audit" "medium"
    fi
fi

lsmod 2>/dev/null | head -n 200 > "$TMP_MODULES" || true
MODULE_COUNT=$(wc -l < "$TMP_MODULES" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${MODULE_COUNT:-}" ] || MODULE_COUNT=0
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
if [ "${TAINT:-0}" != "0" ]; then
    add_finding "triage-linux-ir-kernel-tainted" "kernel.tainted" \
        "Kernel is tainted (taint flags: $TAINT)" "medium" \
        "See /proc/sys/kernel/tainted. Flags can indicate proprietary, unsigned, out-of-tree, or force-loaded modules." \
        "Decode taint flags and remove unsigned or unexpected kernel modules." "/proc/sys/kernel/tainted" "kernel_anomaly" "medium"
fi

# ------------------------------------------------------------------------------
# 4. LD_PRELOAD hijacking and systemd units executing from temporary paths
# ------------------------------------------------------------------------------
if [ -f /etc/ld.so.preload ]; then
    PRELOAD_CONTENT=$(tr '\n' ' ' < /etc/ld.so.preload 2>/dev/null | cut -c1-500)
    if [ -n "$PRELOAD_CONTENT" ]; then
        add_finding "triage-linux-ir-ld-preload" "persistence.ld_preload.active" \
            "Active /etc/ld.so.preload library injection configured" "critical" \
            "Content: $PRELOAD_CONTENT" \
            "Hash and inspect each referenced library; remove unauthorized entries and rebuild the affected package." "/etc/ld.so.preload" "persistence"
    fi
fi

if [ -d /etc/systemd/system ]; then
    SUSP_SVC=$(grep -RhsE '^[[:space:]]*ExecStart=.*(/tmp|/var/tmp|/dev/shm)' /etc/systemd/system 2>/dev/null | head -n 10)
    if [ -n "$SUSP_SVC" ]; then
        add_finding "triage-linux-ir-systemd-tmp-exec" "persistence.systemd.temp_executable" \
            "Systemd unit launches a binary from a temporary directory" "high" \
            "$SUSP_SVC" \
            "Review the unit, capture the referenced binary, and remove unauthorized services." "/etc/systemd/system" "persistence"
    fi
fi
SYSTEMD_UNIT_COUNT=$(systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null | wc -l | tr -d ' ' || echo 0)
[ -n "${SYSTEMD_UNIT_COUNT:-}" ] || SYSTEMD_UNIT_COUNT=0

# ------------------------------------------------------------------------------
# 5. Recently created files in volatile directories
# ------------------------------------------------------------------------------
find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mtime -7 2>/dev/null | head -n 150 > "$TMP_TEMP_FILES" || true
RECENT_TEMP_COUNT=$(wc -l < "$TMP_TEMP_FILES" 2>/dev/null | tr -d ' ' || echo 0)
[ -n "${RECENT_TEMP_COUNT:-}" ] || RECENT_TEMP_COUNT=0
TEMP_FINDING_COUNT=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$f" ] || continue
    if [ -x "$f" ] && [ "$TEMP_FINDING_COUNT" -lt 10 ]; then
        if file -b "$f" 2>/dev/null | grep -qi 'ELF'; then
            add_finding "triage-linux-ir-temp-elf-$(hash_text "$f" | cut -c1-12)" "filesystem.temp.elf_binary" \
                "Executable ELF binary found in a volatile directory" "medium" \
                "File: $f" \
                "Hash the binary, submit it for analysis, and remove it if it is not part of an approved package." "$f" "malware"
            TEMP_FINDING_COUNT=$((TEMP_FINDING_COUNT + 1))
        elif head -c 2 "$f" 2>/dev/null | grep -q '#!'; then
            add_finding "triage-linux-ir-temp-script-$(hash_text "$f" | cut -c1-12)" "filesystem.temp.executable_script" \
                "Executable script found in a volatile directory" "low" \
                "File: $f First line: $(head -n 1 "$f" 2>/dev/null | cut -c1-200)" \
                "Verify the script provenance and remove it if unauthorized." "$f" "malware" "medium"
            TEMP_FINDING_COUNT=$((TEMP_FINDING_COUNT + 1))
        fi
    fi
done < "$TMP_TEMP_FILES"

# ------------------------------------------------------------------------------
# 6. Report assembly
# ------------------------------------------------------------------------------
PROCESSES_JSON=$(json_array_from "$TMP_PROCESSES")
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
SOCKETS_JSON=$(raw_array_from "$TMP_SOCKETS")
ESTABLISHED_JSON=$(raw_array_from "$TMP_ESTABLISHED")
USERS_JSON=$(raw_array_from "$TMP_USERS")
MOUNTS_JSON=$(raw_array_from "$TMP_MOUNTS")
MODULES_JSON=$(raw_array_from "$TMP_MODULES")
TEMPFILES_JSON=$(raw_array_from "$TMP_TEMP_FILES")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")",
    "os": "$(json_escape "$OS_RELEASE")",
    "kernel": "$(json_escape "$KERNEL")",
    "architecture": "$(json_escape "$ARCH")",
    "boot_time": "$(json_escape "$BOOT_TIME")",
    "uptime": "$(json_escape "$UPTIME")",
    "virtualization": "$(json_escape "$VIRT")",
    "current_user": "$(json_escape "$CURRENT_USER")"
  },
  "metrics": {
    "processes": $PROCESS_COUNT,
    "suspicious_process_findings": $SUSPECT_PROC_FINDINGS,
    "listeners": $LISTENER_COUNT,
    "established_connections": $ESTABLISHED_COUNT,
    "logged_in_sessions": $LOGGED_IN_COUNT,
    "kernel_modules": $MODULE_COUNT,
    "systemd_services": $SYSTEMD_UNIT_COUNT,
    "recent_temp_files": $RECENT_TEMP_COUNT,
    "kernel_taint": $TAINT
  },
  "processes": $PROCESSES_JSON,
  "listeners": $SOCKETS_JSON,
  "established_connections": $ESTABLISHED_JSON,
  "logged_in_users": $USERS_JSON,
  "mounts": $MOUNTS_JSON,
  "kernel_modules": $MODULES_JSON,
  "recent_temp_files": $TEMPFILES_JSON,
  "findings": $FINDINGS_JSON
}
EOF
