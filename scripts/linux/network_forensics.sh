#!/bin/sh
# ==============================================================================
# Linux Network Forensics and Exposure Triage (EVA Sec compatible)
# Reviews host networking for command-and-control and exposure indicators:
#   - Interfaces, promiscuous mode, addresses, routes and neighbor cache
#   - DNS resolver configuration and hosts-file redirects
#   - Listening sockets, established connections and connection states
#   - Firewall state, IP forwarding, network namespaces and proxy injection
#
# Read-only. Emits `eva.triage.v1` JSON on stdout.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-network-forensics"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-net.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_LISTENERS="$TMP_DIR/listeners.txt"
TMP_ESTABLISHED="$TMP_DIR/established.txt"
TMP_ADDRS="$TMP_DIR/addrs.txt"
TMP_ROUTES="$TMP_DIR/routes.txt"
TMP_NEIGH="$TMP_DIR/neigh.txt"
TMP_DNS="$TMP_DIR/dns.txt"
TMP_HOSTS_HITS="$TMP_DIR/hosts_hits.txt"
TMP_PROXY="$TMP_DIR/proxy.txt"
TMP_NETNS="$TMP_DIR/netns.txt"
TMP_PORTS="$TMP_DIR/ports.txt"
: > "$TMP_FINDINGS"
: > "$TMP_LISTENERS"
: > "$TMP_ESTABLISHED"
: > "$TMP_ADDRS"
: > "$TMP_ROUTES"
: > "$TMP_NEIGH"
: > "$TMP_DNS"
: > "$TMP_HOSTS_HITS"
: > "$TMP_PROXY"
: > "$TMP_NETNS"
: > "$TMP_PORTS"

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
    _cat=${8:-network_anomaly}
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
# 1. Interfaces and promiscuous mode
# ------------------------------------------------------------------------------
if command -v ip >/dev/null 2>&1; then
    ip -brief addr 2>/dev/null > "$TMP_ADDRS" || true
    ip route show 2>/dev/null > "$TMP_ROUTES" || true
    ip -6 route show 2>/dev/null >> "$TMP_ROUTES" || true
    ip neigh show 2>/dev/null > "$TMP_NEIGH" || true
    ip netns list 2>/dev/null > "$TMP_NETNS" || true
else
    ifconfig -a 2>/dev/null > "$TMP_ADDRS" || true
    route -n 2>/dev/null > "$TMP_ROUTES" || true
    arp -an 2>/dev/null > "$TMP_NEIGH" || true
fi

INTERFACE_COUNT=$(count_lines "$TMP_ADDRS")
[ -n "${INTERFACE_COUNT:-}" ] || INTERFACE_COUNT=0
for _ifdir in /sys/class/net/*; do
    [ -d "$_ifdir" ] || continue
    _ifname=$(basename "$_ifdir")
    _flags=$(cat "$_ifdir/flags" 2>/dev/null || echo 0)
    if [ $((_flags & 0x100)) -ne 0 ] 2>/dev/null; then
        add_finding "triage-linux-net-promisc-$_ifname" "network.interface.promiscuous" \
            "Network interface is in promiscuous mode: $_ifname" "high" \
            "Interface $_ifname flags: $_flags" \
            "Disable promiscuous mode unless packet capture is authorized, and identify the process that enabled it." "/sys/class/net/$_ifname"
    fi
done

# ------------------------------------------------------------------------------
# 2. DNS, hosts file and proxy configuration
# ------------------------------------------------------------------------------
if [ -r /etc/resolv.conf ]; then
    grep -E '^[[:space:]]*(nameserver|search|options)' /etc/resolv.conf 2>/dev/null > "$TMP_DNS" || true
    RESOLVERS=$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
else
    RESOLVERS="none"
fi

grep -Ev '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -Ei 'antivirus|virustotal|defender|security|update|microsoft|windowsupdate|sophos|symantec|crowdstrike|sentinelone|firewall' \
    > "$TMP_HOSTS_HITS" || true
if [ -s "$TMP_HOSTS_HITS" ]; then
    add_finding "triage-linux-net-hosts-redirect" "network.dns.hosts_security_redirect" \
        "Security or update domains are redirected in /etc/hosts" "critical" \
        "$(head -n 5 "$TMP_HOSTS_HITS" | tr '\n' ' ')" \
        "Remove unauthorized hosts entries, restore DNS resolution, and investigate how the file was modified." "/etc/hosts"
fi

PROXY_VARS=""
for _var in HTTP_PROXY HTTPS_PROXY FTP_PROXY ALL_PROXY http_proxy https_proxy ftp_proxy all_proxy; do
    eval "_val=\${$_var:-}"
    if [ -n "$_val" ]; then
        PROXY_VARS="${PROXY_VARS}${_var} "
    fi
done
if [ -n "$PROXY_VARS" ]; then
    printf 'environment: %s\n' "$PROXY_VARS" >> "$TMP_PROXY"
fi
for _f in /etc/apt/apt.conf /etc/apt/apt.conf.d/* /etc/environment /etc/profile.d/*.sh; do
    [ -f "$_f" ] || continue
    if grep -Eqi '^[[:space:]]*(Acquire::.*Proxy|.*_proxy=|export[[:space:]]+.*_proxy=)' "$_f" 2>/dev/null; then
        printf '%s\n' "$_f" >> "$TMP_PROXY"
    fi
done
sort -u "$TMP_PROXY" -o "$TMP_PROXY" 2>/dev/null || true
if [ -s "$TMP_PROXY" ]; then
    add_finding "triage-linux-net-proxy-config" "network.proxy.configuration" \
        "System or shell proxy configuration detected" "medium" \
        "Proxy configuration present in: $(tr '\n' ' ' < "$TMP_PROXY")" \
        "Verify the proxy is authorized; malicious proxies can intercept credentials and command traffic." "" "network_anomaly" "medium"
fi

if [ -r /etc/nsswitch.conf ]; then
    _hosts_line=$(grep -E '^[[:space:]]*hosts:' /etc/nsswitch.conf 2>/dev/null | head -n 1)
    case "$_hosts_line" in
        *files*) ;;
        *) add_finding "triage-linux-net-nsswitch-hosts" "network.dns.nsswitch_misconfigured" \
            "Name service switch does not consult local files first" "low" \
            "nsswitch hosts entry: ${_hosts_line:-missing}" \
            "Restore 'hosts: files dns' in /etc/nsswitch.conf unless a directory service is explicitly required." "/etc/nsswitch.conf" "network_anomaly" "medium" ;;
    esac
fi

# ------------------------------------------------------------------------------
# 3. Sockets, connection states and suspicious listeners
# ------------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
    ss -H -tulpn 2>/dev/null | head -n 400 > "$TMP_LISTENERS" || ss -tulpn 2>/dev/null | sed 1d | head -n 400 > "$TMP_LISTENERS"
    ss -H -tunp state established 2>/dev/null | head -n 300 > "$TMP_ESTABLISHED" || \
        ss -tunp 2>/dev/null | grep -E 'ESTAB|ESTABLISHED' | head -n 300 > "$TMP_ESTABLISHED"
    ss -H -tan 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr > "$TMP_DIR/states.txt" || true
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn 2>/dev/null | sed 1,2d | head -n 400 > "$TMP_LISTENERS"
    netstat -tunp 2>/dev/null | grep -E 'ESTABLISHED' | head -n 300 > "$TMP_ESTABLISHED"
    netstat -tan 2>/dev/null | awk 'NR>2 {print $6}' | sort | uniq -c | sort -nr > "$TMP_DIR/states.txt" || true
fi
: > "${TMP_DIR}/states.txt.tmp"
[ -f "$TMP_DIR/states.txt" ] || : > "$TMP_DIR/states.txt"

LISTENER_COUNT=$(count_lines "$TMP_LISTENERS")
ESTABLISHED_COUNT=$(count_lines "$TMP_ESTABLISHED")
[ -n "${LISTENER_COUNT:-}" ] || LISTENER_COUNT=0
[ -n "${ESTABLISHED_COUNT:-}" ] || ESTABLISHED_COUNT=0

if [ -s "$TMP_LISTENERS" ]; then
    awk '{for (i=1; i<=NF; i++) { if ($i ~ /:[0-9]+$/) { n=split($i,a,":"); print a[n]; break } }}' "$TMP_LISTENERS" \
        | sort -un > "$TMP_PORTS"
fi

while IFS= read -r _port; do
    [ -n "$_port" ] || continue
    case "$_port" in
        23) _sev="high"; _title="Telnet listener exposed on port 23"; _rule="network.service.telnet_exposed"; _rem="Disable telnet and migrate to SSH." ;;
        21) _sev="medium"; _title="FTP listener exposed on port 21"; _rule="network.service.ftp_exposed"; _rem="Disable cleartext FTP or require FTPS/SFTP." ;;
        69) _sev="medium"; _title="TFTP listener exposed on port 69"; _rule="network.service.tftp_exposed"; _rem="Disable TFTP unless required for controlled provisioning." ;;
        111) _sev="medium"; _title="rpcbind listener exposed on port 111"; _rule="network.service.rpcbind_exposed"; _rem="Restrict rpcbind to localhost or disable unused RPC services." ;;
        512|513|514) _sev="high"; _title="Legacy r-service exposed on port $_port"; _rule="network.service.legacy_rsh_exposed"; _rem="Disable rexec/rlogin/rsh and use SSH." ;;
        2049) _sev="medium"; _title="NFS listener exposed on port 2049"; _rule="network.service.nfs_exposed"; _rem="Restrict NFS exports to trusted networks and enable Kerberos." ;;
        2375) _sev="critical"; _title="Unauthenticated Docker API exposed on port 2375"; _rule="container.docker.api_unauthenticated"; _rem="Disable the unauthenticated Docker TCP socket." ;;
        2376) _sev="medium"; _title="Docker TLS API exposed on port 2376"; _rule="container.docker.api_exposed"; _rem="Restrict Docker API access to trusted management networks." ;;
        4444|1337|31337|5555) _sev="high"; _title="Common backdoor port listening on $_port"; _rule="network.listener.suspicious_port"; _rem="Identify the owning process and remove unauthorized software." ;;
        6667) _sev="medium"; _title="IRC listener on port 6667"; _rule="network.listener.irc_port"; _rem="Block IRC traffic and inspect the owning process for botnet activity." ;;
        1080|9050|9001) _sev="medium"; _title="Proxy or Tor-related listener on port $_port"; _rule="network.listener.proxy_port"; _rem="Verify the proxy is authorized and inspect the owning process." ;;
        3389) _sev="medium"; _title="RDP listener exposed on port 3389"; _rule="network.service.rdp_exposed"; _rem="Restrict RDP to a management network or VPN with MFA." ;;
        5985|5986) _sev="medium"; _title="WinRM listener exposed on port $_port"; _rule="network.service.winrm_exposed"; _rem="Disable WinRM or restrict it to trusted management networks." ;;
        *) continue ;;
    esac
    _match=$(grep -E "[:.]$_port([[:space:]]|$)" "$TMP_LISTENERS" 2>/dev/null | head -n 1)
    [ -n "$_match" ] || _match="Port $_port detected in listener table"
    add_finding "triage-linux-net-port-$_port" "$_rule" "$_title" "$_sev" "$_match" "$_rem" "" "network_anomaly"
done < "$TMP_PORTS"

# ------------------------------------------------------------------------------
# 4. Firewall, forwarding and namespaces
# ------------------------------------------------------------------------------
FW_STATUS="none"
if command -v ufw >/dev/null 2>&1; then
    FW_STATUS=$(ufw status 2>/dev/null | head -n 1 || echo "unknown")
elif command -v nft >/dev/null 2>&1; then
    _nft_rules=$(nft list ruleset 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    FW_STATUS="nftables ($_nft_rules lines)"
elif command -v iptables >/dev/null 2>&1; then
    _ipt_rules=$(iptables -S 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    FW_STATUS="iptables ($_ipt_rules rules)"
fi
case "$FW_STATUS" in
    none|"Status: inactive")
        add_finding "triage-linux-net-firewall" "network.firewall.inactive" \
            "Host firewall appears inactive or unconfigured" "medium" \
            "Firewall status: $FW_STATUS" \
            "Enable host-based packet filtering with nftables, iptables, or ufw following the host role." "" "network_anomaly" "medium"
        ;;
esac
[ -n "$FW_STATUS" ] || FW_STATUS="unknown (insufficient privileges)"

IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
IPV6_FORWARD=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)
RP_FILTER=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo unknown)
if [ "$IP_FORWARD" = "1" ] || [ "$IPV6_FORWARD" = "1" ]; then
    add_finding "triage-linux-net-forwarding" "network.sysctl.ip_forwarding" \
        "IP forwarding is enabled" "low" \
        "ipv4.ip_forward=$IP_FORWARD ipv6.forwarding=$IPV6_FORWARD" \
        "Disable forwarding unless the host is an approved router, NAT gateway, or container node." "" "hardening_audit" "medium"
fi
NETNS_COUNT=$(count_lines "$TMP_NETNS")
[ -n "${NETNS_COUNT:-}" ] || NETNS_COUNT=0

# ------------------------------------------------------------------------------
# 5. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
LISTENERS_JSON=$(raw_array_from "$TMP_LISTENERS")
ESTABLISHED_JSON=$(raw_array_from "$TMP_ESTABLISHED")
ADDRS_JSON=$(raw_array_from "$TMP_ADDRS")
ROUTES_JSON=$(raw_array_from "$TMP_ROUTES")
NEIGH_JSON=$(raw_array_from "$TMP_NEIGH")
DNS_JSON=$(raw_array_from "$TMP_DNS")
HOSTS_JSON=$(raw_array_from "$TMP_HOSTS_HITS")
PROXY_JSON=$(raw_array_from "$TMP_PROXY")
NETNS_JSON=$(raw_array_from "$TMP_NETNS")
STATES_JSON=$(raw_array_from "$TMP_DIR/states.txt")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")"
  },
  "network": {
    "interfaces": $ADDRS_JSON,
    "routes": $ROUTES_JSON,
    "neighbors": $NEIGH_JSON,
    "dns_resolvers": "$(json_escape "$RESOLVERS")",
    "dns_config": $DNS_JSON,
    "hosts_redirects": $HOSTS_JSON,
    "proxy_configuration": $PROXY_JSON,
    "firewall_status": "$(json_escape "$FW_STATUS")",
    "ip_forward": "$(json_escape "$IP_FORWARD")",
    "ipv6_forward": "$(json_escape "$IPV6_FORWARD")",
    "rp_filter": "$(json_escape "$RP_FILTER")",
    "network_namespaces": $NETNS_JSON
  },
  "metrics": {
    "interfaces": $INTERFACE_COUNT,
    "listeners": $LISTENER_COUNT,
    "established_connections": $ESTABLISHED_COUNT,
    "network_namespaces": $NETNS_COUNT
  },
  "connection_states": $STATES_JSON,
  "listeners": $LISTENERS_JSON,
  "established_connections": $ESTABLISHED_JSON,
  "findings": $FINDINGS_JSON
}
EOF
