#!/bin/sh
# ==============================================================================
# Linux Container and Kubernetes Triage (EVA Sec compatible)
# Detects container runtime exposure and escape-risk configuration:
#   - Docker/Podman/containerd runtimes and their listening sockets
#   - Privileged containers, host namespace sharing and sensitive host mounts
#   - Dangerous Linux capabilities and root container execution
#   - Kubernetes pods with host namespaces, privileged containers or token mounts
#
# Read-only. Emits `eva.triage.v1` JSON on stdout.
# ==============================================================================

set -u
umask 077

TOOL="triage-linux-containers"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(uname -n 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t eva-ctr.XXXXXX)
TMP_FINDINGS="$TMP_DIR/findings.jsonl"
TMP_CONTAINERS="$TMP_DIR/containers.jsonl"
TMP_RUNTIMES="$TMP_DIR/runtimes.jsonl"
TMP_PODS="$TMP_DIR/pods.jsonl"
TMP_K8S_INFO="$TMP_DIR/k8s.txt"
: > "$TMP_FINDINGS"
: > "$TMP_CONTAINERS"
: > "$TMP_RUNTIMES"
: > "$TMP_PODS"

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
    _cat=${8:-container}
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

# ------------------------------------------------------------------------------
# 1. Container runtime discovery
# ------------------------------------------------------------------------------
RUNTIME_COUNT=0
CONTAINER_COUNT=0
CONTAINER_FINDING_COUNT=0

inspect_runtime() {
    _rt=$1
    _version=""
    case "$_rt" in
        docker)
            _version=$(run_limited 5 docker info --format '{{.ServerVersion}}' 2>/dev/null || true)
            _mode=$(run_limited 5 docker info --format '{{.OperatingSystem}} / {{.Driver}}' 2>/dev/null || true)
            ;;
        podman)
            _version=$(run_limited 5 podman info --format '{{.Version.Version}}' 2>/dev/null || true)
            _mode=$(run_limited 5 podman info --format 'rootless={{.Host.Security.Rootless}}' 2>/dev/null || true)
            ;;
        nerdctl)
            _version=$(run_limited 5 nerdctl version --format '{{.Server.Version}}' 2>/dev/null || true)
            _mode="containerd"
            ;;
        *)
            return 0
            ;;
    esac
    if [ -z "$_version" ]; then
        return 0
    fi
    RUNTIME_COUNT=$((RUNTIME_COUNT + 1))
    printf '{"runtime":"%s","version":"%s","mode":"%s"},\n' \
        "$(json_escape "$_rt")" "$(json_escape "$_version")" "$(json_escape "$_mode")" >> "$TMP_RUNTIMES"

    _ids=$(run_limited 10 "$_rt" ps -q --no-trunc 2>/dev/null | head -n 100 || true)
    [ -n "$_ids" ] || return 0
    for _id in $_ids; do
        CONTAINER_COUNT=$((CONTAINER_COUNT + 1))
        _meta=$(run_limited 5 "$_rt" inspect --format \
            '{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{join .HostConfig.CapAdd ","}}|{{join .HostConfig.SecurityOpt ","}}|{{.HostConfig.RestartPolicy.Name}}' \
            "$_id" 2>/dev/null | head -n 1 || true)
        [ -n "$_meta" ] || _meta="unknown|unknown|unknown|false|default|default|default|false|||"
        _name=$(printf '%s' "$_meta" | awk -F'|' '{print $1}')
        _image=$(printf '%s' "$_meta" | awk -F'|' '{print $2}')
        _status=$(printf '%s' "$_meta" | awk -F'|' '{print $3}')
        _privileged=$(printf '%s' "$_meta" | awk -F'|' '{print $4}')
        _netmode=$(printf '%s' "$_meta" | awk -F'|' '{print $5}')
        _pidmode=$(printf '%s' "$_meta" | awk -F'|' '{print $6}')
        _ipcmode=$(printf '%s' "$_meta" | awk -F'|' '{print $7}')
        _readonly=$(printf '%s' "$_meta" | awk -F'|' '{print $8}')
        _user=$(printf '%s' "$_meta" | awk -F'|' '{print $9}')
        _capadd=$(printf '%s' "$_meta" | awk -F'|' '{print $10}')
        _secopt=$(printf '%s' "$_meta" | awk -F'|' '{print $11}')
        _restart=$(printf '%s' "$_meta" | awk -F'|' '{print $12}')
        _mounts=$(run_limited 5 "$_rt" inspect --format '{{range .Mounts}}{{.Source}}=>{{.Destination}}:rw={{.RW}};{{end}}' "$_id" 2>/dev/null | head -n 1 || true)

        _user_desc="${_user:-root}"
        printf '{"runtime":"%s","id":"%s","name":"%s","image":"%s","status":"%s","privileged":%s,"network_mode":"%s","pid_mode":"%s","ipc_mode":"%s","readonly_rootfs":%s,"user":"%s","cap_add":"%s","security_opts":"%s","restart_policy":"%s","mounts":"%s"},\n' \
            "$(json_escape "$_rt")" "$(json_escape "$_id")" "$(json_escape "$_name")" "$(json_escape "$_image")" "$(json_escape "$_status")" \
            "$([ "$_privileged" = "true" ] && echo true || echo false)" "$(json_escape "$_netmode")" "$(json_escape "$_pidmode")" \
            "$(json_escape "$_ipcmode")" "$([ "$_readonly" = "true" ] && echo true || echo false)" "$(json_escape "$_user_desc")" \
            "$(json_escape "$_capadd")" "$(json_escape "$_secopt")" "$(json_escape "$_restart")" "$(json_escape "$_mounts")" >> "$TMP_CONTAINERS"

        if [ "$_privileged" = "true" ]; then
            add_finding "triage-linux-ctr-privileged-$(hash_text "$_id" | cut -c1-10)" "container.runtime.privileged" \
                "Privileged container is running: $_name" "critical" \
                "Runtime: $_rt Image: $_image Mounts: $_mounts" \
                "Remove --privileged, apply a minimal capability set, and recreate the container from a reviewed manifest." "" "container"
            CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
        fi
        case "$_netmode" in
            host)
                add_finding "triage-linux-ctr-hostnet-$(hash_text "$_id" | cut -c1-10)" "container.runtime.host_network" \
                    "Container shares the host network namespace: $_name" "high" \
                    "Runtime: $_rt Image: $_image" \
                    "Use a dedicated bridge network and publish only required ports." "" "container"
                CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
                ;;
        esac
        case "$_pidmode" in
            host)
                add_finding "triage-linux-ctr-hostpid-$(hash_text "$_id" | cut -c1-10)" "container.runtime.host_pid" \
                    "Container shares the host PID namespace: $_name" "high" \
                    "Runtime: $_rt Image: $_image" \
                    "Remove --pid=host and allow the container to use its own PID namespace." "" "container"
                CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
                ;;
        esac
        case "$_ipcmode" in
            host)
                add_finding "triage-linux-ctr-hostipc-$(hash_text "$_id" | cut -c1-10)" "container.runtime.host_ipc" \
                    "Container shares the host IPC namespace: $_name" "medium" \
                    "Runtime: $_rt Image: $_image" \
                    "Remove --ipc=host unless shared memory is explicitly required." "" "container" "medium"
                CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
                ;;
        esac

        case " $_capadd " in
            *" SYS_ADMIN "*|*" SYS_PTRACE "*|*" SYS_MODULE "*|*" NET_ADMIN "*)
                add_finding "triage-linux-ctr-caps-$(hash_text "$_id" | cut -c1-10)" "container.runtime.dangerous_capabilities" \
                    "Container has dangerous Linux capabilities: $_name" "high" \
                    "Runtime: $_rt CapAdd: $_capadd" \
                    "Drop all capabilities and add back only the minimum required set." "" "container"
                CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
                ;;
        esac

        old_ifs=$IFS
        IFS=';'
        for _mount in $_mounts; do
            IFS=$old_ifs
            _source=$(printf '%s' "$_mount" | awk -F'=>' '{print $1}')
            case "$_source" in
                /|/var/run/docker.sock|/run/docker.sock|/run/podman/podman.sock|/proc|/sys|/etc|/root|/home|/boot)
                    add_finding "triage-linux-ctr-mount-$(hash_text "$_id$_source" | cut -c1-10)" "container.runtime.sensitive_host_mount" \
                        "Container mounts a sensitive host path: $_name" "critical" \
                        "Runtime: $_rt Mount: $_mount" \
                        "Remove the host mount, use a read-only narrowly scoped volume, and never expose the container runtime socket." "" "container"
                    CONTAINER_FINDING_COUNT=$((CONTAINER_FINDING_COUNT + 1))
                    ;;
            esac
            IFS=';'
        done
        IFS=$old_ifs
    done
}

for _rt in docker podman nerdctl; do
    command -v "$_rt" >/dev/null 2>&1 && inspect_runtime "$_rt"
done

# Docker group membership is effectively root-equivalent on the host.
if getent group docker >/dev/null 2>&1; then
    _docker_members=$(getent group docker 2>/dev/null | cut -d: -f4)
    if [ -n "$_docker_members" ]; then
        add_finding "triage-linux-ctr-docker-group" "container.runtime.docker_group_membership" \
            "Users can control the Docker daemon through group membership" "medium" \
            "docker group members: $_docker_members" \
            "Treat docker group members as root-equivalent; restrict membership and prefer rootless runtimes where possible." "/etc/group" "container" "medium"
    fi
fi

# World-writable runtime sockets permit container escape or host compromise.
for _sock in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock; do
    [ -S "$_sock" ] || continue
    _sock_mode=$(stat -c '%a %U:%G' "$_sock" 2>/dev/null || true)
    _sock_perm=$(printf '%s' "$_sock_mode" | awk '{print $1}')
    case "$_sock_perm" in
        *2|*3|*6|*7)
            add_finding "triage-linux-ctr-socket-$(hash_text "$_sock" | cut -c1-10)" "container.runtime.socket_world_writable" \
                "Container runtime socket is world-writable" "critical" \
                "Socket: $_sock permissions: $_sock_mode" \
                "Restrict the socket to root or the dedicated runtime group and audit containers that could access it." "$_sock" "container"
            ;;
    esac
done

# ------------------------------------------------------------------------------
# 2. Kubernetes pod security review
# ------------------------------------------------------------------------------
K8S_AVAILABLE="false"
K8S_NAMESPACE=""
if command -v kubectl >/dev/null 2>&1; then
    if run_limited 5 kubectl version --request-timeout=3s >/dev/null 2>&1; then
        K8S_AVAILABLE="true"
        K8S_NAMESPACE=$(run_limited 5 kubectl config view --minify -o jsonpath='{..namespace}' 2>/dev/null || true)
        [ -n "$K8S_NAMESPACE" ] || K8S_NAMESPACE="default"
        run_limited 10 kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.spec.hostNetwork}{"|"}{.spec.hostPID}{"|"}{.spec.hostIPC}{"|"}{.spec.automountServiceAccountToken}{"|"}{.spec.serviceAccountName}{"|"}{range .spec.containers[*]}{.name}{":"}{.securityContext.privileged}{":"}{.image}{";"}{end}{"\n"}{end}' 2>/dev/null \
            | head -n 100 > "$TMP_K8S_INFO" || true

        while IFS='|' read -r _pod _hostnet _hostpid _hostipc _automount _sa _containers; do
            [ -n "${_pod:-}" ] || continue
            _privileged_containers=$(printf '%s' "$_containers" | tr ';' '\n' | grep -E ':true:' | cut -d: -f1 | tr '\n' ' ')
            printf '{"namespace":"%s","name":"%s","host_network":"%s","host_pid":"%s","host_ipc":"%s","automount_service_account_token":"%s","service_account":"%s","containers":"%s"},\n' \
                "$(json_escape "$K8S_NAMESPACE")" "$(json_escape "$_pod")" "$(json_escape "$_hostnet")" "$(json_escape "$_hostpid")" \
                "$(json_escape "$_hostipc")" "$(json_escape "$_automount")" "$(json_escape "$_sa")" "$(json_escape "$_containers")" >> "$TMP_PODS"

            case "$_hostnet" in true) add_finding "triage-linux-k8s-hostnet-$(hash_text "$_pod" | cut -c1-10)" "kubernetes.pod.host_network" "Kubernetes pod uses hostNetwork: $_pod" "high" "Namespace: $K8S_NAMESPACE" "Remove hostNetwork and expose the service through a controlled Service/Ingress." "" "container" ;; esac
            case "$_hostpid" in true) add_finding "triage-linux-k8s-hostpid-$(hash_text "$_pod" | cut -c1-10)" "kubernetes.pod.host_pid" "Kubernetes pod uses hostPID: $_pod" "high" "Namespace: $K8S_NAMESPACE" "Remove hostPID from the pod security context." "" "container" ;; esac
            case "$_hostipc" in true) add_finding "triage-linux-k8s-hostipc-$(hash_text "$_pod" | cut -c1-10)" "kubernetes.pod.host_ipc" "Kubernetes pod uses hostIPC: $_pod" "medium" "Namespace: $K8S_NAMESPACE" "Remove hostIPC unless shared memory is explicitly required." "" "container" "medium" ;; esac
            if [ -n "$_privileged_containers" ]; then
                add_finding "triage-linux-k8s-privileged-$(hash_text "$_pod" | cut -c1-10)" "kubernetes.pod.privileged_container" \
                    "Kubernetes pod contains a privileged container: $_pod" "critical" \
                    "Namespace: $K8S_NAMESPACE Containers: $_privileged_containers" \
                    "Remove privileged: true, apply a restricted Pod Security Standard, and redeploy." "" "container"
            fi
            case "$_automount" in false) ;; *) if [ -n "${_sa:-}" ] && [ "$_sa" != "default" ]; then :; fi ;; esac
        done < "$TMP_K8S_INFO"
    fi
fi

# ------------------------------------------------------------------------------
# 3. Report assembly
# ------------------------------------------------------------------------------
FINDINGS_JSON=$(json_array_from "$TMP_FINDINGS")
CONTAINERS_JSON=$(json_array_from "$TMP_CONTAINERS")
RUNTIMES_JSON=$(json_array_from "$TMP_RUNTIMES")
PODS_JSON=$(json_array_from "$TMP_PODS")
K8S_RAW_JSON=$(raw_array_from "$TMP_K8S_INFO")

cat <<EOF
{
  "schema": "eva.triage.v1",
  "tool": "$TOOL",
  "collected_at": "$NOW",
  "host": {
    "hostname": "$(json_escape "$HOSTNAME")"
  },
  "metrics": {
    "runtimes": $RUNTIME_COUNT,
    "containers": $CONTAINER_COUNT,
    "container_security_findings": $CONTAINER_FINDING_COUNT,
    "kubernetes_available": $K8S_AVAILABLE,
    "kubernetes_pods": $(wc -l < "$TMP_PODS" 2>/dev/null | tr -d ' ' || echo 0)
  },
  "runtimes": $RUNTIMES_JSON,
  "containers": $CONTAINERS_JSON,
  "kubernetes": {
    "available": $K8S_AVAILABLE,
    "namespace": "$(json_escape "$K8S_NAMESPACE")",
    "pods": $PODS_JSON,
    "raw": $K8S_RAW_JSON
  },
  "findings": $FINDINGS_JSON
}
EOF
