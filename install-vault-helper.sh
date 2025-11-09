#!/usr/bin/env bash

set -Eeuo pipefail

GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m"

msg_info() { printf " ${BLUE}[INFO]${NC} %s\n" "$1"; }
msg_ok() { printf " ${GREEN}[ OK ]${NC} %s\n" "$1"; }
msg_warn() { printf " ${YELLOW}[WARN]${NC} %s\n" "$1"; }
msg_error() { printf " ${RED}[FAIL]${NC} %s\n" "$1"; }

fail_trap() {
    local exit_code=$?
    msg_error "Script aborted at line $1 (exit code: ${exit_code})"
}
trap 'fail_trap $LINENO' ERR

header_info() {
    cat <<'EOF'
===========================================
   HashiCorp Vault :: Proxmox Helper
===========================================
This script creates an LXC on a Proxmox host
and installs HashiCorp Vault with Raft storage.
EOF
}

show_help() {
    cat <<'EOF'
Usage: install-vault-helper.sh [options]

Options:
  -d, --defaults        Use current variable defaults, skip interactive prompts
  -y, --yes             Skip confirmation prompt and proceed immediately
  -h, --help            Show this help message

Environment overrides (optional):
  CT_ID, CT_NAME, CT_CORES, CT_MEMORY, CT_DISK_GB, CT_BRIDGE, CT_VLAN
  STORAGE_POOL, TEMPLATE_STORAGE, TEMPLATE_IMAGE
  CT_PASSWORD, VAULT_FQDN, VAULT_DATA_PATH, TLS_MODE

TLS modes:
  selfsigned (default)  -> Generate a self-signed cert inside the container
  provided              -> Push local cert/key files into the container
  disabled              -> Run Vault without TLS (not recommended)
EOF
}

AUTO_CONFIRM=false
SKIP_PROMPTS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--defaults) SKIP_PROMPTS=true ;;
        -y|--yes) AUTO_CONFIRM=true ;;
        -h|--help) show_help; exit 0 ;;
        *)
            msg_error "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

prompt_default() {
    local prompt="$1"
    local var_name="$2"
    local default_value="$3"
    local current_value="${!var_name:-$default_value}"

    if [[ "$SKIP_PROMPTS" == "true" ]]; then
        eval "$var_name=\"${current_value}\""
        return
    fi

    read -r -p "$prompt [${current_value}]: " response
    if [[ -z "$response" ]]; then
        eval "$var_name=\"${current_value}\""
    else
        eval "$var_name=\"${response}\""
    fi
}

prompt_yes_no() {
    local prompt="$1"
    local var_name="$2"
    local default_answer="${3:-y}"
    local choices

    if [[ "$default_answer" =~ ^[Yy]$ ]]; then
        choices="Y/n"
    else
        choices="y/N"
    fi

    if [[ "$SKIP_PROMPTS" == "true" ]]; then
        eval "$var_name=\"${default_answer}\""
        return
    fi

    read -r -p "$prompt [${choices}]: " response
    response=${response:-$default_answer}

    if [[ "$response" =~ ^[Yy]$ ]]; then
        eval "$var_name=\"y\""
    else
        eval "$var_name=\"n\""
    fi
}

generate_password() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import secrets
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%*+-="
print(''.join(secrets.choice(alphabet) for _ in range(22)))
PY
        return
    fi

    local had_pipefail=0
    if set -o | grep -q 'pipefail.*on'; then
        had_pipefail=1
        set +o pipefail
    fi

    local pw
    pw=$(tr -dc 'A-Za-z0-9!#$%*+-=' </dev/urandom | head -c 22)
    local status=$?

    if [[ $had_pipefail -eq 1 ]]; then
        set -o pipefail
    fi

    printf '%s' "$pw"
    return $status
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || {
        msg_error "Missing required command: ${cmd}"
        exit 1
    }
}

require_command pveversion
require_command pct
require_command pveam

if [[ $EUID -ne 0 ]]; then
    msg_error "Run this script as root on the Proxmox host."
    exit 1
fi

header_info

CT_ID=${CT_ID:-920}
CT_NAME=${CT_NAME:-vault}
CT_CORES=${CT_CORES:-2}
CT_MEMORY=${CT_MEMORY:-4096}
CT_DISK_GB=${CT_DISK_GB:-30}
CT_BRIDGE=${CT_BRIDGE:-vmbr0}
CT_VLAN=${CT_VLAN:-}
STORAGE_POOL=${STORAGE_POOL:-local-lvm}
TEMPLATE_STORAGE=${TEMPLATE_STORAGE:-local}
TEMPLATE_IMAGE=${TEMPLATE_IMAGE:-debian-12-standard_12.2-1_amd64.tar.zst}
CT_PASSWORD=${CT_PASSWORD:-$(generate_password)}
VAULT_FQDN=${VAULT_FQDN:-vault.lan}
VAULT_DATA_PATH=${VAULT_DATA_PATH:-/opt/vault/data}
TLS_MODE=${TLS_MODE:-selfsigned}

prompt_default "Container ID" CT_ID "$CT_ID"
prompt_default "Container hostname" CT_NAME "$CT_NAME"
prompt_default "vCPU cores" CT_CORES "$CT_CORES"
prompt_default "Memory (MiB)" CT_MEMORY "$CT_MEMORY"
prompt_default "Disk size (GiB)" CT_DISK_GB "$CT_DISK_GB"
prompt_default "Bridge interface" CT_BRIDGE "$CT_BRIDGE"
prompt_default "VLAN tag (empty for none)" CT_VLAN "$CT_VLAN"
prompt_default "Rootfs storage pool" STORAGE_POOL "$STORAGE_POOL"
prompt_default "Template storage" TEMPLATE_STORAGE "$TEMPLATE_STORAGE"
prompt_default "Template image" TEMPLATE_IMAGE "$TEMPLATE_IMAGE"
prompt_default "Vault FQDN / API address" VAULT_FQDN "$VAULT_FQDN"
prompt_default "Vault data path" VAULT_DATA_PATH "$VAULT_DATA_PATH"
prompt_default "TLS mode (selfsigned/provided/disabled)" TLS_MODE "$TLS_MODE"

prompt_yes_no "Use DHCP for networking" USE_DHCP "y"

if [[ "$USE_DHCP" == "y" ]]; then
    CT_IP_ADDR=""
    CT_CIDR=""
    CT_GATEWAY=""
else
    prompt_default "Container IP (e.g. 192.168.1.50)" CT_IP_ADDR "${CT_IP_ADDR:-192.168.1.50}"
    prompt_default "CIDR (e.g. 24)" CT_CIDR "${CT_CIDR:-24}"
    prompt_default "Gateway" CT_GATEWAY "${CT_GATEWAY:-192.168.1.1}"
fi

if [[ "$TLS_MODE" == "provided" ]]; then
    if [[ "$SKIP_PROMPTS" == "true" ]]; then
        : # Expect user to export TLS_CERT_PATH / TLS_KEY_PATH beforehand
    else
        prompt_default "Path to TLS certificate (PEM)" TLS_CERT_PATH "${TLS_CERT_PATH:-/root/vault.crt}"
        prompt_default "Path to TLS key (PEM)" TLS_KEY_PATH "${TLS_KEY_PATH:-/root/vault.key}"
    fi
    [[ -f "$TLS_CERT_PATH" ]] || { msg_error "Certificate not found at $TLS_CERT_PATH"; exit 1; }
    [[ -f "$TLS_KEY_PATH" ]] || { msg_error "Key not found at $TLS_KEY_PATH"; exit 1; }
fi

case "$TLS_MODE" in
    selfsigned|provided|disabled) ;;
    *)
        msg_error "Invalid TLS mode: $TLS_MODE"
        exit 1
        ;;
esac

NET_STRING="name=eth0,bridge=${CT_BRIDGE}"
if [[ -n "$CT_VLAN" ]]; then
    NET_STRING+=",tag=${CT_VLAN}"
fi

if [[ "$USE_DHCP" == "y" ]]; then
    NET_STRING+=",ip=dhcp"
    CT_PRIMARY_IP=""
else
    NET_STRING+=",ip=${CT_IP_ADDR}/${CT_CIDR},gw=${CT_GATEWAY}"
    CT_PRIMARY_IP="$CT_IP_ADDR"
fi

VAULT_API_ADDR_PROTO="https"
if [[ "$TLS_MODE" == "disabled" ]]; then
    VAULT_API_ADDR_PROTO="http"
fi

if [[ -n "$CT_PRIMARY_IP" ]]; then
    VAULT_CLUSTER_TARGET="$CT_PRIMARY_IP"
else
    VAULT_CLUSTER_TARGET="${CT_NAME}"
fi

VAULT_API_ADDR="${VAULT_API_ADDR_PROTO}://${VAULT_FQDN}:8200"
VAULT_CLUSTER_ADDR="${VAULT_API_ADDR_PROTO}://${VAULT_CLUSTER_TARGET}:8201"

echo ""
msg_info "Planned configuration"
printf " %-20s %s\n" "CT ID" "$CT_ID"
printf " %-20s %s\n" "Hostname" "$CT_NAME"
printf " %-20s %s\n" "Storage" "${STORAGE_POOL}:${CT_DISK_GB}G"
printf " %-20s %s\n" "CPU / Memory" "${CT_CORES} cores / ${CT_MEMORY} MiB"
if [[ -n "$CT_PRIMARY_IP" ]]; then
    printf " %-20s %s\n" "Networking" "Static ${CT_IP_ADDR}/${CT_CIDR} via ${CT_GATEWAY}"
else
    printf " %-20s %s\n" "Networking" "DHCP on ${CT_BRIDGE}"
fi
printf " %-20s %s\n" "Vault FQDN" "$VAULT_FQDN"
printf " %-20s %s\n" "Vault data path" "$VAULT_DATA_PATH"
printf " %-20s %s\n" "TLS mode" "$TLS_MODE"

if [[ "$AUTO_CONFIRM" == "false" ]]; then
    prompt_yes_no "Continue with these settings" CONTINUE "y"
    if [[ "$CONTINUE" != "y" ]]; then
        msg_warn "Aborted by user."
        exit 0
    fi
fi

TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_IMAGE}"
if ! pveam list "$TEMPLATE_STORAGE" | awk '{print $2}' | grep -q "^${TEMPLATE_IMAGE}$"; then
    msg_info "Downloading ${TEMPLATE_IMAGE} to ${TEMPLATE_STORAGE}..."
    pveam download "$TEMPLATE_STORAGE" "$TEMPLATE_IMAGE"
    msg_ok "Template downloaded"
fi

if pct status "$CT_ID" >/dev/null 2>&1; then
    msg_error "Container ID ${CT_ID} already exists."
    exit 1
fi

msg_info "Creating LXC ${CT_ID} (${CT_NAME})..."
pct create "$CT_ID" "$TEMPLATE_PATH" \
    --hostname "$CT_NAME" \
    --password "$CT_PASSWORD" \
    --cores "$CT_CORES" \
    --memory "$CT_MEMORY" \
    --swap 512 \
    --rootfs "${STORAGE_POOL}:${CT_DISK_GB}G" \
    --net0 "$NET_STRING" \
    --features nesting=1,keyctl=1 \
    --unprivileged 0 \
    --ostype debian
msg_ok "Container definition created"

msg_info "Enabling startup autostart for CT ${CT_ID}"
pct set "$CT_ID" --onboot 1 >/dev/null

msg_info "Starting container ${CT_ID}"
pct start "$CT_ID"
msg_ok "Container started"

if [[ "$TLS_MODE" == "provided" ]]; then
    msg_info "Uploading provided TLS material"
    pct exec "$CT_ID" -- bash -c "mkdir -p /tmp/vault-tls && chmod 700 /tmp/vault-tls"
    pct push "$CT_ID" "$TLS_CERT_PATH" /tmp/vault-tls/vault.crt >/dev/null
    pct push "$CT_ID" "$TLS_KEY_PATH" /tmp/vault-tls/vault.key >/dev/null
    msg_ok "TLS files staged"
fi

SAN_ENTRIES=("DNS:${VAULT_FQDN}" "DNS:${CT_NAME}" "DNS:localhost" "IP:127.0.0.1")
if [[ -n "$CT_PRIMARY_IP" ]]; then
    SAN_ENTRIES+=("IP:${CT_PRIMARY_IP}")
fi
SELF_SIGNED_SAN=$(IFS=,; echo "${SAN_ENTRIES[*]}")

SETUP_SCRIPT=$(mktemp)
cat <<EOF >"$SETUP_SCRIPT"
#!/usr/bin/env bash
set -euo pipefail

VAULT_FQDN="${VAULT_FQDN}"
VAULT_DATA_PATH="${VAULT_DATA_PATH}"
VAULT_NODE_NAME="${CT_NAME}"
TLS_MODE="${TLS_MODE}"
SELF_SIGNED_SAN="${SELF_SIGNED_SAN}"
VAULT_API_ADDR="${VAULT_API_ADDR}"
VAULT_CLUSTER_ADDR="${VAULT_CLUSTER_ADDR}"

install -d -m 0750 -o root -g root /etc/systemd/system/vault.service.d

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl gnupg lsb-release jq unzip openssl

if [[ ! -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]]; then
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com \$(lsb_release -cs) main" >/etc/apt/sources.list.d/hashicorp.list
apt-get update
apt-get install -y vault

install -d -o vault -g vault -m 0750 /opt/vault/tls
install -d -o vault -g vault -m 0750 "${VAULT_DATA_PATH}"

case "\${TLS_MODE}" in
    selfsigned)
        openssl req -newkey rsa:4096 -nodes -keyout /opt/vault/tls/vault.key -x509 -days 825 -out /opt/vault/tls/vault.crt -subj "/CN=\${VAULT_FQDN}" -addext "subjectAltName=\${SELF_SIGNED_SAN}"
        chown vault:vault /opt/vault/tls/vault.*
        chmod 640 /opt/vault/tls/vault.key
        ;;
    provided)
        install -m 0640 -o vault -g vault /tmp/vault-tls/vault.crt /opt/vault/tls/vault.crt
        install -m 0640 -o vault -g vault /tmp/vault-tls/vault.key /opt/vault/tls/vault.key
        ;;
    disabled)
        rm -f /opt/vault/tls/vault.crt /opt/vault/tls/vault.key
        ;;
esac

if [[ "\${TLS_MODE}" == "disabled" ]]; then
    LISTENER_TLS='  tls_disable = true'
else
    LISTENER_TLS=$'  tls_disable = false\n  tls_cert_file = "/opt/vault/tls/vault.crt"\n  tls_key_file = "/opt/vault/tls/vault.key"'
fi

cat <<VAULTCFG >/etc/vault.d/server.hcl
storage "raft" {
  path = "${VAULT_DATA_PATH}"
  node_id = "${CT_NAME}"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
\${LISTENER_TLS}
}

api_addr = "${VAULT_API_ADDR}"
cluster_addr = "${VAULT_CLUSTER_ADDR}"
disable_mlock = false
ui = true
VAULTCFG

chown vault:vault /etc/vault.d/server.hcl
chmod 640 /etc/vault.d/server.hcl

cat <<'OVERRIDE' >/etc/systemd/system/vault.service.d/override.conf
[Service]
LimitNOFILE=65536
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK
ExecStart=
ExecStart=/usr/bin/vault server -config=/etc/vault.d/server.hcl
OVERRIDE

if [[ "\${TLS_MODE}" == "disabled" ]]; then
    PROTO="http"
else
    PROTO="https"
fi
cat <<ENVCONF >/etc/default/vault
VAULT_ADDR=\${PROTO}://0.0.0.0:8200
ENVCONF

systemctl daemon-reload
systemctl enable vault
systemctl restart vault
EOF

pct push "$CT_ID" "$SETUP_SCRIPT" /tmp/vault-setup.sh >/dev/null
pct exec "$CT_ID" -- chmod +x /tmp/vault-setup.sh
msg_info "Configuring Vault inside the container"
pct exec "$CT_ID" -- /tmp/vault-setup.sh
pct exec "$CT_ID" -- rm -f /tmp/vault-setup.sh
rm -f "$SETUP_SCRIPT"
msg_ok "Vault installed and configured"

if [[ "$TLS_MODE" == "provided" ]]; then
    pct exec "$CT_ID" -- rm -rf /tmp/vault-tls
fi

msg_info "Running basic health check"
pct exec "$CT_ID" -- systemctl is-active --quiet vault
msg_ok "Vault service is active"

echo ""
printf " %-15s %s\n" "Container ID:" "$CT_ID"
printf " %-15s %s\n" "Hostname:" "$CT_NAME"
printf " %-15s %s\n" "Root password:" "$CT_PASSWORD"
if [[ -n "$CT_PRIMARY_IP" ]]; then
    printf " %-15s %s\n" "IP address:" "$CT_PRIMARY_IP"
else
    printf " %-15s %s\n" "IP address:" "DHCP (check \`pct exec ${CT_ID} -- ip -brief addr\`)"
fi
printf " %-15s %s\n" "Vault API:" "$VAULT_API_ADDR"
printf " %-15s %s\n" "TLS mode:" "$TLS_MODE"
printf " %-15s %s\n" "Data path:" "$VAULT_DATA_PATH"

cat <<'NEXT'

Next steps:
  1. Export VAULT_ADDR (see /etc/default/vault) and run `vault status` via pct exec.
  2. Initialize the cluster: `pct exec <CTID> -- vault operator init`.
  3. Capture the unseal keys/root token securely; consider configuring auto-unseal.
  4. Adjust /etc/vault.d/server.hcl for HA settings or external storage if required.
NEXT

msg_ok "HashiCorp Vault helper completed"
