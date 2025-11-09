## HashiCorp Vault Proxmox Helper

This repository exposes a single helper script, `install-vault-helper.sh`, that recreates the experience of popular Proxmox automation helpers. When run directly on a Proxmox VE node it will:

- Download a Debian template (if missing) and provision an LXC container with your chosen CPU, RAM, storage, VLAN, and IP settings.
- Install HashiCorp Vault inside the container, configure Raft storage, generate or import TLS certificates, and tune the systemd unit for production defaults.
- Print the resulting access details plus the follow-up steps (`vault operator init`, unseal, etc.).

### One-Command Install (run on your Proxmox host)

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/hasc5314/pub/main/install-vault-helper.sh)"
```

Prefer `curl`?

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/hasc5314/pub/main/install-vault-helper.sh)"
```

Both commands download the latest script directly from this repo and execute it, matching the common “helper script” UX in the Proxmox community. Use `-d` or environment overrides if you want non-interactive behavior.

### Quick Start (manual copy)

```bash
# Clone and enter the repo
git clone https://github.com/hasc5314/pub.git
cd pub

# Copy the helper to a Proxmox host (adjust host/IP as needed)
scp install-vault-helper.sh root@proxmox-node:/root/

# SSH into the host and run it (interactive prompts by default)
ssh root@proxmox-node
bash /root/install-vault-helper.sh
```

### Command Options

```
install-vault-helper.sh [options]

  -d, --defaults   Use the currently exported environment variables or script defaults
  -y, --yes        Skip the “continue?” confirmation after the config summary
  -h, --help       Show the built-in documentation
```

You can override any prompt ahead of time via environment variables, for example:

```bash
CT_ID=950 \
CT_NAME=vault-prod \
CT_BRIDGE=vmbr1 \
CT_IP_ADDR=10.42.0.50 \
CT_CIDR=24 \
CT_GATEWAY=10.42.0.1 \
VAULT_FQDN=vault.example.internal \
TLS_MODE=provided \
TLS_CERT_PATH=/root/certs/vault.crt \
TLS_KEY_PATH=/root/certs/vault.key \
bash install-vault-helper.sh -d -y
```

### TLS Modes

- `selfsigned` (default): Generates a self-signed certificate with SAN entries for the hostname/IP.
- `provided`: Securely uploads your PEM certificate/key into the container (set `TLS_CERT_PATH`/`TLS_KEY_PATH`).
- `disabled`: Turns off TLS entirely (best reserved for lab scenarios).

### After the Script Runs

1. Check Vault status: `pct exec <CTID> -- vault status`
2. Initialize: `pct exec <CTID> -- vault operator init`
3. Record unseal keys/root token securely and consider configuring auto-unseal with an external KMS.
4. Adjust `/etc/vault.d/server.hcl` if you want to join additional Raft peers or change listener bindings.

Feel free to fork or extend the script for multi-node deployments, monitoring hooks, or backup automation.
