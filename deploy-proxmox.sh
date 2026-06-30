#!/usr/bin/env bash
# Deploy to an existing Proxmox LXC (create the container first).
#
#   export PROXMOX_NODE=pve-primary.example
#   export WZ_SENTINEL_CTID=101
#   ./deploy-proxmox.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
: "${PROXMOX_NODE:?Set PROXMOX_NODE}"
: "${WZ_SENTINEL_CTID:?Set WZ_SENTINEL_CTID}"

echo "=== Deploy Warzone Lobby Sentinel (CT${WZ_SENTINEL_CTID}) ==="
bash "$ROOT/deploy-to-lxc.sh"

NODE_IP="${PROXMOX_NODE#root@}"
NODE_IP="${NODE_IP#*@}"
CTID="$WZ_SENTINEL_CTID"
IP="$(ssh -o BatchMode=yes "root@${NODE_IP}" "pct exec ${CTID} -- hostname -I 2>/dev/null" | awk '{print $1}')"
PORT="${WZ_INGEST_PORT:-8098}"

echo ""
echo "  Status:  http://${IP:-<CT-IP>}:${PORT}/v1/status"
echo "  Logs:    ssh root@${NODE_IP} 'pct exec ${CTID} -- journalctl -u warzone-lobby-sentinel -f'"
echo ""
