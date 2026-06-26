#!/usr/bin/env bash
# Provision CT941 on node9 + deploy Warzone Lobby Sentinel (Xbox gaming).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"

export PROXMOX_NODE="${PROXMOX_NODE:-192.168.167.9}"
export WZ_SENTINEL_CTID="${WZ_SENTINEL_CTID:-941}"

echo "=== Provision warzone-sentinel on node9 ==="
bash "$REPO_ROOT/deploy/lxc/provision-warzone-sentinel.sh"

echo "=== Deploy application ==="
bash "$ROOT/deploy-to-lxc.sh"

NODE_IP="${PROXMOX_NODE#root@}"
CTID="$WZ_SENTINEL_CTID"
IP="$(ssh -o BatchMode=yes "root@${NODE_IP}" "pct exec ${CTID} -- hostname -I 2>/dev/null" | awk '{print $1}')"
PORT="${WZ_INGEST_PORT:-8098}"

echo ""
echo "=============================================="
echo " Warzone Sentinel — autonomous Xbox mode"
echo "=============================================="
echo ""
echo "  Status:  http://${IP:-$NODE_IP}:${PORT}/v1/status"
echo ""
echo "No action required. Plays Warzone on Xbox; sentinel reads"
echo "network telemetry from your Firewalla gaming monitor."
echo ""
echo "Logs: ssh root@${NODE_IP} 'pct exec ${CTID} -- journalctl -u warzone-lobby-sentinel -f'"
echo ""
