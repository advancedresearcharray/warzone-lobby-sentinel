#!/usr/bin/env bash
# Deploy Warzone Lobby Sentinel to an existing Proxmox LXC.
#
#   export PROXMOX_NODE=pve-primary.example
#   export WZ_SENTINEL_CTID=101
#   ./deploy-to-lxc.sh
#
set -euo pipefail

: "${WZ_SENTINEL_CTID:?Set WZ_SENTINEL_CTID}"
: "${PROXMOX_NODE:?Set PROXMOX_NODE}"
CTID="${WZ_SENTINEL_CTID}"
PROXMOX_NODE="${PROXMOX_NODE}"
PROXMOX_SSH="${PROXMOX_NODE#root@}"
PROXMOX_SSH="${PROXMOX_SSH#*@}"
PROXMOX_REMOTE="root@${PROXMOX_SSH}"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="/opt/warzone-lobby-sentinel"
BUNDLE="/tmp/warzone-lobby-sentinel.tgz"
TOKEN_SRC="${WZ_TOKEN_SRC:-/root/.secrets/firewalla-api.env}"
XBOX_TOKEN_SRC="${WZ_XBOX_TOKEN_SRC:-/root/.secrets/xbox-notify.json}"

push_token_file() {
  local runner="$1"
  local src="$2"
  local dest="$3"
  if [[ ! -f "$src" ]]; then
    return 0
  fi
  $runner push "$CTID" "$src" "$dest"
  $runner exec "$CTID" -- chmod 600 "$dest"
}

push_token() {
  local runner="$1"
  if [[ ! -f "$TOKEN_SRC" ]]; then
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  grep -E '^FIREWALLA_API_TOKEN=' "$TOKEN_SRC" > "$tmp" || true
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 0
  fi
  $runner push "$CTID" "$tmp" /etc/warzone-sentinel/firewalla.token
  $runner exec "$CTID" -- bash -c 'mkdir -p /etc/warzone-sentinel && chmod 600 /etc/warzone-sentinel/firewalla.token'
  rm -f "$tmp"
}

push_xbox_token() {
  local runner="$1"
  push_token_file "$runner" "$XBOX_TOKEN_SRC" /etc/warzone-sentinel/xbox_notify.json
}

bundle() {
  echo "Building Rust sentinel..."
  (cd "$ROOT_DIR/rust" && cargo build --release)
  mkdir -p "$ROOT_DIR/bin"
  cp "$ROOT_DIR/rust/target/release/warzone-sentinel" "$ROOT_DIR/bin/warzone-sentinel"
  tar czf "$BUNDLE" \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='rust/target' \
    -C "$(dirname "$ROOT_DIR")" \
    "$(basename "$ROOT_DIR")"
}

deploy_local() {
  if ! command -v pct >/dev/null 2>&1; then
    echo "pct not found — run on Proxmox host or set PROXMOX_NODE" >&2
    exit 1
  fi

  bundle
  pct exec "$CTID" -- mkdir -p "$DEST"
  pct push "$CTID" "$BUNDLE" /tmp/warzone-lobby-sentinel.tgz
  pct exec "$CTID" -- bash -c "rm -rf '$DEST' && mkdir -p '$DEST' && tar xzf /tmp/warzone-lobby-sentinel.tgz -C /opt && rm -f /tmp/warzone-lobby-sentinel.tgz"
  pct push "$CTID" "$ROOT_DIR/install-in-ct.sh" /tmp/install-warzone-sentinel.sh
  push_token pct
  push_xbox_token pct
  pct exec "$CTID" -- bash /tmp/install-warzone-sentinel.sh
  rm -f "$BUNDLE"
}

deploy_remote() {
  bundle
  scp -o BatchMode=yes "$BUNDLE" "${PROXMOX_REMOTE}:/tmp/warzone-lobby-sentinel.tgz"
  scp -o BatchMode=yes "$ROOT_DIR/install-in-ct.sh" "${PROXMOX_REMOTE}:/tmp/install-warzone-sentinel.sh"
  if [[ -f "$TOKEN_SRC" ]]; then
    scp -o BatchMode=yes "$TOKEN_SRC" "${PROXMOX_REMOTE}:/tmp/wz-firewalla.token.env"
  fi
  if [[ -f "$XBOX_TOKEN_SRC" ]]; then
    scp -o BatchMode=yes "$XBOX_TOKEN_SRC" "${PROXMOX_REMOTE}:/tmp/wz-xbox-notify.json"
  fi
  ssh -o BatchMode=yes "$PROXMOX_REMOTE" env CTID="$CTID" DEST="$DEST" bash -s <<'REMOTE'
set -euo pipefail
pct exec "$CTID" -- mkdir -p /etc/warzone-sentinel
if [[ -f /tmp/wz-firewalla.token.env ]]; then
  pct push "$CTID" /tmp/wz-firewalla.token.env /etc/warzone-sentinel/firewalla.token
  pct exec "$CTID" -- chmod 600 /etc/warzone-sentinel/firewalla.token
  rm -f /tmp/wz-firewalla.token.env
fi
if [[ -f /tmp/wz-xbox-notify.json ]]; then
  pct push "$CTID" /tmp/wz-xbox-notify.json /etc/warzone-sentinel/xbox_notify.json
  pct exec "$CTID" -- chmod 600 /etc/warzone-sentinel/xbox_notify.json
  rm -f /tmp/wz-xbox-notify.json
fi
pct exec "$CTID" -- mkdir -p "$DEST"
pct push "$CTID" /tmp/warzone-lobby-sentinel.tgz /tmp/warzone-lobby-sentinel.tgz
pct exec "$CTID" -- bash -c "rm -rf '$DEST' && mkdir -p '$DEST' && tar xzf /tmp/warzone-lobby-sentinel.tgz -C /opt && rm -f /tmp/warzone-lobby-sentinel.tgz"
pct push "$CTID" /tmp/install-warzone-sentinel.sh /tmp/install-warzone-sentinel.sh
pct exec "$CTID" -- bash /tmp/install-warzone-sentinel.sh
rm -f /tmp/warzone-lobby-sentinel.tgz /tmp/install-warzone-sentinel.sh
REMOTE
  rm -f "$BUNDLE"
}

if [[ -n "$PROXMOX_NODE" ]] && [[ "$PROXMOX_NODE" != "local" ]]; then
  deploy_remote
elif command -v pct >/dev/null 2>&1; then
  deploy_local
else
  deploy_remote
fi

IP=""
if [[ -n "$PROXMOX_NODE" ]] && [[ "$PROXMOX_NODE" != "local" ]]; then
  IP="$(ssh -o BatchMode=yes "$PROXMOX_REMOTE" "pct exec $CTID -- hostname -I 2>/dev/null" | awk '{print $1}')"
elif command -v pct >/dev/null 2>&1; then
  IP="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
fi

PORT="${WZ_INGEST_PORT:-8098}"
echo ""
echo "Warzone Lobby Sentinel deployed to CT${CTID} on ${PROXMOX_SSH}"
echo "  status:  http://${IP:-<CT-IP>}:${PORT}/v1/status"
echo "  health:  http://${IP:-<CT-IP>}:${PORT}/health"
echo "  logs:    ssh ${PROXMOX_REMOTE} 'pct exec ${CTID} -- journalctl -u warzone-lobby-sentinel -f'"
echo ""
echo "Fully autonomous — polls Firewalla Xbox telemetry via LAN API. Zero manual input."
echo ""
