#!/usr/bin/env bash
# Run inside the LXC after files are staged at /opt/warzone-lobby-sentinel.
set -euo pipefail

INSTALL_ROOT="/opt/warzone-lobby-sentinel"
ENV_FILE="/etc/default/warzone-lobby-sentinel"

apt-get update -qq
apt-get install -y -qq ca-certificates curl >/dev/null

mkdir -p "$INSTALL_ROOT/bin" /etc/warzone-sentinel /var/lib/warzone-sentinel
chmod 700 /var/lib/warzone-sentinel

if [[ -x "$INSTALL_ROOT/bin/warzone-sentinel" ]]; then
  echo "Using Rust binary at $INSTALL_ROOT/bin/warzone-sentinel"
  chmod +x "$INSTALL_ROOT/bin/warzone-sentinel"
else
  apt-get install -y -qq python3 python3-venv python3-pip >/dev/null
  if [[ ! -d "$INSTALL_ROOT/.venv" ]]; then
    python3 -m venv "$INSTALL_ROOT/.venv"
  fi
  "$INSTALL_ROOT/.venv/bin/pip" install -q -U pip
  "$INSTALL_ROOT/.venv/bin/pip" install -q -r "$INSTALL_ROOT/requirements.txt"
fi

chmod +x "$INSTALL_ROOT/tools/run_automated.sh"
[[ -x "$INSTALL_ROOT/bin/warzone-sentinel" ]] && chmod +x "$INSTALL_ROOT/bin/warzone-sentinel"

mkdir -p /etc/warzone-sentinel /var/lib/warzone-sentinel
chmod 700 /var/lib/warzone-sentinel
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0644 "$INSTALL_ROOT/warzone-lobby-sentinel.env.example" "$ENV_FILE"
fi

# Copy Firewalla API token from fleet secret if present (deploy host).
TOKEN_SRC="${WZ_TOKEN_SRC:-/root/.secrets/firewalla-api.env}"
if [[ -f "$TOKEN_SRC" ]]; then
  grep -E '^FIREWALLA_API_TOKEN=' "$TOKEN_SRC" > /etc/warzone-sentinel/firewalla.token || true
  chmod 600 /etc/warzone-sentinel/firewalla.token
fi

install -m 0644 "$INSTALL_ROOT/warzone-lobby-sentinel.service" \
  /etc/systemd/system/warzone-lobby-sentinel.service

systemctl daemon-reload
systemctl enable --now warzone-lobby-sentinel.service
systemctl restart warzone-lobby-sentinel.service
sleep 2
systemctl is-active warzone-lobby-sentinel.service

curl -sf "http://127.0.0.1:${WZ_INGEST_PORT:-8098}/health" 2>/dev/null || true
echo ""
