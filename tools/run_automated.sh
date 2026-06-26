#!/usr/bin/env bash
# Autonomous Xbox Warzone sentinel — Rust core (Python fallback).
set -euo pipefail

INSTALL_ROOT="${WZ_INSTALL_ROOT:-/opt/warzone-lobby-sentinel}"
export WZ_INGEST_HOST="${WZ_INGEST_HOST:-0.0.0.0}"
export WZ_INGEST_PORT="${WZ_INGEST_PORT:-8098}"
export WZ_POLL_INTERVAL_SEC="${WZ_POLL_INTERVAL_SEC:-4}"
export WZ_POLL_INTERVAL_IDLE_SEC="${WZ_POLL_INTERVAL_IDLE_SEC:-12}"

RUST_BIN="${INSTALL_ROOT}/bin/warzone-sentinel"
if [[ -x "$RUST_BIN" ]]; then
  exec "$RUST_BIN"
fi

VENV="${INSTALL_ROOT}/.venv"
exec "${VENV}/bin/python" -m sentinel.autonomous
