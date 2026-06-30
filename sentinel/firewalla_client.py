"""Fetch Xbox gaming telemetry — Firewalla LAN API (primary) or gaming monitor dashboard."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def _get(url: str, headers: dict | None = None, timeout: float = 8.0) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _post(url: str, body: dict, headers: dict | None = None, timeout: float = 12.0) -> dict[str, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _load_token() -> str:
    token = os.environ.get("WZ_FIREWALLA_API_TOKEN", "").strip()
    if token:
        return token
    path = os.environ.get("WZ_FIREWALLA_API_TOKEN_FILE", "/etc/warzone-sentinel/firewalla.token")
    try:
        raw = open(path).read().strip()
        for line in raw.splitlines():
            if line.startswith("FIREWALLA_API_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"')
        return raw.splitlines()[0].strip() if raw else ""
    except OSError:
        return ""


def fetch_snapshot_firewalla(xbox_ip: str | None = None) -> dict[str, Any]:
    """Run gaming-snapshot.sh on Firewalla via LAN API — works from any LAN CT."""
    base = os.environ.get("WZ_ARRAY_FW_API_URL", os.environ.get("WZ_FIREWALLA_API_URL", "http://127.0.0.1:8090")).rstrip("/")
    token = _load_token()
    if not token:
        raise RuntimeError("WZ_FIREWALLA_API_TOKEN not configured")

    ip = xbox_ip or os.environ.get("WZ_XBOX_IP", "").strip()
    args = [ip] if ip else []
    result = _post(
        f"{base}/api/v1/run",
        {"script": "gaming-snapshot.sh", "args": args, "sudo": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    if not result.get("ok"):
        raise RuntimeError(result.get("stderr") or result.get("error") or "snapshot failed")
    stdout = result.get("stdout", "")
    if isinstance(stdout, str) and stdout.strip():
        return json.loads(stdout)
    raise RuntimeError("empty snapshot from Firewalla")


def fetch_snapshot_dashboard(base_url: str) -> dict[str, Any]:
    return _get(f"{base_url.rstrip('/')}/api/snapshot")


def fetch_ai_insights_dashboard(base_url: str) -> dict[str, Any]:
    try:
        return _get(f"{base_url.rstrip('/')}/api/ai-insights")
    except urllib.error.HTTPError:
        return {}


def probe_firewalla() -> bool:
    base = os.environ.get("WZ_ARRAY_FW_API_URL", os.environ.get("WZ_FIREWALLA_API_URL", "http://127.0.0.1:8090")).rstrip("/")
    try:
        data = _get(f"{base}/api/health", timeout=3.0)
        return bool(data.get("ok"))
    except Exception:
        return False


def probe_dashboard(base_url: str) -> bool:
    try:
        _get(f"{base_url.rstrip('/')}/api/health", timeout=3.0)
        return True
    except Exception:
        try:
            fetch_snapshot_dashboard(base_url)
            return True
        except Exception:
            return False


def fetch_snapshot() -> dict[str, Any]:
    """Best available source — Firewalla API first, then gaming monitor dashboard."""
    if probe_firewalla():
        try:
            return fetch_snapshot_firewalla()
        except Exception:
            pass
    monitor = os.environ.get("WZ_GAMING_MONITOR_URL", "").strip()
    if monitor and probe_dashboard(monitor):
        return fetch_snapshot_dashboard(monitor)
    raise RuntimeError("No Firewalla API or gaming monitor reachable")


def fetch_insights() -> dict[str, Any]:
    monitor = os.environ.get("WZ_GAMING_MONITOR_URL", "").strip()
    if monitor and probe_dashboard(monitor):
        return fetch_ai_insights_dashboard(monitor)
    return {}
