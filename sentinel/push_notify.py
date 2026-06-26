"""Phone push via ntfy.sh — reliable alerts while gaming."""

from __future__ import annotations

import json
import os
import secrets
import urllib.request


def _config_path() -> str:
    return os.environ.get("WZ_NTFY_CONFIG_FILE", "/etc/warzone-sentinel/ntfy.json")


def _load_config() -> dict:
    try:
        return json.loads(open(_config_path()).read())
    except OSError:
        return {}


def _save_config(data: dict) -> None:
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)


def _server() -> str:
    return os.environ.get("WZ_NTFY_SERVER", "https://ntfy.sh").rstrip("/")


def topic() -> str:
    explicit = os.environ.get("WZ_NTFY_TOPIC", "").strip()
    if explicit:
        return explicit
    cfg = _load_config()
    if cfg.get("topic"):
        return str(cfg["topic"])
    generated = f"warzone-sentinel-{secrets.token_hex(4)}"
    _save_config({"topic": generated, "server": _server()})
    return generated


def subscribe_url() -> str:
    return f"{_server()}/{topic()}"


def configured() -> bool:
    return os.environ.get("WZ_NTFY_ENABLED", "1").strip() not in ("0", "false", "no")


def _header_safe(text: str) -> str:
    return text.replace("\u2014", "-").replace("\u2013", "-").encode("latin-1", "replace").decode("latin-1")


def notify(title: str, body: str, *, tags: str = "warning,video_game") -> bool:
    if not configured():
        return False
    url = subscribe_url()
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Title": _header_safe(title[:200]),
            "Tags": tags,
            "Priority": "high",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        print(f"[ntfy] failed: {exc}", flush=True)
        return False
