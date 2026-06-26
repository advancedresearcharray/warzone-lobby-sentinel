"""Send alerts to Xbox console via Xbox Live message (native notification toast)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Public Xbox app client (OpenXbox / Home Assistant pattern).
CLIENT_ID = os.environ.get("WZ_XBOX_CLIENT_ID", "000000004C12AE6F")
REDIRECT_URI = os.environ.get(
    "WZ_XBOX_REDIRECT_URI",
    "https://login.live.com/oauth20_desktop.srf",
)
AUTHORIZE_URL = os.environ.get(
    "WZ_XBOX_AUTHORIZE_URL",
    "https://login.live.com/oauth20_authorize.srf",
)
TOKEN_URL = os.environ.get(
    "WZ_XBOX_TOKEN_URL",
    "https://login.live.com/oauth20_token.srf",
)
SCOPES = os.environ.get("WZ_XBOX_SCOPES", "XboxLive.signin XboxLive.offline_access")

_last_notify_at = 0.0


def _token_path() -> str:
    return os.environ.get("WZ_XBOX_NOTIFY_TOKEN_FILE", "/etc/warzone-sentinel/xbox_notify.json")


def _enabled() -> bool:
    return os.environ.get("WZ_XBOX_NOTIFY_ENABLED", "1").strip() not in ("0", "false", "no")


def _load_token() -> dict[str, Any]:
    try:
        return json.loads(open(_token_path()).read())
    except OSError:
        return {}


def _save_token(data: dict[str, Any]) -> None:
    path = _token_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)


def _post_form(url: str, fields: dict[str, str], headers: dict | None = None) -> dict[str, Any]:
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def _post_json(url: str, payload: dict, headers: dict) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def _get_json(url: str, headers: dict) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def authorize_url(state: str = "wzsentinel") -> str:
    """Browser sign-in URL (Live.com auth-code flow)."""
    params = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPES,
            "state": state,
        }
    )
    return f"{AUTHORIZE_URL}?{params}"


def _extract_auth_code(redirect_url: str) -> str:
    parsed = urllib.parse.urlparse(redirect_url.strip())
    query = urllib.parse.parse_qs(parsed.query)
    fragment = urllib.parse.parse_qs(parsed.fragment)
    for bucket in (query, fragment):
        code = bucket.get("code", [None])[0]
        if code:
            return code
    raise ValueError("No authorization code in redirect URL")


def exchange_auth_code(code_or_redirect: str) -> dict[str, Any]:
    """Exchange OAuth code (or full redirect URL) for refresh/access tokens."""
    code = code_or_redirect.strip()
    if code.startswith("http://") or code.startswith("https://"):
        code = _extract_auth_code(code)
    return _post_form(
        TOKEN_URL,
        {
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )


def save_tokens(tok: dict[str, Any]) -> None:
    store = {
        "refresh_token": tok["refresh_token"],
        "access_token": tok.get("access_token"),
        "updated_at": time.time(),
    }
    _save_token(store)


def _refresh_access_token(refresh_token: str) -> dict[str, Any]:
    return _post_form(
        TOKEN_URL,
        {
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": REDIRECT_URI,
        },
    )


def _xbox_auth(access_token: str) -> tuple[str, str, str]:
    """Return (uhs, xsts_token, xuid) from Xbox Live auth."""
    user = _post_json(
        "https://user.auth.xboxlive.com/user/authenticate",
        {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={access_token}",
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        },
        {"Content-Type": "application/json", "Accept": "application/json"},
    )
    user_token = user["Token"]
    xsts = _post_json(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        {
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
            "RelyingParty": "http://xboxlive.com",
            "TokenType": "JWT",
        },
        {"Content-Type": "application/json", "Accept": "application/json"},
    )
    xui = xsts["DisplayClaims"]["xui"][0]
    uhs = xui["uhs"]
    xuid = str(xui.get("xid") or xui.get("xuid") or "")
    if not xuid:
        raise RuntimeError(f"No xuid in XSTS claims: {xui}")
    return uhs, xsts["Token"], xuid


def _auth_header() -> tuple[str, str, str]:
    store = _load_token()
    refresh = store.get("refresh_token")
    if not refresh:
        raise RuntimeError("Xbox notify not configured — run setup-xbox-notify.py")

    tok = _refresh_access_token(refresh)
    if tok.get("refresh_token"):
        store["refresh_token"] = tok["refresh_token"]
    store["access_token"] = tok["access_token"]
    store["updated_at"] = time.time()

    uhs, xsts, xuid = _xbox_auth(tok["access_token"])
    if not store.get("xuid"):
        store["xuid"] = xuid
    _save_token(store)
    return uhs, xsts, xuid


def _xbl_headers(uhs: str, xsts: str) -> dict[str, str]:
    return {
        "Authorization": f"XBL3.0 x={uhs};{xsts}",
        "x-xbl-contract-version": "1",
        "Accept": "application/json",
    }


def _my_xuid(headers: dict[str, str], xuid: str | None = None) -> str:
    store = _load_token()
    if store.get("xuid"):
        return str(store["xuid"])
    if xuid:
        store["xuid"] = xuid
        _save_token(store)
        return xuid
    raise RuntimeError("No xuid available — re-run Xbox setup")


def _send_live_message(text: str) -> None:
    uhs, xsts, xuid = _auth_header()
    headers = _xbl_headers(uhs, xsts)
    xuid = _my_xuid(headers, xuid)

    if len(text) > 256:
        text = text[:253] + "..."

    # OpenXbox MessageProvider — POST to conversation with self triggers console toast.
    url = f"https://xblmessaging.xboxlive.com/network/Xbox/users/me/conversations/users/xuid({xuid})"
    _post_json(
        url,
        {
            "parts": [
                {
                    "contentType": "text",
                    "version": 0,
                    "text": text,
                }
            ]
        },
        headers,
    )


def notify_session_alert(
    level: str,
    score: float,
    phase: str,
    game: str,
    recommendation: str,
    anomalies: list[str],
    *,
    force: bool = False,
) -> bool:
    """Push native Xbox notification via self-message. Returns True if sent."""
    global _last_notify_at

    if not _enabled():
        return False

    cooldown = float(os.environ.get("WZ_XBOX_NOTIFY_COOLDOWN_SEC", "120"))
    now = time.time()
    if not force and now - _last_notify_at < cooldown:
        return False

    title = f"Warzone Sentinel — {level}"
    lines = [recommendation, f"Integrity {score:.0f}% · {phase} · {game}"]
    lines.extend(anomalies[:3])
    body = "\n".join(lines)
    if len(body) > 256:
        body = body[:253] + "..."

    try:
        _send_live_message(f"{title}\n{body}")
        _last_notify_at = now
        print(
            "[xbox-notify] Message sent to Xbox Live "
            "(self-chat is auto-muted — use phone push for on-screen alerts)",
            flush=True,
        )
        return True
    except Exception as exc:
        print(f"[xbox-notify] failed: {exc}", flush=True)
        return False


def configured() -> bool:
    return bool(_load_token().get("refresh_token"))
