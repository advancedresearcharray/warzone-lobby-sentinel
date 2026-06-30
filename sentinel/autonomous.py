"""Fully autonomous Xbox Warzone monitor — polls Firewalla, zero manual input."""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel.enrich import enrich_snapshot
from sentinel.firewalla_client import fetch_insights, fetch_snapshot, probe_firewalla
from sentinel.learning import ENGINE
from sentinel.network_session import NetworkSessionScorer, SessionRisk
from sentinel import alert_notify, push_notify, xbox_notify


class _State:
    risk: SessionRisk | None = None
    last_error: str | None = None
    source: str = ""
    updated_at: float = 0.0
    polls: int = 0


STATE = _State()
SCORER = NetworkSessionScorer()


def poll_once() -> SessionRisk:
    snapshot = enrich_snapshot(fetch_snapshot())
    insights = fetch_insights()
    return SCORER.score(snapshot, insights)


def _log_alert(risk: SessionRisk) -> None:
    print(
        f"\n{'!' * 60}\n"
        f"WZ ALERT [{risk.level}] score={risk.score:.0f} phase={risk.phase} game={risk.game}\n"
        f"{risk.recommendation}\n"
        + "\n".join(f"  - {a}" for a in risk.anomalies[:5])
        + f"\n{'!' * 60}\n",
        flush=True,
    )
    alert_notify.notify_session_alert(
        risk.level,
        risk.score,
        risk.phase,
        risk.game,
        risk.recommendation,
        risk.anomalies,
        cheater_lobby=risk.cheater_lobby,
    )


def run_poll_loop() -> None:
    interval = float(os.environ.get("WZ_POLL_INTERVAL_SEC", "4"))
    api = os.environ.get("WZ_ARRAY_FW_API_URL", os.environ.get("WZ_FIREWALLA_API_URL", "http://127.0.0.1:8090"))
    STATE.source = f"firewalla:{api}" if probe_firewalla() else "unconfigured"
    print(f"Autonomous Xbox mode — polling Firewalla {api} every {interval}s", flush=True)
    if alert_notify.status()["phone_push"] or alert_notify.status()["xbox_live"]:
        st = alert_notify.status()
        if st["phone_subscribe_url"]:
            print(f"Phone alerts: subscribe once → {st['phone_subscribe_url']}", flush=True)
        if st["xbox_live"]:
            print("Xbox Live: configured (messages only — self-chat won't toast)", flush=True)
    else:
        print("Alerts: open /v1/alerts/setup once", flush=True)

    while True:
        try:
            risk = poll_once()
            STATE.risk = risk
            STATE.last_error = None
            STATE.updated_at = time.time()
            STATE.polls += 1
            STATE.source = f"firewalla:{api}"
            if SCORER.should_alert(risk):
                _log_alert(risk)
            elif STATE.polls % 15 == 0 and risk.phase in ("matchmaking", "in-match"):
                print(
                    f"[wz] {risk.phase} {risk.game} integrity={risk.score:.0f} ({risk.level})",
                    flush=True,
                )
        except Exception as exc:
            STATE.last_error = str(exc)
            if STATE.polls == 0 or STATE.polls % 20 == 0:
                print(f"[wz] poll error: {exc}", flush=True)
        time.sleep(interval)


class StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, code: int, body: str) -> None:
        page = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WZ Sentinel Xbox Setup</title>
<style>body{{font-family:system-ui;max-width:640px;margin:2rem auto;padding:0 1rem}}
a.btn{{display:inline-block;background:#107c10;color:#fff;padding:.75rem 1.25rem;text-decoration:none;border-radius:6px}}
textarea{{width:100%;min-height:80px}}</style>
</head><body>{body}</body></html>"""
        data = page.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/v1/health"):
            self._json(200, {
                "ok": STATE.last_error is None or STATE.risk is not None,
                "mode": "autonomous",
                "platform": "xbox",
                "source": STATE.source,
                "polls": STATE.polls,
                "error": STATE.last_error,
                "alerts": alert_notify.status(),
                "learning": ENGINE.insights(),
            })
            return
        if path in ("/v1/status", "/status"):
            risk = STATE.risk
            body: dict[str, Any] = {
                "autonomous": True,
                "source": STATE.source,
                "updated_at": STATE.updated_at,
                "session": risk.to_dict() if risk else None,
            }
            self._json(200, body)
            return
        if path in ("/v1/feedback", "/feedback"):
            risk = STATE.risk
            body: dict[str, Any] = {
                "ok": True,
                "message": "Send POST with {\"bad_lobby\": true|false, \"note\": \"optional\"}",
                "last_verdict": (risk.cheater_lobby if risk else None),
                "learning": ENGINE.insights(),
            }
            self._json(200, body)
            return
            st = alert_notify.status()
            ntfy_url = st.get("phone_subscribe_url") or push_notify.subscribe_url()
            oauth = xbox_notify.authorize_url()
            self._html(
                200,
                f"""<h1>Warzone Sentinel alerts</h1>
<h2>Phone (recommended)</h2>
<p>Xbox auto-mutes messages you send yourself — they <strong>won't pop up on screen</strong>.
Use phone push while you play (Xbox app or ntfy on same Wi‑Fi):</p>
<p><a class="btn" href="{ntfy_url}" target="_blank" rel="noopener">Subscribe on this phone</a></p>
<p>Or install the <a href="https://ntfy.sh/app">ntfy app</a> and subscribe to topic:<br>
<code>{ntfy_url.split('/')[-1]}</code></p>
<p><a href="/v1/alerts/test">Send test alert</a></p>
<h2>Xbox Live (optional)</h2>
<p>Stores messages in your inbox only. Same Microsoft account as your console must be signed in.</p>
<p><a href="/v1/xbox/setup">Link Microsoft account</a></p>
<p class="muted">Status: phone={'on' if st['phone_push'] else 'off'}, xbox={'on' if st['xbox_live'] else 'off'}</p>""",
            )
            return
        if path in ("/v1/alerts/test", "/alerts/test"):
            ok = alert_notify.notify_session_alert(
                "TEST",
                50,
                "matchmaking",
                "Warzone",
                "Test alert — subscribe to phone push for on-screen notifications while playing.",
                ["Sentinel is working"],
                force=True,
            )
            msg = "<h1>Test sent</h1><p>Check your phone notification.</p>" if ok else "<h1>Send failed</h1>"
            self._html(200 if ok else 500, msg + "<p><a href='/v1/alerts/setup'>Back</a></p>")
            return
        if path in ("/v1/xbox/test", "/xbox/test"):
            self.send_response(302)
            self.send_header("Location", "/v1/alerts/test")
            self.end_headers()
            return
        if path in ("/v1/xbox/setup", "/xbox/setup"):
            url = xbox_notify.authorize_url()
            self._html(
                200,
                f"""<h1>Xbox Live (optional)</h1>
<p>Messages to yourself are <strong>muted by Xbox</strong> and won't toast on console.
Use <a href="/v1/alerts/setup">phone push</a> for alerts while playing.</p>
<ol>
<li><a class="btn" href="{url}" target="_blank" rel="noopener">Sign in with Microsoft</a></li>
<li>Copy the full redirect URL after sign-in.</li>
<li>Paste below.</li>
</ol>
<form method="POST" action="/v1/xbox/setup">
<label>Paste redirect URL<br>
<textarea name="redirect_url" placeholder="https://login.live.com/oauth20_desktop.srf?code=..."></textarea></label><br><br>
<button type="submit">Save</button>
</form>
<p><a href="/v1/alerts/setup">← Back to alerts setup</a></p>""",
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in ("/v1/feedback", "/feedback"):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode() if length else ""
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON"})
                return
            if "bad_lobby" not in payload:
                self._json(400, {"error": "bad_lobby (boolean) required"})
                return
            bad = bool(payload["bad_lobby"])
            note = str(payload.get("note") or "")
            ENGINE.record_feedback(bad, note)
            risk = STATE.risk
            self._json(200, {
                "ok": True,
                "bad_lobby": bad,
                "note": note[:200],
                "last_verdict": (risk.cheater_lobby if risk else None),
                "learning": ENGINE.insights(),
            })
            return
        if path in ("/v1/xbox/setup", "/xbox/setup"):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode() if length else ""
            fields = parse_qs(raw)
            redirect = (fields.get("redirect_url") or [""])[0].strip()
            if not redirect:
                self._html(400, "<h1>Missing redirect URL</h1><p><a href='/v1/xbox/setup'>Back</a></p>")
                return
            try:
                tok = xbox_notify.exchange_auth_code(redirect)
                xbox_notify.save_tokens(tok)
                self._html(
                    200,
                    "<h1>Microsoft account linked</h1>"
                    "<p>Inbox messages only — use <a href='/v1/alerts/setup'>phone push</a> for on-screen alerts.</p>",
                )
            except Exception as exc:
                self._html(
                    400,
                    f"<h1>Setup failed</h1><p>{exc}</p><p><a href='/v1/xbox/setup'>Try again</a></p>",
                )
            return
        self._json(404, {"error": "not found"})


def serve_status(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), StatusHandler)
    print(f"Status http://{host}:{port}/v1/status", flush=True)
    server.serve_forever()


def main() -> None:
    host = os.environ.get("WZ_INGEST_HOST", "0.0.0.0")
    port = int(os.environ.get("WZ_INGEST_PORT", "8098"))
    threading.Thread(target=serve_status, args=(host, port), daemon=True).start()
    run_poll_loop()


if __name__ == "__main__":
    main()
