"""HTTP event ingest + Xbox phone companion (console has no Overwolf)."""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentinel.events import replay_events


XBOX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <title>WZ Sentinel — Xbox</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 16px; background: #0d1117; color: #e6edf3; }
    h1 { font-size: 1.25rem; margin: 0 0 4px; }
    p.sub { color: #8b949e; font-size: 0.85rem; margin: 0 0 16px; }
    input { width: 100%; padding: 12px; font-size: 16px; border-radius: 8px; border: 1px solid #30363d; background: #161b22; color: #e6edf3; margin-bottom: 10px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 16px; }
    button { padding: 14px 8px; font-size: 0.9rem; border: 0; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .sig { background: #21262d; color: #ff7b72; border: 1px solid #f85149; }
  .lobby { background: #1f6feb; color: #fff; grid-column: span 2; }
  .refresh { background: #238636; color: #fff; grid-column: span 2; }
    #status { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; font-size: 0.8rem; white-space: pre-wrap; min-height: 120px; }
    .ok { color: #3fb950; }
    .warn { color: #d29922; }
    .bad { color: #f85149; }
  </style>
</head>
<body>
  <h1>WZ Sentinel</h1>
  <p class="sub">Xbox companion — report suspicious players from your phone on the same Wi‑Fi.</p>
  <input id="name" type="text" placeholder="Gamertag (from scoreboard)" autocomplete="off" autocapitalize="off">
  <div class="grid">
    <button class="sig" onclick="report('prefire')">Prefire / ESP</button>
    <button class="sig" onclick="report('snap')">Snap aim</button>
    <button class="sig" onclick="report('wallhack')">Wall / radar</button>
    <button class="sig" onclick="report('lag')">Lag switch</button>
    <button class="lobby" onclick="addLobby()">Add to lobby watchlist</button>
    <button class="refresh" onclick="loadStatus()">Refresh watchlist</button>
  </div>
  <div id="status">Tap Refresh watchlist…</div>
  <script>
    async function post(ev) {
      const r = await fetch('/v1/events', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(ev) });
      return r.json();
    }
    function player() {
      const n = document.getElementById('name').value.trim();
      if (!n) { alert('Enter gamertag'); throw new Error('no name'); }
      return n;
    }
    async function report(kind) {
      const name = player();
      const map = {
        prefire: { type: 'prefire', player: name, before_los: true, source: 'xbox' },
        snap: { type: 'killcam_result', player: name, aimbot_probability: 0.85, source: 'xbox', detail: 'snap aim reported' },
        wallhack: { type: 'prefire', player: name, before_los: true, source: 'xbox', note: 'wallhack' },
        lag: { type: 'ping', player: name, ping_ms: 250, source: 'xbox' },
      };
      await post(map[kind]);
      document.getElementById('status').textContent = 'Reported ' + name + ' (' + kind + ')';
      setTimeout(loadStatus, 500);
    }
    async function addLobby() {
      const name = player();
      await post({ type: 'lobby', players: [{ name, lifetime_kd: 2.5, headshot_pct: 0.4, source: 'xbox_manual' }] });
      document.getElementById('status').textContent = 'Added ' + name + ' to lobby watchlist';
      setTimeout(loadStatus, 500);
    }
    async function loadStatus() {
      const el = document.getElementById('status');
      el.textContent = 'Loading…';
      try {
        const r = await fetch('/v1/status');
        const d = await r.json();
        if (!d.live || !d.live.length) { el.textContent = 'No flagged players yet. Report someone during a match.'; return; }
        el.innerHTML = d.live.map(p => {
          const cls = p.level === 'CRITICAL' || p.level === 'HIGH' ? 'bad' : (p.level === 'MEDIUM' ? 'warn' : 'ok');
          return '<span class="'+cls+'">['+p.level+'] '+p.score.toFixed(0)+' — '+p.name+'</span>';
        }).join('\\n');
      } catch (e) { el.textContent = 'Error: ' + e; }
    }
    loadStatus();
  </script>
</body>
</html>
"""


class IngestHandler(BaseHTTPRequestHandler):
    events_path: Path

    def log_message(self, fmt: str, *args) -> None:
        print(f"[ingest] {self.address_string()} {fmt % args}")

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, body: dict) -> None:
        self._send(code, json.dumps(body).encode(), "application/json")

    def _append_events(self, events: list[dict]) -> int:
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a") as f:
            for ev in events:
                if isinstance(ev, dict):
                    f.write(json.dumps(ev) + "\n")
        return len(events)

    def _live_status(self) -> dict:
        if not self.events_path.is_file():
            return {"live": [], "lobby_stress": 0.0}
        lines = self.events_path.read_text().strip().splitlines()[-500:]
        events = [json.loads(ln) for ln in lines if ln.strip()]
        if not any(e.get("type") == "tick" for e in events):
            events.append({"type": "tick", "match_time_sec": time.time() % 3600})
        match = replay_events(events)
        stress, _ = match.lobby_report()
        live = [r.to_dict() for r in match.live_report(min_score=15.0)]
        return {"lobby_stress": stress, "live": live[:12]}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/v1/health"):
            self._json(200, {"ok": True, "events": str(self.events_path), "platform": "xbox-ready"})
            return
        if path in ("/xbox", "/v1/xbox"):
            self._send(200, XBOX_HTML.encode(), "text/html; charset=utf-8")
            return
        if path == "/v1/status":
            self._json(200, self._live_status())
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in ("/v1/events", "/events"):
            self._json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        events = payload if isinstance(payload, list) else [payload]
        accepted = self._append_events([e for e in events if isinstance(e, dict)])
        self._json(200, {"accepted": accepted})


def serve(host: str, port: int, events_path: Path) -> None:
    IngestHandler.events_path = events_path
    server = ThreadingHTTPServer((host, port), IngestHandler)
    print(f"Ingest on http://{host}:{port} (Xbox UI: /xbox) → {events_path}")
    server.serve_forever()


def main() -> None:
    import os

    host = os.environ.get("WZ_INGEST_HOST", "0.0.0.0")
    port = int(os.environ.get("WZ_INGEST_PORT", "8098"))
    events = Path(os.environ.get("WZ_EVENTS_FILE", "/var/lib/warzone-sentinel/live_events.ndjson"))
    serve(host, port, events)


if __name__ == "__main__":
    main()
