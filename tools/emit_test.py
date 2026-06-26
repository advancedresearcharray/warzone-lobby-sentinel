#!/usr/bin/env python3
"""Emit test events into live_events.ndjson to verify the watch pipeline."""

import json
import time
from pathlib import Path

OUT = Path("/var/lib/warzone-sentinel/live_events.ndjson")
OUT.parent.mkdir(parents=True, exist_ok=True)

EVENTS = [
    {"type": "lobby", "players": [
        {"name": "GhostSnap99", "lifetime_kd": 3.8, "session_kd": 12.0, "headshot_pct": 0.61, "rank_tier": "Gold"},
        {"name": "LegitGrinder", "lifetime_kd": 0.88, "headshot_pct": 0.19, "rank_tier": "Platinum"},
    ]},
    {"type": "tick", "match_time_sec": 30},
    {"type": "ping", "player": "GhostSnap99", "ping_ms": 32},
    {"type": "ping", "player": "GhostSnap99", "ping_ms": 200},
    {"type": "kill", "killer": "GhostSnap99", "victim": "LegitGrinder", "match_time_sec": 42,
     "headshot": True, "killer_ping_ms": 30, "victim_visible_ms": 30,
     "killer_x": 1000, "killer_y": 500},
    {"type": "kill", "killer": "GhostSnap99", "victim": "You", "match_time_sec": 45,
     "headshot": True, "killer_x": 5000, "killer_y": 3000, "victim_visible_ms": 25},
    {"type": "prefire", "player": "GhostSnap99", "before_los": True},
    {"type": "killcam_result", "player": "GhostSnap99", "aimbot_probability": 0.88},
]

def main() -> None:
    print(f"Writing test events to {OUT}")
    for ev in EVENTS:
        with OUT.open("a") as f:
            f.write(json.dumps(ev) + "\n")
        print(f"  + {ev['type']}")
        time.sleep(1)

if __name__ == "__main__":
    main()
