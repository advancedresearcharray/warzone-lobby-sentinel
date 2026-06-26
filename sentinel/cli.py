#!/usr/bin/env python3
"""Warzone Lobby Sentinel — automated cheat-risk detection CLI."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from sentinel import __version__
from sentinel.events import LiveMatch, iter_ndjson, load_events, replay_events
from sentinel.killcam import analyze_killcam
from sentinel.store import MatchStore


def _print_risks(risks: list, title: str, lobby_stress: float | None = None) -> None:
    print(f"\n{'=' * 60}")
    print(title)
    if lobby_stress is not None:
        print(f"Lobby Stress Index: {lobby_stress:.0%}")
    print(f"{'=' * 60}")
    if not risks:
        print("No flagged players.")
        return
    for r in risks:
        sig = ", ".join(f"{k}={v:.2f}" for k, v in sorted(r.signals.items()) if v > 0.15)
        print(f"  [{r.level:8}] {r.score:5.1f}  {r.name}")
        if sig:
            print(f"             └─ {sig}")


def cmd_analyze(args: argparse.Namespace) -> int:
    events = load_events(Path(args.file))
    match = replay_events(events)
    stress, lobby_risks = match.lobby_report()
    live_risks = match.live_report(min_score=args.min_score)

    _print_risks(lobby_risks[: args.top], "PRE-MATCH LOBBY RISK", stress)
    _print_risks(live_risks[: args.top], "IN-MATCH LIVE RISK (baseline + network)")

    if args.save:
        store = MatchStore(Path(args.db))
        mid = store.start_match(match.mode)
        store.finish_match(mid, stress, live_risks or lobby_risks)
        print(f"\nSaved match #{mid} to {args.db}")

    if args.json:
        print(json.dumps({
            "lobby_stress": stress,
            "lobby": [r.to_dict() for r in lobby_risks],
            "live": [r.to_dict() for r in live_risks],
        }, indent=2))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    path = Path(args.file)
    store = MatchStore(Path(args.db)) if args.save else None
    match = LiveMatch()
    match_id = store.start_match() if store else None
    last_size = 0
    last_report = 0.0

    print(f"Watching {path} — append NDJSON events to automate scoring.")
    print("Event types: lobby, kill, death, ping, prefire, killcam_result, tick")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            if not path.exists():
                time.sleep(args.interval)
                continue

            size = path.stat().st_size
            if size < last_size:
                last_size = 0  # file rotated
            if size > last_size:
                with path.open() as f:
                    f.seek(last_size)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        ev = json.loads(line)
                        match.ingest(ev)
                        if store:
                            store.log_event(ev.get("type", "unknown"), ev, match_id)
                last_size = size

            now = time.time()
            if now - last_report >= args.interval:
                live = match.live_report(min_score=args.min_score)
                if live:
                    _print_risks(live[: args.top], f"LIVE WATCHLIST @ {match.match_duration_sec:.0f}s")
                last_report = now

            time.sleep(0.25)
    except KeyboardInterrupt:
        if store and match_id is not None:
            stress, lobby = match.lobby_report()
            live = match.live_report()
            store.finish_match(match_id, stress, live or lobby)
            print(f"\nSession saved as match #{match_id}")
        return 0


def cmd_watch_killcams(args: argparse.Namespace) -> int:
    folder = Path(args.folder)
    folder.mkdir(parents=True, exist_ok=True)
    events_file = Path(args.events)
    seen: set[str] = set()

    print(f"Watching {folder} for new killcam clips → appending to {events_file}")

    try:
        while True:
            for clip in sorted(folder.glob("*.mp4")) + sorted(folder.glob("*.mkv")):
                key = f"{clip.name}:{clip.stat().st_mtime}"
                if key in seen:
                    continue
                seen.add(key)
                print(f"Analyzing {clip.name}...")
                try:
                    result = analyze_killcam(clip)
                    player = clip.stem.split("_")[0]  # e.g. CheaterX_2024.mp4
                    ev = {
                        "type": "killcam_result",
                        "player": player,
                        "aimbot_probability": result.aimbot_probability,
                        "detail": result.detail,
                    }
                    with events_file.open("a") as f:
                        f.write(json.dumps(ev) + "\n")
                    print(f"  → {player}: aimbot_prob={result.aimbot_probability:.0%} ({result.detail})")
                except Exception as exc:
                    print(f"  → failed: {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def cmd_killcam(args: argparse.Namespace) -> int:
    result = analyze_killcam(Path(args.file))
    print(json.dumps({
        "path": result.path,
        "frames": result.frames_analyzed,
        "snap_velocity_p99": round(result.snap_velocity_p99, 3),
        "jerk_variance": round(result.jerk_variance, 5),
        "aimbot_probability": round(result.aimbot_probability, 3),
        "detail": result.detail,
    }, indent=2))
    return 0


def cmd_watchlist(args: argparse.Namespace) -> int:
    store = MatchStore(Path(args.db))
    rows = store.top_watchlist(args.limit)
    print(f"\nHistorical watchlist ({args.db}):")
    for r in rows:
        ban = " [BANNED]" if r["ban_hits"] else ""
        print(f"  peak={r['peak']:.1f}  sightings={r['sightings']}  {r['player_name']}{ban}")
    return 0


def cmd_mark_banned(args: argparse.Namespace) -> int:
    store = MatchStore(Path(args.db))
    n = store.mark_banned(args.name)
    print(f"Marked {n} records for '{args.name}' — use this to tune your weights over time.")
    return 0


def cmd_demo(_: argparse.Namespace) -> int:
    sample = Path(__file__).resolve().parent.parent / "samples" / "match_events.json"
    events = load_events(sample)
    match = replay_events(events)
    stress, lobby = match.lobby_report()
    live = match.live_report()
    _print_risks(lobby[:5], "DEMO: PRE-MATCH LOBBY RISK", stress)
    _print_risks(live[:5], "DEMO: IN-MATCH LIVE RISK")
    print("\nRun with your own data:")
    print("  python -m sentinel watch samples/live_events.ndjson")
    print("  python -m sentinel analyze samples/match_events.json")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Automated Warzone cheat-risk scoring from lobby stats + live events + killcams.",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Run demo with sample match data")
    demo.set_defaults(func=cmd_demo)

    analyze = sub.add_parser("analyze", help="One-shot analyze a match JSON/NDJSON file")
    analyze.add_argument("file", help="Path to match events JSON")
    analyze.add_argument("--top", type=int, default=10)
    analyze.add_argument("--min-score", type=float, default=0.0)
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--save", action="store_true")
    analyze.add_argument("--db", default="/var/lib/warzone-sentinel/matches.db")
    analyze.set_defaults(func=cmd_analyze)

    watch = sub.add_parser("watch", help="Tail NDJSON events file for live automated scoring")
    watch.add_argument("file", help="NDJSON events file to tail")
    watch.add_argument("--interval", type=float, default=5.0, help="Report interval seconds")
    watch.add_argument("--top", type=int, default=8)
    watch.add_argument("--min-score", type=float, default=25.0)
    watch.add_argument("--save", action="store_true", default=True)
    watch.add_argument("--db", default="/var/lib/warzone-sentinel/matches.db")
    watch.set_defaults(func=cmd_watch)

    wkc = sub.add_parser("watch-killcams", help="Auto-analyze new killcam videos → append events")
    wkc.add_argument("--folder", default="/var/lib/warzone-sentinel/killcams")
    wkc.add_argument("--events", default="/var/lib/warzone-sentinel/live_events.ndjson")
    wkc.add_argument("--interval", type=float, default=2.0)
    wkc.set_defaults(func=cmd_watch_killcams)

    kc = sub.add_parser("killcam", help="Analyze a single killcam video")
    kc.add_argument("file")
    kc.set_defaults(func=cmd_killcam)

    wl = sub.add_parser("watchlist", help="Show historical high-risk players")
    wl.add_argument("--limit", type=int, default=15)
    wl.add_argument("--db", default="/var/lib/warzone-sentinel/matches.db")
    wl.set_defaults(func=cmd_watchlist)

    ban = sub.add_parser("mark-banned", help="Tag a player as later-banned for weight tuning")
    ban.add_argument("name")
    ban.add_argument("--db", default="/var/lib/warzone-sentinel/matches.db")
    ban.set_defaults(func=cmd_mark_banned)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Expand ~
    for attr in ("db", "folder", "events"):
        if hasattr(args, attr):
            setattr(args, attr, str(Path(getattr(args, attr)).expanduser()))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
