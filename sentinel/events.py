"""Event ingestion and live match state machine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from sentinel.baseline import PlayerStats, SessionState
from sentinel.network import KillEvent, analyze_kill_sequence
from sentinel.scorer import PlayerRisk, score_live_player, score_lobby


@dataclass
class LiveMatch:
    mode: str | None = None
    started_at_sec: float = 0.0
    match_duration_sec: float = 0.0
    players: dict[str, PlayerStats] = field(default_factory=dict)
    sessions: dict[str, SessionState] = field(default_factory=dict)
    kills: list[KillEvent] = field(default_factory=list)
    killcam_scores: dict[str, float] = field(default_factory=dict)

    def _session(self, name: str) -> SessionState:
        if name not in self.sessions:
            self.sessions[name] = SessionState(name=name)
        return self.sessions[name]

    def ingest(self, event: dict[str, Any]) -> None:
        etype = event.get("type", "")
        if etype == "lobby":
            for p in event.get("players", []):
                stats = PlayerStats(
                    name=p["name"],
                    lifetime_kd=p.get("lifetime_kd"),
                    session_kd=p.get("session_kd"),
                    headshot_pct=p.get("headshot_pct"),
                    rank_tier=p.get("rank_tier"),
                    account_level=p.get("account_level"),
                )
                self.players[stats.name] = stats
                self._session(stats.name)
        elif etype == "kill":
            killer = event["killer"]
            self._session(killer).kills += 1
            self._session(killer).kill_times_sec.append(float(event.get("match_time_sec", 0)))
            if event.get("headshot"):
                self._session(killer).headshots += 1
            self.kills.append(
                KillEvent(
                    killer=killer,
                    victim=event.get("victim", ""),
                    match_time_sec=float(event.get("match_time_sec", 0)),
                    killer_ping_ms=event.get("killer_ping_ms"),
                    victim_ping_ms=event.get("victim_ping_ms"),
                    killer_x=event.get("killer_x"),
                    killer_y=event.get("killer_y"),
                    victim_x=event.get("victim_x"),
                    victim_y=event.get("victim_y"),
                    was_headshot=bool(event.get("headshot")),
                    victim_visible_ms=event.get("victim_visible_ms"),
                )
            )
        elif etype == "death":
            victim = event.get("victim") or event.get("player")
            if victim:
                self._session(victim).deaths += 1
        elif etype == "ping":
            name = event["player"]
            self._session(name).ping_samples.append(float(event["ping_ms"]))
        elif etype == "prefire":
            name = event["player"]
            s = self._session(name)
            s.engagements += 1
            if event.get("before_los"):
                s.prefire_events += 1
        elif etype == "killcam_result":
            self.killcam_scores[event["player"]] = float(event.get("aimbot_probability", 0))
        elif etype == "tick":
            self.match_duration_sec = float(event.get("match_time_sec", self.match_duration_sec))

    def lobby_report(self) -> tuple[float, list[PlayerRisk]]:
        return score_lobby(list(self.players.values()))

    def live_report(self, min_score: float = 0.0) -> list[PlayerRisk]:
        causality = analyze_kill_sequence(self.kills)
        risks: list[PlayerRisk] = []
        for name, session in self.sessions.items():
            if session.kills == 0 and session.deaths == 0 and name not in self.players:
                continue
            stats = self.players.get(name)
            kc = self.killcam_scores.get(name)
            risk = score_live_player(stats, session, self.match_duration_sec, causality, kc)
            if risk.score >= min_score:
                risks.append(risk)
        risks.sort(key=lambda r: r.score, reverse=True)
        return risks


def load_events(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if isinstance(data, list):
        return data
    return data.get("events", [])


def iter_ndjson(path: Path) -> Iterator[dict]:
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def replay_events(events: list[dict]) -> LiveMatch:
    match = LiveMatch()
    for ev in events:
        match.ingest(ev)
    return match
