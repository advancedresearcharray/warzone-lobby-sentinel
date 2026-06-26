"""Aggregate signals into a 0–100 cheat-risk score."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.baseline import (
    PlayerStats,
    SessionState,
    lobby_stress_index,
    score_player_stats,
    score_session_state,
)
from sentinel.network import CausalityResult


# Weights tuned for multi-signal clustering (not single-feature conviction).
WEIGHTS: dict[str, float] = {
    "lifetime_kd_z": 12,
    "session_kd_spike": 18,
    "headshot_pct_z": 14,
    "rank_stat_mismatch": 16,
    "kill_velocity": 15,
    "session_headshot_rate": 12,
    "ping_volatility": 8,
    "causality_violations": 20,
    "prefire_index": 14,
    "impossible_reaction": 22,
    "impossible_travel": 20,
    "killcam_snap": 25,
    "lobby_stress": 10,
}


@dataclass
class PlayerRisk:
    name: str
    score: float
    level: str
    signals: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"name": self.name, "score": round(self.score, 1), "level": self.level, "signals": self.signals}


def risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "CLEAN"


def combine_signals(signals: dict[str, float]) -> float:
    total_weight = 0.0
    weighted = 0.0
    for key, value in signals.items():
        w = WEIGHTS.get(key, 10)
        weighted += value * w
        total_weight += w
    if total_weight == 0:
        return 0.0
    return min(100.0, (weighted / total_weight) * 100.0)


def score_lobby(players: list[PlayerStats]) -> tuple[float, list[PlayerRisk]]:
    stress = lobby_stress_index(players)
    risks: list[PlayerRisk] = []
    for p in players:
        signals = score_player_stats(p)
        if stress > 0.3:
            signals["lobby_stress"] = stress
        score = combine_signals(signals)
        risks.append(PlayerRisk(name=p.name, score=score, level=risk_level(score), signals=signals))
    risks.sort(key=lambda r: r.score, reverse=True)
    return stress, risks


def score_live_player(
    stats: PlayerStats | None,
    session: SessionState,
    match_duration_sec: float,
    causality: list[CausalityResult],
    killcam_snap: float | None = None,
) -> PlayerRisk:
    signals: dict[str, float] = {}
    if stats:
        signals.update(score_player_stats(stats))
    signals.update(score_session_state(session, match_duration_sec))

    for c in causality:
        if c.killer == session.name:
            key = c.violation_type
            signals[key] = max(signals.get(key, 0.0), c.severity)

    if killcam_snap is not None:
        signals["killcam_snap"] = killcam_snap

    score = combine_signals(signals)
    return PlayerRisk(name=session.name, score=score, level=risk_level(score), signals=signals)
