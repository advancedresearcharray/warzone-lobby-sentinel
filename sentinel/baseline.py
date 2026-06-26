"""Population baselines and per-player statistical anomaly detection."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any


# Warzone population norms (approximate; tune from your own match history).
POPULATION = {
    "kd": {"mean": 0.92, "std": 0.55, "suspicious": 2.5},
    "headshot_pct": {"mean": 0.20, "std": 0.08, "suspicious": 0.45},
    "session_kd_multiplier": {"mean": 1.0, "std": 0.6, "suspicious": 3.0},
    "kills_per_minute": {"mean": 0.35, "std": 0.25, "suspicious": 1.2},
}


def zscore(value: float, mean: float, std: float) -> float:
    if std <= 0:
        return 0.0
    return (value - mean) / std


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


@dataclass
class PlayerStats:
    name: str
    lifetime_kd: float | None = None
    session_kd: float | None = None
    headshot_pct: float | None = None
    rank_tier: str | None = None
    account_level: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionState:
    """Tracks in-match events for one player."""

    name: str
    kills: int = 0
    deaths: int = 0
    headshots: int = 0
    kill_times_sec: list[float] = field(default_factory=list)
    ping_samples: list[float] = field(default_factory=list)
    causality_violations: int = 0
    prefire_events: int = 0
    engagements: int = 0

    @property
    def kills_per_minute(self) -> float:
        if len(self.kill_times_sec) < 2:
            return float(self.kills)
        span = max(self.kill_times_sec) - min(self.kill_times_sec)
        minutes = max(span / 60.0, 1 / 60.0)
        return self.kills / minutes

    @property
    def headshot_rate(self) -> float:
        if self.kills == 0:
            return 0.0
        return self.headshots / self.kills

    @property
    def ping_volatility(self) -> float:
        if len(self.ping_samples) < 2:
            return 0.0
        mean = sum(self.ping_samples) / len(self.ping_samples)
        var = sum((p - mean) ** 2 for p in self.ping_samples) / len(self.ping_samples)
        return math.sqrt(var) / max(mean, 1.0)


def rank_tier_score(tier: str | None, lifetime_kd: float | None) -> float:
    """Flag rank/stat mismatches (smurf or boosted account signal)."""
    if not tier or lifetime_kd is None:
        return 0.0
    tier = tier.lower()
    high_rank = any(t in tier for t in ("crimson", "iridescent", "top 250", "top250"))
    if high_rank and lifetime_kd < 0.9:
        return 0.85
    if high_rank and lifetime_kd < 1.2:
        return 0.55
    return 0.0


def score_player_stats(stats: PlayerStats) -> dict[str, float]:
    """Score a player from lobby / tracker stats before the match."""
    signals: dict[str, float] = {}

    if stats.lifetime_kd is not None:
        kd_z = zscore(stats.lifetime_kd, POPULATION["kd"]["mean"], POPULATION["kd"]["std"])
        signals["lifetime_kd_z"] = clamp(kd_z / 4.0)

    if stats.session_kd is not None and stats.lifetime_kd is not None and stats.lifetime_kd > 0:
        mult = stats.session_kd / stats.lifetime_kd
        mult_z = zscore(mult, POPULATION["session_kd_multiplier"]["mean"], POPULATION["session_kd_multiplier"]["std"])
        signals["session_kd_spike"] = clamp(mult_z / 3.0)

    if stats.headshot_pct is not None:
        hs_z = zscore(stats.headshot_pct, POPULATION["headshot_pct"]["mean"], POPULATION["headshot_pct"]["std"])
        signals["headshot_pct_z"] = clamp(hs_z / 4.0)

    mismatch = rank_tier_score(stats.rank_tier, stats.lifetime_kd)
    if mismatch:
        signals["rank_stat_mismatch"] = mismatch

    return signals


def score_session_state(state: SessionState, match_duration_sec: float) -> dict[str, float]:
    """Score live in-match behavioral signals."""
    signals: dict[str, float] = {}

    kpm = state.kills_per_minute
    kpm_z = zscore(kpm, POPULATION["kills_per_minute"]["mean"], POPULATION["kills_per_minute"]["std"])
    signals["kill_velocity"] = clamp(kpm_z / 4.0)

    if state.kills >= 3:
        hs_z = zscore(state.headshot_rate, POPULATION["headshot_pct"]["mean"], POPULATION["headshot_pct"]["std"])
        signals["session_headshot_rate"] = clamp(hs_z / 4.0)

    if state.ping_volatility > 0.5:
        signals["ping_volatility"] = clamp(state.ping_volatility)

    if state.causality_violations > 0:
        signals["causality_violations"] = clamp(state.causality_violations / 3.0)

    if state.engagements > 0:
        prefire_ratio = state.prefire_events / state.engagements
        signals["prefire_index"] = clamp(prefire_ratio * 2.0)

    return signals


def lobby_stress_index(players: list[PlayerStats]) -> float:
    """0–1 score for how abnormal the whole lobby is."""
    if not players:
        return 0.0
    high_kd = sum(1 for p in players if p.lifetime_kd and p.lifetime_kd > 1.5)
    high_hs = sum(1 for p in players if p.headshot_pct and p.headshot_pct > 0.35)
    n = len(players)
    return clamp((high_kd / n) * 0.6 + (high_hs / n) * 0.4)
