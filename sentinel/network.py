"""Network timing and kill-causality checks."""

from __future__ import annotations

import math
from dataclasses import dataclass


# Approximate max sprint speed m/s in Warzone (conservative).
MAX_TRAVEL_MPS = 7.0
MIN_SERVER_TICK_MS = 60.0


@dataclass
class KillEvent:
    killer: str
    victim: str
    match_time_sec: float
    killer_ping_ms: float | None = None
    victim_ping_ms: float | None = None
  # Optional world positions for travel checks.
    killer_x: float | None = None
    killer_y: float | None = None
    victim_x: float | None = None
    victim_y: float | None = None
    was_headshot: bool = False
    victim_visible_ms: float | None = None  # Time victim was visible before shot.


@dataclass
class CausalityResult:
    killer: str
    violation_type: str
    detail: str
    severity: float  # 0–1


def _dist(x1: float, y1: float, x2: float, y2: float) -> float:
    return math.hypot(x2 - x1, y2 - y1)


def min_reaction_time_ms(killer_ping: float | None, victim_ping: float | None) -> float:
    """Lower bound on human reaction time given network RTT."""
    kp = killer_ping or 40.0
    vp = victim_ping or 40.0
    return (kp / 2.0) + (vp / 2.0) + MIN_SERVER_TICK_MS


def check_impossible_reaction(kill: KillEvent) -> CausalityResult | None:
    if kill.victim_visible_ms is None:
        return None
    floor_ms = min_reaction_time_ms(kill.killer_ping_ms, kill.victim_ping_ms)
    if kill.victim_visible_ms < floor_ms * 0.6:
        return CausalityResult(
            killer=kill.killer,
            violation_type="impossible_reaction",
            detail=f"visible {kill.victim_visible_ms:.0f}ms < network floor {floor_ms:.0f}ms",
            severity=clamp_severity(1.0 - (kill.victim_visible_ms / floor_ms)),
        )
    return None


def check_impossible_travel(prev: KillEvent, curr: KillEvent) -> CausalityResult | None:
    """Same killer, two kills too far apart in too little time."""
    if prev.killer != curr.killer:
        return None
    if None in (prev.killer_x, prev.killer_y, curr.killer_x, curr.killer_y):
        return None
    dt = curr.match_time_sec - prev.match_time_sec
    if dt <= 0:
        return None
    dist = _dist(prev.killer_x, prev.killer_y, curr.killer_x, curr.killer_y)  # type: ignore[arg-type]
    min_time = dist / MAX_TRAVEL_MPS
    if dt < min_time * 0.85:
        return CausalityResult(
            killer=curr.killer,
            violation_type="impossible_travel",
            detail=f"{dist:.0f}m in {dt:.1f}s (need >={min_time:.1f}s)",
            severity=clamp_severity((min_time - dt) / max(min_time, 1.0)),
        )
    return None


def clamp_severity(value: float) -> float:
    return max(0.0, min(1.0, value))


def analyze_kill_sequence(kills: list[KillEvent]) -> list[CausalityResult]:
    """Run network/causality checks on ordered kill events."""
    results: list[CausalityResult] = []
    by_killer: dict[str, list[KillEvent]] = {}

    for kill in sorted(kills, key=lambda k: k.match_time_sec):
        r = check_impossible_reaction(kill)
        if r:
            results.append(r)

        prior = by_killer.get(kill.killer, [])
        if prior:
            t = check_impossible_travel(prior[-1], kill)
            if t:
                results.append(t)
        by_killer.setdefault(kill.killer, []).append(kill)

    return results
