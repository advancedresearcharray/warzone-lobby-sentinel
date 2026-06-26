"""Cheater / shadow-pool lobby verdict from Xbox network telemetry."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from sentinel.enrich import classify_host
from sentinel.learning import AdaptiveThresholds


@dataclass
class CheaterLobbyVerdict:
    label: str  # LIKELY | POSSIBLE | CLEAN
    confidence: float
    reasons: list[str] = field(default_factory=list)
    mm_delta: float | None = None

    @property
    def likely(self) -> bool:
        return self.label == "LIKELY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 1),
            "likely": self.likely,
            "reasons": self.reasons[:6],
        }


def _items_with_roles(snapshot: dict) -> list[dict]:
    items: list[dict] = []
    for item in snapshot.get("connections", {}).get("items", []):
        host = item.get("hostname") or item.get("host") or item.get("label") or ""
        rid = item.get("roleId") or classify_host(host)
        items.append({**item, "roleId": rid, "hostname": host or item.get("hostname", "")})
    for dest in snapshot.get("destinations", []):
        host = dest.get("hostname") or dest.get("label") or ""
        rid = dest.get("roleId") or classify_host(host)
        items.append({**dest, "roleId": rid, "hostname": host})
    for key in ("recentFlows", "recent_flows"):
        for flow in snapshot.get(key) or []:
            host = flow.get("hostname") or flow.get("host") or flow.get("label") or ""
            if not host or host.replace(".", "").isdigit():
                continue
            items.append({
                "roleId": classify_host(host),
                "hostname": host,
                "latencyMs": flow.get("latencyMs"),
                "upload": flow.get("upload", 0),
                "download": flow.get("download", 0),
            })
    return items


def _role_counts(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        rid = item.get("roleId") or "unknown"
        if rid != "unknown":
            counts[rid] = counts.get(rid, 0) + 1
    return counts


def _latencies(items: list[dict], *roles: str) -> list[float]:
    out: list[float] = []
    for item in items:
        if roles and item.get("roleId") not in roles:
            continue
        lat = item.get("latencyMs")
        if lat is not None:
            out.append(float(lat))
    return out


def assess(
    snapshot: dict,
    phase: str,
    *,
    wan_history: list[float] | None = None,
    crit_history: list[float] | None = None,
    conn_history: list[int] | None = None,
    thresholds: AdaptiveThresholds | None = None,
    learn_adjust: float | None = None,
    learn_notes: list[str] | None = None,
) -> CheaterLobbyVerdict:
    """Return cheater-lobby verdict from live telemetry."""
    th = thresholds or AdaptiveThresholds()
    items = _items_with_roles(snapshot)
    roles: dict[str, int] = {}
    for item in items:
        rid = item.get("roleId") or "unknown"
        if rid != "unknown":
            roles[rid] = roles.get(rid, 0) + 1
    for rid, n in (snapshot.get("_enriched") or {}).get("roleCounts", {}).items():
        if rid != "unknown":
            roles[rid] = roles.get(rid, 0) + n

    conns = int(snapshot.get("connections", {}).get("count") or 0)
    wan = snapshot.get("wan", {}).get("latencyMs")
    wan_f = float(wan) if wan is not None else None

    score = 0.0
    reasons: list[str] = []

    if phase not in ("matchmaking", "in-match"):
        return CheaterLobbyVerdict("CLEAN", 0.0, ["Not in lobby or match"])

    mm_delta_val: float | None = None

    # --- Matchmaking: shadow-pool placement signatures ---
    if phase == "matchmaking":
        if conns >= th.conn_matchmaking_high:
            score += 0.28
            reasons.append(f"Shadow-pool fan-out ({conns} live connections during queue)")
        elif conns >= th.conn_matchmaking_elevated:
            score += 0.14
            reasons.append(f"Elevated matchmaking traffic ({conns} connections)")

        if roles.get("matchmaking", 0) >= 2:
            score += 0.12
            reasons.append("Multiple PlayFab session endpoints active")

        if roles.get("azure-qos", 0) >= 2:
            score += 0.15
            reasons.append("Multi-region QoS probing — distant lobby selection pattern")

        mm_lats = _latencies(items, "matchmaking", "warzone-game", "azure-qos")
        if mm_lats and wan_f is not None:
            worst = max(mm_lats)
            delta = worst - wan_f
            mm_delta_val = delta
            if delta >= th.mm_delta_bad:
                score += 0.32
                reasons.append(f"Bad lobby placement (+{delta:.0f} ms vs your best path)")
            elif delta >= th.mm_delta_warn:
                score += 0.18
                reasons.append(f"Distant matchmaking server (+{delta:.0f} ms vs baseline)")

        if roles.get("xbox-live", 0) >= 4:
            score += 0.1
            reasons.append("Xbox Live session churn — unstable lobby assignment")

        if conn_history and len(conn_history) >= 6:
            peak = max(conn_history[-6:])
            if peak >= 80 and conns >= peak * 0.7:
                score += 0.08
                reasons.append("Sustained high fan-out through entire queue")

    # --- In-match: manipulation / bad server pool signatures ---
    if phase == "in-match":
        demonware = roles.get("warzone-game", 0)
        gameplay = demonware + roles.get("matchmaking", 0) + roles.get("game-assets", 0)
        telemetry = roles.get("telemetry", 0)

        if demonware >= 1 and telemetry >= 2 and telemetry >= demonware:
            score += 0.22
            reasons.append("Anti-cheat telemetry spike vs Demonware gameplay")

        if crit_history and len(crit_history) >= 6:
            jitter = statistics.pstdev(crit_history[-6:]) if len(crit_history) > 1 else 0.0
            mean_lat = statistics.mean(crit_history[-6:])
            if jitter >= th.jitter_bad:
                score += 0.25
                reasons.append(f"Server latency unstable (σ={jitter:.0f} ms) — lag-comp lobby sign")
            if mean_lat >= 75:
                score += 0.18
                reasons.append(f"High Demonware latency ({mean_lat:.0f} ms) — overseas shadow route")

        if wan_history and len(wan_history) >= 8:
            wan_j = statistics.pstdev(wan_history[-8:]) if len(wan_history) > 1 else 0.0
            if wan_j >= th.wan_jitter_bad:
                score += 0.2
                reasons.append("WAN latency swinging mid-match — manipulation pattern")

        if gameplay >= 2 and telemetry == 0 and conns < 40:
            score -= 0.08

    if learn_adjust is not None:
        score = learn_adjust
        if learn_notes:
            reasons.extend(learn_notes[:3])

    score = max(0.0, min(1.0, score))
    confidence = round(score * 100, 1)

    if score >= 0.48:
        label = "LIKELY"
    elif score >= 0.22:
        label = "POSSIBLE"
    else:
        label = "CLEAN"
        reasons = ["Telemetry matches normal Warzone pools"]

    v = CheaterLobbyVerdict(label, confidence, reasons, mm_delta=mm_delta_val)
    return v
