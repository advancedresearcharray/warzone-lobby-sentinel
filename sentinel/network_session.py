"""Autonomous session risk from Xbox network telemetry (no gamertags on console)."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

from sentinel.cheater_lobby import assess as assess_cheater_lobby
from sentinel.learning import ENGINE


@dataclass
class SessionRisk:
    score: float
    level: str
    phase: str
    game: str
    recommendation: str
    signals: dict[str, float] = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)
    cheater_lobby: dict[str, Any] = field(default_factory=dict)
    learning: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "level": self.level,
            "phase": self.phase,
            "game": self.game,
            "recommendation": self.recommendation,
            "signals": {k: round(v, 3) for k, v in self.signals.items()},
            "anomalies": self.anomalies,
            "cheater_lobby": self.cheater_lobby,
            "learning": self.learning,
        }


def _level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "CLEAN"


def _role_counts(snapshot: dict) -> dict[str, int]:
    enriched = snapshot.get("_enriched", {}).get("roleCounts")
    if enriched:
        return {k: v for k, v in enriched.items() if k != "unknown"}
    counts: dict[str, int] = {}
    for item in snapshot.get("connections", {}).get("items", []):
        rid = item.get("roleId") or "unknown"
        counts[rid] = counts.get(rid, 0) + 1
    return counts


def _critical_latencies(snapshot: dict) -> list[float]:
    out: list[float] = []
    for item in snapshot.get("connections", {}).get("items", []):
        if item.get("tier") == "critical" and item.get("latencyMs") is not None:
            out.append(float(item["latencyMs"]))
    for d in snapshot.get("destinations", []):
        if d.get("tier") == "critical" and d.get("latencyMs") is not None:
            out.append(float(d["latencyMs"]))
    return out


class NetworkSessionScorer:
    """Rolling baseline + live scoring — in-memory only, no database."""

    def __init__(self) -> None:
        self._wan_history: list[float] = []
        self._crit_history: list[float] = []
        self._conn_history: list[int] = []
        self._last_phase = "idle"
        self._match_started_at: float | None = None
        self._last_alert_at = 0.0

    def _track(self, snapshot: dict) -> None:
        wan = snapshot.get("wan", {}).get("latencyMs")
        if wan is not None:
            self._wan_history.append(float(wan))
            self._wan_history = self._wan_history[-120:]
        crit = _critical_latencies(snapshot)
        if crit:
            self._crit_history.append(statistics.mean(crit))
            self._crit_history = self._crit_history[-120:]
        conns = int(snapshot.get("connections", {}).get("count") or 0)
        self._conn_history.append(conns)
        self._conn_history = self._conn_history[-120:]

    def score(self, snapshot: dict, insights: dict | None = None) -> SessionRisk:
        insights = insights or {}
        phase_info = insights.get("sessionPhase") or insights.get("phase") or {}
        enriched = snapshot.get("_enriched") or {}
        phase = phase_info.get("phase") or enriched.get("phase") or self._infer_phase(snapshot)
        game = (phase_info.get("game") or {}).get("id") or enriched.get("game") or self._infer_game(snapshot)
        game_label = (phase_info.get("game") or {}).get("label") or game

        self._track(snapshot)
        if phase in ("in-match", "matchmaking") and self._last_phase not in ("in-match", "matchmaking"):
            self._match_started_at = time.time()
        if phase == "idle":
            self._match_started_at = None
        self._last_phase = phase

        signals: dict[str, float] = {}
        anomalies: list[str] = []

        if game not in ("warzone", "unknown") and phase != "in-match":
            return SessionRisk(
                score=0.0,
                level="CLEAN",
                phase=phase,
                game=game_label,
                recommendation="Not in Warzone — monitoring idle",
                signals=signals,
                anomalies=anomalies,
            )

        roles = _role_counts(snapshot)
        conns = int(snapshot.get("connections", {}).get("count") or 0)
        wan = snapshot.get("wan", {}).get("latencyMs")
        crit_lats = _critical_latencies(snapshot)

        # Shadow / cheater-pool proxies from network shape.
        if phase == "matchmaking":
            if (roles.get("matchmaking", 0) + roles.get("warzone-game", 0)) >= 2 and conns >= 8:
                signals["heavy_matchmaking"] = min(1.0, conns / 20.0)
                anomalies.append(f"Dense matchmaking fan-out ({conns} connections)")
            if roles.get("xbox-live", 0) >= 3:
                signals["xbox_live_churn"] = 0.5

        if phase == "in-match":
            telemetry = roles.get("telemetry", 0)
            gameplay = roles.get("warzone-game", 0) + roles.get("game-assets", 0)
            if telemetry >= 3 and gameplay >= 2 and telemetry >= roles.get("warzone-game", 0):
                signals["telemetry_noise"] = min(1.0, telemetry / max(gameplay, 1))
                anomalies.append("Anti-cheat telemetry spike vs gameplay traffic")

            if len(self._crit_history) >= 8:
                recent = self._crit_history[-8:]
                jitter = statistics.pstdev(recent) if len(recent) > 1 else 0.0
                mean_lat = statistics.mean(recent)
                if jitter >= 12:
                    signals["server_latency_jitter"] = min(1.0, jitter / 40.0)
                    anomalies.append(f"Game server latency unstable (σ={jitter:.0f}ms)")
                if mean_lat >= 70:
                    signals["high_server_latency"] = min(1.0, (mean_lat - 50) / 80.0)
                    anomalies.append(f"High Demonware latency ({mean_lat:.0f}ms)")

            if len(self._wan_history) >= 10:
                wan_recent = self._wan_history[-10:]
                wan_jitter = statistics.pstdev(wan_recent) if len(wan_recent) > 1 else 0.0
                if wan_jitter >= 15:
                    signals["wan_jitter"] = min(1.0, wan_jitter / 50.0)
                    anomalies.append("WAN latency swinging — possible lag manipulation in lobby")

        for a in insights.get("anomalies") or []:
            sev = a.get("severity", "medium")
            weight = 0.9 if sev == "high" else 0.55 if sev == "medium" else 0.3
            key = f"advisor_{a.get('type', 'unknown')}"
            signals[key] = max(signals.get(key, 0.0), weight)
            msg = a.get("message")
            if msg:
                anomalies.append(msg)

        sec = insights.get("security") or snapshot.get("security") or {}
        for alert in sec.get("alerts") or []:
            signals["inbound_attack"] = 0.85
            anomalies.append(alert.get("message") or alert.get("type") or "Inbound flood detected")

        # Suboptimal matchmaking path from destinations.
        for d in snapshot.get("destinations", []):
            if d.get("roleId") == "matchmaking" and d.get("routePathQuality") == "suboptimal":
                signals["suboptimal_matchmaking_path"] = 0.75
                anomalies.append(f"Suboptimal path to {d.get('hostname', 'matchmaking')}")

        weights = {
            "heavy_matchmaking": 14,
            "xbox_live_churn": 8,
            "telemetry_noise": 16,
            "server_latency_jitter": 18,
            "high_server_latency": 12,
            "wan_jitter": 15,
            "inbound_attack": 10,
            "suboptimal_matchmaking_path": 14,
        }
        total_w = 0.0
        weighted = 0.0
        for k, v in signals.items():
            w = weights.get(k, 10)
            weighted += v * w
            total_w += w
        score = min(100.0, (weighted / total_w) * 100.0) if total_w else 0.0

        thresholds = ENGINE.thresholds()
        base_verdict = assess_cheater_lobby(
            snapshot,
            phase,
            wan_history=self._wan_history,
            crit_history=self._crit_history,
            conn_history=self._conn_history,
            thresholds=thresholds,
        )
        server_jitter = None
        if len(self._crit_history) >= 6 and len(self._crit_history) > 1:
            server_jitter = statistics.pstdev(self._crit_history[-6:])

        adjusted, learn_notes = ENGINE.adjust_score(
            base_verdict.confidence / 100.0,
            {
                "conns": conns,
                "phase": phase,
                "mm_delta": base_verdict.mm_delta,
            },
        )
        verdict = assess_cheater_lobby(
            snapshot,
            phase,
            wan_history=self._wan_history,
            crit_history=self._crit_history,
            conn_history=self._conn_history,
            thresholds=thresholds,
            learn_adjust=adjusted,
            learn_notes=learn_notes if learn_notes else None,
        )
        cheater = verdict.to_dict()

        ENGINE.record_poll(
            snapshot,
            phase,
            cheater,
            mm_delta=base_verdict.mm_delta,
            server_jitter=server_jitter,
        )
        learning_info = ENGINE.insights()

        # Cheater-lobby verdict is the primary score in lobby/match.
        if phase in ("matchmaking", "in-match"):
            score = verdict.confidence
            if verdict.label == "LIKELY":
                level = "CRITICAL" if score >= 75 else "HIGH"
            elif verdict.label == "POSSIBLE":
                level = "MEDIUM" if score >= 35 else "LOW"
            else:
                level = "CLEAN"
        else:
            if phase not in ("matchmaking", "in-match"):
                score *= 0.15
            level = _level(score)

        if verdict.label == "LIKELY":
            rec = "Cheater lobby likely — back out now."
        elif verdict.label == "POSSIBLE":
            rec = "Possible cheater lobby — elevated shadow-pool signals."
        elif level in ("CRITICAL", "HIGH"):
            rec = "Bad lobby telemetry — consider backing out."
        elif level == "MEDIUM":
            rec = "Some suspicious network signs — stay alert."
        else:
            rec = "Clean lobby — telemetry looks normal."

        display_anomalies = verdict.reasons if verdict.label != "CLEAN" else ["Telemetry matches normal Warzone pools"]
        display_anomalies = list(dict.fromkeys(display_anomalies + anomalies))[:8]

        return SessionRisk(
            score=score,
            level=level,
            phase=phase,
            game=game_label,
            recommendation=rec,
            signals=signals,
            anomalies=display_anomalies,
            cheater_lobby=cheater,
            learning=learning_info,
        )

    def should_alert(self, risk: SessionRisk, cooldown_sec: float = 90.0) -> bool:
        cl = risk.cheater_lobby or {}
        if cl.get("label") not in ("LIKELY", "POSSIBLE") and risk.level not in ("CRITICAL", "HIGH"):
            return False
        if risk.phase not in ("matchmaking", "in-match"):
            return False
        now = time.time()
        if now - self._last_alert_at < cooldown_sec:
            return False
        self._last_alert_at = now
        return True

    @staticmethod
    def _infer_phase(snapshot: dict) -> str:
        roles = _role_counts(snapshot)
        if (roles.get("warzone-game", 0) or 0) >= 1:
            return "in-match"
        if (roles.get("matchmaking", 0) or 0) >= 1:
            return "matchmaking"
        if int(snapshot.get("connections", {}).get("count") or 0) == 0:
            return "idle"
        return "background"

    @staticmethod
    def _infer_game(snapshot: dict) -> str:
        enriched = snapshot.get("_enriched") or {}
        if enriched.get("game") == "warzone":
            return "warzone"
        for item in snapshot.get("connections", {}).get("items", []):
            host = (item.get("hostname") or item.get("label") or "").lower()
            if "demonware" in host or "playfab" in host or "callofduty" in host:
                return "warzone"
        for key in ("recentFlows", "recent_flows"):
            for flow in snapshot.get(key) or []:
                host = (flow.get("hostname") or flow.get("host") or flow.get("label") or "").lower()
                if any(x in host for x in ("demonware", "playfab", "callofduty", "activision")):
                    return "warzone"
        return "unknown"
