"""AI learning layer — baselines, session memory, adaptive cheater-lobby thresholds."""

from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_SAMPLES = 120
MIN_SAMPLES = 8
MAX_SESSIONS = 40
MAX_LOBBIES = 200


def _data_path() -> Path:
    p = os.environ.get("WZ_LEARNING_FILE", "/var/lib/warzone-sentinel/ai-learning.json")
    path = Path(p)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    idx = min(len(s) - 1, int((p / 100) * len(s)))
    return s[idx]


def _push(arr: list, item: dict, limit: int = MAX_SAMPLES) -> None:
    arr.append(item)
    while len(arr) > limit:
        arr.pop(0)


@dataclass
class AdaptiveThresholds:
    conn_matchmaking_high: float = 90.0
    conn_matchmaking_elevated: float = 55.0
    mm_delta_bad: float = 45.0
    mm_delta_warn: float = 25.0
    jitter_bad: float = 14.0
    wan_jitter_bad: float = 18.0
    source: str = "default"
    samples: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "conn_matchmaking_high": round(self.conn_matchmaking_high, 1),
            "conn_matchmaking_elevated": round(self.conn_matchmaking_elevated, 1),
            "mm_delta_bad": round(self.mm_delta_bad, 1),
            "mm_delta_warn": round(self.mm_delta_warn, 1),
            "jitter_bad": round(self.jitter_bad, 1),
            "wan_jitter_bad": round(self.wan_jitter_bad, 1),
            "source": self.source,
            "samples": self.samples,
        }


class LearningEngine:
    def __init__(self) -> None:
        self._state = self._load()

    def _default_state(self) -> dict:
        return {
            "history": {
                "wan_latency": [],
                "conn_count": [],
                "matchmaking_latency": [],
                "mm_delta": [],
                "cheater_scores": [],
            },
            "sessions": {"active": None, "completed": []},
            "lobbies": [],
            "feedback": [],
        }

    def _load(self) -> dict:
        path = _data_path()
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return self._default_state()

    def save(self) -> None:
        tmp = _data_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=2))
        tmp.replace(_data_path())
        try:
            os.chmod(_data_path(), 0o600)
        except OSError:
            pass

    def thresholds(self) -> AdaptiveThresholds:
        h = self._state["history"]
        n = len(h["conn_count"])
        if n < MIN_SAMPLES:
            return AdaptiveThresholds(samples=n)

        conns = [x["v"] for x in h["conn_count"] if x.get("phase") == "matchmaking"]
        mm_deltas = [x["v"] for x in h["mm_delta"] if x["v"] is not None]
        wan_jitter_samples = []
        wan_vals = [x["v"] for x in h["wan_latency"]]
        if len(wan_vals) >= 10:
            for i in range(8, len(wan_vals)):
                chunk = wan_vals[i - 8 : i]
                if len(chunk) > 1:
                    wan_jitter_samples.append(statistics.pstdev(chunk))

        t = AdaptiveThresholds(source="learned", samples=n)
        if conns:
            p75 = _percentile(conns, 75) or 55
            p90 = _percentile(conns, 90) or 90
            t.conn_matchmaking_elevated = max(40, min(120, p75 * 1.15))
            t.conn_matchmaking_high = max(60, min(180, p90 * 1.1))
        if mm_deltas:
            p75 = _percentile(mm_deltas, 75) or 25
            p90 = _percentile(mm_deltas, 90) or 45
            t.mm_delta_warn = max(15, min(50, p75))
            t.mm_delta_bad = max(30, min(80, p90))
        if wan_jitter_samples:
            p90 = _percentile(wan_jitter_samples, 90) or 18
            t.wan_jitter_bad = max(12, min(35, p90))

        crit_jitter = [x["v"] for x in h.get("server_jitter", []) if x.get("v") is not None]
        if len(crit_jitter) >= MIN_SAMPLES:
            p90 = _percentile(crit_jitter, 90) or 14
            t.jitter_bad = max(10, min(30, p90))

        return t

    def record_poll(
        self,
        snapshot: dict,
        phase: str,
        verdict: dict,
        *,
        mm_delta: float | None = None,
        server_jitter: float | None = None,
    ) -> None:
        ts = time.time()
        h = self._state["history"]
        conns = int(snapshot.get("connections", {}).get("count") or 0)
        wan = snapshot.get("wan", {}).get("latencyMs")

        if wan is not None:
            _push(h["wan_latency"], {"ts": ts, "v": float(wan), "phase": phase})
        _push(h["conn_count"], {"ts": ts, "v": conns, "phase": phase})
        if mm_delta is not None:
            _push(h["mm_delta"], {"ts": ts, "v": float(mm_delta), "phase": phase})
        if server_jitter is not None:
            if "server_jitter" not in h:
                h["server_jitter"] = []
            _push(h["server_jitter"], {"ts": ts, "v": float(server_jitter), "phase": phase})
        _push(h["cheater_scores"], {"ts": ts, "v": verdict.get("confidence", 0), "label": verdict.get("label")})

        self._update_session(phase, verdict, conns, snapshot)
        self._record_lobby(phase, verdict, conns, mm_delta, snapshot)
        self.save()

    def _update_session(self, phase: str, verdict: dict, conns: int, snapshot: dict) -> None:
        sess = self._state["sessions"]
        gaming = phase in ("matchmaking", "in-match")
        now = time.time()

        if gaming and not sess["active"]:
            sess["active"] = {
                "started_at": now,
                "game": (snapshot.get("_enriched") or {}).get("game", "warzone"),
                "phases": [],
                "peak_conns": conns,
                "worst_verdict": verdict.get("label", "CLEAN"),
                "worst_score": verdict.get("confidence", 0),
            }

        if sess["active"]:
            active = sess["active"]
            active["peak_conns"] = max(active.get("peak_conns", 0), conns)
            phases = active.setdefault("phases", [])
            if not phases or phases[-1].get("phase") != phase:
                phases.append({"phase": phase, "at": now})
            if verdict.get("confidence", 0) >= active.get("worst_score", 0):
                active["worst_score"] = verdict.get("confidence", 0)
                active["worst_verdict"] = verdict.get("label", "CLEAN")

            if not gaming and phase in ("idle", "background"):
                active["ended_at"] = now
                active["duration_sec"] = int(now - active["started_at"])
                _push(sess["completed"], active, MAX_SESSIONS)
                sess["active"] = None

    def _record_lobby(
        self,
        phase: str,
        verdict: dict,
        conns: int,
        mm_delta: float | None,
        snapshot: dict,
    ) -> None:
        if phase not in ("matchmaking", "in-match"):
            return
        roles = (snapshot.get("_enriched") or {}).get("roleCounts", {})
        entry = {
            "ts": time.time(),
            "phase": phase,
            "label": verdict.get("label"),
            "confidence": verdict.get("confidence", 0),
            "conns": conns,
            "mm_delta": mm_delta,
            "roles": roles,
        }
        _push(self._state["lobbies"], entry, MAX_LOBBIES)

    def record_feedback(self, bad_lobby: bool, note: str = "") -> None:
        """User confirmed good/bad lobby — trains similarity weights."""
        fb = {
            "ts": time.time(),
            "bad_lobby": bad_lobby,
            "note": note[:200],
            "last_lobby": (self._state["lobbies"] or [None])[-1],
        }
        _push(self._state["feedback"], fb, 100)
        self.save()

    def adjust_score(self, base_score: float, features: dict) -> tuple[float, list[str]]:
        """Boost/reduce score using learned baselines + past bad lobbies + user feedback."""
        notes: list[str] = []
        score = base_score
        t = self.thresholds()

        conns = features.get("conns", 0)
        if t.source == "learned" and features.get("phase") == "matchmaking":
            if conns > t.conn_matchmaking_high:
                score += 0.12
                notes.append(f"Conn fan-out above your learned baseline ({conns:.0f}>{t.conn_matchmaking_high:.0f})")
            elif conns < t.conn_matchmaking_elevated * 0.6 and base_score > 0.15:
                score -= 0.1
                notes.append("Conn count below your normal matchmaking baseline")

        mm_delta = features.get("mm_delta")
        if mm_delta is not None and t.source == "learned":
            if mm_delta >= t.mm_delta_bad:
                score += 0.1
                notes.append(f"Matchmaking path worse than your learned bad threshold (+{mm_delta:.0f} ms)")
            elif mm_delta < t.mm_delta_warn * 0.8 and score > 0.2:
                score -= 0.08

        # Similarity to past bad lobbies (verdict LIKELY or user feedback bad)
        bad_refs = [
            lb for lb in self._state["lobbies"]
            if lb.get("label") == "LIKELY" or any(
                f.get("bad_lobby") and abs(f.get("ts", 0) - lb.get("ts", 0)) < 300
                for f in self._state["feedback"]
            )
        ]
        if bad_refs and conns:
            similar = sum(
                1 for lb in bad_refs[-30:]
                if abs(lb.get("conns", 0) - conns) <= max(15, conns * 0.25)
            )
            if similar >= 3:
                score += min(0.15, similar * 0.04)
                notes.append(f"Matches {similar} prior bad-lobby sessions on your network")

        good_feedback = [f for f in self._state["feedback"] if not f.get("bad_lobby")]
        if good_feedback and base_score < 0.35:
            score -= 0.05

        return max(0.0, min(1.0, score)), notes

    def insights(self) -> dict[str, Any]:
        h = self._state["history"]
        completed = self._state["sessions"].get("completed", [])
        lobbies = self._state["lobbies"]
        bad = [lb for lb in lobbies if lb.get("label") in ("LIKELY", "POSSIBLE")]
        t = self.thresholds()

        patterns: list[str] = []
        if t.source == "learned":
            patterns.append(
                f"Learned baselines from {t.samples} samples — "
                f"matchmaking fan-out ~{t.conn_matchmaking_elevated:.0f}/{t.conn_matchmaking_high:.0f} conns"
            )
        if len(bad) >= 5:
            avg_c = statistics.mean(lb["conns"] for lb in bad[-20:] if lb.get("conns"))
            patterns.append(f"Bad lobbies on your network avg {avg_c:.0f} connections during queue")
        if len(completed) >= 3:
            worst = max(completed[-10:], key=lambda s: s.get("worst_score", 0))
            patterns.append(
                f"Recent worst session: {worst.get('worst_verdict')} ({worst.get('worst_score', 0):.0f}%)"
            )

        return {
            "thresholds": t.to_dict(),
            "samples": {k: len(v) for k, v in h.items()},
            "sessions_completed": len(completed),
            "lobbies_tracked": len(lobbies),
            "feedback_count": len(self._state["feedback"]),
            "patterns": patterns[:5],
            "active_session": self._state["sessions"].get("active"),
        }


ENGINE = LearningEngine()
