"""Persistent match history for ban-regression tuning."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from sentinel.scorer import PlayerRisk


class MatchStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    mode TEXT,
                    lobby_stress REAL
                );
                CREATE TABLE IF NOT EXISTS player_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    match_id INTEGER NOT NULL,
                    player_name TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    banned_later INTEGER DEFAULT 0,
                    FOREIGN KEY (match_id) REFERENCES matches(id)
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    match_id INTEGER,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (match_id) REFERENCES matches(id)
                );
                """
            )

    def start_match(self, mode: str | None = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO matches (started_at, mode) VALUES (?, ?)",
                (datetime.now(timezone.utc).isoformat(), mode),
            )
            return int(cur.lastrowid)

    def finish_match(self, match_id: int, lobby_stress: float, risks: list[PlayerRisk]) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE matches SET lobby_stress = ? WHERE id = ?", (lobby_stress, match_id))
            for r in risks:
                conn.execute(
                    "INSERT INTO player_scores (match_id, player_name, risk_score, risk_level, signals_json) VALUES (?, ?, ?, ?, ?)",
                    (match_id, r.name, r.score, r.level, json.dumps(r.signals)),
                )

    def log_event(self, event_type: str, payload: dict, match_id: int | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (match_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (match_id, event_type, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
            )

    def mark_banned(self, player_name: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE player_scores SET banned_later = 1 WHERE player_name = ? COLLATE NOCASE",
                (player_name,),
            )
            return cur.rowcount

    def top_watchlist(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT player_name, MAX(risk_score) AS peak, COUNT(*) AS sightings,
                       SUM(banned_later) AS ban_hits
                FROM player_scores
                GROUP BY player_name
                ORDER BY peak DESC, sightings DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def export_report(self, match_id: int) -> dict:
        with self._connect() as conn:
            match = conn.execute("SELECT * FROM matches WHERE id = ?", (match_id,)).fetchone()
            players = conn.execute(
                "SELECT * FROM player_scores WHERE match_id = ? ORDER BY risk_score DESC",
                (match_id,),
            ).fetchall()
        return {
            "match": dict(match) if match else None,
            "players": [
                {
                    "name": p["player_name"],
                    "score": p["risk_score"],
                    "level": p["risk_level"],
                    "signals": json.loads(p["signals_json"]),
                }
                for p in players
            ],
        }
