"""Unified alert delivery — Xbox (best effort) + phone push (reliable)."""

from __future__ import annotations

from sentinel import push_notify, xbox_notify


def notify_session_alert(
    level: str,
    score: float,
    phase: str,
    game: str,
    recommendation: str,
    anomalies: list[str],
    *,
    cheater_lobby: dict | None = None,
    force: bool = False,
) -> bool:
    cl = cheater_lobby or {}
    label = cl.get("label", level)
    title = f"Warzone — Cheater lobby {label}"
    lines = [recommendation]
    if cl.get("reasons"):
        lines.extend(cl["reasons"][:3])
    elif anomalies:
        lines.extend(anomalies[:3])
    body = "\n".join(lines)

    phone_ok = push_notify.notify(title, body)
    xbox_ok = xbox_notify.notify_session_alert(
        level,
        score,
        phase,
        game,
        recommendation,
        anomalies,
        force=force,
    )
    return phone_ok or xbox_ok


def status() -> dict:
    return {
        "phone_push": push_notify.configured(),
        "phone_subscribe_url": push_notify.subscribe_url() if push_notify.configured() else None,
        "xbox_live": xbox_notify.configured(),
    }
