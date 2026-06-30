"""Classify Firewalla snapshot flows — raw API lacks roleId; gaming monitor would add this."""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

_ROLES: dict | None = None
_PTR_CACHE: dict[str, str] = {}


def _load_roles() -> dict:
    global _ROLES
    if _ROLES is not None:
        return _ROLES
    for path in (
        Path("/opt/warzone-lobby-sentinel/data/server-roles.json"),
        Path(__file__).resolve().parents[1] / "data" / "server-roles.json",
    ):
        if path.is_file():
            _ROLES = json.loads(path.read_text())
            return _ROLES
    _ROLES = {"rules": []}
    return _ROLES


def _ip_from_remote(remote: str) -> str:
    remote = (remote or "").strip()
    if not remote:
        return ""
    if remote.count(".") == 3 and ":" in remote:
        return remote.rsplit(":", 1)[0]
    if remote.count(".") == 3:
        return remote
    return ""


def _port_from_remote(remote: str) -> int | None:
    remote = (remote or "").strip()
    if remote.count(".") == 3 and ":" in remote:
        tail = remote.rsplit(":", 1)[-1]
        return int(tail) if tail.isdigit() else None
    return None


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


def _classify_local_ip(ip: str) -> str | None:
    if not ip or not _is_private_ip(ip):
        return None
    if ip == "192.0.2.1":
        return "lan-gateway"
    return "lan-local"


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _classify_cidr(ip: str) -> str | None:
    if not ip:
        return None
    for rule in _load_roles()["rules"]:
        for cidr in rule.get("cidrs") or []:
            if _ip_in_cidr(ip, cidr):
                return rule["id"]
    return None


@lru_cache(maxsize=512)
def _reverse_ptr(ip: str) -> str:
    try:
        out = subprocess.check_output(
            ["dig", "+short", "+time=1", "+tries=1", "-x", ip, "@1.1.1.1"],
            text=True,
            timeout=3,
        )
        line = out.splitlines()[0].strip().rstrip(".").lower() if out.strip() else ""
        return line
    except (subprocess.SubprocessError, OSError, IndexError):
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return (host or "").lower()
        except OSError:
            return ""


def classify_host(hostname: str) -> str:
    host = (hostname or "").lower().strip()
    if not host:
        return "unknown"
    for rule in _load_roles()["rules"]:
        if any(x in host for x in rule.get("matchExclude", [])):
            continue
        if any(p in host for p in rule["match"]):
            return rule["id"]
    return "unknown"


def _is_vps_provider_host(ip: str, hostname_hint: str = "") -> bool:
    if not ip:
        return False
    hint = (hostname_hint or "").lower()
    if any(x in hint for x in ("vultr", "choopa", "linode", "digitalocean", "your-server")):
        return True
    if ip.startswith(("45.76.", "45.77.", "66.42.", "96.30.", "108.61.", "149.28.", "155.138.", "207.148.", "140.82.", "144.202.")):
        return True
    if hostname_hint and classify_host(hostname_hint) == "vps-probe-host":
        return True
    return False


def _classify_udp_game_role(ip: str, port: int | None, proto: str) -> str | None:
    if not ip or _is_private_ip(ip):
        return None
    if (proto or "").lower() != "udp":
        return None
    if port in (3074, 3075):
        return "dedicated-server"
    if port is not None and port >= 1024:
        return "p2p-mesh"
    return None


def _peer_fallback(ip: str, port: int | None, proto: str) -> str | None:
    return _classify_udp_game_role(ip, port, proto)


def _is_inbound_player_peer_port(port: int | None, proto: str) -> bool:
    if (proto or "").lower() != "udp":
        return False
    if port in (3074, 3075):
        return True
    return port is not None and port >= 1024


def classify_inbound_endpoint(
    remote: str = "",
    hostname_hint: str = "",
    port: int | None = None,
    proto: str = "",
) -> str:
    ip = _ip_from_remote(remote)
    if port is None:
        port = _port_from_remote(remote)

    if ip:
        local = _classify_local_ip(ip)
        if local:
            return local
        role = _classify_cidr(ip)
        if role:
            return role

    hint = (hostname_hint or "").strip()
    if hint and not _ip_from_remote(hint):
        role = classify_host(hint)
        if role not in {"unknown", "vps-probe-host"}:
            return role

    if _is_inbound_player_peer_port(port, proto):
        mesh = _classify_udp_game_role(ip, port, proto)
        if mesh:
            return mesh

    return classify_endpoint(remote, hostname_hint, port, proto)


def classify_endpoint(
    remote: str = "",
    hostname_hint: str = "",
    port: int | None = None,
    proto: str = "",
) -> str:
    ip = _ip_from_remote(remote)
    if port is None:
        port = _port_from_remote(remote)

    if ip:
        local = _classify_local_ip(ip)
        if local:
            return local
        role = _classify_cidr(ip)
        if role:
            return role

    hint = (hostname_hint or "").strip()
    if hint and not _ip_from_remote(hint):
        role = classify_host(hint)
        if role != "unknown":
            return role

    if ip:
        ptr = _PTR_CACHE.get(ip) or _reverse_ptr(ip)
        if ptr:
            _PTR_CACHE[ip] = ptr
            role = classify_host(ptr)
            if role != "unknown":
                return role

    peer = _peer_fallback(ip, port, proto)
    if peer:
        return peer

    if hint:
        role = classify_host(hint)
        if role != "unknown":
            return role

    if ip:
        return classify_host(ip)
    return classify_host(remote)


def classify_value(item: dict[str, Any]) -> str:
    rid = item.get("roleId")
    if rid:
        return str(rid)
    remote = str(item.get("remote") or item.get("ip") or "")
    host = str(item.get("hostname") or item.get("label") or item.get("host") or "")
    port_raw = item.get("port") or item.get("remotePort")
    port = int(port_raw) if str(port_raw or "").isdigit() else _port_from_remote(remote)
    proto = str(item.get("proto") or "")
    return classify_endpoint(remote, host, port, proto)


def _flow_hosts(snapshot: dict) -> list[str]:
    hosts: list[str] = []
    for key in ("recentFlows", "recent_flows"):
        for flow in snapshot.get(key) or []:
            remote = str(flow.get("remote") or "")
            host = flow.get("hostname") or flow.get("host") or flow.get("label") or ""
            if host and not _ip_from_remote(str(host)):
                hosts.append(str(host))
            elif remote:
                role = classify_endpoint(remote, str(host))
                if role != "unknown":
                    hosts.append(f"{remote} ({role})")
    for bucket in snapshot.get("dnsDestinations") or snapshot.get("dns_destinations") or []:
        h = bucket.get("hostname") or bucket.get("label") or ""
        if h:
            hosts.append(h)
    for item in snapshot.get("connections", {}).get("items", []):
        remote = str(item.get("remote") or item.get("ip") or "")
        host = item.get("hostname") or item.get("host") or item.get("label") or ""
        if host and not _ip_from_remote(str(host)):
            hosts.append(str(host))
        elif remote:
            role = classify_value(item)
            if role != "unknown":
                hosts.append(f"{remote} ({role})")
    return hosts


def enrich_snapshot(snapshot: dict) -> dict:
    """Return snapshot with roleCounts + inferred phase/game from netbot flow hostnames."""
    if not snapshot or snapshot.get("error"):
        return snapshot

    role_counts: dict[str, int] = {}
    classified: list[dict[str, Any]] = []
    for host in _flow_hosts(snapshot):
        if " (" in host and host.endswith(")"):
            rid = host.rsplit(" (", 1)[1][:-1]
        else:
            rid = classify_host(host)
        role_counts[rid] = role_counts.get(rid, 0) + 1
        if rid != "unknown":
            classified.append({"hostname": host, "roleId": rid})

    xbox_online = bool((snapshot.get("xbox") or {}).get("online"))
    conns = int(snapshot.get("connections", {}).get("count") or 0)

    game = "unknown"
    if role_counts.get("warzone-game") or role_counts.get("game-assets") or role_counts.get("telemetry") or role_counts.get("matchmaking") or role_counts.get("dedicated-server"):
        game = "warzone"

    phase = "idle"
    if role_counts.get("warzone-game") or role_counts.get("dedicated-server"):
        phase = "in-match"
    elif role_counts.get("matchmaking") or (role_counts.get("azure-qos", 0) >= 2 and conns >= 80):
        phase = "matchmaking"
    elif game == "warzone" and xbox_online and conns >= 20 and (
        role_counts.get("game-assets") or role_counts.get("telemetry")
    ):
        phase = "in-match"
    elif game == "warzone" and xbox_online and conns >= 22 and (
        role_counts.get("game-assets") or role_counts.get("matchmaking") or role_counts.get("telemetry", 0) >= 2
    ):
        phase = "matchmaking"
    elif xbox_online and conns >= 15:
        phase = "background"
    elif not xbox_online and conns == 0:
        phase = "idle"

    out = dict(snapshot)
    out["_enriched"] = {
        "roleCounts": role_counts,
        "classified": classified[:20],
        "phase": phase,
        "game": game,
    }
    return out
