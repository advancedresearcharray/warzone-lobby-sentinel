#!/usr/bin/env python3
"""Redact site-specific and PII-like network identifiers from sentinel log exports."""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

# Private / site ranges → RFC 5737 documentation space
_PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_HOST = re.compile(
    r"\b(?:thirtynince|node9|opencase|pve-primary|pve-node-[ab]|array-firewall)\b",
    re.I,
)
_CT = re.compile(r"\bCT(?:ID)?\s*[=:]?\s*\d{3,4}\b", re.I)
_PCT = re.compile(r"\bpct\s+(?:push|exec)\s+\d{3,4}\b", re.I)

_pub_map: dict[str, str] = {}
_pub_seq = 0


def _map_ip(ip: str) -> str:
    global _pub_seq
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if any(addr in net for net in _PRIVATE):
        return "192.0.2.10" if str(addr).endswith(".1") or str(addr).endswith(".3") else "192.0.2.50"
    if ip not in _pub_map:
        _pub_seq += 1
        _pub_map[ip] = f"198.18.0.{(_pub_seq % 250) + 1}"
    return _pub_map[ip]


def redact(text: str) -> str:
    text = _HOST.sub("pve-host", text)
    text = _CT.sub("CT###", text)
    text = _PCT.sub("pct exec ###", text)
    text = _MAC.sub("aa:bb:cc:dd:ee:ff", text)
    text = _IPV4.sub(lambda m: _map_ip(m.group(0)), text)
    return text


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <input> <output>", file=sys.stderr)
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(redact(src.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
