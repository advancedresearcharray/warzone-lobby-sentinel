# Sentinel log exports

Redacted runtime logs exported from the production sentinel for offline review. **No site-specific LAN IPs, MACs, container IDs, or hostnames** — public IPv4 addresses are mapped to `198.18.0.0/15` documentation space; private addresses become `192.0.2.x`.

## Files

| File | Description |
|------|-------------|
| `journal-14d.txt` | `journalctl -u warzone-lobby-sentinel` — last 14 days (ISO timestamps) |
| `sessions/` | Recent lobby session metadata, peer snapshots, and `final.json` risk summaries |
| `manifest.json` | Export metadata (source, time, file list) |

## Regenerate

From a host with SSH to the sentinel appliance:

```bash
export PROXMOX_NODE=pve-primary.example
export SENTINEL_CTID=100   # container running warzone-lobby-sentinel

ssh root@${PROXMOX_NODE} "pct exec ${SENTINEL_CTID} -- journalctl -u warzone-lobby-sentinel --no-pager --since '14 days ago' -o short-iso" \
  > /tmp/sentinel-journal-raw.txt

python3 scripts/sanitize-logs.py /tmp/sentinel-journal-raw.txt logs/journal-14d.txt
```

Session archives: tarball under `/var/lib/warzone-sentinel/sessions/` on the appliance, then run `sanitize-logs.py` on each file.

## Notes

- Raw logs stay on the appliance (`journalctl`, `/var/lib/warzone-sentinel/`).
- `ai-learning.json` is **not** exported (large, may contain session-specific fingerprints).
- Search for `[vps-block]`, `[subnet-block]`, `peer-strict`, and `network_guard` in the journal for firewall automation trails.
