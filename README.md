# Warzone Lobby Sentinel

Autonomous **Xbox Warzone** lobby integrity agent — cheat/VPS peer detection, packet-shield coordination, and tight integration with [array-firewall](https://github.com/advancedresearcharray/array-firewall).

Runs as a **Rust** service (Python fallback) on the same host as array-firewall or on a dedicated LXC. Polls gaming telemetry, scores lobby risk, and drives firewall actions (peer blocklist, subnet blocks, upload/download assist, network guard buffers) with **no manual input during play**.

## What it does

| Area | Behavior |
|------|----------|
| **Lobby risk** | Packet/session scoring, cheater-lobby fingerprints, AI learning baselines |
| **Peer tracking** | Inbound identical-peer mesh detection (VPS probe patterns) |
| **Firewall sync** | Calls array-firewall API — block peers, block /24 subnets, sync packet shield |
| **Network guard** | In-match buffer modes (desync/kick), flood guard, MoCA tuning hooks |
| **Notifications** | ntfy push + optional Xbox Live inbox (cooldown-gated) |
| **Dashboard** | Built-in UI at `:8098/v1/dashboard` (embeddable in array-firewall Gaming Ops) |

## Deployment reference

Set site-specific values in `/etc/default/warzone-lobby-sentinel` or a local secrets file — **do not commit them**.

| Variable | Purpose |
|----------|---------|
| `PROXMOX_NODE` | Proxmox host SSH target (for `deploy-to-lxc.sh`) |
| `WZ_SENTINEL_CTID` | LXC ID when deploying to a container |
| `WZ_ARRAY_FW_API_URL` | array-firewall API base (co-hosted: `http://127.0.0.1:8090`) |
| `WZ_ARRAY_FW_API_TOKEN_FILE` | Bearer token file for the API |
| `WZ_XBOX_IP` | Console IP on the gaming LAN |
| `WZ_INGEST_PORT` | Sentinel HTTP port (default `8098`) |

| Item | Example |
|------|---------|
| array-firewall API | `http://${ARRAY_FW_IP}:8090` |
| Sentinel dashboard | `http://${ARRAY_FW_IP}:8098/v1/dashboard` |
| Health | `http://${ARRAY_FW_IP}:8098/health` |

## Quick start

### Co-hosted on array-firewall (recommended)

```bash
# On the firewall appliance after array-firewall is installed
cd /opt/warzone-lobby-sentinel
cp warzone-lobby-sentinel.env.example /etc/default/warzone-lobby-sentinel
# Edit: WZ_ARRAY_FW_API_URL, WZ_XBOX_IP, token paths
./install-in-ct.sh
```

### Remote Proxmox LXC

```bash
export PROXMOX_NODE=pve-primary.example
export WZ_SENTINEL_CTID=101
export WZ_ARRAY_FW_API_URL=http://192.0.2.10:8090   # RFC 5737 example only

./deploy-to-lxc.sh
```

Or use `./deploy-proxmox.sh` to provision a new container and deploy in one step.

### Build Rust binary locally

```bash
cd rust && cargo build --release
install -m755 target/release/warzone-sentinel ../bin/warzone-sentinel
```

## Configuration

Copy `warzone-lobby-sentinel.env.example` → `/etc/default/warzone-lobby-sentinel`.

Key settings:

- **`WZ_ARRAY_FW_API_URL`** / **`WZ_ARRAY_FW_API_TOKEN_FILE`** — firewall API access
- **`WZ_XBOX_IP`** — console to protect and tune QoS for
- **`WZ_POLL_INTERVAL_SEC`** — active poll interval (idle interval separate)
- **`WZ_NTFY_*`** — phone alerts while in match
- **`WZ_XBOX_NOTIFY_*`** — optional Xbox Live self-messages

systemd unit: `warzone-lobby-sentinel.service` → `tools/run_automated.sh` → `bin/warzone-sentinel`.

## API (HTTP)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/v1/status` | Full sentinel + peer + network guard snapshot |
| GET | `/v1/dashboard` | HTML dashboard |
| POST | `/v1/peers/shield` | Apply peer-strict shield via firewall |
| POST | `/v1/peers/clear` | Clear peer tracker table |

Firewall integration is implemented in `rust/src/firewalla.rs` (peers, subnets, shield, QoS boosts, network guard).

## Repository layout

```
rust/                 # Rust core (primary runtime)
sentinel/             # Python fallback + helpers
tools/                # run_automated.sh, setup scripts
data/                 # Static role hints (server-roles.json)
samples/              # Overwolf bridge sample
install-in-ct.sh      # In-container install
deploy-to-lxc.sh      # Push bundle to existing LXC
deploy-proxmox.sh     # Provision + deploy on Proxmox
```

## Related projects

- [array-firewall](https://github.com/advancedresearcharray/array-firewall) — gateway, packet shield, peer/subnet blocklists, Gaming Ops dashboard

## License

See repository defaults; treat gaming telemetry and API tokens as sensitive operational data.
