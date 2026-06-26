//! On-the-fly Firewalla/MoCA tuning to limit cheater network impact (kick floods, lag manipulation).

use crate::firewalla::FirewallaClient;
use crate::network_session::SessionRisk;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BufferMode {
    Stable,
    Light,
    Desync,
    Kick,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
enum FloodMode {
    Off,
    Shield,
    Defend,
    Harden,
}

pub struct NetworkGuard {
    buffer_mode: Mutex<BufferMode>,
    flood_mode: Mutex<FloodMode>,
    last_apply_at: Mutex<f64>,
    last_flood_at: Mutex<f64>,
    firewalla_tuned: Mutex<bool>,
    last_bytes_in: Mutex<u64>,
    last_packets: Mutex<u64>,
    kick_spikes: Mutex<u32>,
    /// User clicked "Stop defenses" — no auto-engage until session ends.
    defenses_disabled: Mutex<bool>,
    /// After manual release, skip auto-engage until this timestamp (avoid re-glitching).
    pause_until: Mutex<f64>,
}

impl NetworkGuard {
    pub fn new() -> Self {
        Self {
            buffer_mode: Mutex::new(BufferMode::Stable),
            flood_mode: Mutex::new(FloodMode::Off),
            last_apply_at: Mutex::new(0.0),
            last_flood_at: Mutex::new(0.0),
            firewalla_tuned: Mutex::new(false),
            last_bytes_in: Mutex::new(0),
            last_packets: Mutex::new(0),
            kick_spikes: Mutex::new(0),
            defenses_disabled: Mutex::new(false),
            pause_until: Mutex::new(0.0),
        }
    }

    pub async fn evaluate(&self, fw: &FirewallaClient, risk: &SessionRisk, snapshot: &Value) -> Value {
        let kick_spike = self.detect_kick_spike(snapshot);
        let now = now_secs();
        let user_blocked = *self.defenses_disabled.lock();
        let paused = now < *self.pause_until.lock() || user_blocked;
        let in_match = risk.phase == "in-match";

        let (target_buffer, target_flood) = if paused {
            (BufferMode::Stable, FloodMode::Off)
        } else if in_match {
            // In-match: size-aware packet shield only — no buffers or heavy rate limits.
            (BufferMode::Stable, target_in_match_shield(risk, snapshot, kick_spike))
        } else {
            (
                target_buffer_mode(risk, snapshot, kick_spike),
                target_flood_mode(risk, snapshot, kick_spike),
            )
        };

        let gameplay_safe = in_match || paused;

        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();

        if target_buffer != BufferMode::Stable {
            let need = buffer != target_buffer
                || now - *self.last_apply_at.lock() > 90.0
                || kick_spike;
            if need {
                if let Ok(msg) = self.apply_buffer(fw, target_buffer).await {
                    tracing::info!(
                        "[network-guard] buffer {:?} — {msg}",
                        target_buffer
                    );
                    *self.buffer_mode.lock() = target_buffer;
                    *self.last_apply_at.lock() = now;
                }
            }
        } else if buffer != BufferMode::Stable {
            if let Ok(msg) = self.restore_buffers(fw).await {
                tracing::info!("[network-guard] stable profile restored — {msg}");
                *self.buffer_mode.lock() = BufferMode::Stable;
                *self.last_apply_at.lock() = now;
            }
        }

        if target_flood != FloodMode::Off {
            let need = flood != target_flood
                || now - *self.last_flood_at.lock() > 90.0
                || kick_spike;
            if need {
                if let Ok(msg) = self.apply_flood(fw, target_flood, kick_spike, risk, snapshot).await {
                    tracing::info!("[network-guard] flood {:?} — {msg}", target_flood);
                    *self.flood_mode.lock() = target_flood;
                    *self.last_flood_at.lock() = now;
                }
            }
        } else if flood != FloodMode::Off {
            if let Ok(msg) = self.relax_flood_guard(fw).await {
                tracing::info!("[network-guard] flood guard relaxed — {msg}");
                *self.flood_mode.lock() = FloodMode::Off;
                *self.last_flood_at.lock() = now;
            }
        }

        self.status_json(risk, snapshot, kick_spike, paused || user_blocked, gameplay_safe)
    }

    fn detect_kick_spike(&self, snapshot: &Value) -> bool {
        let bytes_in = snapshot
            .pointer("/sample/bytesIn")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let packets = snapshot
            .pointer("/sample/packets")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let window = snapshot
            .pointer("/sample/windowSec")
            .and_then(|v| v.as_f64())
            .unwrap_or(3.0)
            .max(0.5);
        let mbps = (bytes_in as f64 * 8.0) / window / 1_000_000.0;

        let prev_bytes = *self.last_bytes_in.lock();
        let prev_packets = *self.last_packets.lock();
        *self.last_bytes_in.lock() = bytes_in;
        *self.last_packets.lock() = packets;

        let spike = (bytes_in > 0 && prev_bytes > 0 && bytes_in > prev_bytes * 5 && mbps > 30.0)
            || mbps > 85.0
            || (packets > 900 && mbps > 20.0)
            || (packets > 0 && prev_packets > 150 && packets > prev_packets * 4 && mbps > 15.0);

        if spike {
            *self.kick_spikes.lock() += 1;
        }
        spike
    }

    pub fn status_json(
        &self,
        risk: &SessionRisk,
        snapshot: &Value,
        kick_spike: bool,
        paused: bool,
        gameplay_safe: bool,
    ) -> Value {
        let conns = snapshot
            .pointer("/connections/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();
        let in_match = risk.phase == "in-match";
        let non_game_drop = has_non_game_traffic(risk, snapshot);
        let peer_attack = has_peer_attack_signal(risk);
        let suspicious_peers = suspicious_peer_ips(risk);

        json!({
            "mode": match buffer {
                BufferMode::Stable => "stable",
                BufferMode::Light => "light",
                BufferMode::Desync => "desync",
                BufferMode::Kick => "kick",
            },
            "engage": flood != FloodMode::Off || (!in_match && buffer != BufferMode::Stable),
            "defense_active": flood != FloodMode::Off || (!in_match && buffer != BufferMode::Stable),
            "kick_spike": kick_spike,
            "kick_spikes_session": *self.kick_spikes.lock(),
            "paused": paused,
            "monitor_only_in_match": gameplay_safe && risk.phase == "in-match",
            "pause_remaining_sec": if paused && *self.pause_until.lock() > now_secs() {
                (*self.pause_until.lock() - now_secs()).max(0.0) as u64
            } else {
                0
            },
            "flood_guard": {
                "active": flood != FloodMode::Off,
                "level": match flood {
                    FloodMode::Off => "off",
                    FloodMode::Shield => "shield",
                    FloodMode::Defend => "defend",
                    FloodMode::Harden => "harden",
                },
                "engage": flood != FloodMode::Off,
                "connections": conns,
                "description": match flood {
                    FloodMode::Shield if peer_attack => {
                        "Peer probe shield — drops tiny floods from suspicious player/VPS peers"
                    }
                    FloodMode::Shield if non_game_drop => {
                        "Packet shield + non-game port drop — only Xbox game ports allowed inbound"
                    }
                    FloodMode::Shield => {
                        "Tiny-packet shield (≤79B dropped) — normal game traffic unchanged"
                    }
                    FloodMode::Harden => "Aggressive per-source limits on game ports — kick attack mitigation",
                    FloodMode::Defend => "Per-source rate limits on Xbox/Warzone ports",
                    FloodMode::Off => "Inactive",
                },
            },
            "mitigation": if in_match && flood == FloodMode::Shield {
                if peer_attack {
                    "In-match: peer probe shield — blocking tiny packets from suspicious peers".into()
                } else if non_game_drop {
                    "In-match: packet shield — non-game inbound dropped, game ports only".into()
                } else {
                    "In-match: packet shield — blocks tiny flood packets, aim traffic untouched".into()
                }
            } else if gameplay_safe && in_match {
                "In-match: detection only — network tuning disabled to protect aim/hit reg".into()
            } else if paused {
                "Defenses paused — monitoring only".into()
            } else {
                mitigation_summary(buffer, flood, kick_spike, non_game_drop, peer_attack)
            },
            "packet_shield": {
                "active": flood == FloodMode::Shield,
                "non_game_drop": non_game_drop,
                "peer_attack": peer_attack,
                "suspicious_peers": suspicious_peers,
                "tiny_max_bytes": 79,
                "description": if peer_attack {
                    "Drops tiny inbound probes from flagged game-peer hosts (often VPS/Vultr)"
                } else if non_game_drop {
                    "Drops inbound traffic not on Xbox game ports when non-game hosts detected"
                } else {
                    "Drops inbound UDP/TCP ≤79 bytes (kick probes); normal Warzone packets pass"
                },
            },
            "xbox_ip": std::env::var("WZ_XBOX_IP").unwrap_or_else(|_| "192.168.167.65".into()),
            "actions": {
                "buffer_profile": "gaming-buffer-tune.sh apply desync|kick|max",
                "moca_qos": "gaming-moca-tune.sh (DSCP EF on game ports)",
                "firewalla_cpu": "gaming-firewalla-tune.sh apply",
                "flood_guard": "gaming-flood-guard.sh defend|harden|relax",
                "packet_shield": "gaming-packet-shield.sh shield|strict|relax",
            },
        })
    }

    async fn apply_flood(
        &self,
        fw: &FirewallaClient,
        mode: FloodMode,
        kick_spike: bool,
        risk: &SessionRisk,
        snapshot: &Value,
    ) -> Result<String, String> {
        match mode {
            FloodMode::Shield => {
                let level = shield_level(risk, snapshot, kick_spike);
                let peer_ips = suspicious_peer_ips(risk);
                let mut args: Vec<String> = vec!["shield".into(), level.to_string()];
                args.extend(peer_ips);
                let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
                fw.run_script("gaming-packet-shield.sh", &arg_refs, true)
                    .await
                    .map(|out| out.lines().last().unwrap_or("packet shield active").into())
            }
            FloodMode::Defend | FloodMode::Harden => {
                let _ = fw.run_script("gaming-packet-shield.sh", &["relax"], true).await;
                let arg = if mode == FloodMode::Harden { "harden" } else { "defend" };
                fw.run_script("gaming-flood-guard.sh", &[arg], true)
                    .await
                    .map(|out| out.lines().last().unwrap_or(arg).into())
            }
            FloodMode::Off => self.relax_all(fw).await,
        }
    }

    async fn relax_flood_guard(&self, fw: &FirewallaClient) -> Result<String, String> {
        self.relax_all(fw).await
    }

    async fn relax_all(&self, fw: &FirewallaClient) -> Result<String, String> {
        let _ = fw.run_script("gaming-packet-shield.sh", &["relax"], true).await;
        fw.run_script("gaming-flood-guard.sh", &["relax"], true)
            .await
            .map(|out| out.lines().last().unwrap_or("guards relaxed").into())
    }

    async fn apply_buffer(&self, fw: &FirewallaClient, mode: BufferMode) -> Result<String, String> {
        let ip = fw.xbox_ip();
        let profile = match mode {
            BufferMode::Stable => "normal",
            BufferMode::Light => "light",
            BufferMode::Desync => "desync",
            BufferMode::Kick => "kick",
        };
        let buf = fw
            .run_script("gaming-buffer-tune.sh", &["apply", profile, &ip], true)
            .await?;
        if matches!(mode, BufferMode::Desync | BufferMode::Kick) && !*self.firewalla_tuned.lock() {
            let _ = fw
                .run_script("gaming-firewalla-tune.sh", &["apply", &ip], true)
                .await;
            *self.firewalla_tuned.lock() = true;
        }
        if matches!(mode, BufferMode::Desync | BufferMode::Kick) {
            let _ = fw.run_script("gaming-moca-tune.sh", &["apply"], true).await;
        }
        Ok(buf.lines().next().unwrap_or("buffer applied").into())
    }

    async fn restore_buffers(&self, fw: &FirewallaClient) -> Result<String, String> {
        let _ = fw.run_script("gaming-moca-tune.sh", &["relax"], true).await;
        fw.run_script("gaming-buffer-tune.sh", &["off"], true)
            .await
            .map(|out| out.lines().next().unwrap_or("buffers restored").into())
    }

    pub fn current_status(&self) -> Value {
        let user_blocked = *self.defenses_disabled.lock();
        let paused = now_secs() < *self.pause_until.lock() || user_blocked;
        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();
        json!({
            "mode": match buffer {
                BufferMode::Stable => "stable",
                BufferMode::Light => "light",
                BufferMode::Desync => "desync",
                BufferMode::Kick => "kick",
            },
            "engage": buffer != BufferMode::Stable || flood != FloodMode::Off,
            "defense_active": buffer != BufferMode::Stable || flood != FloodMode::Off,
            "paused": paused,
            "pause_remaining_sec": if paused {
                (*self.pause_until.lock() - now_secs()).max(0.0) as u64
            } else {
                0
            },
            "flood_guard": {
                "active": flood != FloodMode::Off,
                "level": match flood {
                    FloodMode::Off => "off",
                    FloodMode::Shield => "shield",
                    FloodMode::Defend => "defend",
                    FloodMode::Harden => "harden",
                },
            },
            "mitigation": if paused {
                "Defenses paused — monitoring only".to_string()
            } else {
                mitigation_summary(buffer, flood, false, false, false)
            },
        })
    }

    pub fn clear_session_block(&self) {
        *self.defenses_disabled.lock() = false;
        *self.pause_until.lock() = 0.0;
    }

    pub async fn release_if_engaged(&self, fw: &FirewallaClient) -> bool {
        self.clear_session_block();
        self.release_now(fw).await
    }

    /// User-triggered: tear down defenses and block auto-engage for this session.
    pub async fn release_and_pause(&self, fw: &FirewallaClient, _pause_sec: f64) -> bool {
        *self.defenses_disabled.lock() = true;
        *self.pause_until.lock() = now_secs() + 86400.0;
        self.release_now(fw).await
    }

    pub async fn release_now(&self, fw: &FirewallaClient) -> bool {
        let mut released = false;
        let had_buffer = *self.buffer_mode.lock() != BufferMode::Stable;
        let had_flood = *self.flood_mode.lock() != FloodMode::Off;
        match self.restore_buffers(fw).await {
            Ok(msg) => {
                if had_buffer {
                    tracing::info!("[network-guard] stable profile restored — {msg}");
                }
                *self.buffer_mode.lock() = BufferMode::Stable;
                *self.last_apply_at.lock() = now_secs();
                released = true;
            }
            Err(e) => tracing::warn!("[network-guard] buffer release failed: {e}"),
        }
        match self.relax_flood_guard(fw).await {
            Ok(msg) => {
                if had_flood {
                    tracing::info!("[network-guard] flood guard relaxed — {msg}");
                }
                *self.flood_mode.lock() = FloodMode::Off;
                *self.last_flood_at.lock() = now_secs();
                released = true;
            }
            Err(e) => tracing::warn!("[network-guard] flood relax failed: {e}"),
        }
        *self.kick_spikes.lock() = 0;
        *self.last_bytes_in.lock() = 0;
        *self.last_packets.lock() = 0;
        released
    }
}

fn mitigation_summary(
    buffer: BufferMode,
    flood: FloodMode,
    kick_spike: bool,
    non_game_drop: bool,
    peer_attack: bool,
) -> String {
    let mut parts = Vec::new();
    match buffer {
        BufferMode::Light => parts.push("light buffers"),
        BufferMode::Kick => parts.push("max buffers + MoCA QoS"),
        BufferMode::Desync => parts.push("desync buffers + MoCA QoS"),
        BufferMode::Stable => {}
    }
    match flood {
        FloodMode::Shield if peer_attack => parts.push("peer probe shield (VPS/tiny floods)"),
        FloodMode::Shield if non_game_drop => parts.push("packet shield + non-game port drop"),
        FloodMode::Shield => parts.push("tiny-packet shield (≤79B)"),
        FloodMode::Harden => parts.push("hardened flood guard on game ports"),
        FloodMode::Defend => parts.push("flood guard per-source limits"),
        FloodMode::Off => {}
    }
    if kick_spike {
        parts.push("kick spike detected — escalated defense");
    }
    if parts.is_empty() {
        "Monitoring — defenses idle".into()
    } else {
        format!("Active: {}", parts.join(", "))
    }
}

fn is_gaming_phase(phase: &str) -> bool {
    phase == "in-match" || phase == "matchmaking"
}

fn cheater_label(risk: &SessionRisk) -> &str {
    risk.cheater_lobby
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn has_attack_signal(risk: &SessionRisk) -> bool {
    risk.signals.iter().any(|(k, v)| {
        matches!(
            k.as_str(),
            "inbound_flood"
                | "inbound_attack"
                | "packet_storm"
                | "tiny_packet_flood"
                | "packet_cheat"
                | "inbound_elevated"
                | "unknown_inbound"
                | "unknown_inbound_fanout"
                | "unknown_inbound_packets"
                | "peer_tiny_flood"
                | "peer_micro_burst"
                | "suspicious_peer"
        ) && *v >= 0.35
    })
}

fn has_peer_attack_signal(risk: &SessionRisk) -> bool {
    risk.signals.iter().any(|(k, v)| {
        matches!(
            k.as_str(),
            "peer_tiny_flood" | "peer_micro_burst" | "suspicious_peer"
        ) && *v >= 0.25
    })
}

fn suspicious_peer_ips(risk: &SessionRisk) -> Vec<String> {
    risk.packets
        .pointer("/metrics/suspicious_peers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            let mut ips: Vec<String> = arr
                .iter()
                .filter_map(|p| p.get("ip").and_then(|v| v.as_str()).map(String::from))
                .collect();
            ips.sort();
            ips.dedup();
            ips
        })
        .unwrap_or_default()
}

fn shield_level(risk: &SessionRisk, snapshot: &Value, kick_spike: bool) -> &'static str {
    if has_peer_attack_signal(risk) {
        return "peer-strict";
    }
    if kick_spike || has_non_game_traffic(risk, snapshot) {
        return "strict";
    }
    "normal"
}

fn has_non_game_traffic(risk: &SessionRisk, snapshot: &Value) -> bool {
    if risk.signals.iter().any(|(k, v)| {
        matches!(
            k.as_str(),
            "unknown_inbound" | "unknown_inbound_fanout" | "unknown_inbound_packets"
        ) && *v >= 0.35
    }) {
        return true;
    }

    let unknown = snapshot
        .pointer("/packetCapture/metrics/unknown_inbound_packets")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let game = snapshot
        .pointer("/packetCapture/metrics/game_inbound_packets")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    unknown >= 10 && unknown > game
}

fn target_in_match_shield(risk: &SessionRisk, snapshot: &Value, kick_spike: bool) -> FloodMode {
    if kick_spike
        || has_attack_signal(risk)
        || has_peer_attack_signal(risk)
        || has_non_game_traffic(risk, snapshot)
    {
        return FloodMode::Shield;
    }
    let label = cheater_label(risk);
    if matches!(label, "LIKELY" | "POSSIBLE" | "USER_BAD") {
        return FloodMode::Shield;
    }
    if risk
        .learning
        .pointer("/active_session/confirmed_bad")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return FloodMode::Shield;
    }
    let tiny_ratio = snapshot
        .pointer("/packetCapture/stats/tinyInbound")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let inbound = snapshot
        .pointer("/packetCapture/stats/inbound")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if inbound >= 5.0 && tiny_ratio / inbound >= 0.25 {
        return FloodMode::Shield;
    }
    FloodMode::Off
}

fn target_flood_mode(risk: &SessionRisk, snapshot: &Value, kick_spike: bool) -> FloodMode {
    if risk.phase == "in-match" || !is_gaming_phase(&risk.phase) {
        return FloodMode::Off;
    }

    let label = cheater_label(risk);
    if kick_spike && (has_attack_signal(risk) || matches!(label, "USER_BAD")) {
        return FloodMode::Harden;
    }
    if kick_spike || has_attack_signal(risk) || has_non_game_traffic(risk, snapshot) {
        return FloodMode::Shield;
    }
    if matches!(label, "LIKELY" | "USER_BAD" | "POSSIBLE") {
        return FloodMode::Shield;
    }

    let conns = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if conns >= 70 {
        return FloodMode::Shield;
    }

    FloodMode::Off
}

fn target_buffer_mode(risk: &SessionRisk, _snapshot: &Value, kick_spike: bool) -> BufferMode {
    if risk.phase == "in-match" || !is_gaming_phase(&risk.phase) {
        return BufferMode::Stable;
    }

    if kick_spike {
        return BufferMode::Light;
    }

    let label = cheater_label(risk);
    if matches!(label, "LIKELY" | "USER_BAD" | "POSSIBLE") {
        return BufferMode::Light;
    }

    BufferMode::Stable
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

static GUARD: OnceLock<NetworkGuard> = OnceLock::new();

pub fn guard() -> &'static NetworkGuard {
    GUARD.get_or_init(NetworkGuard::new)
}

// Legacy helpers for tests / external use
pub fn should_engage_flood(risk: &SessionRisk, snapshot: &Value) -> bool {
    target_flood_mode(risk, snapshot, false) != FloodMode::Off
}

pub fn should_engage_desync(risk: &SessionRisk, snapshot: &Value) -> bool {
    target_buffer_mode(risk, snapshot, false) != BufferMode::Stable
}
