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
    moca_qos_active: Mutex<bool>,
    last_moca_at: Mutex<f64>,
    wan_history: Mutex<Vec<f64>>,
    upload_boost_active: Mutex<bool>,
    last_upload_boost_at: Mutex<f64>,
    last_upload_warn_at: Mutex<f64>,
    last_rqd_buffer_at: Mutex<f64>,
    rqd_profile: Mutex<String>,
    cached_shaped_mbps: Mutex<f64>,
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
            moca_qos_active: Mutex::new(false),
            last_moca_at: Mutex::new(0.0),
            wan_history: Mutex::new(Vec::new()),
            upload_boost_active: Mutex::new(false),
            last_upload_boost_at: Mutex::new(0.0),
            last_upload_warn_at: Mutex::new(0.0),
            last_rqd_buffer_at: Mutex::new(0.0),
            rqd_profile: Mutex::new(String::new()),
            cached_shaped_mbps: Mutex::new(950.0),
        }
    }

    fn track_wan_latency(&self, snapshot: &Value) {
        if let Some(ms) = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()) {
            let mut h = self.wan_history.lock();
            h.push(ms);
            if h.len() > 24 {
                let drop = h.len() - 24;
                h.drain(0..drop);
            }
        }
    }

    fn wan_jitter_ms(&self) -> f64 {
        let h = self.wan_history.lock();
        if h.len() < 4 {
            return 0.0;
        }
        pstdev(&h[h.len().saturating_sub(8)..])
    }

    fn target_gaming_buffer(&self, phase: &str, kick_spike: bool) -> BufferMode {
        if !is_gaming_phase(phase) {
            return BufferMode::Stable;
        }
        if kick_spike {
            return BufferMode::Kick;
        }
        if phase == "in-match" {
            // Lowest Xbox CAKE RTT (3ms upload + 3ms download pipe).
            return BufferMode::Kick;
        }
        if self.wan_jitter_ms() >= 15.0 {
            return BufferMode::Kick;
        }
        // Matchmaking — tight 5ms Xbox buffers (never widen to light/15ms).
        BufferMode::Desync
    }

    pub async fn evaluate(&self, fw: &FirewallaClient, risk: &SessionRisk, snapshot: &Value) -> Value {
        self.track_wan_latency(snapshot);
        let game_kick = risk
            .game_state
            .get("recent_kick")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let kick_spike = game_kick || self.detect_kick_spike(snapshot);
        let now = now_secs();
        let user_blocked = *self.defenses_disabled.lock();
        let paused = now < *self.pause_until.lock() || user_blocked;
        let in_match = risk.phase == "in-match";
        let gaming = is_gaming_phase(&risk.phase);

        let (target_buffer, target_flood) = if paused {
            (BufferMode::Stable, FloodMode::Off)
        } else if in_match {
            (
                self.target_gaming_buffer(&risk.phase, kick_spike),
                target_in_match_shield(risk, snapshot, kick_spike),
            )
        } else if gaming {
            (
                self.target_gaming_buffer(&risk.phase, kick_spike),
                target_flood_mode(risk, snapshot, kick_spike),
            )
        } else {
            (
                target_buffer_mode(risk, snapshot, kick_spike),
                target_flood_mode(risk, snapshot, kick_spike),
            )
        };

        let gameplay_safe = in_match || paused;

        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();

        if gaming && !paused {
            let need = buffer != target_buffer
                || now - *self.last_apply_at.lock() > 90.0
                || kick_spike;
            if need {
                if let Ok(msg) = self.apply_buffer(fw, target_buffer).await {
                    tracing::info!(
                        "[network-guard] buffer {:?} (wan jitter {:.1}ms) — {msg}",
                        target_buffer,
                        self.wan_jitter_ms()
                    );
                    *self.buffer_mode.lock() = target_buffer;
                    *self.last_apply_at.lock() = now;
                }
            }
        } else if target_buffer != BufferMode::Stable {
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

        let target_moca = is_gaming_phase(&risk.phase) && !paused;
        let moca = *self.moca_qos_active.lock();
        if target_moca {
            let need = !moca || now - *self.last_moca_at.lock() > 90.0;
            if need {
                if let Ok(msg) = self.apply_moca_qos(fw).await {
                    tracing::info!("[network-guard] MoCA DSCP EF — {msg}");
                    *self.moca_qos_active.lock() = true;
                    *self.last_moca_at.lock() = now;
                }
            }
        } else if moca {
            if let Ok(msg) = self.relax_moca_qos(fw).await {
                tracing::info!("[network-guard] MoCA QoS relaxed — {msg}");
                *self.moca_qos_active.lock() = false;
                *self.last_moca_at.lock() = now;
            }
        }

        let target_upload_boost = gaming && !paused;
        let upload_active = *self.upload_boost_active.lock();
        if target_upload_boost {
            let need = !upload_active || now - *self.last_upload_boost_at.lock() > 90.0;
            if need {
                if let Ok(msg) = self.apply_upload_boost(fw).await {
                    tracing::info!("[network-guard] upload boost — {msg}");
                    *self.upload_boost_active.lock() = true;
                    *self.last_upload_boost_at.lock() = now;
                    if let Ok(st) = fw.upload_boost_status().await {
                        if let Some(m) = st
                            .pointer("/state/shaped_mbps")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                        {
                            *self.cached_shaped_mbps.lock() = m;
                        }
                    }
                }
            }
        } else if upload_active {
            if let Ok(msg) = self.relax_upload_boost(fw).await {
                tracing::info!("[network-guard] upload boost relaxed — {msg}");
                *self.upload_boost_active.lock() = false;
                *self.last_upload_boost_at.lock() = now;
            }
        }

        let queue_telemetry = if gaming && now - *self.last_upload_warn_at.lock() > 30.0 {
            fw.fetch_telemetry_queues().await.ok()
        } else {
            None
        };
        let (upload_pressure, upload_alerts, upload_mbps, shaped_mbps, util_pct) =
            self.upload_pressure(snapshot, queue_telemetry.as_ref());
        if upload_pressure {
            let warn_cooldown = 60.0;
            if now - *self.last_upload_warn_at.lock() >= warn_cooldown {
                for alert in &upload_alerts {
                    tracing::warn!("[upload-assist] {alert}");
                }
                *self.last_upload_warn_at.lock() = now;
            }
            let rqd_cooldown = 45.0;
            if gaming && !paused && now - *self.last_rqd_buffer_at.lock() >= rqd_cooldown {
                let sample = rqd_sample_from(snapshot, queue_telemetry.as_ref(), upload_mbps, util_pct, kick_spike, in_match);
                match self.apply_rqd_buffer(fw, &sample).await {
                    Ok((profile, msg)) => {
                        tracing::info!("[network-guard] RQD buffer {profile} — {msg}");
                        *self.rqd_profile.lock() = profile.clone();
                        *self.last_rqd_buffer_at.lock() = now;
                        let mode = buffer_mode_from_profile(&profile);
                        if mode != buffer {
                            *self.buffer_mode.lock() = mode;
                            *self.last_apply_at.lock() = now;
                        }
                    }
                    Err(e) => tracing::warn!("[network-guard] RQD buffer failed: {e}"),
                }
            }
        }
        if shaped_mbps > 0.0 {
            *self.cached_shaped_mbps.lock() = shaped_mbps;
        }

        self.status_json(
            risk,
            snapshot,
            kick_spike,
            paused || user_blocked,
            gameplay_safe,
            upload_pressure,
            &upload_alerts,
            upload_mbps,
            util_pct,
        )
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
        upload_pressure: bool,
        upload_alerts: &[String],
        upload_mbps: f64,
        util_pct: f64,
    ) -> Value {
        let conns = snapshot
            .pointer("/connections/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();
        let moca_qos = *self.moca_qos_active.lock();
        let upload_boost = *self.upload_boost_active.lock();
        let shaped_mbps = *self.cached_shaped_mbps.lock();
        let in_match = risk.phase == "in-match";
        let non_game_drop = has_non_game_traffic(risk, snapshot);
        let peer_attack = has_peer_attack_signal(risk);
        let suspicious_peers = suspicious_peer_ips(risk);

        let gaming = is_gaming_phase(&risk.phase);
        let buffer_active = gaming || buffer != BufferMode::Stable;
        let game_kick = risk
            .game_state
            .get("recent_kick")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        json!({
            "mode": match buffer {
                BufferMode::Stable => "gaming",
                BufferMode::Light => "light",
                BufferMode::Desync => "desync",
                BufferMode::Kick => "kick",
            },
            "wan_jitter_ms": (self.wan_jitter_ms() * 10.0).round() / 10.0,
            "engage": flood != FloodMode::Off || buffer_active,
            "defense_active": flood != FloodMode::Off || buffer_active,
            "kick_spike": kick_spike,
            "kick_source": if game_kick { "game_state" } else if kick_spike { "traffic" } else { "none" },
            "lobby_reputation_gate": lobby_reputation_gate(risk),
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
            "mitigation": if risk.phase == "matchmaking" && flood == FloodMode::Off {
                "Matchmaking: fast queue — defenses off until attack or bad lobby signals".into()
            } else if in_match && flood == FloodMode::Shield {
                "In-match: Warzone + Xbox Live allowlist only — all other inbound dropped".into()
            } else if flood == FloodMode::Shield && risk.phase == "matchmaking" {
                "Matchmaking: all inbound P2P blocked — Xbox Live / CoD service ports only".into()
            } else if gameplay_safe && in_match {
                "In-match: detection only — network tuning disabled to protect aim/hit reg".into()
            } else if paused {
                "Defenses paused — monitoring only".into()
            } else {
                mitigation_summary(buffer, flood, kick_spike, non_game_drop, peer_attack)
            },
            "packet_shield": {
                "active": flood == FloodMode::Shield,
                "console_mode": flood == FloodMode::Shield
                    && (risk.phase == "matchmaking" || risk.phase == "in-match"),
                "in_match_mode": flood == FloodMode::Shield && in_match,
                "non_game_drop": non_game_drop,
                "peer_attack": peer_attack,
                "suspicious_peers": suspicious_peers,
                "tiny_max_bytes": 79,
                "description": if flood == FloodMode::Shield && in_match {
                    "In-match — Warzone + Xbox Live CIDRs only; LAN + established; everything else dropped"
                } else if flood == FloodMode::Shield
                    && risk.phase == "matchmaking"
                {
                    "Matchmaking — all inbound P2P blocked; allowlisted service ports only"
                } else if peer_attack {
                    "Drops tiny inbound probes from flagged game-peer hosts (often VPS/Vultr)"
                } else if non_game_drop {
                    "Drops inbound traffic not on Xbox game ports when non-game hosts detected"
                } else {
                    "Drops inbound UDP/TCP ≤79 bytes (kick probes); normal Warzone packets pass"
                },
            },
            "xbox_ip": std::env::var("WZ_XBOX_IP").unwrap_or_else(|_| "192.168.167.65".into()),
            "path": {
                "type": "wired-moca",
                "label": std::env::var("WZ_XBOX_PATH_LABEL")
                    .unwrap_or_else(|_| "Wired · MoCA".into()),
            },
            "moca_qos": {
                "active": moca_qos,
                "dscp": if moca_qos { "ef" } else { "off" },
                "description": if moca_qos {
                    "DSCP EF on Xbox game ports — MoCA/QoS path priority during lobby/match"
                } else {
                    "Inactive — enables automatically in matchmaking or in-match"
                },
            },
            "upload_assist": {
                "active": upload_boost,
                "buffer_profile": match buffer {
                    BufferMode::Stable => "gaming",
                    BufferMode::Light => "light",
                    BufferMode::Desync => "desync",
                    BufferMode::Kick => "kick",
                },
                "in_match_desync": risk.phase == "in-match"
                    && matches!(buffer, BufferMode::Desync | BufferMode::Kick),
                "pressure": upload_pressure,
                "egress_mbps": (upload_mbps * 10.0).round() / 10.0,
                "shaped_mbps": shaped_mbps,
                "utilization_pct": (util_pct * 10.0).round() / 10.0,
                "alerts": upload_alerts,
                "rqd_profile": (*self.rqd_profile.lock()).clone(),
                "rqd_auto_on_pressure": true,
                "description": if upload_boost {
                    "Xbox HTB ceil raised to ~98% shaped upload — other tiers trimmed"
                } else if gaming {
                    "Upload boost pending — applies on next poll"
                } else {
                    "Inactive — enables in matchmaking or in-match"
                },
            },
            "actions": {
                "buffer_profile": "gaming-buffer-tune.sh apply gaming|light|desync|kick",
                "moca_qos": "gaming-moca-tune.sh (DSCP EF on game ports)",
                "firewalla_cpu": "gaming-firewalla-tune.sh apply",
                "flood_guard": "gaming-flood-guard.sh defend|harden|relax",
                "packet_shield": "gaming-packet-shield.sh shield|strict|relax",
                "upload_boost": "gaming-upload-boost.sh apply|relax",
            },
        })
    }

    fn upload_pressure(
        &self,
        snapshot: &Value,
        queues: Option<&Value>,
    ) -> (bool, Vec<String>, f64, f64, f64) {
        let mut alerts = Vec::new();
        let shaped = *self.cached_shaped_mbps.lock();
        let window = snapshot
            .pointer("/sample/windowSec")
            .and_then(|v| v.as_f64())
            .unwrap_or(3.0)
            .max(0.5);
        let upload_bytes = snapshot
            .pointer("/traffic/summary/xbox_upload_bytes")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                snapshot
                    .pointer("/traffic/metrics/xbox_upload_bytes")
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(0);
        let upload_mbps = if upload_bytes > 0 {
            (upload_bytes as f64 * 8.0) / window / 1_000_000.0
        } else {
            0.0
        };
        let util_pct = if shaped > 0.0 && upload_mbps > 0.0 {
            (upload_mbps / shaped) * 100.0
        } else {
            0.0
        };
        let mut pressure = false;
        if util_pct >= 80.0 {
            pressure = true;
            alerts.push(format!(
                "Xbox upload {:.0} Mbps — {:.0}% of shaped {:.0} Mbps ceiling",
                upload_mbps, util_pct, shaped
            ));
        }
        if let Some(q) = queues {
            if let Some(egress) = q.pointer("/queues/egress_upload") {
                let saturated = egress.get("saturated").and_then(|v| v.as_bool()).unwrap_or(false);
                let backlog = egress
                    .get("backlog_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let grade = egress
                    .get("buffer_grade")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if saturated || backlog > 65_536 || grade == "poor" {
                    pressure = true;
                    alerts.push(format!(
                        "Upload queue pressure — backlog {}B grade {}",
                        backlog, grade
                    ));
                }
            }
        }
        (pressure, alerts, upload_mbps, shaped, util_pct)
    }

    async fn apply_rqd_buffer(&self, fw: &FirewallaClient, sample: &Value) -> Result<(String, String), String> {
        let resp = fw.apply_rqd_buffer_profile(sample.clone()).await?;
        if resp.get("ok").and_then(|v| v.as_bool()) == Some(false) {
            return Err(resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("rqd buffer apply failed")
                .into());
        }
        let profile = resp
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or("gaming")
            .to_string();
        let msg = resp
            .pointer("/applied/stdout")
            .and_then(|v| v.as_str())
            .or_else(|| resp.get("stdout").and_then(|v| v.as_str()))
            .unwrap_or("rqd buffer applied")
            .to_string();
        Ok((profile, msg))
    }

    async fn apply_upload_boost(&self, fw: &FirewallaClient) -> Result<String, String> {
        fw.run_script("gaming-upload-boost.sh", &["apply"], true)
            .await
            .map(|out| out.lines().last().unwrap_or("upload boost active").into())
    }

    async fn relax_upload_boost(&self, fw: &FirewallaClient) -> Result<String, String> {
        fw.run_script("gaming-upload-boost.sh", &["relax"], true)
            .await
            .map(|out| out.lines().last().unwrap_or("upload boost relaxed").into())
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
            BufferMode::Stable => "gaming",
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
        Ok(buf.lines().next().unwrap_or("buffer applied").into())
    }

    async fn apply_moca_qos(&self, fw: &FirewallaClient) -> Result<String, String> {
        fw.run_script("gaming-moca-tune.sh", &["apply"], true)
            .await
            .map(|out| out.lines().last().unwrap_or("moca-qos=ef").into())
    }

    async fn relax_moca_qos(&self, fw: &FirewallaClient) -> Result<String, String> {
        fw.run_script("gaming-moca-tune.sh", &["relax"], true)
            .await
            .map(|out| out.lines().last().unwrap_or("moca-qos=relaxed").into())
    }

    async fn restore_buffers(&self, fw: &FirewallaClient) -> Result<String, String> {
        let _ = self.relax_moca_qos(fw).await;
        *self.moca_qos_active.lock() = false;
        if *self.upload_boost_active.lock() {
            let _ = self.relax_upload_boost(fw).await;
            *self.upload_boost_active.lock() = false;
        }
        fw.run_script("gaming-buffer-tune.sh", &["off"], true)
            .await
            .map(|out| out.lines().next().unwrap_or("buffers restored").into())
    }

    pub fn current_status(&self) -> Value {
        let user_blocked = *self.defenses_disabled.lock();
        let paused = now_secs() < *self.pause_until.lock() || user_blocked;
        let buffer = *self.buffer_mode.lock();
        let flood = *self.flood_mode.lock();
        let moca_qos = *self.moca_qos_active.lock();
        json!({
            "mode": match buffer {
                BufferMode::Stable => "gaming",
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
            "moca_qos": {
                "active": moca_qos,
                "dscp": if moca_qos { "ef" } else { "off" },
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

fn buffer_mode_from_profile(profile: &str) -> BufferMode {
    match profile {
        "kick" => BufferMode::Kick,
        "desync" => BufferMode::Desync,
        "light" => BufferMode::Light,
        _ => BufferMode::Stable,
    }
}

fn rqd_sample_from(
    snapshot: &Value,
    queues: Option<&Value>,
    upload_mbps: f64,
    util_pct: f64,
    kick_spike: bool,
    in_match: bool,
) -> Value {
    let mut sample = json!({
        "upload_util_pct": util_pct,
        "utilization_pct": util_pct,
        "kick_spike": if kick_spike { 1.0 } else { 0.0 },
        "in_match": if in_match { 1.0 } else { 0.0 },
        "desync_hint": if util_pct >= 70.0 { 1.0 } else { 0.0 },
    });
    if upload_mbps > 0.0 {
        sample["egress_mbps"] = json!(upload_mbps);
    }
    if let Some(q) = queues {
        if let Some(egress) = q.pointer("/queues/egress_upload") {
            if let Some(backlog) = egress.get("backlog_bytes").and_then(|v| v.as_u64()) {
                sample["queue_pressure"] = json!(backlog);
                sample["backlog_bytes"] = json!(backlog);
            }
            if let Some(sat) = egress.get("saturated").and_then(|v| v.as_bool()) {
                if sat {
                    sample["desync_hint"] = json!(1.0);
                }
            }
        }
    }
    if let Some(jitter) = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()) {
        sample["wan_jitter_ms"] = json!(jitter);
    }
    sample
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
        BufferMode::Stable => parts.push("gaming CAKE rtt=8ms (idle baseline)"),
        BufferMode::Light => parts.push("light buffers (10ms CAKE)"),
        BufferMode::Kick => parts.push("minimum buffers (3ms CAKE) + MoCA QoS"),
        BufferMode::Desync => parts.push("tight buffers (5ms CAKE) + upload boost"),
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
    if lobby_reputation_gate(risk) && risk.phase == "matchmaking" {
        return "peer-strict";
    }
    if risk.phase == "in-match" {
        return "in-match";
    }
    if has_peer_attack_signal(risk) && !suspicious_peer_ips(risk).is_empty() {
        return "peer-strict";
    }
    if risk.phase == "matchmaking" {
        // Console profile — all inbound P2P blocked; infrastructure service ports only.
        return "console";
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
    // Console mode: always shield in-match so only game-port + allowlisted traffic reaches Xbox.
    FloodMode::Shield
}

fn lobby_reputation_gate(risk: &SessionRisk) -> bool {
    risk.lobby_reputation
        .get("gate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn target_flood_mode(risk: &SessionRisk, snapshot: &Value, kick_spike: bool) -> FloodMode {
    if risk.phase == "matchmaking" {
        if lobby_reputation_gate(risk) {
            return FloodMode::Shield;
        }
        return FloodMode::Shield;
    }
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
    if kick_spike {
        return BufferMode::Light;
    }

    let label = cheater_label(risk);
    if matches!(label, "LIKELY" | "USER_BAD" | "POSSIBLE") {
        return BufferMode::Light;
    }

    BufferMode::Stable
}

fn pstdev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    var.sqrt()
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
