use crate::game_state::store as game_store;
use crate::ai_advisor::{analyze, AiContext};
use crate::cheater_lobby::{assess, CheaterVerdict};
use crate::enrich::classify_value;
use crate::information_flow::{packet_byte_fingerprint, state_from_snapshot, InformationFlowTracker};
use crate::learning::engine;
use crate::packets::analyze_packets;
use crate::traffic::analyze_inbound;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct SessionRisk {
    pub score: f64,
    pub level: String,
    pub phase: String,
    pub game: String,
    pub recommendation: String,
    pub signals: Vec<(String, f64)>,
    pub anomalies: Vec<String>,
    pub cheater_lobby: Value,
    pub learning: Value,
    pub ai: Value,
    pub inbound: Value,
    pub packets: Value,
    pub information_flow: Value,
    pub lobby_reputation: Value,
    pub game_state: Value,
}

impl SessionRisk {
    pub fn to_json(&self) -> Value {
        let signals: serde_json::Map<String, Value> = self
            .signals
            .iter()
            .map(|(k, v)| (k.clone(), json!((v * 1000.0).round() / 1000.0)))
            .collect();
        json!({
            "score": (self.score * 10.0).round() / 10.0,
            "level": self.level,
            "phase": self.phase,
            "game": self.game,
            "recommendation": self.recommendation,
            "cheater_answer": crate::cheater_lobby::answer_json(&self.cheater_lobby),
            "signals": signals,
            "anomalies": self.anomalies,
            "cheater_lobby": self.cheater_lobby,
            "learning": self.learning,
            "ai": self.ai,
            "inbound_analysis": self.inbound,
            "packet_analysis": self.packets,
            "information_flow": self.information_flow,
            "lobby_reputation": self.lobby_reputation,
            "game_state": self.game_state,
            "playlist": game_store().playlist(),
        })
    }

    pub fn with_reputation(mut self, reputation: Value, offender_ips: &[String]) -> Self {
        self.lobby_reputation = reputation;
        if !offender_ips.is_empty() {
            if let Some(obj) = self.lobby_reputation.as_object_mut() {
                obj.insert("offender_ips".into(), json!(offender_ips.len()));
                obj.insert(
                    "gate".into(),
                    json!(obj.get("gate").and_then(|v| v.as_bool()).unwrap_or(false)
                        || offender_ips.len() >= 3),
                );
            }
        }
        self
    }
}

#[derive(Clone, Debug)]
pub struct AlertDecision {
    pub send: bool,
    pub reason: &'static str,
}

pub struct NetworkSessionScorer {
    wan_history: Vec<f64>,
    crit_history: Vec<f64>,
    conn_history: Vec<i64>,
    last_phase: String,
    last_verdict_label: String,
    last_alert_at: f64,
    last_alert_label: String,
    gaming_session: bool,
    session_peak_conns: i64,
    low_activity_polls: u8,
    lobby_exited: bool,
    saw_warzone_game: bool,
    in_match_polls: u32,
    conn_decline_polls: u8,
    manual_in_match: bool,
    score_history: Vec<f64>,
    flow_tracker: InformationFlowTracker,
    last_kick_handled_at: f64,
}

impl Default for NetworkSessionScorer {
    fn default() -> Self {
        Self {
            wan_history: Vec::new(),
            crit_history: Vec::new(),
            conn_history: Vec::new(),
            last_phase: "idle".into(),
            last_verdict_label: "CLEAN".into(),
            last_alert_at: 0.0,
            last_alert_label: String::new(),
            gaming_session: false,
            session_peak_conns: 0,
            low_activity_polls: 0,
            lobby_exited: false,
            saw_warzone_game: false,
            in_match_polls: 0,
            conn_decline_polls: 0,
            manual_in_match: false,
            score_history: Vec::new(),
            flow_tracker: InformationFlowTracker::default(),
            last_kick_handled_at: 0.0,
        }
    }
}

fn verdict_rank(label: &str) -> u8 {
    match label {
        "USER_BAD" | "LIKELY" => 2,
        "POSSIBLE" => 1,
        _ => 0,
    }
}

impl NetworkSessionScorer {
    pub fn score(&mut self, snapshot: &Value, insights: &Value) -> SessionRisk {
        let enriched_phase = snapshot
            .pointer("/_enriched/phase")
            .and_then(|v| v.as_str());
        let phase_info = insights.get("sessionPhase").or_else(|| insights.get("phase"));
        let mut phase = phase_info
            .and_then(|p| p.get("phase"))
            .and_then(|v| v.as_str())
            .or(enriched_phase)
            .unwrap_or("idle")
            .to_string();

        let game = phase_info
            .and_then(|p| p.pointer("/game/id"))
            .and_then(|v| v.as_str())
            .or_else(|| snapshot.pointer("/_enriched/game").and_then(|v| v.as_str()))
            .map(String::from)
            .unwrap_or_else(|| self.infer_game(snapshot));

        let game_label = phase_info
            .and_then(|p| p.pointer("/game/label"))
            .and_then(|v| v.as_str())
            .unwrap_or(&game)
            .to_string();

        self.track(snapshot);

        let playlist = game_store().playlist();
        if game_store().recent_kick(120.0) {
            if let Some(age) = game_store().kick_age_sec() {
                let kick_ts = now_secs() - age;
                if self.last_kick_handled_at < kick_ts {
                    engine().record_kick_event("game-state kick event (Overwolf/Xbox)");
                    self.last_kick_handled_at = kick_ts;
                }
            }
        }

        let roles = role_counts(snapshot);
        let conns = snapshot
            .pointer("/connections/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as i64;
        phase = self.refine_phase(&phase, &roles, conns);
        if self.manual_in_match && !self.lobby_exited {
            phase = "in-match".into();
        }

        if phase == "matchmaking" || phase == "in-match" {
            self.gaming_session = true;
            self.session_peak_conns = self.session_peak_conns.max(conns);
            self.low_activity_polls = 0;
            if phase == "matchmaking" {
                self.lobby_exited = false;
            }
        } else if self.gaming_session
            && (phase == "background" || phase == "idle")
            && (self.last_phase == "in-match" || self.last_phase == "matchmaking")
        {
            // Left lobby — reset alert state for next queue.
            self.last_verdict_label = "CLEAN".into();
            self.gaming_session = false;
            self.session_peak_conns = 0;
            self.low_activity_polls = 0;
            self.in_match_polls = 0;
            self.conn_decline_polls = 0;
        }

        if phase == "post-match" {
            self.lobby_exited = true;
            self.gaming_session = false;
        }

        self.last_phase = phase.clone();

        let mut signals = Vec::new();
        let mut anomalies = Vec::new();

        if game != "warzone" && game != "unknown" && phase != "in-match" {
            return SessionRisk {
                score: 0.0,
                level: "CLEAN".into(),
                phase,
                game: game_label,
                recommendation: "Not in Warzone — monitoring idle".into(),
                signals,
                anomalies,
                cheater_lobby: json!({}),
                learning: engine().insights(),
                ai: json!({"summary": "Not in Warzone — AI idle"}),
                inbound: json!({}),
                packets: json!({}),
                information_flow: json!({}),
                lobby_reputation: json!({}),
                game_state: game_store().to_json(),
            };
        }

        if phase == "background" || phase == "idle" || phase == "post-match" {
            let clean = CheaterVerdict {
                label: "CLEAN".into(),
                confidence: 0.0,
                reasons: vec![],
                mm_delta: None,
            };
            engine().record_poll(snapshot, &phase, &clean, None, None, &playlist);
            let rec = if phase == "post-match" {
                "Left lobby — monitoring for next queue.".into()
            } else {
                "Out of lobby — session logged.".into()
            };
            return SessionRisk {
                score: 0.0,
                level: "CLEAN".into(),
                phase,
                game: game_label,
                recommendation: rec,
                signals,
                anomalies: vec!["Not in matchmaking or in-match".into()],
                cheater_lobby: json!({"label": "CLEAN", "confidence": 0.0, "reasons": []}),
                learning: engine().insights(),
                ai: json!({"summary": "Out of lobby — session logged for learning"}),
                inbound: json!({}),
                packets: json!({}),
                information_flow: json!({}),
                lobby_reputation: json!({}),
                game_state: game_store().to_json(),
            };
        }

        if phase == "matchmaking" {
            if roles.get("matchmaking").copied().unwrap_or(0)
                + roles.get("warzone-game").copied().unwrap_or(0)
                + roles.get("dedicated-server").copied().unwrap_or(0)
                >= 2
                && conns >= 8
            {
                signals.push(("heavy_matchmaking".into(), (conns as f64 / 20.0).min(1.0)));
                anomalies.push(format!("Dense matchmaking fan-out ({conns} connections)"));
            }
            if roles.get("xbox-live").copied().unwrap_or(0) >= 3 {
                signals.push(("xbox_live_churn".into(), 0.5));
            }
        }

        if phase == "in-match" {
            let telemetry = roles.get("telemetry").copied().unwrap_or(0);
            let gameplay = roles.get("warzone-game").copied().unwrap_or(0)
                + roles.get("dedicated-server").copied().unwrap_or(0)
                + roles.get("game-assets").copied().unwrap_or(0);
            if telemetry >= 3 && gameplay >= 2 && telemetry >= roles.get("warzone-game").copied().unwrap_or(0) + roles.get("dedicated-server").copied().unwrap_or(0) {
                signals.push((
                    "telemetry_noise".into(),
                    (telemetry as f64 / gameplay.max(1) as f64).min(1.0),
                ));
                anomalies.push("Anti-cheat telemetry spike vs gameplay traffic".into());
            }
            if self.crit_history.len() >= 8 {
                let recent = &self.crit_history[self.crit_history.len() - 8..];
                let jitter = pstdev(recent);
                let mean_lat = mean(recent);
                if jitter >= 12.0 {
                    signals.push(("server_latency_jitter".into(), (jitter / 40.0).min(1.0)));
                    anomalies.push(format!("Game server latency unstable (σ={jitter:.0}ms)"));
                }
                if mean_lat >= 70.0 {
                    signals.push((
                        "high_server_latency".into(),
                        ((mean_lat - 50.0) / 80.0).min(1.0),
                    ));
                    anomalies.push(format!("High Demonware latency ({mean_lat:.0}ms)"));
                }
            }
            if self.wan_history.len() >= 10 {
                let recent = &self.wan_history[self.wan_history.len() - 10..];
                let wan_j = pstdev(recent);
                if wan_j >= 15.0 {
                    signals.push(("wan_jitter".into(), (wan_j / 50.0).min(1.0)));
                    anomalies.push(
                        "WAN latency swinging — possible lag manipulation in lobby".into(),
                    );
                }
            }
        }

        if let Some(arr) = insights.get("anomalies").and_then(|v| v.as_array()) {
            for a in arr {
                let sev = a.get("severity").and_then(|v| v.as_str()).unwrap_or("medium");
                let w = match sev {
                    "high" => 0.9,
                    "medium" => 0.55,
                    _ => 0.3,
                };
                let key = format!(
                    "advisor_{}",
                    a.get("type").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                signals.push((key, w));
                if let Some(msg) = a.get("message").and_then(|v| v.as_str()) {
                    anomalies.push(msg.into());
                }
            }
        }

        let eng = engine();
        let th = eng.thresholds_for_playlist(&playlist);
        let baseline = eng.inbound_baseline();
        let inbound = analyze_inbound(snapshot, &phase, baseline.as_ref(), &th);
        let packets = analyze_packets(snapshot, &phase, conns);

        let net_state = state_from_snapshot(snapshot, conns, &phase);
        let pkt_bytes = packet_byte_fingerprint(snapshot);
        let flow_step = self.flow_tracker.step(&net_state, &pkt_bytes);
        let flow_json = self.flow_tracker.to_json(&flow_step);

        if flow_step.superlinear {
            signals.push(("superlinear_flow".into(), (flow_step.flow_bits / 8.0).min(1.0)));
            anomalies.push(format!(
                "Information flow spike: {:.2} bits/step (IFC Zenodo 17373031)",
                flow_step.flow_bits
            ));
        } else if flow_step.flow_bits >= 4.0 {
            signals.push(("info_flow_spike".into(), (flow_step.flow_bits / 8.0).min(1.0)));
        }
        if flow_step.prg_like {
            signals.push(("prg_like_traffic".into(), 0.72));
            anomalies.push("PRG-like uniform packet bytes — synthetic traffic proxy".into());
        }
        if flow_step.byte_flow >= 6.5 && (phase == "matchmaking" || phase == "in-match") {
            signals.push(("byte_flow_entropy".into(), (flow_step.byte_flow / 8.0).min(1.0)));
        }
        for a in &flow_step.alerts {
            if !anomalies.iter().any(|x| x == a) {
                anomalies.push(a.clone());
            }
        }

        for (k, v) in &inbound.signals {
            signals.push((k.clone(), *v));
        }
        for (k, v) in &packets.signals {
            signals.push((k.clone(), *v));
        }
        if inbound.score >= 0.15 {
            signals.push(("inbound_attack".into(), inbound.score));
        }
        if packets.score >= 0.15 {
            signals.push(("packet_cheat".into(), packets.score));
        }
        for a in &inbound.alerts {
            if !anomalies.iter().any(|x| x == a) {
                anomalies.push(a.clone());
            }
        }
        for a in &packets.alerts {
            if !anomalies.iter().any(|x| x == a) {
                anomalies.push(a.clone());
            }
        }

        let weights: std::collections::HashMap<&str, f64> = [
            ("heavy_matchmaking", 14.0),
            ("xbox_live_churn", 8.0),
            ("telemetry_noise", 16.0),
            ("server_latency_jitter", 18.0),
            ("high_server_latency", 12.0),
            ("wan_jitter", 15.0),
            ("inbound_attack", 10.0),
            ("inbound_flood", 12.0),
            ("inbound_elevated", 8.0),
            ("packet_storm", 11.0),
            ("unknown_inbound_fanout", 13.0),
            ("quiet_pool_inbound", 14.0),
            ("tiny_packet_flood", 14.0),
            ("inbound_remote_fanout", 13.0),
            ("peer_tiny_flood", 16.0),
            ("peer_micro_burst", 15.0),
            ("suspicious_peer", 14.0),
            ("unknown_inbound_packets", 12.0),
            ("packet_cheat", 12.0),
            ("info_flow_spike", 13.0),
            ("superlinear_flow", 15.0),
            ("prg_like_traffic", 14.0),
            ("byte_flow_entropy", 12.0),
            ("suboptimal_matchmaking_path", 14.0),
        ]
        .into_iter()
        .collect();

        let mut total_w = 0.0;
        let mut weighted = 0.0;
        for (k, v) in &signals {
            let w = weights.get(k.as_str()).copied().unwrap_or(10.0);
            weighted += v * w;
            total_w += w;
        }
        let mut score = if total_w > 0.0 {
            (weighted / total_w * 100.0).min(100.0)
        } else {
            0.0
        };

        let base = assess(
            snapshot,
            &phase,
            &self.wan_history,
            &self.crit_history,
            &self.conn_history,
            &th,
            None,
            None,
            Some(&inbound),
            Some(&packets),
        );
        let server_jitter = if self.crit_history.len() >= 6 {
            Some(pstdev(
                &self.crit_history[self.crit_history.len().saturating_sub(6)..],
            ))
        } else {
            None
        };

        let (mut adjusted, learn_notes) =
            eng.adjust_score(base.confidence / 100.0, conns, &phase, base.mm_delta, &playlist);

        // In-match: fold session signals into score (telemetry noise, conn fan-out, inbound).
        if phase == "in-match" {
            for (k, v) in &signals {
                if k == "telemetry_noise" && *v >= 0.45 {
                    adjusted = adjusted.max(0.28);
                }
                if k == "server_latency_jitter" && *v >= 0.4 {
                    adjusted = adjusted.max(0.32);
                }
                if (k == "inbound_flood" || k == "inbound_attack") && *v >= 0.4 {
                    adjusted = adjusted.max(0.35);
                }
                if (k == "tiny_packet_flood" || k == "packet_cheat") && *v >= 0.4 {
                    adjusted = adjusted.max(0.38);
                }
                if (k == "peer_tiny_flood" || k == "suspicious_peer") && *v >= 0.35 {
                    adjusted = adjusted.max(0.40);
                }
                if (k == "superlinear_flow" || k == "prg_like_traffic") && *v >= 0.35 {
                    adjusted = adjusted.max(0.42);
                }
                if k == "info_flow_spike" && *v >= 0.45 {
                    adjusted = adjusted.max(0.36);
                }
            }
            if conns >= 80 {
                adjusted = adjusted.max(0.25);
            }
            if eng
                .insights()
                .pointer("/active_session/confirmed_bad")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                adjusted = adjusted.max(0.58);
            }
        }

        let verdict = assess(
            snapshot,
            &phase,
            &self.wan_history,
            &self.crit_history,
            &self.conn_history,
            &th,
            Some(adjusted),
            Some(&learn_notes),
            Some(&inbound),
            Some(&packets),
        );

        eng.record_poll(snapshot, &phase, &verdict, base.mm_delta, server_jitter, &playlist);
        let learning_info = eng.insights();
        let cheater = verdict.to_json();
        let lobby_reputation = eng.lobby_reputation(
            snapshot,
            conns,
            &phase,
            base.mm_delta,
            &playlist,
            &[],
        );

        let level;
        if phase == "matchmaking" || phase == "in-match" {
            score = verdict.confidence;
            level = match verdict.label.as_str() {
                "LIKELY" => {
                    if score >= 75.0 {
                        "CRITICAL".into()
                    } else {
                        "HIGH".into()
                    }
                }
                "POSSIBLE" => {
                    if score >= 35.0 {
                        "MEDIUM".into()
                    } else {
                        "LOW".into()
                    }
                }
                _ => "CLEAN".into(),
            };
        } else {
            score *= 0.15;
            level = level_from_score(score);
        }

        let recommendation = match verdict.label.as_str() {
            "LIKELY" | "USER_BAD" => {
                "Cheater lobby — packet shield active (blocks tiny flood packets; normal aim traffic unchanged)."
            }
            "POSSIBLE" => {
                "Possible cheater lobby — light packet shield if tiny floods detected."
            }
            _ if level == "CRITICAL" || level == "HIGH" => {
                "Elevated risk — cheater detection active; network path unchanged during match."
            }
            _ if level == "MEDIUM" => {
                "Monitoring — detection active, defenses idle in-match."
            }
            _ => "Detection on standby.",
        }
        .to_string();

        let mut display = if verdict.label != "CLEAN" {
            verdict.reasons.clone()
        } else {
            vec!["Telemetry matches normal Warzone pools".into()]
        };
        for a in anomalies {
            if !display.contains(&a) {
                display.push(a);
            }
        }
        display.truncate(8);

        self.score_history.push(score);
        if self.score_history.len() > 48 {
            self.score_history.drain(0..self.score_history.len() - 48);
        }

        let wan_jitter = if self.wan_history.len() >= 6 {
            Some(pstdev(
                &self.wan_history[self.wan_history.len().saturating_sub(8)..],
            ))
        } else {
            None
        };

        let ai = analyze(
            &AiContext {
                phase: phase.clone(),
                conns,
                base_score: base.confidence,
                adjusted_score: adjusted * 100.0,
                final_score: score,
                final_label: verdict.label.clone(),
                learn_notes,
                base_reasons: base.reasons,
                signals: signals.clone(),
                mm_delta: base.mm_delta,
                wan_jitter,
                server_jitter,
                conn_history: self.conn_history.clone(),
                score_history: self.score_history.clone(),
            },
            snapshot,
        );

        SessionRisk {
            score,
            level,
            phase,
            game: game_label,
            recommendation,
            signals,
            anomalies: display,
            cheater_lobby: cheater,
            learning: learning_info,
            ai,
            inbound: inbound.to_json(),
            packets: packets.to_json(),
            information_flow: flow_json,
            lobby_reputation,
            game_state: game_store().to_json(),
        }
    }

    pub fn should_alert(&mut self, risk: &SessionRisk) -> AlertDecision {
        if self.lobby_exited {
            return AlertDecision {
                send: false,
                reason: "left_lobby",
            };
        }

        let label = risk
            .cheater_lobby
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("CLEAN");

        // New queue/match session — reset so first bad verdict triggers immediately.
        if self.last_phase != risk.phase
            && (risk.phase == "matchmaking" || risk.phase == "in-match")
            && self.last_phase != "matchmaking"
            && self.last_phase != "in-match"
        {
            self.last_verdict_label = "CLEAN".into();
        }
        self.last_phase = risk.phase.clone();

        if risk.phase != "matchmaking" && risk.phase != "in-match" {
            self.last_verdict_label = label.into();
            return AlertDecision {
                send: false,
                reason: "idle",
            };
        }

        let rank = verdict_rank(label);
        let prev_rank = verdict_rank(&self.last_verdict_label);
        self.last_verdict_label = label.into();

        if rank == 0 {
            return AlertDecision {
                send: false,
                reason: "clean",
            };
        }

        let now = now_secs();
        let escalated = rank > prev_rank;
        let first_bad = prev_rank == 0;
        let cooldown = if label == "LIKELY" || label == "USER_BAD" {
            45.0
        } else {
            90.0
        };

        if first_bad || escalated {
            self.last_alert_at = now;
            self.last_alert_label = label.into();
            return AlertDecision {
                send: true,
                reason: if escalated && !first_bad {
                    "escalation"
                } else {
                    "auto_detect"
                },
            };
        }

        if now - self.last_alert_at >= cooldown {
            self.last_alert_at = now;
            self.last_alert_label = label.into();
            return AlertDecision {
                send: true,
                reason: "reminder",
            };
        }

        AlertDecision {
            send: false,
            reason: "cooldown",
        }
    }

    pub fn last_auto_alert(&self) -> Value {
        if self.last_alert_at <= 0.0 {
            return json!(null);
        }
        json!({
            "at": self.last_alert_at,
            "label": self.last_alert_label,
        })
    }

    pub fn mark_lobby_exit(&mut self) {
        self.lobby_exited = true;
        self.manual_in_match = false;
        self.gaming_session = false;
        self.last_verdict_label = "CLEAN".into();
        self.session_peak_conns = 0;
        self.in_match_polls = 0;
        self.conn_decline_polls = 0;
        self.low_activity_polls = 0;
        self.last_phase = "post-match".into();
        self.last_kick_handled_at = 0.0;
    }

    pub fn mark_in_match(&mut self) {
        self.manual_in_match = true;
        self.lobby_exited = false;
        self.gaming_session = true;
        self.last_verdict_label = "CLEAN".into();
        self.last_phase = "in-match".into();
        self.in_match_polls = 0;
        self.conn_decline_polls = 0;
        self.low_activity_polls = 0;
    }

    pub fn dashboard_meta(&self) -> Value {
        let server_jitter = if self.crit_history.len() >= 6 {
            Some(pstdev(
                &self.crit_history[self.crit_history.len().saturating_sub(8)..],
            ))
        } else {
            None
        };
        json!({
            "manual_in_match": self.manual_in_match,
            "gaming_session": self.gaming_session,
            "lobby_exited": self.lobby_exited,
            "session_peak_conns": self.session_peak_conns,
            "wan_latency_ms": self.wan_history.last(),
            "wan_jitter_ms": if self.wan_history.len() >= 6 {
                Some(pstdev(&self.wan_history[self.wan_history.len().saturating_sub(8)..]))
            } else {
                None::<f64>
            },
            "server_latency_ms": self.crit_history.last(),
            "server_jitter_ms": server_jitter,
            "conn_count": self.conn_history.last(),
            "wan_history": self.wan_history.iter().rev().take(24).copied().collect::<Vec<_>>(),
            "server_history": self.crit_history.iter().rev().take(24).copied().collect::<Vec<_>>(),
            "conn_history": self.conn_history.iter().rev().take(24).copied().collect::<Vec<_>>(),
            "last_alert": self.last_auto_alert(),
        })
    }

    fn refine_phase(
        &mut self,
        phase: &str,
        roles: &std::collections::HashMap<String, u32>,
        conns: i64,
    ) -> String {
        if self.lobby_exited {
            return "post-match".into();
        }

        if phase != "in-match" && phase != "matchmaking" {
            return phase.into();
        }

        // Home screen / dashboard idle — Xbox Live alone is not matchmaking.
        if phase == "matchmaking" {
            let warzone_game = roles.get("warzone-game").copied().unwrap_or(0);
            let matchmaking = roles.get("matchmaking").copied().unwrap_or(0);
            let assets = roles.get("game-assets").copied().unwrap_or(0);
            let telemetry = roles.get("telemetry").copied().unwrap_or(0);
            let qos = roles.get("azure-qos").copied().unwrap_or(0);
            if warzone_game == 0
                && matchmaking == 0
                && assets == 0
                && telemetry < 2
                && qos < 2
            {
                return "background".into();
            }
        }

        let warzone_game = roles.get("warzone-game").copied().unwrap_or(0);
        let matchmaking = roles.get("matchmaking").copied().unwrap_or(0);
        let persisted_peak = engine()
            .insights()
            .pointer("/active_session/peak_conns")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as i64;
        let peak = self.session_peak_conns.max(conns).max(persisted_peak);

        if warzone_game > 0 {
            self.saw_warzone_game = true;
        }
        if phase == "in-match" {
            self.in_match_polls = self.in_match_polls.saturating_add(1);
        }

        // Match ended: Demonware dropped after being seen in this session.
        if phase == "in-match"
            && self.saw_warzone_game
            && warzone_game == 0
            && self.in_match_polls >= 3
        {
            return "post-match".into();
        }

        // Connection fan-out collapsing after a heavy session.
        if self.conn_history.len() >= 2 {
            let prev = self.conn_history[self.conn_history.len() - 2];
            if conns + 8 < prev {
                self.conn_decline_polls = self.conn_decline_polls.saturating_add(1);
            } else {
                self.conn_decline_polls = 0;
            }
            if self.conn_decline_polls >= 3 && peak >= 50 {
                return "post-match".into();
            }
        }

        if warzone_game == 0 && matchmaking == 0 {
            if peak >= 50 && conns < peak / 2 {
                return "post-match".into();
            }
            if peak >= 80 && conns < 50 {
                return "post-match".into();
            }
            if conns < 35 {
                self.low_activity_polls = self.low_activity_polls.saturating_add(1);
                if self.low_activity_polls >= 2 {
                    return "post-match".into();
                }
            } else {
                self.low_activity_polls = 0;
            }
        }

        phase.into()
    }

    fn track(&mut self, snapshot: &Value) {
        if let Some(wan) = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()) {
            self.wan_history.push(wan);
            if self.wan_history.len() > 120 {
                self.wan_history.drain(0..self.wan_history.len() - 120);
            }
        }
        let crit = critical_latencies(snapshot);
        if !crit.is_empty() {
            self.crit_history.push(mean(&crit));
            if self.crit_history.len() > 120 {
                self.crit_history.drain(0..self.crit_history.len() - 120);
            }
        }
        let conns = snapshot
            .pointer("/connections/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as i64;
        self.conn_history.push(conns);
        if self.conn_history.len() > 120 {
            self.conn_history.drain(0..self.conn_history.len() - 120);
        }
    }

    fn infer_game(&self, snapshot: &Value) -> String {
        if snapshot.pointer("/_enriched/game").and_then(|v| v.as_str()) == Some("warzone") {
            return "warzone".into();
        }
        if let Some(items) = snapshot.pointer("/connections/items").and_then(|v| v.as_array()) {
            for item in items {
                let host = item
                    .get("hostname")
                    .or(item.get("label"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if host.contains("demonware") || host.contains("playfab") || host.contains("callofduty")
                {
                    return "warzone".into();
                }
            }
        }
        for key in ["recentFlows", "recent_flows"] {
            if let Some(flows) = snapshot.get(key).and_then(|v| v.as_array()) {
                for flow in flows {
                    let host = flow
                        .get("hostname")
                        .or(flow.get("host"))
                        .or(flow.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if ["demonware", "playfab", "callofduty", "activision"]
                        .iter()
                        .any(|x| host.contains(x))
                    {
                        return "warzone".into();
                    }
                }
            }
        }
        "unknown".into()
    }
}

fn role_counts(snapshot: &Value) -> std::collections::HashMap<String, u32> {
    if let Some(rc) = snapshot.pointer("/_enriched/roleCounts").and_then(|v| v.as_object()) {
        return rc
            .iter()
            .filter(|(k, _)| *k != "unknown")
            .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0) as u32))
            .collect();
    }
    let mut counts = std::collections::HashMap::new();
    if let Some(items) = snapshot.pointer("/connections/items").and_then(|v| v.as_array()) {
        for item in items {
            let rid = item
                .get("roleId")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| classify_value(item));
            *counts.entry(rid).or_default() += 1;
        }
    }
    counts
}

fn critical_latencies(snapshot: &Value) -> Vec<f64> {
    let mut out = Vec::new();
    if let Some(items) = snapshot.pointer("/connections/items").and_then(|v| v.as_array()) {
        for item in items {
            if item.get("tier").and_then(|v| v.as_str()) == Some("critical") {
                if let Some(lat) = item.get("latencyMs").and_then(|v| v.as_f64()) {
                    out.push(lat);
                }
            }
        }
    }
    if let Some(dests) = snapshot.get("destinations").and_then(|v| v.as_array()) {
        for d in dests {
            if d.get("tier").and_then(|v| v.as_str()) == Some("critical") {
                if let Some(lat) = d.get("latencyMs").and_then(|v| v.as_f64()) {
                    out.push(lat);
                }
            }
        }
    }
    out
}

fn pstdev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let m = mean(vals);
    (vals.iter().map(|v| (v - m).powi(2)).sum::<f64>() / vals.len() as f64).sqrt()
}

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        0.0
    } else {
        vals.iter().sum::<f64>() / vals.len() as f64
    }
}

fn level_from_score(score: f64) -> String {
    if score >= 75.0 {
        "CRITICAL".into()
    } else if score >= 55.0 {
        "HIGH".into()
    } else if score >= 35.0 {
        "MEDIUM".into()
    } else if score >= 15.0 {
        "LOW".into()
    } else {
        "CLEAN".into()
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
