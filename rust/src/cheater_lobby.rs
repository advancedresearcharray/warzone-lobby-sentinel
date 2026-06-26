use crate::enrich::{classify_endpoint, classify_value, phase_code, role_index};
use crate::learning::AdaptiveThresholds;
use crate::packets::PacketAnalysis;
use crate::traffic::InboundAnalysis;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct CheaterVerdict {
    pub label: String,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub mm_delta: Option<f64>,
}

impl CheaterVerdict {
    pub fn to_json(&self) -> Value {
        json!({
            "label": self.label,
            "confidence": (self.confidence * 10.0).round() / 10.0,
            "likely": self.label == "LIKELY",
            "reasons": self.reasons.iter().take(6).collect::<Vec<_>>(),
        })
    }
}

/// Plain-language cheater lobby answer for dashboard and alerts.
pub fn answer_json(cheater: &Value) -> Value {
    let label = cheater
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("CLEAN");
    let confidence = cheater
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let reasons: Vec<String> = cheater
        .get("reasons")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|r| r.as_str().map(String::from))
                .take(4)
                .collect()
        })
        .unwrap_or_default();

    let (is_cheater, headline, plain) = match label {
        "LIKELY" | "USER_BAD" => (
            "yes",
            "CHEATER LOBBY",
            format!(
                "Yes — likely cheater lobby ({:.0}% confidence)",
                confidence
            ),
        ),
        "POSSIBLE" => (
            "maybe",
            "POSSIBLE CHEATER LOBBY",
            format!(
                "Maybe — possible cheater lobby ({:.0}% confidence)",
                confidence
            ),
        ),
        _ => (
            "no",
            "CLEAN LOBBY",
            "No — telemetry looks like a normal lobby".into(),
        ),
    };

    json!({
        "is_cheater_lobby": is_cheater,
        "headline": headline,
        "plain": plain,
        "label": label,
        "confidence": confidence,
        "reasons": reasons,
    })
}

fn items_with_roles(snapshot: &Value) -> Vec<(String, Option<f64>)> {
    let mut items = Vec::new();
    if let Some(arr) = snapshot.pointer("/connections/items").and_then(|v| v.as_array()) {
        for item in arr {
            let rid = item
                .get("roleId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| classify_value(item));
            let lat = item.get("latencyMs").and_then(|v| v.as_f64());
            items.push((rid, lat));
        }
    }
    if let Some(arr) = snapshot.get("destinations").and_then(|v| v.as_array()) {
        for d in arr {
            let rid = d
                .get("roleId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    let remote = d.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                    let host = d
                        .get("hostname")
                        .or(d.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    classify_endpoint(remote, host)
                });
            let lat = d.get("latencyMs").and_then(|v| v.as_f64());
            items.push((rid, lat));
        }
    }
    for key in ["recentFlows", "recent_flows"] {
        if let Some(flows) = snapshot.get(key).and_then(|v| v.as_array()) {
            for flow in flows {
                let remote = flow.get("remote").and_then(|v| v.as_str()).unwrap_or("");
                let host = flow
                    .get("hostname")
                    .or(flow.get("host"))
                    .or(flow.get("label"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if host.is_empty() && remote.is_empty() {
                    continue;
                }
                let lat = flow.get("latencyMs").and_then(|v| v.as_f64());
                items.push((classify_endpoint(remote, host), lat));
            }
        }
    }
    items
}

fn pstdev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64).sqrt()
}

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        0.0
    } else {
        vals.iter().sum::<f64>() / vals.len() as f64
    }
}

pub fn assess(
    snapshot: &Value,
    phase: &str,
    wan_history: &[f64],
    crit_history: &[f64],
    conn_history: &[i64],
    th: &AdaptiveThresholds,
    learn_adjust: Option<f64>,
    learn_notes: Option<&[String]>,
    inbound: Option<&InboundAnalysis>,
    packets: Option<&PacketAnalysis>,
) -> CheaterVerdict {
    if phase != "matchmaking" && phase != "in-match" {
        return CheaterVerdict {
            label: "CLEAN".into(),
            confidence: 0.0,
            reasons: vec!["Not in lobby or match".into()],
            mm_delta: None,
        };
    }

    let items = items_with_roles(snapshot);
    let mut roles: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (rid, _) in &items {
        if rid != "unknown" {
            *roles.entry(rid.clone()).or_default() += 1;
        }
    }
    if let Some(rc) = snapshot
        .pointer("/_enriched/roleCounts")
        .and_then(|v| v.as_object())
    {
        for (k, v) in rc {
            if k != "unknown" {
                *roles.entry(k.clone()).or_default() += v.as_u64().unwrap_or(0) as u32;
            }
        }
    }

    let conns = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as i64;
    let wan_f = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64());

    let mut score = 0.0f64;
    let mut reasons = Vec::new();
    let mut mm_delta_val = None;

    if phase == "matchmaking" {
        if conns as f64 >= th.conn_matchmaking_high {
            score += 0.28;
            reasons.push(format!(
                "Shadow-pool fan-out ({conns} live connections during queue)"
            ));
        } else if conns as f64 >= th.conn_matchmaking_elevated {
            score += 0.14;
            reasons.push(format!("Elevated matchmaking traffic ({conns} connections)"));
        }
        if roles.get("matchmaking").copied().unwrap_or(0) >= 2 {
            score += 0.12;
            reasons.push("Multiple PlayFab session endpoints active".into());
        }
        if roles.get("azure-qos").copied().unwrap_or(0) >= 2 {
            score += 0.15;
            reasons.push("Multi-region QoS probing — distant lobby selection pattern".into());
        }

        let mm_lats: Vec<f64> = items
            .iter()
            .filter(|(r, lat)| {
                lat.is_some()
                    && (r == "matchmaking" || r == "warzone-game" || r == "azure-qos")
            })
            .filter_map(|(_, lat)| *lat)
            .collect();
        if let (Some(worst), Some(wan)) = (mm_lats.iter().copied().reduce(f64::max), wan_f) {
            let delta = worst - wan;
            mm_delta_val = Some(delta);
            if delta >= th.mm_delta_bad {
                score += 0.32;
                reasons.push(format!(
                    "Bad lobby placement (+{delta:.0} ms vs your best path)"
                ));
            } else if delta >= th.mm_delta_warn {
                score += 0.18;
                reasons.push(format!(
                    "Distant matchmaking server (+{delta:.0} ms vs baseline)"
                ));
            }
        }
        if roles.get("xbox-live").copied().unwrap_or(0) >= 4 {
            score += 0.1;
            reasons.push("Xbox Live session churn — unstable lobby assignment".into());
        }
        if conn_history.len() >= 6 {
            let peak = *conn_history.iter().rev().take(6).max().unwrap_or(&0);
            if peak >= 80 && conns >= ((peak as f64) * 0.7) as i64 {
                score += 0.08;
                reasons.push("Sustained high fan-out through entire queue".into());
            }
        }
    }

    if phase == "in-match" {
        let demonware = roles.get("warzone-game").copied().unwrap_or(0);
        let gameplay = demonware
            + roles.get("matchmaking").copied().unwrap_or(0)
            + roles.get("game-assets").copied().unwrap_or(0);
        let telemetry = roles.get("telemetry").copied().unwrap_or(0);

        if demonware >= 1 && telemetry >= 2 && telemetry >= demonware {
            score += 0.22;
            reasons.push("Anti-cheat telemetry spike vs Demonware gameplay".into());
        }
        if crit_history.len() >= 6 {
            let recent = &crit_history[crit_history.len().saturating_sub(6)..];
            let jitter = pstdev(recent);
            let mean_lat = mean(recent);
            if jitter >= th.jitter_bad {
                score += 0.25;
                reasons.push(format!(
                    "Server latency unstable (σ={jitter:.0} ms) — lag-comp lobby sign"
                ));
            }
            if mean_lat >= 75.0 {
                score += 0.18;
                reasons.push(format!(
                    "High Demonware latency ({mean_lat:.0} ms) — overseas shadow route"
                ));
            }
        }
        if wan_history.len() >= 8 {
            let recent = &wan_history[wan_history.len().saturating_sub(8)..];
            let wan_j = pstdev(recent);
            if wan_j >= th.wan_jitter_bad {
                score += 0.2;
                reasons.push("WAN latency swinging mid-match — manipulation pattern".into());
            }
        }
        if gameplay >= 2 && telemetry == 0 && conns < 40 {
            score -= 0.08;
        }

        // Xbox in-match: Demonware hostnames often missing from recentFlows (UDP).
        let xbox_live = roles.get("xbox-live").copied().unwrap_or(0);
        let assets = roles.get("game-assets").copied().unwrap_or(0);
        if conns >= 100 {
            score += 0.26;
            reasons.push(format!(
                "Heavy in-match fan-out ({conns} connections) — shadow-pool / lag-comp load"
            ));
        } else if conns >= 65 {
            score += 0.16;
            reasons.push(format!("Elevated in-match connections ({conns})"));
        }
        if assets >= 1 && telemetry >= 1 && xbox_live >= 3 {
            score += 0.18;
            reasons.push(
                "Xbox in-match pattern (CoD assets + telemetry + Xbox Live churn)".into(),
            );
        }
        if demonware == 0 && assets >= 1 && conns >= 50 && phase == "in-match" {
            score += 0.12;
            reasons.push(
                "Live Warzone session without Demonware DNS — typical Xbox UDP gameplay".into(),
            );
        }
    }

    if let Some(adj) = learn_adjust {
        // Learning adjusts upward; never wipe a non-zero telemetry score to 0.
        if adj > score {
            score = adj;
        } else if score < 0.12 && adj >= 0.12 {
            score = adj;
        }
        if let Some(notes) = learn_notes {
            reasons.extend(notes.iter().take(3).cloned());
        }
    }

    if let Some(inb) = inbound {
        if inb.score > score {
            score = inb.score;
        } else if score < 0.15 && inb.score >= 0.15 {
            score = inb.score;
        }
        for alert in inb.alerts.iter().take(4) {
            if !reasons.iter().any(|r| r == alert) {
                reasons.push(alert.clone());
            }
        }
    }

    if let Some(pkt) = packets {
        if pkt.score > score {
            score = pkt.score;
        } else if score < 0.15 && pkt.score >= 0.15 {
            score = pkt.score;
        }
        for alert in pkt.alerts.iter().take(4) {
            if !reasons.iter().any(|r| r == alert) {
                reasons.push(alert.clone());
            }
        }
    }

    score = score.clamp(0.0, 1.0);
    let confidence = (score * 1000.0).round() / 10.0;
    let label = if score >= 0.48 {
        "LIKELY".to_string()
    } else if score >= 0.22 {
        "POSSIBLE".to_string()
    } else if phase == "in-match"
        && score >= 0.12
        && (conns >= 65 || roles.get("telemetry").copied().unwrap_or(0) >= 1)
    {
        reasons.push("In-match Xbox telemetry elevated — possible bad pool".into());
        "POSSIBLE".to_string()
    } else if phase == "matchmaking"
        && score >= 0.12
        && roles.get("xbox-live").copied().unwrap_or(0) >= 2
        && conns >= 18
        && conns <= 45
    {
        reasons.push(format!(
            "Quiet matchmaking pool ({conns} conns) with Xbox Live churn — cheater lobby pattern"
        ));
        "POSSIBLE".to_string()
    } else {
        reasons = vec!["Telemetry matches normal Warzone pools".into()];
        "CLEAN".to_string()
    };

    let confidence = if label == "POSSIBLE" && confidence < 22.0 {
        24.0
    } else {
        confidence
    };

    CheaterVerdict {
        label,
        confidence,
        reasons,
        mm_delta: mm_delta_val,
    }
}

pub fn role_pairs(snapshot: &Value) -> Vec<(u8, u16)> {
    snapshot
        .pointer("/_enriched/roleCounts")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter(|(k, _)| *k != "unknown")
                .map(|(k, v)| (role_index(k), v.as_u64().unwrap_or(0) as u16))
                .collect()
        })
        .unwrap_or_default()
}

pub fn phase_str(snapshot: &Value) -> String {
    snapshot
        .pointer("/_enriched/phase")
        .and_then(|v| v.as_str())
        .unwrap_or("idle")
        .to_string()
}

#[allow(dead_code)]
pub fn phase_code_from_str(phase: &str) -> u8 {
    phase_code(phase)
}
