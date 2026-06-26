//! AI advisor — explainability, similar-lobby matching, trajectory prediction, recommendations.

use crate::cheater_lobby::role_pairs;
use crate::enrich::phase_code;
use crate::fold::{fold_telemetry, FOLD_DIM};
use crate::learning::engine;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct AiContext {
    pub phase: String,
    pub conns: i64,
    pub base_score: f64,
    pub adjusted_score: f64,
    pub final_score: f64,
    pub final_label: String,
    pub learn_notes: Vec<String>,
    pub base_reasons: Vec<String>,
    pub signals: Vec<(String, f64)>,
    pub mm_delta: Option<f64>,
    pub wan_jitter: Option<f64>,
    pub server_jitter: Option<f64>,
    pub conn_history: Vec<i64>,
    pub score_history: Vec<f64>,
}

pub fn analyze(ctx: &AiContext, snapshot: &Value) -> Value {
    let similar = engine().find_similar_lobbies(snapshot, ctx.conns, &ctx.phase, ctx.mm_delta, 5);
    let calibration = engine().calibration();
    let breakdown = score_breakdown(ctx);
    let trajectory = trajectory_analysis(ctx);
    let prediction = predict_trajectory(ctx, &trajectory);
    let recommendations = build_recommendations(ctx, &similar, &prediction, &calibration);

    json!({
        "version": "2.1",
        "summary": ai_summary(ctx, &prediction),
        "score_breakdown": breakdown,
        "similar_lobbies": similar,
        "trajectory": trajectory,
        "prediction": prediction,
        "recommendations": recommendations,
        "calibration": calibration,
        "features": active_features(ctx, snapshot),
    })
}

fn ai_summary(ctx: &AiContext, prediction: &Value) -> String {
    let trend = prediction
        .get("trend")
        .and_then(|v| v.as_str())
        .unwrap_or("stable");
    match (ctx.final_label.as_str(), trend) {
        ("LIKELY", "worsening") => {
            "High-confidence bad lobby — cheater detection active; network path unchanged in-match.".into()
        }
        ("LIKELY", _) => {
            "Likely cheater lobby — flood guard + buffers active to protect your connection.".into()
        }
        ("POSSIBLE", "worsening") => {
            "Marginal lobby worsening — defenses escalating if attack signals appear.".into()
        }
        ("POSSIBLE", _) => {
            "Borderline lobby — partial defense engaged; monitoring for kick floods.".into()
        }
        ("CLEAN", "worsening") => {
            "Currently clean but fan-out rising — early warning before verdict flips.".into()
        }
        _ => "Telemetry matches your learned clean profile for this phase.".into(),
    }
}

fn score_breakdown(ctx: &AiContext) -> Value {
    let rules_pct = (ctx.base_score * 100.0).min(100.0);
    let learning_delta = ((ctx.adjusted_score - ctx.base_score) * 100.0).clamp(-30.0, 30.0);
    let signal_boost = ((ctx.final_score / 100.0 - ctx.adjusted_score) * 100.0).clamp(0.0, 25.0);
    let learning_pct = (ctx.adjusted_score * 100.0).min(100.0);

    let mut sources = vec![
        json!({
            "source": "rules",
            "label": "Firewalla telemetry rules",
            "contribution": round1(rules_pct),
            "detail": ctx.base_reasons.iter().take(3).collect::<Vec<_>>(),
        }),
    ];
    if !ctx.learn_notes.is_empty() || learning_delta.abs() > 0.5 {
        sources.push(json!({
            "source": "learning",
            "label": "Personalized AI (your network)",
            "contribution": round1(learning_delta),
            "adjusted_score": round1(learning_pct),
            "detail": ctx.learn_notes.iter().take(4).collect::<Vec<_>>(),
        }));
    }
    if !ctx.signals.is_empty() {
        let sig_detail: Vec<_> = ctx
            .signals
            .iter()
            .filter(|(_, v)| *v >= 0.25)
            .map(|(k, v)| format!("{k}: {:.0}%", v * 100.0))
            .take(4)
            .collect();
        if !sig_detail.is_empty() {
            sources.push(json!({
                "source": "signals",
                "label": "Live session signals",
                "contribution": round1(signal_boost),
                "detail": sig_detail,
            }));
        }
    }

    json!({
        "final_score": round1(ctx.final_score),
        "final_label": ctx.final_label,
        "sources": sources,
    })
}

fn trajectory_analysis(ctx: &AiContext) -> Value {
    let conn = ctx.conn_history.iter().rev().take(12).copied().collect::<Vec<_>>();
    let scores = ctx.score_history.iter().rev().take(12).copied().collect::<Vec<_>>();
    let conn_delta = if conn.len() >= 2 {
        conn.first().copied().unwrap_or(0) as i64 - conn.last().copied().unwrap_or(0) as i64
    } else {
        0
    };
    let score_delta = if scores.len() >= 2 {
        scores.first().copied().unwrap_or(0.0) - scores.last().copied().unwrap_or(0.0)
    } else {
        0.0
    };
    json!({
        "connections": conn,
        "scores": scores.iter().map(|s| round1(*s)).collect::<Vec<_>>(),
        "conn_delta_12p": conn_delta,
        "score_delta_12p": round1(score_delta),
    })
}

fn predict_trajectory(ctx: &AiContext, trajectory: &Value) -> Value {
    let conn_delta = trajectory
        .get("conn_delta_12p")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let score_delta = trajectory
        .get("score_delta_12p")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let th = engine().thresholds();

    let mut risk_factors = Vec::new();
    if conn_delta > 15 {
        risk_factors.push(format!("Connection fan-out rising (+{conn_delta} over ~48s)"));
    }
    if score_delta > 8.0 {
        risk_factors.push(format!("Verdict score climbing (+{:.0} pts)", score_delta));
    }
    if ctx.conns as f64 > th.conn_matchmaking_high && ctx.phase != "post-match" {
        risk_factors.push(format!(
            "Above your learned high baseline ({:.0} conns)",
            th.conn_matchmaking_high
        ));
    }
    if ctx.server_jitter.unwrap_or(0.0) > th.jitter_bad {
        risk_factors.push("Server jitter exceeds learned bad threshold".into());
    }

    let trend = if score_delta > 5.0 || conn_delta > 20 {
        "worsening"
    } else if score_delta < -5.0 && conn_delta < -10 {
        "improving"
    } else {
        "stable"
    };

    let prob_bad = estimate_bad_probability(ctx, conn_delta, score_delta, &risk_factors);

    json!({
        "trend": trend,
        "estimated_bad_probability": round1(prob_bad * 100.0),
        "risk_factors": risk_factors,
        "early_warning": trend == "worsening" && ctx.final_label == "CLEAN",
    })
}

fn estimate_bad_probability(
    ctx: &AiContext,
    conn_delta: i64,
    score_delta: f64,
    factors: &[String],
) -> f64 {
    let mut p = ctx.final_score / 100.0;
    p += (conn_delta as f64 / 100.0).clamp(0.0, 0.15);
    p += (score_delta / 100.0).clamp(0.0, 0.12);
    p += (factors.len() as f64 * 0.03).min(0.12);
    if ctx.final_label == "LIKELY" {
        p = p.max(0.55);
    } else if ctx.final_label == "POSSIBLE" {
        p = p.max(0.28);
    }
    p.clamp(0.0, 0.95)
}

fn build_recommendations(
    ctx: &AiContext,
    similar: &[Value],
    prediction: &Value,
    calibration: &Value,
) -> Vec<Value> {
    let mut recs = Vec::new();

    match ctx.final_label.as_str() {
        "LIKELY" => {
            recs.push(json!({
                "priority": "high",
                "action": "defend",
                "text": "Cheater lobby — peer probe shield targets VPS/player tiny floods; normal game packets pass.",
            }));
            recs.push(json!({
                "priority": "medium",
                "action": "stop_defenses",
                "text": "Still glitching when aiming? Hit Stop defenses — removes all network rules.",
            }));
            recs.push(json!({
                "priority": "high",
                "action": "mark_bad",
                "text": "Mark cheater lobby after match — trains defense thresholds for your network.",
            }));
        }
        "POSSIBLE" => {
            recs.push(json!({
                "priority": "medium",
                "action": "defend",
                "text": "Defenses partially engaged — per-source limits active on suspicious traffic.",
            }));
            recs.push(json!({
                "priority": "high",
                "action": "mark_bad",
                "text": "Seeing cheaters? Hit Mark cheater lobby — do not mark clean in a bad lobby.",
            }));
        }
        _ if prediction.get("early_warning").and_then(|v| v.as_bool()).unwrap_or(false) => {
            recs.push(json!({
                "priority": "medium",
                "action": "watch",
                "text": "Early warning — fan-out rising while verdict still CLEAN. Re-check in 10s.",
            }));
        }
        _ => {
            recs.push(json!({
                "priority": "low",
                "action": "continue",
                "text": "Telemetry looks normal for your MoCA path — mark clean after match to train AI.",
            }));
        }
    }

    let bad_neighbors = similar
        .iter()
        .filter(|s| {
            matches!(
                s.get("label").and_then(|v| v.as_str()),
                Some("USER_BAD") | Some("LIKELY") | Some("USER_MARGINAL")
            )
        })
        .count();
    if bad_neighbors >= 2 {
        recs.push(json!({
            "priority": "high",
            "action": "pattern_match",
            "text": format!("32D fold matches {bad_neighbors} prior bad lobbies — high pattern confidence."),
        }));
    }

    let good_neighbors = similar
        .iter()
        .filter(|s| {
            matches!(
                s.get("label").and_then(|v| v.as_str()),
                Some("CLEAN") | Some("USER_GOOD")
            )
        })
        .count();
    if good_neighbors >= 2 && ctx.final_label == "POSSIBLE" && ctx.final_score < 42.0 {
        recs.push(json!({
            "priority": "low",
            "action": "false_positive_hint",
            "text": format!("Also similar to {good_neighbors} lobbies you marked clean — possible false alarm."),
        }));
    }

    if ctx.phase == "in-match" || ctx.phase == "matchmaking" {
        recs.push(json!({
            "priority": "info",
            "action": "network_guard",
            "text": "In-match: tiny-packet shield only. Matchmaking: light buffers + shield on cheater lobbies.",
        }));
    }

    if calibration
        .get("needs_clean_marks")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && matches!(ctx.final_label.as_str(), "CLEAN")
        && !matches!(ctx.phase.as_str(), "in-match" | "matchmaking")
    {
        recs.push(json!({
            "priority": "info",
            "action": "train_ai",
            "text": "Next time you have a genuinely good lobby, mark it clean — builds your normal fan-out profile.",
        }));
    }

    recs
}

fn active_features(ctx: &AiContext, snapshot: &Value) -> Value {
    let roles = snapshot.pointer("/_enriched/roleCounts").cloned().unwrap_or(json!({}));
    json!({
        "connections": ctx.conns,
        "phase": ctx.phase,
        "wan_jitter_ms": ctx.wan_jitter.map(round1),
        "server_jitter_ms": ctx.server_jitter.map(round1),
        "mm_delta_ms": ctx.mm_delta.map(round1),
        "role_counts": roles,
        "fold_dim": FOLD_DIM,
    })
}

pub fn current_fold(snapshot: &Value, conns: i64, phase: &str, score: f64, mm_delta: Option<f64>) -> [f32; FOLD_DIM] {
    fold_telemetry(
        conns as f32,
        snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()).map(|v| v as f32),
        mm_delta.map(|v| v as f32),
        None,
        None,
        &role_pairs(snapshot),
        phase_code(phase),
        (score / 100.0) as f32,
    )
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}
