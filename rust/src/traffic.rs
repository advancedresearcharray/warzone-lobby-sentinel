//! Live traffic inspection and inbound cheat-pattern analysis from Firewalla snapshots.

use crate::enrich::{classify_endpoint, classify_value, is_unknown_inbound};
use crate::learning::AdaptiveThresholds;
use crate::metrics::InboundBaseline;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct InboundAnalysis {
    pub score: f64,
    pub signals: Vec<(String, f64)>,
    pub alerts: Vec<String>,
    pub verdict: String,
    pub metrics: Value,
}

impl InboundAnalysis {
    pub fn to_json(&self) -> Value {
        json!({
            "score": (self.score * 1000.0).round() / 10.0,
            "verdict": self.verdict,
            "alerts": self.alerts,
            "signals": self.signals.iter().map(|(k,v)| (k.clone(), json!((v * 1000.0).round() / 1000.0))).collect::<serde_json::Map<_,_>>(),
            "metrics": self.metrics,
        })
    }
}

#[derive(Clone, Debug)]
struct SampleMetrics {
    inbound_mbps: f64,
    outbound_mbps: f64,
    inbound_kpps: f64,
    total_kpps: f64,
    connections: i64,
    inbound_conns: usize,
    unknown_inbound_conns: usize,
    xbox_download_bytes: u64,
    xbox_upload_bytes: u64,
    in_out_byte_ratio: f64,
    wan_latency_ms: Option<f64>,
}

pub fn collect_sample_metrics(snapshot: &Value) -> SampleMetrics {
    let sample = snapshot.get("sample").and_then(|v| v.as_object());
    let window_sec = sample
        .and_then(|s| s.get("windowSec"))
        .and_then(|v| v.as_f64())
        .unwrap_or(3.0)
        .max(0.5);
    let bytes_in = sample
        .and_then(|s| s.get("bytesIn"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let bytes_out = sample
        .and_then(|s| s.get("bytesOut"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let packets = sample
        .and_then(|s| s.get("packets"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let inbound_mbps = (bytes_in as f64 * 8.0) / window_sec / 1_000_000.0;
    let outbound_mbps = (bytes_out as f64 * 8.0) / window_sec / 1_000_000.0;
    let total_kpps = packets as f64 / window_sec / 1000.0;
    let inbound_kpps = if packets > 0 && bytes_in >= bytes_out {
        total_kpps
    } else {
        0.0
    };

    let connections = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as i64;

    let mut inbound_conns = 0usize;
    let mut unknown_inbound = 0usize;
    if let Some(items) = snapshot.pointer("/connections/items").and_then(|v| v.as_array()) {
        for c in items {
            let dir = c.get("direction").and_then(|v| v.as_str()).unwrap_or("out");
            if dir != "in" {
                continue;
            }
            inbound_conns += 1;
            let role = c
                .get("roleId")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| classify_value(c));
            if is_unknown_inbound(&role) {
                unknown_inbound += 1;
            }
        }
    }

    let flows = snapshot
        .get("recentFlows")
        .or(snapshot.get("recent_flows"))
        .and_then(|v| v.as_array());
    let mut xbox_download = 0u64;
    let mut xbox_upload = 0u64;
    if let Some(arr) = flows {
        for f in arr {
            xbox_download += f.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
            xbox_upload += f.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        }
    }

    let in_out_byte_ratio = if xbox_upload > 0 {
        xbox_download as f64 / xbox_upload as f64
    } else if xbox_download > 0 {
        99.0
    } else {
        1.0
    };

    SampleMetrics {
        inbound_mbps,
        outbound_mbps,
        inbound_kpps,
        total_kpps,
        connections,
        inbound_conns,
        unknown_inbound_conns: unknown_inbound,
        xbox_download_bytes: xbox_download,
        xbox_upload_bytes: xbox_upload,
        in_out_byte_ratio,
        wan_latency_ms: snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()),
    }
}

/// Analyze inbound packets/flows for cheater-lobby indicators.
pub fn analyze_inbound(
    snapshot: &Value,
    phase: &str,
    baseline: Option<&InboundBaseline>,
    th: &AdaptiveThresholds,
) -> InboundAnalysis {
    if phase != "matchmaking" && phase != "in-match" {
        return InboundAnalysis {
            score: 0.0,
            signals: vec![],
            alerts: vec!["Not in lobby or match — inbound analysis idle".into()],
            verdict: "idle".into(),
            metrics: json!({}),
        };
    }

    let m = collect_sample_metrics(snapshot);
    let base_in = baseline.map(|b| b.inbound_mbps).unwrap_or(5.0).max(0.1);
    let base_out = baseline.map(|b| b.outbound_mbps).unwrap_or(1.0).max(0.1);
    let base_conn = baseline.map(|b| b.connections).unwrap_or(40.0);
    let base_kpps = baseline.map(|b| b.total_kpps).unwrap_or(0.08).max(0.01);

    let mut score = 0.0f64;
    let mut signals = Vec::new();
    let mut alerts = Vec::new();

    // --- Packet/sample-level (Firewalla tcpdump window) ---
    if m.inbound_mbps > th.inbound_mbps_bad
        && m.inbound_mbps > base_in * 4.0
        && m.inbound_mbps > m.outbound_mbps * 2.5
    {
        score += 0.28;
        signals.push(("inbound_flood".into(), (m.inbound_mbps / 80.0).min(1.0)));
        alerts.push(format!(
            "Inbound flood {:.1} Mbps ({}× baseline) — lag-comp / shadow-pool download burst",
            m.inbound_mbps,
            (m.inbound_mbps / base_in).round()
        ));
    } else if m.inbound_mbps > th.inbound_mbps_elevated && m.inbound_mbps > base_in * 2.5 {
        score += 0.14;
        signals.push(("inbound_elevated".into(), (m.inbound_mbps / 40.0).min(0.85)));
        alerts.push(format!(
            "Elevated inbound {:.1} Mbps vs your {:.1} Mbps baseline",
            m.inbound_mbps, base_in
        ));
    }

    if m.total_kpps > base_kpps * 8.0 && m.total_kpps > 3.0 && m.connections as f64 > base_conn * 1.8 {
        score += 0.18;
        signals.push(("packet_storm".into(), (m.total_kpps / 8.0).min(1.0)));
        alerts.push(format!(
            "Packet storm {:.1} kpps with {} connections — abnormal lobby load",
            m.total_kpps, m.connections
        ));
    }

    if m.connections > 120 {
        score += 0.16;
        signals.push(("connection_surge".into(), ((m.connections as f64 - 80.0) / 80.0).min(1.0)));
        alerts.push(format!(
            "{} active connections — lobby/boot surge pattern",
            m.connections
        ));
    }

    // --- Inbound socket fan-out ---
    if m.inbound_conns >= 8 && m.unknown_inbound_conns >= 4 {
        score += 0.20;
        signals.push((
            "unknown_inbound_fanout".into(),
            (m.unknown_inbound_conns as f64 / 12.0).min(1.0),
        ));
        alerts.push(format!(
            "{} inbound sockets from unknown hosts — peer relay / shadow pool",
            m.unknown_inbound_conns
        ));
    } else if m.inbound_conns >= 5 && m.unknown_inbound_conns >= 2 {
        score += 0.10;
        signals.push(("unknown_inbound".into(), 0.5));
        alerts.push(format!(
            "Inbound from {} unidentified remotes",
            m.unknown_inbound_conns
        ));
    }

    // --- Flow asymmetry (Xbox receiving far more than sending) ---
    if m.in_out_byte_ratio > th.in_out_ratio_bad && m.xbox_download_bytes > 512_000 {
        score += 0.16;
        signals.push(("inbound_asymmetry".into(), (m.in_out_byte_ratio / 8.0).min(1.0)));
        alerts.push(format!(
            "Download/upload ratio {:.1}× — receiving heavy lobby sync traffic",
            m.in_out_byte_ratio
        ));
    }

    // --- Role-specific inbound flows ---
    let mut role_download: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    if let Some(flows) = snapshot
        .get("recentFlows")
        .or(snapshot.get("recent_flows"))
        .and_then(|v| v.as_array())
    {
        for f in flows {
            let down = f.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
            if down == 0 {
                continue;
            }
            let remote = f.get("remote").and_then(|v| v.as_str()).unwrap_or("");
            let host = f
                .get("hostname")
                .or(f.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let role = classify_endpoint(remote, host);
            *role_download.entry(role).or_default() += down;
        }
    }

    let telemetry_dl = *role_download.get("telemetry").unwrap_or(&0);
    let game_dl = role_download.get("warzone-game").copied().unwrap_or(0)
        + role_download.get("game-assets").copied().unwrap_or(0);

    if phase == "in-match" && telemetry_dl > 256_000 && telemetry_dl > game_dl {
        score += 0.18;
        signals.push(("inbound_telemetry_spike".into(), 0.75));
        alerts.push(
            "Heavy inbound anti-cheat telemetry download — suspicious lobby telemetry".into(),
        );
    }

    if phase == "matchmaking"
        && m.connections >= 18
        && m.connections <= 45
        && m.inbound_mbps > base_in * 2.0
        && m.xbox_download_bytes > 128_000
    {
        score += 0.22;
        signals.push(("quiet_pool_inbound".into(), 0.7));
        alerts.push(format!(
            "Quiet matchmaking pool ({} conns) with heavy inbound {:.1} Mbps — cheater lobby pattern",
            m.connections, m.inbound_mbps
        ));
    }

    if phase == "in-match" && m.inbound_mbps > 15.0 && m.outbound_mbps < 3.0 {
        score += 0.12;
        signals.push(("inbound_heavy_outbound_light".into(), 0.55));
        alerts.push(
            "In-match: high inbound, low outbound — passive receive / lag-comp lobby".into(),
        );
    }

    score = score.clamp(0.0, 1.0);
    let verdict = if score >= 0.45 {
        "likely_cheater_traffic".into()
    } else if score >= 0.18 {
        "suspicious_inbound".into()
    } else {
        "normal_inbound".into()
    };

    InboundAnalysis {
        score,
        signals,
        alerts,
        verdict,
        metrics: json!({
            "inbound_mbps": round2(m.inbound_mbps),
            "outbound_mbps": round2(m.outbound_mbps),
            "total_kpps": round2(m.total_kpps),
            "connections": m.connections,
            "inbound_connections": m.inbound_conns,
            "unknown_inbound_connections": m.unknown_inbound_conns,
            "xbox_download_bytes": m.xbox_download_bytes,
            "xbox_upload_bytes": m.xbox_upload_bytes,
            "in_out_byte_ratio": round2(m.in_out_byte_ratio),
            "wan_latency_ms": m.wan_latency_ms,
            "baseline_inbound_mbps": round2(base_in),
            "baseline_connections": round2(base_conn),
            "download_by_role": role_download.iter().map(|(k,v)| (k.clone(), json!(*v))).collect::<serde_json::Map<_,_>>(),
        }),
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn connection_items(snapshot: &Value) -> Vec<Value> {
    if let Some(items) = snapshot
        .pointer("/connections/items")
        .and_then(|v| v.as_array())
    {
        if !items.is_empty() {
            return items.clone();
        }
    }
    snapshot
        .pointer("/connections/folded")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

pub fn inspect(snapshot: &Value, direction: &str) -> Value {
    let want = direction.to_lowercase();
    let all_dirs = want == "all";

    let connections = connection_items(snapshot);
    let total_count = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(connections.len() as u64);
    let items_shown = connections.len() as u64;
    let truncated = snapshot
        .pointer("/connections/truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(total_count > items_shown);

    let flows = snapshot
        .get("recentFlows")
        .or(snapshot.get("recent_flows"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out_conns = Vec::new();
    let mut in_conns = Vec::new();
    for c in &connections {
        let dir = c.get("direction").and_then(|v| v.as_str()).unwrap_or("out");
        let row = conn_row(c);
        if dir == "in" {
            in_conns.push(row);
        } else {
            out_conns.push(row);
        }
    }

    let mut out_flows = Vec::new();
    let mut in_flows = Vec::new();
    let mut xbox_upload: u64 = 0;
    let mut xbox_download: u64 = 0;
    for f in &flows {
        let up = f.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        let down = f.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
        xbox_upload += up;
        xbox_download += down;
        let row = flow_row(f);
        // Firewalla flow.direction is WAN-relative; upload/download are Xbox-relative.
        if up > 0 {
            out_flows.push(row.clone());
        }
        if down > 0 {
            in_flows.push(row);
        }
    }

    out_flows.sort_by(|a, b| {
        b.get("upload_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .cmp(
                &a.get("upload_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            )
    });
    in_flows.sort_by(|a, b| {
        b.get("download_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .cmp(
                &a.get("download_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            )
    });

    let selected_conns = if want == "in" {
        in_conns.clone()
    } else if all_dirs {
        let mut all = out_conns.clone();
        all.extend(in_conns.clone());
        all
    } else {
        out_conns.clone()
    };

    let selected_flows = if want == "in" {
        in_flows.clone()
    } else if all_dirs {
        let mut all = out_flows.clone();
        all.extend(in_flows.clone());
        all
    } else {
        out_flows.clone()
    };

    let role_summary = role_counts(&selected_conns);

    json!({
        "direction": if all_dirs { "all" } else { want.as_str() },
        "summary": {
            "connections_total": total_count,
            "connections_shown": items_shown,
            "connections_truncated": truncated,
            "connections_out": out_conns.len(),
            "connections_in": in_conns.len(),
            "connections_list": selected_conns.len(),
            "flows_with_upload": out_flows.len(),
            "flows_with_download": in_flows.len(),
            "xbox_upload_bytes": xbox_upload,
            "xbox_download_bytes": xbox_download,
            "sample_window_sec": snapshot.pointer("/sample/windowSec"),
            "sample_bytes_out": snapshot.pointer("/sample/bytesOut"),
            "sample_bytes_in": snapshot.pointer("/sample/bytesIn"),
            "flow_source": snapshot.get("flowSource").or(snapshot.get("flow_source")),
            "note": "Connections use socket direction; flow upload/download are Xbox-relative (Firewalla flow.direction is WAN-relative).",
        },
        "by_role": role_summary,
        "connections": selected_conns.iter().take(96).collect::<Vec<_>>(),
        "flows": selected_flows.iter().take(48).collect::<Vec<_>>(),
        "dns_destinations": snapshot
            .get("dnsDestinations")
            .or(snapshot.get("dns_destinations")),
    })
}

fn conn_row(c: &Value) -> Value {
    let host = c
        .get("hostname")
        .or(c.get("label"))
        .or(c.get("host"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let role = c
        .get("roleId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| classify_value(c));
    json!({
        "direction": c.get("direction").unwrap_or(&json!("out")),
        "proto": c.get("proto"),
        "state": c.get("state"),
        "hostname": if host.is_empty() { Value::Null } else { json!(host) },
        "role": role,
        "remote": c.get("remote"),
        "ip": c.get("ip"),
        "port": c.get("port"),
        "scope": c.get("scope"),
        "latency_ms": c.get("latencyMs"),
        "local": c.get("local"),
    })
}

fn flow_row(f: &Value) -> Value {
    let remote = f.get("remote").and_then(|v| v.as_str()).unwrap_or("");
    let host = f
        .get("hostname")
        .or(f.get("label"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let role = classify_endpoint(remote, host);
    json!({
        "direction": f.get("direction"),
        "hostname": if host.is_empty() { Value::Null } else { json!(host) },
        "role": role,
        "remote": f.get("remote"),
        "category": f.get("category"),
        "upload_bytes": f.get("upload"),
        "download_bytes": f.get("download"),
        "duration_sec": f.get("duration"),
        "timestamp": f.get("timestamp"),
    })
}

fn role_counts(conns: &[Value]) -> Value {
    let mut counts = std::collections::BTreeMap::new();
    for c in conns {
        let role = c
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *counts.entry(role).or_insert(0u32) += 1;
    }
    let mut rows: Vec<_> = counts
        .into_iter()
        .map(|(role, n)| json!({"role": role, "count": n}))
        .collect();
    rows.sort_by(|a, b| {
        b.get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .cmp(&a.get("count").and_then(|v| v.as_u64()).unwrap_or(0))
    });
    json!(rows)
}

pub fn format_bytes(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
