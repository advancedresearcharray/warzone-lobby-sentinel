//! Direct packet capture inspection for cheat behavior (tcpdump records from Firewalla).

use crate::enrich::{
    classify_endpoint_with_port, extract_ip, is_game_peer, is_known_traffic, is_unknown_inbound,
    peer_display_label,
};
use serde_json::{json, Value};
use std::collections::HashMap;

const TINY_PKT_MAX: u64 = 79;
const PEER_TINY_SIGNAL: u32 = 4;
const PEER_BURST_SIGNAL: u32 = 6;

#[derive(Clone, Debug)]
pub struct PacketAnalysis {
    pub score: f64,
    pub signals: Vec<(String, f64)>,
    pub alerts: Vec<String>,
    pub verdict: String,
    pub metrics: Value,
}

impl PacketAnalysis {
    pub fn to_json(&self) -> Value {
        json!({
            "score": (self.score * 1000.0).round() / 10.0,
            "verdict": self.verdict,
            "alerts": self.alerts,
            "signals": self
                .signals
                .iter()
                .map(|(k, v)| (k.clone(), json!((v * 1000.0).round() / 1000.0)))
                .collect::<serde_json::Map<_, _>>(),
            "metrics": self.metrics,
        })
    }
}

fn packet_block(snapshot: &Value) -> Option<&Value> {
    snapshot.get("packetCapture").or(snapshot.get("packet_capture"))
}

fn stats(snapshot: &Value) -> Option<&Value> {
    packet_block(snapshot).and_then(|p| p.get("stats"))
}

fn records(snapshot: &Value) -> Vec<Value> {
    packet_block(snapshot)
        .and_then(|p| p.get("records"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Analyze captured packets for cheater-lobby behavior.
pub fn analyze_packets(snapshot: &Value, phase: &str, conns: i64) -> PacketAnalysis {
    if phase != "matchmaking" && phase != "in-match" {
        return idle_analysis("Not in lobby or match");
    }

    let st = match stats(snapshot) {
        Some(s) if s.get("total").and_then(|v| v.as_u64()).unwrap_or(0) > 0 => s,
        _ => {
            return PacketAnalysis {
                score: 0.0,
                signals: vec![],
                alerts: vec!["Packet capture unavailable (Firewalla tcpdump skipped or idle)".into()],
                verdict: "no_capture".into(),
                metrics: json!({"enabled": false}),
            };
        }
    };

    let total = st.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let inbound = st.get("inbound").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let tiny_in = st.get("tinyInbound").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let large_in = st.get("largeInbound").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let unique_in = st.get("uniqueInboundRemotes").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let udp_in = st.get("udpInbound").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let syn_in = st.get("tcpSynInbound").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
    let avg_in = st.get("avgInboundSize").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let avg_out = st.get("avgOutboundSize").and_then(|v| v.as_f64()).unwrap_or(0.0);

    let mut score = 0.0f64;
    let mut signals = Vec::new();
    let mut alerts = Vec::new();

    let in_ratio = if total > 0.0 { inbound / total } else { 0.0 };
    let tiny_in_ratio = if inbound > 0.0 { tiny_in / inbound } else { 0.0 };

    // Probe/flood: many tiny inbound packets
    if tiny_in >= 15.0 && tiny_in_ratio >= 0.35 {
        score += 0.24;
        signals.push(("tiny_packet_flood".into(), (tiny_in / 40.0).min(1.0)));
        alerts.push(format!(
            "{tiny_in:.0} tiny inbound packets ({:.0}% of capture) — probe/stress pattern",
            tiny_in_ratio * 100.0
        ));
    } else if tiny_in >= 8.0 && tiny_in_ratio >= 0.25 {
        score += 0.12;
        signals.push(("tiny_packet_elevated".into(), 0.5));
        alerts.push(format!("Elevated tiny inbound packets ({tiny_in:.0})"));
    }

    // Many distinct inbound remotes in short window — peer fan-out / shadow pool
    if unique_in >= 12.0 {
        score += 0.22;
        signals.push(("inbound_remote_fanout".into(), (unique_in / 20.0).min(1.0)));
        alerts.push(format!(
            "{unique_in:.0} unique inbound remotes in packet window — multi-peer lobby load"
        ));
    } else if unique_in >= 7.0 && phase == "matchmaking" {
        score += 0.14;
        signals.push(("inbound_remote_elevated".into(), 0.55));
        alerts.push(format!("Multiple inbound remotes ({unique_in:.0}) during matchmaking"));
    }

    // TCP SYN inbound without normal gaming profile
    if syn_in >= 3.0 {
        score += 0.20;
        signals.push(("tcp_syn_inbound".into(), (syn_in / 8.0).min(1.0)));
        alerts.push(format!("{syn_in:.0} inbound TCP SYN packets — connection probe pattern"));
    }

    // Heavy UDP inbound during quiet connection count
    if udp_in >= 20.0 && conns >= 18 && conns <= 50 {
        score += 0.18;
        signals.push(("udp_inbound_quiet_pool".into(), 0.65));
        alerts.push(format!(
            "{udp_in:.0} inbound UDP packets with only {conns} connections — quiet cheater pool"
        ));
    }

    // Large inbound game-sized packets from many sources (lag-comp sync)
    if large_in >= 8.0 && unique_in >= 5.0 {
        score += 0.16;
        signals.push(("large_inbound_burst".into(), (large_in / 20.0).min(1.0)));
        alerts.push(format!(
            "{large_in:.0} large inbound packets from {unique_in:.0} remotes — lobby sync burst"
        ));
    }

    // Inbound-heavy packet ratio with low outbound avg size (passive receive manipulation)
    if in_ratio >= 0.65 && avg_in > 200.0 && avg_out < 120.0 && inbound >= 30.0 {
        score += 0.14;
        signals.push(("inbound_packet_asymmetry".into(), in_ratio));
        alerts.push(format!(
            "Inbound packet ratio {:.0}% with avg in {avg_in:.0}B vs out {avg_out:.0}B",
            in_ratio * 100.0
        ));
    }

    // Role classification on packet remotes
    let recs = records(snapshot);
    let mut unknown_in = 0u32;
    let mut game_in = 0u32;
    for r in &recs {
        if r.get("dir").and_then(|v| v.as_str()) != Some("in") {
            continue;
        }
        let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("");
        let host = r.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
        let port = r.get("remotePort").and_then(|v| v.as_u64()).map(|p| p as u16);
        let proto = r.get("proto").and_then(|v| v.as_str()).unwrap_or("");
        let role = classify_endpoint_with_port(remote, host, port, proto);
        if is_unknown_inbound(&role) {
            unknown_in += 1;
        } else if is_known_traffic(&role) {
            game_in += 1;
        }
    }
    if unknown_in >= 10 && unknown_in > game_in {
        score += 0.18;
        signals.push(("unknown_inbound_packets".into(), (unknown_in as f64 / 30.0).min(1.0)));
        alerts.push(format!(
            "{unknown_in} inbound packets from unknown hosts vs {game_in} game-tagged"
        ));
    }

    // Micro-burst: same remote, same size, many packets
    let mut size_runs: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for r in &recs {
        if r.get("dir").and_then(|v| v.as_str()) != Some("in") {
            continue;
        }
        let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("?");
        let len = r.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        *size_runs.entry(format!("{remote}:{len}")).or_default() += 1;
    }
    let mut micro_burst_peer = false;
    if let Some((key, count)) = size_runs.iter().max_by_key(|(_, c)| *c) {
        if *count >= 12 {
            score += 0.12;
            signals.push(("micro_burst".into(), (*count as f64 / 25.0).min(1.0)));
            alerts.push(format!(
                "Micro-burst: {count} identical-size packets from {key}"
            ));
        }
        if *count >= PEER_BURST_SIGNAL {
            let remote = key.rsplit_once(':').map(|(r, _)| r).unwrap_or(key.as_str());
            micro_burst_peer = is_game_peer(&classify_record_role(&recs, remote));
        }
    }

    // Game-peer probe traffic (P2P / VPS peers — likely kick probe source)
    let peer_report = analyze_game_peers(&recs);
    let mut peer_tiny_in = 0u32;
    let mut peer_in = 0u32;
    for alert in &peer_report.alerts {
        alerts.push(alert.clone());
    }
    if peer_report.max_tiny >= PEER_TINY_SIGNAL {
        peer_tiny_in = peer_report.max_tiny;
        score += 0.20;
        signals.push((
            "peer_tiny_flood".into(),
            (peer_report.max_tiny as f64 / 12.0).min(1.0),
        ));
    }
    if peer_report.max_burst >= PEER_BURST_SIGNAL || micro_burst_peer {
        score += 0.18;
        let burst = peer_report
            .max_burst
            .max(if micro_burst_peer { PEER_BURST_SIGNAL } else { 0 });
        signals.push(("peer_micro_burst".into(), (burst as f64 / 15.0).min(1.0)));
    }
    if !peer_report.suspicious.is_empty() {
        score += 0.15;
        signals.push((
            "suspicious_peer".into(),
            (peer_report.suspicious.len() as f64 / 3.0).min(1.0),
        ));
        peer_in = peer_report
            .suspicious
            .iter()
            .map(|p| p.get("packets").and_then(|v| v.as_u64()).unwrap_or(0) as u32)
            .sum();
    }

    score = score.clamp(0.0, 1.0);
    let verdict = if score >= 0.42 {
        "likely_cheat_packets".into()
    } else if score >= 0.16 {
        "suspicious_packets".into()
    } else {
        "normal_packets".into()
    };

    PacketAnalysis {
        score,
        signals,
        alerts,
        verdict,
        metrics: json!({
            "enabled": true,
            "total": total,
            "inbound": inbound,
            "outbound": st.get("outbound"),
            "inbound_ratio": round2(in_ratio),
            "tiny_inbound": tiny_in,
            "large_inbound": large_in,
            "unique_inbound_remotes": unique_in,
            "udp_inbound": udp_in,
            "tcp_syn_inbound": syn_in,
            "avg_inbound_size": avg_in,
            "avg_outbound_size": avg_out,
            "unknown_inbound_packets": unknown_in,
            "game_inbound_packets": game_in,
            "peer_inbound_packets": peer_in,
            "peer_tiny_inbound": peer_tiny_in,
            "suspicious_peers": peer_report.suspicious,
            "records_in_snapshot": recs.len(),
        }),
    }
}

struct PeerReport {
    alerts: Vec<String>,
    suspicious: Vec<Value>,
    max_tiny: u32,
    max_burst: u32,
}

#[derive(Default)]
struct PeerAgg {
    ip: String,
    remote: String,
    label: String,
    tiny: u32,
    total: u32,
    max_same_size: u32,
}

fn record_role(r: &Value) -> String {
    if let Some(rid) = r.get("roleId").and_then(|v| v.as_str()) {
        if !rid.is_empty() {
            return rid.to_string();
        }
    }
    let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("");
    let host = r.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
    let port = r.get("remotePort").and_then(|v| v.as_u64()).map(|p| p as u16);
    let proto = r.get("proto").and_then(|v| v.as_str()).unwrap_or("");
    classify_endpoint_with_port(remote, host, port, proto)
}

fn classify_record_role(recs: &[Value], remote: &str) -> String {
    for r in recs {
        if r.get("remote").and_then(|v| v.as_str()) == Some(remote) {
            return record_role(r);
        }
    }
    classify_endpoint_with_port(remote, "", None, "udp")
}

fn analyze_game_peers(recs: &[Value]) -> PeerReport {
    let mut by_ip: HashMap<String, PeerAgg> = HashMap::new();
    let mut size_runs: HashMap<String, u32> = HashMap::new();

    for r in recs {
        if r.get("dir").and_then(|v| v.as_str()) != Some("in") {
            continue;
        }
        let role = record_role(r);
        if !is_game_peer(&role) {
            continue;
        }
        let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("?");
        let ip = extract_ip(remote);
        if ip.is_empty() {
            continue;
        }
        let len = r.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        let host = r.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
        let entry = by_ip.entry(ip.clone()).or_insert_with(|| PeerAgg {
            ip: ip.clone(),
            remote: remote.to_string(),
            label: peer_display_label(&ip, host),
            ..Default::default()
        });
        entry.total += 1;
        if len <= TINY_PKT_MAX {
            entry.tiny += 1;
        }
        let burst_key = format!("{remote}:{len}");
        let burst = size_runs.entry(burst_key).or_insert(0);
        *burst += 1;
        entry.max_same_size = entry.max_same_size.max(*burst);
    }

    let mut report = PeerReport {
        alerts: vec![],
        suspicious: vec![],
        max_tiny: 0,
        max_burst: 0,
    };

    for peer in by_ip.values() {
        report.max_tiny = report.max_tiny.max(peer.tiny);
        report.max_burst = report.max_burst.max(peer.max_same_size);
        let suspicious = peer.tiny >= PEER_TINY_SIGNAL
            || peer.max_same_size >= PEER_BURST_SIGNAL
            || (peer.tiny >= 3 && peer.total >= 6);
        if !suspicious {
            continue;
        }
        let mut reasons = Vec::new();
        if peer.tiny >= PEER_TINY_SIGNAL {
            reasons.push(format!("{} tiny packets", peer.tiny));
        }
        if peer.max_same_size >= PEER_BURST_SIGNAL {
            reasons.push(format!("burst×{}", peer.max_same_size));
        }
        report.alerts.push(format!(
            "Suspicious peer: {} @ {} — {}",
            peer.label,
            peer.ip,
            reasons.join(", ")
        ));
        report.suspicious.push(json!({
            "ip": peer.ip,
            "remote": peer.remote,
            "label": peer.label,
            "vendor": peer.label,
            "packets": peer.total,
            "tiny_packets": peer.tiny,
            "max_burst": peer.max_same_size,
            "reasons": reasons,
        }));
    }

    report
}

pub fn inspect_capture(capture: &Value, phase: &str, conns: i64) -> Value {
    let analysis = analyze_packets(capture, phase, conns);
    let recs = capture
        .get("records")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let flows = capture
        .get("flows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    json!({
        "analysis": analysis.to_json(),
        "captured": capture.get("captured"),
        "captureCount": capture.get("captureCount"),
        "records": recs.iter().take(100).collect::<Vec<_>>(),
        "flows": flows.iter().take(24).collect::<Vec<_>>(),
        "stats": capture.get("stats"),
    })
}

fn idle_analysis(msg: &str) -> PacketAnalysis {
    PacketAnalysis {
        score: 0.0,
        signals: vec![],
        alerts: vec![msg.into()],
        verdict: "idle".into(),
        metrics: json!({}),
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
