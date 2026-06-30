//! Direct packet capture inspection for cheat behavior (tcpdump records from array-firewall).

use crate::enrich::{
    classify_endpoint_with_port, classify_inbound_endpoint, extract_ip, inbound_display_label,
    is_game_peer, is_infrastructure, is_known_traffic, is_unknown_inbound, is_vps_game_peer,
    is_vps_probe_role,
    resolve_inbound_peer_role, should_drop_inbound, should_show_in_peer_table,
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
        _ => return no_capture_analysis(snapshot),
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
        let role = classify_inbound_endpoint(remote, host, port, proto);
        if should_drop_inbound(&role, port, proto, phase) {
            continue;
        }
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
        if should_drop_inbound(&classify_record_role(&recs, remote), None, "udp", phase) {
            continue;
        }
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
            micro_burst_peer = is_vps_probe_role(&classify_record_role(&recs, remote));
        }
    }

    // Game-peer probe traffic (P2P / VPS peers — likely kick probe source)
    let peer_report = analyze_game_peers(&recs);
    let identical_peers = analyze_inbound_identical(&recs, phase);
    let mut peer_tiny_in = 0u32;
    let mut peer_in = 0u32;
    let mut suspicious: Vec<Value> = Vec::new();
    for row in &identical_peers {
        let label = row.get("label").and_then(|v| v.as_str()).unwrap_or("");
        let role = row.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if row.get("vps_probe").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(ip) = row.get("ip").and_then(|v| v.as_str()) {
                suspicious.push(json!({
                    "ip": ip,
                    "label": label,
                    "role": role,
                    "vps_probe": true,
                    "reason": "vultr_vps_probe",
                }));
            }
        }
    }
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
    if !suspicious.is_empty() {
        score += 0.18;
        signals.push((
            "suspicious_peer".into(),
            (suspicious.len() as f64 / 3.0).min(1.0),
        ));
        alerts.push(format!(
            "{} VPS probe host(s) detected — auto-block active",
            suspicious.len()
        ));
    } else if !peer_report.suspicious.is_empty() {
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
            "suspicious_peers": suspicious,
            "vps_game_peers": identical_peers
                .iter()
                .filter(|row| row.get("vps_probe").and_then(|v| v.as_bool()) == Some(true))
                .collect::<Vec<_>>(),
            "inbound_identical_peers": identical_peers,
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
struct IdenticalPeerAgg {
    ip: String,
    remote: String,
    hostname: String,
    label: String,
    role: String,
    total: u32,
    tiny: u32,
    max_identical: u32,
    identical_size: u64,
    packet_size_min: u64,
    packet_size_max: u64,
}

/// Per inbound IP: max run of same-size packets in the capture window.
fn analyze_inbound_identical(recs: &[Value], phase: &str) -> Vec<Value> {
    let mut by_ip: HashMap<String, IdenticalPeerAgg> = HashMap::new();
    let mut size_runs: HashMap<String, u32> = HashMap::new();

    for r in recs {
        if r.get("dir").and_then(|v| v.as_str()) != Some("in") {
            continue;
        }
        let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("?");
        let ip = extract_ip(remote);
        if ip.is_empty() {
            continue;
        }
        let len = r.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        let host = r.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
        let role = record_role(r);
        if !should_show_in_peer_table(&role, phase) {
            continue;
        }
        let entry = by_ip.entry(ip.clone()).or_insert_with(|| IdenticalPeerAgg {
            ip: ip.clone(),
            remote: remote.to_string(),
            hostname: host.to_string(),
            label: inbound_display_label(&ip, host, &role),
            role: role.clone(),
            ..Default::default()
        });
        if entry.role.is_empty() || entry.role == "unknown" {
            entry.role = role;
        }
        entry.total += 1;
        if len > 0 {
            if entry.packet_size_min == 0 || len < entry.packet_size_min {
                entry.packet_size_min = len;
            }
            if len > entry.packet_size_max {
                entry.packet_size_max = len;
            }
        }
        if len <= TINY_PKT_MAX {
            entry.tiny += 1;
        }
        let burst_key = format!("{ip}:{len}");
        let burst = size_runs.entry(burst_key).or_insert(0);
        *burst += 1;
        if *burst > entry.max_identical {
            entry.max_identical = *burst;
            entry.identical_size = len;
        }
    }

    let mut rows: Vec<Value> = by_ip
        .values()
        .map(|p| {
            let role = resolve_inbound_peer_role(
                &p.ip,
                &p.hostname,
                &p.role,
                p.max_identical,
                u64::from(p.tiny),
                u64::from(p.total),
                p.packet_size_min,
                p.packet_size_max,
            );
            let label = inbound_display_label(&p.ip, &p.hostname, &role);
            let confirmed = is_vps_probe_role(&role);
            let vps_probe = is_vps_probe_role(&role) && is_vps_game_peer(&label, &role);
            let fixed_size = p.packet_size_min > 0
                && p.packet_size_min == p.packet_size_max
                && p.max_identical >= PEER_BURST_SIGNAL;
            json!({
                "ip": p.ip,
                "remote": p.remote,
                "label": label,
                "role": role,
                "confirmed": confirmed,
                "total_packets": p.total,
                "tiny_packets": p.tiny,
                "identical_count": p.max_identical,
                "identical_size": p.identical_size,
                "packet_size_min": p.packet_size_min,
                "packet_size_max": p.packet_size_max,
                "fixed_size": fixed_size,
                "vps_probe": vps_probe,
                "suspicious": confirmed
                    && (vps_probe
                        || fixed_size
                        || p.max_identical >= PEER_BURST_SIGNAL
                        || p.tiny >= PEER_TINY_SIGNAL
                        || (p.tiny >= 3 && p.total >= 6)),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let ac = a.get("identical_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bc = b.get("identical_count").and_then(|v| v.as_u64()).unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            a.get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("ip").and_then(|v| v.as_str()).unwrap_or(""))
        })
    });
    rows
}

fn parse_port(r: &Value) -> Option<u16> {
    r.get("remotePort").and_then(|v| v.as_u64()).map(|p| p as u16)
}

fn proto_from(r: &Value) -> &str {
    r.get("proto").and_then(|v| v.as_str()).unwrap_or("")
}

fn record_role(r: &Value) -> String {
    if let Some(rid) = r.get("roleId").and_then(|v| v.as_str()) {
        if !rid.is_empty() {
            return rid.to_string();
        }
    }
    let remote = r.get("remote").and_then(|v| v.as_str()).unwrap_or("");
    let host = r.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
    let port = parse_port(r);
    let proto = proto_from(r);
    if r.get("dir").and_then(|v| v.as_str()) == Some("in") {
        return classify_inbound_endpoint(remote, host, port, proto);
    }
    classify_endpoint_with_port(remote, host, port, proto)
}

fn classify_record_role(recs: &[Value], remote: &str) -> String {
    for r in recs {
        if r.get("remote").and_then(|v| v.as_str()) == Some(remote) {
            return record_role(r);
        }
    }
    classify_inbound_endpoint(remote, "", None, "udp")
}

fn analyze_game_peers(_recs: &[Value]) -> PeerReport {
    // Unverified P2P-shaped traffic is dropped at console shield — not scored or alerted.
    PeerReport {
        alerts: vec![],
        suspicious: vec![],
        max_tiny: 0,
        max_burst: 0,
    }
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

fn no_capture_analysis(snapshot: &Value) -> PacketAnalysis {
    let online = snapshot
        .pointer("/xbox/online")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let capture_enabled = snapshot
        .pointer("/packetCapture/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let stats_disabled = stats(snapshot)
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        == Some(false);
    let pressure = snapshot
        .pointer("/preabstract/mode")
        .and_then(|v| v.as_str())
        .unwrap_or("normal");
    let window_sec = snapshot
        .pointer("/sample/windowSec")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    let (alert, reason) = if !online {
        (
            "Xbox offline — packet capture runs when the console is on the network.",
            "xbox_offline",
        )
    } else if !capture_enabled || stats_disabled || pressure != "normal" {
        (
            "Packet capture paused on array-firewall (memory pressure mode).",
            "memory_pressure",
        )
    } else {
        (
            "No Xbox traffic in the capture window — idle or between Warzone sessions.",
            "idle_window",
        )
    };

    PacketAnalysis {
        score: 0.0,
        signals: vec![],
        alerts: vec![alert.into()],
        verdict: "no_capture".into(),
        metrics: json!({
            "enabled": false,
            "reason": reason,
            "xbox_online": online,
            "capture_enabled": capture_enabled,
            "pressure_mode": pressure,
            "window_sec": window_sec,
        }),
    }
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
