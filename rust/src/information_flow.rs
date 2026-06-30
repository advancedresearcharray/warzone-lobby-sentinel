//! Information Flow Complexity (Zenodo 17373031).
//!
//! Flow(M,x,t) = H(State_t | State_{t-1}) — measures new information per
//! computational step. Applied to network/packet state for cheat detection.

use serde_json::{json, Value};
use std::collections::HashMap;

pub const ZENODO_URL: &str = "https://zenodo.org/records/17373031";
pub const ZENODO_DOI: &str = "10.5281/zenodo.17373031";

#[derive(Clone, Debug, Default)]
pub struct NetworkState {
    pub flows: u8,
    pub ports: u8,
    pub hosts: u8,
    pub tcp_ratio: u8,
    pub udp_ratio: u8,
    pub tiny_in_ratio: u8,
    pub unique_in_remotes: u8,
    pub conns: u8,
    pub phase: u8,
}

impl NetworkState {
    pub fn key(&self) -> String {
        format!(
            "f={} p={} h={} t={} u={} ti={} ir={} c={} ph={}",
            self.flows,
            self.ports,
            self.hosts,
            self.tcp_ratio,
            self.udp_ratio,
            self.tiny_in_ratio,
            self.unique_in_remotes,
            self.conns,
            self.phase
        )
    }
}

fn discretize(v: f64, edges: &[f64]) -> u8 {
    for (i, &e) in edges.iter().enumerate() {
        if v <= e {
            return i as u8;
        }
    }
    edges.len() as u8
}

pub fn state_from_snapshot(snapshot: &Value, conns: i64, phase: &str) -> NetworkState {
    let st = snapshot
        .pointer("/packetCapture/stats")
        .or_else(|| snapshot.pointer("/packet_capture/stats"));

    let total = st.and_then(|s| s.get("total")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let inbound = st.and_then(|s| s.get("inbound")).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let tiny_in = st
        .and_then(|s| s.get("tinyInbound"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let unique_in = st
        .and_then(|s| s.get("uniqueInboundRemotes"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let udp_in = st.and_then(|s| s.get("udpInbound")).and_then(|v| v.as_f64()).unwrap_or(0.0);

    let tcp_ratio = if total > 0.0 {
        (total - udp_in.min(total)) / total
    } else {
        0.0
    };
    let udp_ratio = if total > 0.0 { udp_in / total } else { 0.0 };
    let tiny_ratio = if inbound > 0.0 { tiny_in / inbound } else { 0.0 };

    let flow_count = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_i64())
        .unwrap_or(conns) as f64;

    let phase_code = match phase {
        "matchmaking" => 2,
        "in-match" => 3,
        "background" => 1,
        _ => 0,
    };

    NetworkState {
        flows: discretize(flow_count, &[15.0, 40.0, 70.0, 100.0, 150.0]),
        ports: discretize(unique_in, &[3.0, 8.0, 14.0, 22.0]),
        hosts: discretize(unique_in, &[4.0, 10.0, 18.0, 30.0]),
        tcp_ratio: discretize(tcp_ratio, &[0.2, 0.4, 0.6, 0.8]),
        udp_ratio: discretize(udp_ratio, &[0.2, 0.4, 0.6, 0.8]),
        tiny_in_ratio: discretize(tiny_ratio, &[0.15, 0.3, 0.45, 0.6]),
        unique_in_remotes: discretize(unique_in, &[4.0, 8.0, 14.0, 20.0]),
        conns: discretize(conns as f64, &[30.0, 60.0, 90.0, 130.0]),
        phase: phase_code,
    }
}

pub fn shannon_entropy(counts: &HashMap<u8, u32>) -> f64 {
    let n: u32 = counts.values().sum();
    if n == 0 {
        return 0.0;
    }
    let nf = n as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / nf;
            -p * p.log2()
        })
        .sum()
}

pub fn flow_surprisal(transitions: &HashMap<String, HashMap<String, u32>>, prev: &str, cur: &str) -> f64 {
    let bucket = transitions.get(prev);
    let total: u32 = bucket.map(|b| b.values().sum()).unwrap_or(0);
    if total == 0 {
        return 8.0;
    }
    let count = bucket.and_then(|b| b.get(cur)).copied().unwrap_or(0);
    let p = (count.max(1) as f64) / ((total + 1) as f64);
    (-p.log2()).max(0.0)
}

pub fn flow_transition_bytes(prev: &[u8], cur: &[u8]) -> f64 {
    if cur.is_empty() {
        return 0.0;
    }
    let n = prev.len().min(cur.len()).min(4096);
    if n == 0 {
        return 8.0;
    }
    let mut counts: HashMap<u8, u32> = HashMap::new();
    for i in 0..n {
        let d = cur[i] ^ prev.get(i).copied().unwrap_or(0);
        *counts.entry(d).or_insert(0) += 1;
    }
    shannon_entropy(&counts)
}

pub fn compression_bound_bits(certificates: u32) -> f64 {
    let n = certificates.max(1) as f64;
    n.log2()
}

pub fn pigeonhole_min_flow(total_bits: f64, steps: u32) -> f64 {
    if steps == 0 {
        return total_bits;
    }
    total_bits / steps as f64
}

pub fn prg_uniformity(data: &[u8]) -> (f64, f64, bool) {
    if data.len() < 32 {
        return (0.0, 0.0, false);
    }
    let sample = &data[..data.len().min(512)];
    let mut counts = [0u32; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let mut map: HashMap<u8, u32> = HashMap::new();
    for (i, &c) in counts.iter().enumerate() {
        if c > 0 {
            map.insert(i as u8, c);
        }
    }
    let ent = shannon_entropy(&map);
    let expected = sample.len() as f64 / 256.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected.max(1e-6)
        })
        .sum();
    let uniformity = (1.0 - chi / 512.0).clamp(0.0, 1.0);
    let prg_like = ent >= 7.2 && uniformity >= 0.65;
    (ent, uniformity, prg_like)
}

#[derive(Clone, Debug, Default)]
pub struct FlowStep {
    pub flow_bits: f64,
    pub total_flow_bits: f64,
    pub steps: u32,
    pub superlinear: bool,
    pub prg_like: bool,
    pub byte_flow: f64,
    pub alerts: Vec<String>,
}

#[derive(Default)]
pub struct InformationFlowTracker {
    transitions: HashMap<String, HashMap<String, u32>>,
    last_key: String,
    total_flow_bits: f64,
    steps: u32,
    prev_bytes: Vec<u8>,
}

impl InformationFlowTracker {
    pub fn step(&mut self, state: &NetworkState, packet_bytes: &[u8]) -> FlowStep {
        let cur_key = state.key();
        let mut flow = 0.0;
        if !self.last_key.is_empty() && self.last_key != cur_key {
            flow = flow_surprisal(&self.transitions, &self.last_key, &cur_key);
            self.transitions
                .entry(self.last_key.clone())
                .or_default()
                .entry(cur_key.clone())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            self.steps += 1;
            self.total_flow_bits += flow;
        }
        self.last_key = cur_key;

        let byte_flow = if !self.prev_bytes.is_empty() && !packet_bytes.is_empty() {
            flow_transition_bytes(&self.prev_bytes, packet_bytes)
        } else {
            0.0
        };
        if !packet_bytes.is_empty() {
            self.prev_bytes = packet_bytes[..packet_bytes.len().min(512)].to_vec();
        }

        let cert_bits = compression_bound_bits(self.transitions.len().max(1) as u32 * 8);
        let min_step = pigeonhole_min_flow(cert_bits, self.steps.max(1));
        let superlinear = flow > min_step * 2.0 && flow >= 4.0 && self.steps >= 3;

        let (_, _, prg_like) = prg_uniformity(packet_bytes);

        let mut alerts = Vec::new();
        if superlinear {
            alerts.push(format!(
                "Super-linear IFC step: {flow:.2} bits (bound {min_step:.2})"
            ));
        }
        if prg_like && (state.phase == 2 || state.phase == 3) {
            alerts.push("PRG-like byte uniformity in packet window — synthetic traffic proxy".into());
        }
        if byte_flow >= 7.0 && (state.phase == 2 || state.phase == 3) {
            alerts.push(format!("High byte-transition entropy {byte_flow:.2} bits"));
        }

        FlowStep {
            flow_bits: (flow * 10000.0).round() / 10000.0,
            total_flow_bits: (self.total_flow_bits * 10000.0).round() / 10000.0,
            steps: self.steps,
            superlinear,
            prg_like,
            byte_flow: (byte_flow * 10000.0).round() / 10000.0,
            alerts,
        }
    }

    pub fn to_json(&self, step: &FlowStep) -> Value {
        json!({
            "zenodo": { "doi": ZENODO_DOI, "url": ZENODO_URL },
            "definition": "Flow(M,x,t) = H(State_t | State_{t-1})",
            "flow_bits": step.flow_bits,
            "byte_flow_bits": step.byte_flow,
            "total_flow_bits": step.total_flow_bits,
            "steps": step.steps,
            "superlinear_flow": step.superlinear,
            "prg_like": step.prg_like,
            "alerts": step.alerts,
            "barriers": {
                "natural_proofs": "dynamic real-valued measure — not boolean function property",
                "relativization": "internal state transitions — not oracle black-box",
                "algebraization": "Shannon entropy — not finite-field algebra",
            },
        })
    }
}

pub fn packet_byte_fingerprint(snapshot: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    let recs = snapshot
        .pointer("/packetCapture/records")
        .or_else(|| snapshot.pointer("/packet_capture/records"))
        .and_then(|v| v.as_array());
    let Some(recs) = recs else {
        return out;
    };
    for r in recs.iter().take(128) {
        let len = r.get("len").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let proto = if r.get("proto").and_then(|v| v.as_str()) == Some("udp") {
            1u8
        } else {
            2u8
        };
        out.push(len);
        out.push(proto);
        let ip = r
            .get("remote")
            .or_else(|| r.get("src"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        for part in ip.split('.').take(4) {
            if let Ok(oct) = part.parse::<u8>() {
                out.push(oct);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_state_zero_surprisal_after_learning() {
        let mut t: HashMap<String, HashMap<String, u32>> = HashMap::new();
        t.entry("a".into()).or_default().insert("b".into(), 10);
        let s = flow_surprisal(&t, "a", "b");
        assert!(s < 1.0);
    }

    #[test]
    fn byte_flow_nonzero_on_change() {
        let a = flow_transition_bytes(b"hello", b"world");
        assert!(a > 0.0);
    }
}
