use crate::cheater_lobby::{role_pairs, CheaterVerdict};
use crate::enrich::phase_code;
use crate::fold::{compress_folds, cosine_similarity, fold_telemetry, FOLD_DIM};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::OnceLock;

const MAX_SAMPLES: usize = 120;
const MIN_SAMPLES: usize = 8;
const MAX_SESSIONS: usize = 40;
const MAX_OUTCOMES: usize = 50;
const MAX_LOBBIES: usize = 200;

fn is_good_label(label: &str) -> bool {
    label == "CLEAN" || label == "USER_GOOD"
}

fn is_marginal_label(label: &str) -> bool {
    label == "POSSIBLE" || label == "USER_MARGINAL"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdaptiveThresholds {
    #[serde(default = "def_conn_high")]
    pub conn_matchmaking_high: f64,
    #[serde(default = "def_conn_elev")]
    pub conn_matchmaking_elevated: f64,
    #[serde(default = "def_mm_bad")]
    pub mm_delta_bad: f64,
    #[serde(default = "def_mm_warn")]
    pub mm_delta_warn: f64,
    #[serde(default = "def_jitter")]
    pub jitter_bad: f64,
    #[serde(default = "def_wan_jitter")]
    pub wan_jitter_bad: f64,
    #[serde(default)]
    pub conn_good_ceiling: f64,
    #[serde(default)]
    pub conn_marginal_low: f64,
    #[serde(default)]
    pub conn_marginal_high: f64,
    #[serde(default = "def_inbound_elev")]
    pub inbound_mbps_elevated: f64,
    #[serde(default = "def_inbound_bad")]
    pub inbound_mbps_bad: f64,
    #[serde(default = "def_in_out_ratio")]
    pub in_out_ratio_bad: f64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub samples: usize,
}

fn def_conn_high() -> f64 {
    90.0
}
fn def_conn_elev() -> f64 {
    55.0
}
fn def_mm_bad() -> f64 {
    45.0
}
fn def_mm_warn() -> f64 {
    25.0
}
fn def_jitter() -> f64 {
    14.0
}
fn def_wan_jitter() -> f64 {
    18.0
}
fn def_inbound_elev() -> f64 {
    25.0
}
fn def_inbound_bad() -> f64 {
    80.0
}
fn def_in_out_ratio() -> f64 {
    6.0
}

impl Default for AdaptiveThresholds {
    fn default() -> Self {
        Self {
            conn_matchmaking_high: 90.0,
            conn_matchmaking_elevated: 55.0,
            mm_delta_bad: 45.0,
            mm_delta_warn: 25.0,
            jitter_bad: 14.0,
            wan_jitter_bad: 18.0,
            conn_good_ceiling: 0.0,
            conn_marginal_low: 0.0,
            conn_marginal_high: 0.0,
            inbound_mbps_elevated: 25.0,
            inbound_mbps_bad: 80.0,
            in_out_ratio_bad: 6.0,
            source: "default".into(),
            samples: 0,
        }
    }
}

impl AdaptiveThresholds {
    pub fn to_json(&self) -> Value {
        json!({
            "conn_matchmaking_high": round1(self.conn_matchmaking_high),
            "conn_matchmaking_elevated": round1(self.conn_matchmaking_elevated),
            "mm_delta_bad": round1(self.mm_delta_bad),
            "mm_delta_warn": round1(self.mm_delta_warn),
            "jitter_bad": round1(self.jitter_bad),
            "wan_jitter_bad": round1(self.wan_jitter_bad),
            "conn_good_ceiling": round1(self.conn_good_ceiling),
            "conn_marginal_low": round1(self.conn_marginal_low),
            "conn_marginal_high": round1(self.conn_marginal_high),
            "inbound_mbps_elevated": round1(self.inbound_mbps_elevated),
            "inbound_mbps_bad": round1(self.inbound_mbps_bad),
            "in_out_ratio_bad": round1(self.in_out_ratio_bad),
            "source": self.source,
            "samples": self.samples,
        })
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[derive(Serialize, Deserialize, Clone)]
struct Sample {
    ts: f64,
    v: f64,
    #[serde(default)]
    phase: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize, Deserialize, Default)]
struct History {
    wan_latency: Vec<Sample>,
    conn_count: Vec<Sample>,
    matchmaking_latency: Vec<Sample>,
    mm_delta: Vec<Sample>,
    cheater_scores: Vec<Sample>,
    #[serde(default)]
    server_jitter: Vec<Sample>,
    #[serde(default)]
    inbound_mbps: Vec<Sample>,
    #[serde(default)]
    outbound_mbps: Vec<Sample>,
    #[serde(default)]
    packet_kpps: Vec<Sample>,
    #[serde(default)]
    in_out_ratio: Vec<Sample>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct SessionActive {
    started_at: f64,
    game: String,
    phases: Vec<Value>,
    peak_conns: i64,
    worst_verdict: String,
    worst_score: f64,
    #[serde(default)]
    confirmed_bad: bool,
    #[serde(default)]
    user_marked_good: bool,
    #[serde(default)]
    desync_polls: u32,
    #[serde(default)]
    flood_polls: u32,
    #[serde(default)]
    gaming_polls: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ended_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_sec: Option<i64>,
}

#[derive(Serialize, Deserialize, Default)]
struct Sessions {
    active: Option<SessionActive>,
    completed: Vec<SessionActive>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LobbyEntry {
    ts: f64,
    phase: String,
    label: String,
    confidence: f64,
    conns: i64,
    mm_delta: Option<f64>,
    #[serde(default)]
    fold: Option<[f32; FOLD_DIM]>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SessionOutcome {
    ended_at: f64,
    worst_verdict: String,
    worst_score: f64,
    peak_conns: i64,
    confirmed_bad: bool,
    user_marked_good: bool,
    desync_polls: u32,
    flood_polls: u32,
    duration_sec: i64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Feedback {
    ts: f64,
    bad_lobby: bool,
    note: String,
    last_lobby: Option<LobbyEntry>,
    #[serde(default)]
    verdict_at_feedback: String,
    #[serde(default)]
    score_at_feedback: f64,
}

#[derive(Serialize, Deserialize, Default)]
struct LearningState {
    history: History,
    sessions: Sessions,
    lobbies: Vec<LobbyEntry>,
    feedback: Vec<Feedback>,
    #[serde(default)]
    outcomes: Vec<SessionOutcome>,
    #[serde(default)]
    folded_blob: Option<Vec<u8>>,
    #[serde(default)]
    engine: String,
}

fn data_path() -> PathBuf {
    PathBuf::from(
        std::env::var("WZ_LEARNING_FILE")
            .unwrap_or_else(|_| "/var/lib/warzone-sentinel/ai-learning.json".into()),
    )
}

fn binary_path() -> PathBuf {
    data_path().with_extension("bin")
}

fn push_sample<T: Clone>(arr: &mut Vec<T>, item: T, limit: usize) {
    arr.push(item);
    if arr.len() > limit {
        arr.drain(0..arr.len() - limit);
    }
}

fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((p / 100.0) * s.len() as f64) as usize;
    Some(s[idx.min(s.len() - 1)])
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = s.len() / 2;
    if s.len() % 2 == 0 {
        (s[mid - 1] + s[mid]) / 2.0
    } else {
        s[mid]
    }
}

pub struct LearningEngine {
    state: Mutex<LearningState>,
}

impl LearningEngine {
    pub fn new() -> Self {
        let state = Self::load_state();
        Self {
            state: Mutex::new(state),
        }
    }

    fn load_state() -> LearningState {
        let json_path = data_path();
        if json_path.exists() {
            if let Ok(raw) = std::fs::read_to_string(&json_path) {
                if let Ok(mut s) = serde_json::from_str::<LearningState>(&raw) {
                    s.engine = "rust".into();
                    return s;
                }
            }
        }
        let bin_path = binary_path();
        if bin_path.exists() {
            if let Ok(raw) = std::fs::read(&bin_path) {
                if let Ok(s) = zstd::decode_all(raw.as_slice()) {
                    if let Ok(st) = serde_json::from_slice::<LearningState>(&s) {
                        return st;
                    }
                }
            }
        }
        LearningState {
            engine: "rust".into(),
            ..Default::default()
        }
    }

    pub fn save(&self) {
        let mut st = self.state.lock();
        st.engine = "rust".into();
        // Sync compressed fold archive from lobby entries.
        let folds: Vec<[f32; FOLD_DIM]> = st
            .lobbies
            .iter()
            .filter_map(|l| l.fold)
            .collect();
        st.folded_blob = if folds.is_empty() {
            None
        } else {
            Some(compress_folds(&folds))
        };

        if let Some(parent) = data_path().parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // JSON for human/debug compatibility.
        if let Ok(json) = serde_json::to_string_pretty(&*st) {
            let tmp = data_path().with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, data_path());
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(data_path(), std::fs::Permissions::from_mode(0o600));
                }
            }
        }

        // ZSTD binary — ~10-50x smaller than JSON for fold history.
        if let Ok(bytes) = serde_json::to_vec(&*st) {
            if let Ok(compressed) = zstd::encode_all(bytes.as_slice(), 5) {
                let tmp = binary_path().with_extension("bintmp");
                if std::fs::write(&tmp, compressed).is_ok() {
                    let _ = std::fs::rename(&tmp, binary_path());
                }
            }
        }
    }

    pub fn thresholds(&self) -> AdaptiveThresholds {
        let st = self.state.lock();
        Self::thresholds_from_state(&st)
    }

    fn thresholds_from_state(st: &LearningState) -> AdaptiveThresholds {
        let n = st.history.conn_count.len();
        if n < MIN_SAMPLES {
            return AdaptiveThresholds {
                samples: n,
                ..Default::default()
            };
        }

        let conns: Vec<f64> = st
            .history
            .conn_count
            .iter()
            .filter(|x| x.phase == "matchmaking")
            .map(|x| x.v)
            .collect();
        let user_bad_conns: Vec<f64> = st
            .lobbies
            .iter()
            .filter(|lb| lb.label == "USER_BAD" || lb.label == "LIKELY")
            .map(|lb| lb.conns as f64)
            .collect();
        let good_conns: Vec<f64> = st
            .lobbies
            .iter()
            .filter(|lb| is_good_label(&lb.label))
            .map(|lb| lb.conns as f64)
            .chain(
                st.feedback
                    .iter()
                    .filter(|f| !f.bad_lobby)
                    .filter_map(|f| f.last_lobby.as_ref().map(|l| l.conns as f64)),
            )
            .collect();
        let marginal_conns: Vec<f64> = st
            .lobbies
            .iter()
            .filter(|lb| is_marginal_label(&lb.label))
            .map(|lb| lb.conns as f64)
            .collect();
        let mm_deltas: Vec<f64> = st.history.mm_delta.iter().map(|x| x.v).collect();

        let wan_vals: Vec<f64> = st.history.wan_latency.iter().map(|x| x.v).collect();
        let mut wan_jitter_samples = Vec::new();
        if wan_vals.len() >= 10 {
            for i in 8..wan_vals.len() {
                let chunk = &wan_vals[i - 8..i];
                if chunk.len() > 1 {
                    wan_jitter_samples.push(pstdev(chunk));
                }
            }
        }

        let mut t = AdaptiveThresholds {
            source: "learned".into(),
            samples: n,
            ..Default::default()
        };

        if let Some(p75) = percentile(&conns, 75.0) {
            let p90 = percentile(&conns, 90.0).unwrap_or(90.0);
            t.conn_matchmaking_elevated = (p75 * 1.15).clamp(40.0, 120.0);
            t.conn_matchmaking_high = (p90 * 1.1).clamp(60.0, 180.0);
        }
        // User-confirmed bad lobbies anchor lower thresholds (cheater pools can look "quiet").
        if !user_bad_conns.is_empty() {
            if let Some(p50) = percentile(&user_bad_conns, 50.0) {
                t.conn_matchmaking_elevated = t.conn_matchmaking_elevated.min((p50 * 1.1).clamp(18.0, 80.0));
                t.conn_matchmaking_high = t.conn_matchmaking_high.min((p50 * 1.35).clamp(28.0, 100.0));
            }
        }
        if good_conns.len() >= 5 {
            if let Some(p75) = percentile(&good_conns, 75.0) {
                t.conn_good_ceiling = (p75 * 1.1).clamp(15.0, 100.0);
            }
        }
        if !marginal_conns.is_empty() && t.conn_good_ceiling > 0.0 {
            if let (Some(p25), Some(p75)) = (
                percentile(&marginal_conns, 25.0),
                percentile(&marginal_conns, 75.0),
            ) {
                t.conn_marginal_low = p25.max(t.conn_good_ceiling * 0.9);
                t.conn_marginal_high = p75.min(t.conn_matchmaking_elevated);
            }
        } else if t.conn_good_ceiling > 0.0 {
            t.conn_marginal_low = t.conn_good_ceiling;
            t.conn_marginal_high = t.conn_matchmaking_elevated;
        }
        if let Some(p75) = percentile(&mm_deltas, 75.0) {
            let p90 = percentile(&mm_deltas, 90.0).unwrap_or(45.0);
            t.mm_delta_warn = p75.clamp(15.0, 50.0);
            t.mm_delta_bad = p90.clamp(30.0, 80.0);
        }
        if let Some(p90) = percentile(&wan_jitter_samples, 90.0) {
            t.wan_jitter_bad = p90.clamp(12.0, 35.0);
        }
        let crit: Vec<f64> = st.history.server_jitter.iter().map(|x| x.v).collect();
        if crit.len() >= MIN_SAMPLES {
            if let Some(p90) = percentile(&crit, 90.0) {
                t.jitter_bad = p90.clamp(10.0, 30.0);
            }
        }
        let inbound: Vec<f64> = st
            .history
            .inbound_mbps
            .iter()
            .filter(|x| x.phase == "matchmaking" || x.phase == "in-match")
            .map(|x| x.v)
            .collect();
        if inbound.len() >= MIN_SAMPLES {
            if let Some(p75) = percentile(&inbound, 75.0) {
                t.inbound_mbps_elevated = (p75 * 2.0).clamp(8.0, 60.0);
            }
            if let Some(p90) = percentile(&inbound, 90.0) {
                t.inbound_mbps_bad = (p90 * 3.5).clamp(25.0, 200.0);
            }
        }
        let ratios: Vec<f64> = st.history.in_out_ratio.iter().map(|x| x.v).collect();
        if ratios.len() >= MIN_SAMPLES {
            if let Some(p90) = percentile(&ratios, 90.0) {
                t.in_out_ratio_bad = p90.clamp(3.0, 15.0);
            }
        }
        t
    }

    /// Rolling median baseline for inbound traffic analysis.
    pub fn inbound_baseline(&self) -> Option<crate::metrics::InboundBaseline> {
        let st = self.state.lock();
        if st.history.inbound_mbps.len() < 8 {
            return None;
        }
        let take = |v: &Vec<Sample>| -> Vec<f64> { v.iter().rev().take(40).map(|s| s.v).collect() };
        Some(crate::metrics::InboundBaseline {
            inbound_mbps: median(&take(&st.history.inbound_mbps)),
            outbound_mbps: median(&take(&st.history.outbound_mbps)),
            total_kpps: median(&take(&st.history.packet_kpps)),
            connections: median(&take(&st.history.conn_count)),
            wan_latency_ms: median(
                &st.history
                    .wan_latency
                    .iter()
                    .rev()
                    .take(40)
                    .map(|s| s.v)
                    .collect::<Vec<_>>(),
            ),
        })
    }

    pub fn record_poll(
        &self,
        snapshot: &Value,
        phase: &str,
        verdict: &CheaterVerdict,
        mm_delta: Option<f64>,
        server_jitter: Option<f64>,
    ) {
        let ts = now();
        let mut st = self.state.lock();
        let conns = snapshot
            .pointer("/connections/count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as i64;
        let wan = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64());

        if let Some(w) = wan {
            push_sample(
                &mut st.history.wan_latency,
                Sample {
                    ts,
                    v: w,
                    phase: phase.into(),
                    label: String::new(),
                },
                MAX_SAMPLES,
            );
        }
        push_sample(
            &mut st.history.conn_count,
            Sample {
                ts,
                v: conns as f64,
                phase: phase.into(),
                label: verdict.label.clone(),
            },
            MAX_SAMPLES,
        );
        if let Some(d) = mm_delta {
            push_sample(
                &mut st.history.mm_delta,
                Sample {
                    ts,
                    v: d,
                    phase: phase.into(),
                    label: String::new(),
                },
                MAX_SAMPLES,
            );
        }
        if let Some(j) = server_jitter {
            push_sample(
                &mut st.history.server_jitter,
                Sample {
                    ts,
                    v: j,
                    phase: phase.into(),
                    label: String::new(),
                },
                MAX_SAMPLES,
            );
        }

        let window_sec = snapshot
            .pointer("/sample/windowSec")
            .and_then(|v| v.as_f64())
            .unwrap_or(3.0)
            .max(0.5);
        let bytes_in = snapshot
            .pointer("/sample/bytesIn")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let bytes_out = snapshot
            .pointer("/sample/bytesOut")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let packets = snapshot
            .pointer("/sample/packets")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let inbound_mbps = (bytes_in as f64 * 8.0) / window_sec / 1_000_000.0;
        let outbound_mbps = (bytes_out as f64 * 8.0) / window_sec / 1_000_000.0;
        let kpps = packets as f64 / window_sec / 1000.0;
        let ratio = if bytes_out > 0 {
            bytes_in as f64 / bytes_out as f64
        } else if bytes_in > 0 {
            99.0
        } else {
            1.0
        };
        push_sample(
            &mut st.history.inbound_mbps,
            Sample {
                ts,
                v: inbound_mbps,
                phase: phase.into(),
                label: verdict.label.clone(),
            },
            MAX_SAMPLES,
        );
        push_sample(
            &mut st.history.outbound_mbps,
            Sample {
                ts,
                v: outbound_mbps,
                phase: phase.into(),
                label: String::new(),
            },
            MAX_SAMPLES,
        );
        push_sample(
            &mut st.history.packet_kpps,
            Sample {
                ts,
                v: kpps,
                phase: phase.into(),
                label: String::new(),
            },
            MAX_SAMPLES,
        );
        push_sample(
            &mut st.history.in_out_ratio,
            Sample {
                ts,
                v: ratio,
                phase: phase.into(),
                label: String::new(),
            },
            MAX_SAMPLES,
        );

        push_sample(
            &mut st.history.cheater_scores,
            Sample {
                ts,
                v: verdict.confidence,
                phase: phase.into(),
                label: verdict.label.clone(),
            },
            MAX_SAMPLES,
        );

        self.update_session_locked(&mut st, phase, verdict, conns, snapshot);
        self.record_lobby_locked(&mut st, phase, verdict, conns, mm_delta, snapshot);
        drop(st);
        self.save();
    }

    fn update_session_locked(
        &self,
        st: &mut LearningState,
        phase: &str,
        verdict: &CheaterVerdict,
        conns: i64,
        snapshot: &Value,
    ) {
        let gaming = phase == "matchmaking" || phase == "in-match";
        let now_ts = now();

        if gaming && st.sessions.active.is_none() {
            st.sessions.active = Some(SessionActive {
                started_at: now_ts,
                game: snapshot
                    .pointer("/_enriched/game")
                    .and_then(|v| v.as_str())
                    .unwrap_or("warzone")
                    .into(),
                phases: vec![],
                peak_conns: conns,
                worst_verdict: verdict.label.clone(),
                worst_score: verdict.confidence,
                confirmed_bad: false,
                user_marked_good: false,
                desync_polls: 0,
                flood_polls: 0,
                gaming_polls: 0,
                ended_at: None,
                duration_sec: None,
            });
        }

        if let Some(active) = st.sessions.active.as_mut() {
            active.peak_conns = active.peak_conns.max(conns);
            active.gaming_polls = active.gaming_polls.saturating_add(1);
            let last_phase = active
                .phases
                .last()
                .and_then(|p| p.get("phase"))
                .and_then(|v| v.as_str());
            if last_phase != Some(phase) {
                active.phases.push(json!({"phase": phase, "at": now_ts}));
            }
            if verdict.confidence >= active.worst_score {
                active.worst_score = verdict.confidence;
                active.worst_verdict = verdict.label.clone();
            }
            if !gaming && (phase == "idle" || phase == "background" || phase == "post-match") {
                let mut done = active.clone();
                done.ended_at = Some(now_ts);
                done.duration_sec = Some((now_ts - done.started_at) as i64);
                push_sample(&mut st.sessions.completed, done.clone(), MAX_SESSIONS);
                push_sample(
                    &mut st.outcomes,
                    SessionOutcome {
                        ended_at: now_ts,
                        worst_verdict: done.worst_verdict.clone(),
                        worst_score: done.worst_score,
                        peak_conns: done.peak_conns,
                        confirmed_bad: done.confirmed_bad,
                        user_marked_good: done.user_marked_good,
                        desync_polls: done.desync_polls,
                        flood_polls: done.flood_polls,
                        duration_sec: done.duration_sec.unwrap_or(0),
                    },
                    MAX_OUTCOMES,
                );
                st.sessions.active = None;
            }
        }
    }

    pub fn record_guard_activity(&self, desync_active: bool, flood_active: bool) {
        let mut st = self.state.lock();
        if let Some(active) = st.sessions.active.as_mut() {
            if desync_active {
                active.desync_polls = active.desync_polls.saturating_add(1);
            }
            if flood_active {
                active.flood_polls = active.flood_polls.saturating_add(1);
            }
        }
    }

    fn relabel_recent_lobbies(st: &mut LearningState, conns: i64, label: &str, window_sec: f64) {
        let ts = now();
        for lb in st.lobbies.iter_mut().rev().take(30) {
            if ts - lb.ts > window_sec {
                break;
            }
            let tol = (lb.conns / 4).max(8);
            if (lb.conns - conns).abs() <= tol {
                lb.label = label.into();
            }
        }
    }

    fn record_lobby_locked(
        &self,
        st: &mut LearningState,
        phase: &str,
        verdict: &CheaterVerdict,
        conns: i64,
        mm_delta: Option<f64>,
        snapshot: &Value,
    ) {
        if phase != "matchmaking" && phase != "in-match" {
            return;
        }
        let roles = role_pairs(snapshot);
        let fold = fold_telemetry(
            conns as f32,
            snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64()).map(|v| v as f32),
            mm_delta.map(|v| v as f32),
            None,
            None,
            &roles,
            phase_code(phase),
            (verdict.confidence / 100.0) as f32,
        );
        push_sample(
            &mut st.lobbies,
            LobbyEntry {
                ts: now(),
                phase: phase.into(),
                label: verdict.label.clone(),
                confidence: verdict.confidence,
                conns,
                mm_delta,
                fold: Some(fold),
            },
            MAX_LOBBIES,
        );
    }

    pub fn record_feedback(&self, bad_lobby: bool, note: &str, verdict_label: &str, verdict_score: f64) {
        let mut st = self.state.lock();
        if bad_lobby {
            if let Some(last) = st.lobbies.last_mut() {
                last.label = if verdict_label == "POSSIBLE" {
                    "USER_MARGINAL".into()
                } else {
                    "USER_BAD".into()
                };
                last.confidence = last.confidence.max(55.0);
            }
            if let Some(ref lb) = st.lobbies.last() {
                let conns = lb.conns;
                Self::relabel_recent_lobbies(&mut st, conns, "USER_BAD", 600.0);
            }
            if let Some(active) = st.sessions.active.as_mut() {
                active.confirmed_bad = true;
                active.worst_verdict = "LIKELY".into();
                let kick = note.to_lowercase().contains("kick");
                active.worst_score = active.worst_score.max(if kick { 90.0 } else { 75.0 });
            }
            st.sessions
                .completed
                .iter_mut()
                .rev()
                .take(3)
                .for_each(|s| s.confirmed_bad = true);
        } else {
            if let Some(last) = st.lobbies.last_mut() {
                last.label = "USER_GOOD".into();
            }
            if let Some(ref lb) = st.lobbies.last() {
                let conns = lb.conns;
                Self::relabel_recent_lobbies(&mut st, conns, "USER_GOOD", 600.0);
            }
            if let Some(active) = st.sessions.active.as_mut() {
                active.user_marked_good = true;
                if active.worst_verdict == "LIKELY" || active.worst_verdict == "POSSIBLE" {
                    active.worst_verdict = "CLEAN".into();
                    active.worst_score = active.worst_score.min(20.0);
                }
            }
        }
        let last = st.lobbies.last().cloned();
        push_sample(
            &mut st.feedback,
            Feedback {
                ts: now(),
                bad_lobby,
                note: note.chars().take(200).collect(),
                last_lobby: last,
                verdict_at_feedback: verdict_label.into(),
                score_at_feedback: verdict_score,
            },
            100,
        );
        drop(st);
        self.save();
    }

    pub fn end_active_session(&self) -> bool {
        let mut st = self.state.lock();
        let Some(mut done) = st.sessions.active.take() else {
            return false;
        };
        let now_ts = now();
        done.ended_at = Some(now_ts);
        done.duration_sec = Some((now_ts - done.started_at) as i64);
        push_sample(&mut st.sessions.completed, done.clone(), MAX_SESSIONS);
        push_sample(
            &mut st.outcomes,
            SessionOutcome {
                ended_at: now_ts,
                worst_verdict: done.worst_verdict.clone(),
                worst_score: done.worst_score,
                peak_conns: done.peak_conns,
                confirmed_bad: done.confirmed_bad,
                user_marked_good: done.user_marked_good,
                desync_polls: done.desync_polls,
                flood_polls: done.flood_polls,
                duration_sec: done.duration_sec.unwrap_or(0),
            },
            MAX_OUTCOMES,
        );
        drop(st);
        self.save();
        true
    }

    pub fn adjust_score(
        &self,
        base_score: f64,
        conns: i64,
        phase: &str,
        mm_delta: Option<f64>,
    ) -> (f64, Vec<String>) {
        let st = self.state.lock();
        if st
            .sessions
            .active
            .as_ref()
            .is_some_and(|a| a.confirmed_bad)
        {
            return (
                0.58,
                vec!["You confirmed cheaters this session — treating as LIKELY".into()],
            );
        }
        let t = Self::thresholds_from_state(&st);
        let mut notes = Vec::new();
        let mut score = base_score;

        if t.source == "learned" && phase == "matchmaking" {
            if conns as f64 > t.conn_matchmaking_high {
                score += 0.12;
                notes.push(format!(
                    "Conn fan-out above your learned baseline ({conns}>{:.0})",
                    t.conn_matchmaking_high
                ));
            } else if t.conn_good_ceiling > 0.0 && (conns as f64) <= t.conn_good_ceiling {
                score -= 0.12;
                notes.push(format!(
                    "Conn fan-out within your learned clean profile (≤{:.0})",
                    t.conn_good_ceiling
                ));
            } else if t.conn_marginal_low > 0.0
                && (conns as f64) >= t.conn_marginal_low
                && (conns as f64) <= t.conn_marginal_high
            {
                score += 0.06;
                notes.push(format!(
                    "Marginal fan-out zone for your network ({:.0}–{:.0} conns)",
                    t.conn_marginal_low, t.conn_marginal_high
                ));
            } else if (conns as f64) < t.conn_matchmaking_elevated * 0.6 && base_score > 0.15 {
                score -= 0.1;
                notes.push("Conn count below your normal matchmaking baseline".into());
            }
        }
        if let Some(d) = mm_delta {
            if t.source == "learned" {
                if d >= t.mm_delta_bad {
                    score += 0.1;
                    notes.push(format!(
                        "Matchmaking path worse than your learned bad threshold (+{d:.0} ms)"
                    ));
                } else if d < t.mm_delta_warn * 0.8 && score > 0.2 {
                    score -= 0.08;
                }
            }
        }

        // User-confirmed bad lobby — match similar conn fingerprint (your last miss was ~23-27 conns).
        let now_ts = now();
        for fb in st.feedback.iter().rev().take(20) {
            if !fb.bad_lobby {
                continue;
            }
            if now_ts - fb.ts > 86400.0 {
                break;
            }
            if let Some(ref lb) = fb.last_lobby {
                if lb.phase == phase || phase == "in-match" {
                    let tol = (lb.conns / 4).max(8) as i64;
                    if (lb.conns - conns).abs() <= tol {
                        score = score.max(0.30);
                        notes.push(format!(
                            "Matches your confirmed bad lobby (~{} conns) — treating as POSSIBLE",
                            lb.conns
                        ));
                        break;
                    }
                }
            }
        }

        // 32D fold similarity vs good lobbies — reduces false positives.
        let good_folds: Vec<[f32; FOLD_DIM]> = st
            .lobbies
            .iter()
            .filter(|lb| is_good_label(&lb.label))
            .filter_map(|lb| lb.fold)
            .collect();
        if !good_folds.is_empty() {
            let current = fold_telemetry(
                conns as f32,
                None,
                mm_delta.map(|v| v as f32),
                None,
                None,
                &[],
                phase_code(phase),
                base_score as f32,
            );
            let good_hits = good_folds
                .iter()
                .rev()
                .take(40)
                .filter(|gf| cosine_similarity(&current, gf) > 0.82)
                .count();
            if good_hits >= 2 {
                let cut = (good_hits as f64 * 0.04).min(0.15);
                score -= cut;
                notes.push(format!(
                    "32D fold matches {good_hits} prior clean-lobby fingerprints"
                ));
            }
        }

        // Fold-vector similarity — O(n) pattern match vs conn-only heuristic.
        let bad_folds: Vec<[f32; FOLD_DIM]> = st
            .lobbies
            .iter()
            .filter(|lb| {
                lb.label == "LIKELY"
                    || lb.label == "USER_BAD"
                    || lb.label == "USER_MARGINAL"
                    || st.feedback.iter().any(|f| f.bad_lobby && (f.ts - lb.ts).abs() < 300.0)
            })
            .filter_map(|lb| lb.fold)
            .collect();

        if !bad_folds.is_empty() {
            let current = fold_telemetry(
                conns as f32,
                None,
                mm_delta.map(|v| v as f32),
                None,
                None,
                &[],
                phase_code(phase),
                base_score as f32,
            );
            let similar = bad_folds
                .iter()
                .rev()
                .take(30)
                .filter(|bf| cosine_similarity(&current, bf) > 0.85)
                .count();
            if similar >= 2 {
                let boost = (similar as f64 * 0.05).min(0.18);
                score += boost;
                notes.push(format!(
                    "32D fold matches {similar} prior bad-lobby fingerprints (sim>0.85)"
                ));
            }
        } else {
            // Fallback conn similarity.
            let bad_refs: Vec<_> = st
                .lobbies
                .iter()
                .filter(|lb| {
                    lb.label == "LIKELY"
                        || st.feedback.iter().any(|f| {
                            f.bad_lobby && (f.ts - lb.ts).abs() < 300.0
                        })
                })
                .collect();
            if !bad_refs.is_empty() && conns > 0 {
                let similar = bad_refs
                    .iter()
                    .rev()
                    .take(30)
                    .filter(|lb| (lb.conns - conns).unsigned_abs() <= (15.max((conns / 4) as u64)))
                    .count();
                if similar >= 3 {
                    score += (similar as f64 * 0.04).min(0.15);
                    notes.push(format!(
                        "Matches {similar} prior bad-lobby sessions on your network"
                    ));
                }
            }
        }

        if st.feedback.iter().any(|f| !f.bad_lobby) && base_score < 0.35 && phase != "in-match" {
            score -= 0.08;
            notes.push("Recent clean-lobby feedback on your network".into());
        }

        // Learn from false positives: auto verdict high but user said clean.
        for fb in st.feedback.iter().rev().take(15) {
            if fb.bad_lobby {
                continue;
            }
            if fb.verdict_at_feedback == "LIKELY" || fb.verdict_at_feedback == "POSSIBLE" {
                score -= 0.06;
                notes.push("Prior false alarm — similar session marked clean".into());
                break;
            }
        }

        if phase == "in-match" && conns >= 65 {
            score = score.max(0.26);
            if notes.is_empty() {
                notes.push(format!(
                    "In-match connection load ({conns}) above learned baseline"
                ));
            }
        }

        (score.clamp(0.0, 1.0), notes)
    }

    pub fn insights(&self) -> Value {
        let st = self.state.lock();
        let t = Self::thresholds_from_state(&st);
        let bad: Vec<_> = st
            .lobbies
            .iter()
            .filter(|lb| lb.label == "LIKELY" || lb.label == "USER_BAD" || lb.label == "USER_MARGINAL")
            .collect();
        let good: Vec<_> = st
            .lobbies
            .iter()
            .filter(|lb| is_good_label(&lb.label))
            .collect();
        let marginal: Vec<_> = st
            .lobbies
            .iter()
            .filter(|lb| is_marginal_label(&lb.label))
            .collect();
        let mut patterns = Vec::new();
        if t.source == "learned" {
            patterns.push(format!(
                "Learned baselines from {} samples — matchmaking fan-out ~{:.0}/{:.0} conns",
                t.samples, t.conn_matchmaking_elevated, t.conn_matchmaking_high
            ));
        }
        if t.conn_good_ceiling > 0.0 {
            patterns.push(format!(
                "Clean lobbies on your network: typically ≤{:.0} connections",
                t.conn_good_ceiling
            ));
        }
        if t.conn_marginal_low > 0.0 && t.conn_marginal_high > t.conn_marginal_low {
            patterns.push(format!(
                "Marginal zone (watch closely): {:.0}–{:.0} connections",
                t.conn_marginal_low, t.conn_marginal_high
            ));
        }
        if good.len() >= 3 {
            let avg: f64 =
                good.iter().map(|lb| lb.conns as f64).sum::<f64>() / good.len() as f64;
            patterns.push(format!(
                "Good lobby profile: ~{avg:.0} avg connections ({} samples)",
                good.len()
            ));
        }
        if bad.len() >= 3 {
            let avg: f64 = bad
                .iter()
                .rev()
                .take(20)
                .map(|lb| lb.conns as f64)
                .sum::<f64>()
                / bad.len().min(20) as f64;
            patterns.push(format!(
                "Bad lobby profile: ~{avg:.0} avg connections ({} samples)",
                bad.len().min(20)
            ));
        }
        if marginal.len() >= 2 {
            let avg: f64 =
                marginal.iter().map(|lb| lb.conns as f64).sum::<f64>() / marginal.len() as f64;
            patterns.push(format!(
                "Marginal lobbies avg {avg:.0} connections — often borderline shadow-pool"
            ));
        }
        if !st.outcomes.is_empty() {
            let with_guard: Vec<_> = st
                .outcomes
                .iter()
                .filter(|o| o.desync_polls > 0 || o.flood_polls > 0)
                .collect();
            let user_confirmed = with_guard.iter().filter(|o| o.confirmed_bad).count();
            let auto_likely = with_guard
                .iter()
                .filter(|o| !o.confirmed_bad && o.worst_verdict == "LIKELY")
                .count();
            if !with_guard.is_empty() {
                let detail = if user_confirmed > 0 && auto_likely > 0 {
                    format!("{user_confirmed} you marked bad, {auto_likely} auto LIKELY")
                } else if user_confirmed > 0 {
                    format!("{user_confirmed} you marked bad")
                } else {
                    format!("{auto_likely} auto-detected LIKELY")
                };
                patterns.push(format!(
                    "Network guard (desync+flood) ran in {} sessions — {detail}",
                    with_guard.len()
                ));
            }
        }
        patterns.extend(build_improvement_hints(
            &st,
            st.sessions
                .active
                .as_ref()
                .map(|a| a.worst_verdict.as_str()),
        ));
        if st.sessions.completed.len() >= 3 {
            if let Some(worst) = st
                .sessions
                .completed
                .iter()
                .rev()
                .take(10)
                .max_by(|a, b| {
                    a.worst_score
                        .partial_cmp(&b.worst_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            {
                patterns.push(format!(
                    "Recent worst session: {} ({:.0}%)",
                    worst.worst_verdict, worst.worst_score
                ));
            }
        }

        let fold_count = st.lobbies.iter().filter(|l| l.fold.is_some()).count();
        let blob_kb = st
            .folded_blob
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(0) as f64
            / 1024.0;

        let good_fb = st.feedback.iter().filter(|f| !f.bad_lobby).count();
        let bad_fb = st.feedback.iter().filter(|f| f.bad_lobby).count();

        json!({
            "engine": "rust",
            "fold_dim": FOLD_DIM,
            "folded_lobbies": fold_count,
            "fold_blob_kb": (blob_kb * 10.0).round() / 10.0,
            "thresholds": t.to_json(),
            "profiles": {
                "good_samples": good.len(),
                "bad_samples": bad.len(),
                "marginal_samples": marginal.len(),
                "good_feedback": good_fb,
                "bad_feedback": bad_fb,
            },
            "samples": {
                "wan_latency": st.history.wan_latency.len(),
                "conn_count": st.history.conn_count.len(),
                "matchmaking_latency": st.history.matchmaking_latency.len(),
                "mm_delta": st.history.mm_delta.len(),
                "cheater_scores": st.history.cheater_scores.len(),
            },
            "sessions_completed": st.sessions.completed.len(),
            "outcomes_tracked": st.outcomes.len(),
            "lobbies_tracked": st.lobbies.len(),
            "feedback_count": st.feedback.len(),
            "patterns": patterns.into_iter().take(10).collect::<Vec<_>>(),
            "active_session": st.sessions.active,
        })
    }

    pub fn find_similar_lobbies(
        &self,
        snapshot: &Value,
        conns: i64,
        phase: &str,
        mm_delta: Option<f64>,
        limit: usize,
    ) -> Vec<Value> {
        let st = self.state.lock();
        let wan = snapshot.pointer("/wan/latencyMs").and_then(|v| v.as_f64());
        let current = fold_telemetry(
            conns as f32,
            wan.map(|v| v as f32),
            mm_delta.map(|v| v as f32),
            None,
            None,
            &role_pairs(snapshot),
            phase_code(phase),
            0.0,
        );
        let mut scored: Vec<(f32, &LobbyEntry)> = st
            .lobbies
            .iter()
            .filter_map(|lb| lb.fold.map(|f| (cosine_similarity(&current, &f), lb)))
            .filter(|(sim, _)| *sim > 0.55)
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored
            .into_iter()
            .take(limit)
            .map(|(sim, lb)| {
                json!({
                    "similarity": ((sim as f64 * 1000.0).round() / 1000.0),
                    "label": lb.label,
                    "confidence": lb.confidence,
                    "conns": lb.conns,
                    "phase": lb.phase,
                    "age_sec": (now() - lb.ts).round() as i64,
                })
            })
            .collect()
    }

    pub fn calibration(&self) -> Value {
        let st = self.state.lock();
        let false_alarms = st
            .feedback
            .iter()
            .filter(|f| {
                !f.bad_lobby
                    && (f.verdict_at_feedback == "LIKELY" || f.verdict_at_feedback == "POSSIBLE")
            })
            .count();
        let true_positives = st
            .feedback
            .iter()
            .filter(|f| {
                f.bad_lobby
                    && (f.verdict_at_feedback == "LIKELY" || f.verdict_at_feedback == "POSSIBLE")
            })
            .count();
        let missed = st
            .feedback
            .iter()
            .filter(|f| f.bad_lobby && f.verdict_at_feedback == "CLEAN")
            .count();
        let good_fb = st.feedback.iter().filter(|f| !f.bad_lobby).count();
        let bad_fb = st.feedback.iter().filter(|f| f.bad_lobby).count();
        let total = st.feedback.len();
        json!({
            "feedback_total": total,
            "true_positives": true_positives,
            "false_alarms": false_alarms,
            "missed_bad": missed,
            "good_marks": good_fb,
            "bad_marks": bad_fb,
            "needs_clean_marks": good_fb < 5,
            "precision_pct": if true_positives + false_alarms > 0 {
                Some(round1(
                    true_positives as f64 / (true_positives + false_alarms) as f64 * 100.0,
                ))
            } else {
                None::<f64>
            },
        })
    }

    pub fn folded_archive_size(&self) -> usize {
        self.state
            .lock()
            .folded_blob
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(0)
    }
}

fn build_improvement_hints(st: &LearningState, active_verdict: Option<&str>) -> Vec<String> {
    let mut hints = Vec::new();
    let good_fb = st.feedback.iter().filter(|f| !f.bad_lobby).count();
    let bad_fb = st.feedback.iter().filter(|f| f.bad_lobby).count();
    let in_bad_lobby = matches!(
        active_verdict,
        Some("LIKELY") | Some("POSSIBLE") | Some("USER_BAD") | Some("USER_MARGINAL")
    );
    let false_alarms = st
        .feedback
        .iter()
        .filter(|f| !f.bad_lobby && (f.verdict_at_feedback == "LIKELY" || f.verdict_at_feedback == "POSSIBLE"))
        .count();
    let missed = st
        .feedback
        .iter()
        .filter(|f| f.bad_lobby && f.verdict_at_feedback == "CLEAN")
        .count();

    if good_fb < 3 && !in_bad_lobby {
        hints.push(
            "When you get a genuinely good lobby, mark it clean — teaches the AI your normal fan-out".into(),
        );
    }
    if bad_fb >= 2 && good_fb == 0 && !in_bad_lobby {
        hints.push(
            "After a good match (no cheaters), mark clean so the AI learns what normal looks like on your network".into(),
        );
    }
    if false_alarms >= 2 && !in_bad_lobby {
        hints.push(format!(
            "{false_alarms} false alarms logged — mark clean only on lobbies that were actually good"
        ));
    }
    if missed >= 1 {
        hints.push(format!(
            "{missed} missed bad lobby(ies) — bad marks anchor lower detection thresholds"
        ));
    }
    if st.outcomes.iter().any(|o| o.desync_polls > 5 && o.user_marked_good) {
        hints.push(
            "Desync+flood guard ran during sessions you marked clean — network tuning may be helping".into(),
        );
    }
    if st.outcomes.iter().any(|o| o.confirmed_bad && o.desync_polls == 0) {
        hints.push(
            "Bad lobby with no guard engagement — auto-tuning will engage earlier next time".into(),
        );
    }
    if st.lobbies.iter().filter(|l| l.label == "USER_GOOD").count() >= 5 {
        hints.push(
            "32D fold has clean fingerprints — similarity matching active for false-positive reduction".into(),
        );
    }
    hints
}

fn pstdev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    (vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64).sqrt()
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

static ENGINE: OnceLock<LearningEngine> = OnceLock::new();

pub fn engine() -> &'static LearningEngine {
    ENGINE.get_or_init(LearningEngine::new)
}
