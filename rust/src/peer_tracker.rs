//! Accumulated inbound peer / identical-packet table per gaming session (hex id + JSON files).

use crate::enrich::{
    inbound_display_label, is_vps_game_peer, resolve_inbound_peer_role, should_show_in_peer_table,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn ts_slug() -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{n}")
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PeerRow {
    pub ip: String,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub role: String,
    pub identical_count: u32,
    pub identical_size: u64,
    #[serde(default)]
    pub packet_size_min: u64,
    #[serde(default)]
    pub packet_size_max: u64,
    pub total_packets: u64,
    pub tiny_packets: u64,
    #[serde(default)]
    pub poll_hits: u32,
    pub first_seen: f64,
    pub last_seen: f64,
    #[serde(default)]
    pub suspicious: bool,
    #[serde(default)]
    pub vps_probe: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct SessionMeta {
    session_hex: String,
    started_at: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ended_at: Option<f64>,
    #[serde(default)]
    phase: String,
    #[serde(default)]
    clear_count: u32,
    #[serde(default)]
    snapshot_files: Vec<String>,
}

#[derive(Default)]
struct TrackerState {
    session_hex: Option<String>,
    session_started: f64,
    phase: String,
    rows: HashMap<String, PeerRow>,
    clear_count: u32,
    snapshot_files: Vec<String>,
}

pub struct PeerTracker {
    inner: Mutex<TrackerState>,
    base_dir: PathBuf,
}

impl PeerTracker {
    pub fn new(base_dir: PathBuf) -> Self {
        if let Err(e) = fs::create_dir_all(&base_dir) {
            tracing::warn!("[peer-tracker] mkdir {}: {e}", base_dir.display());
        }
        Self {
            inner: Mutex::new(TrackerState::default()),
            base_dir,
        }
    }

    pub fn from_env() -> Self {
        let dir = std::env::var("WZ_SESSIONS_DIR")
            .unwrap_or_else(|_| "/var/lib/warzone-sentinel/sessions".into());
        Self::new(PathBuf::from(dir))
    }

    fn session_dir(&self, hex: &str) -> PathBuf {
        self.base_dir.join(hex)
    }

    fn new_session_hex() -> String {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:016x}", t & 0xffff_ffff_ffff_ffff)
    }

    pub fn ensure_session(&self, phase: &str) -> String {
        let mut st = self.inner.lock();
        if st.session_hex.is_none() && (phase == "matchmaking" || phase == "in-match") {
            let hex = Self::new_session_hex();
            st.session_hex = Some(hex.clone());
            st.session_started = now_secs();
            st.phase = phase.into();
            st.rows.clear();
            st.clear_count = 0;
            st.snapshot_files.clear();
            drop(st);
            if let Some(hex) = self.inner.lock().session_hex.clone() {
                self.write_session_meta(&hex, phase, false);
            }
            hex
        } else {
            st.session_hex.clone().unwrap_or_default()
        }
    }

    pub fn set_phase(&self, phase: &str) {
        let mut st = self.inner.lock();
        let was_gaming = st.phase == "matchmaking" || st.phase == "in-match";
        let is_gaming = phase == "matchmaking" || phase == "in-match";
        st.phase = phase.into();
        if was_gaming && !is_gaming {
            st.rows.clear();
        }
        if (phase == "matchmaking" || phase == "in-match") && st.session_hex.is_none() {
            let hex = Self::new_session_hex();
            st.session_hex = Some(hex.clone());
            st.session_started = now_secs();
            drop(st);
            self.write_session_meta(&hex, phase, false);
        }
    }

    pub fn ingest_identical_peers(&self, phase: &str, peers: &[Value]) {
        if phase != "matchmaking" && phase != "in-match" {
            return;
        }
        self.ensure_session(phase);
        let now = now_secs();
        let mut st = self.inner.lock();
        st.phase = phase.into();
        let Some(hex) = st.session_hex.clone() else {
            return;
        };
        st.rows.retain(|_, row| should_show_in_peer_table(&row.role, phase));

        for p in peers {
            let role = p.get("role").and_then(|v| v.as_str()).unwrap_or("");
            if !should_show_in_peer_table(role, phase) {
                continue;
            }
            let ip = p
                .get("ip")
                .or(p.get("remote"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if ip.is_empty() {
                continue;
            }
            let identical = p
                .get("identical_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let size = p
                .get("identical_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let poll_min = p.get("packet_size_min").and_then(|v| v.as_u64()).unwrap_or(0);
            let poll_max = p.get("packet_size_max").and_then(|v| v.as_u64()).unwrap_or(0);
            let total = p
                .get("total_packets")
                .or(p.get("packets"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let tiny = p.get("tiny_packets").and_then(|v| v.as_u64()).unwrap_or(0);
            let suspicious = p.get("suspicious").and_then(|v| v.as_bool()).unwrap_or(false);
            let vps_probe = p
                .get("vps_probe")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || is_vps_game_peer(
                    p.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                    p.get("role").and_then(|v| v.as_str()).unwrap_or(""),
                );

            let host_hint = p
                .get("hostname")
                .or(p.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let resolved_role = resolve_inbound_peer_role(
                &ip,
                host_hint,
                role,
                identical,
                tiny,
                total,
                poll_min,
                poll_max,
            );
            let entry = st.rows.entry(ip.clone()).or_insert_with(|| PeerRow {
                ip: ip.clone(),
                remote: p.get("remote").and_then(|v| v.as_str()).unwrap_or(&ip).into(),
                label: inbound_display_label(&ip, host_hint, &resolved_role),
                role: resolved_role.clone(),
                identical_count: 0,
                identical_size: 0,
                packet_size_min: 0,
                packet_size_max: 0,
                total_packets: 0,
                tiny_packets: 0,
                poll_hits: 0,
                first_seen: now,
                last_seen: now,
                suspicious: false,
                vps_probe: false,
            });
            entry.poll_hits += 1;
            entry.last_seen = now;
            entry.total_packets += total;
            entry.tiny_packets += tiny;
            let resolved = resolve_inbound_peer_role(
                &ip,
                host_hint,
                &entry.role,
                entry.identical_count.max(identical),
                entry.tiny_packets,
                entry.total_packets,
                entry.packet_size_min,
                entry.packet_size_max,
            );
            entry.role = resolved.clone();
            entry.label = inbound_display_label(&ip, host_hint, &resolved);
            if identical > entry.identical_count {
                entry.identical_count = identical;
                entry.identical_size = size;
            }
            if poll_min > 0 {
                entry.packet_size_min = if entry.packet_size_min == 0 {
                    poll_min
                } else {
                    entry.packet_size_min.min(poll_min)
                };
            }
            if poll_max > 0 {
                entry.packet_size_max = entry.packet_size_max.max(poll_max);
            }
            let fixed_size = p.get("fixed_size").and_then(|v| v.as_bool()).unwrap_or(false)
                || (entry.packet_size_min > 0
                    && entry.packet_size_min == entry.packet_size_max
                    && entry.identical_count >= 6);
            entry.suspicious = entry.suspicious || suspicious || vps_probe || fixed_size
                || entry.identical_count >= 6
                || entry.tiny_packets >= 4;
            entry.vps_probe = entry.vps_probe || vps_probe;
        }

        let rows: Vec<PeerRow> = st.rows.values().cloned().collect();
        drop(st);
        self.write_peers_latest(&hex, phase, &rows);
    }

    pub fn clear_table(&self) -> Result<Value, String> {
        let mut st = self.inner.lock();
        let Some(hex) = st.session_hex.clone() else {
            st.rows.clear();
            return Ok(json!({
                "ok": true,
                "message": "Table cleared (no active session)",
                "session_hex": null,
            }));
        };
        let phase = st.phase.clone();
        let rows: Vec<PeerRow> = st.rows.values().cloned().collect();
        let snap_name = format!("clear-{}-{}.json", st.clear_count + 1, ts_slug());
        st.clear_count += 1;
        st.snapshot_files.push(snap_name.clone());
        let clear_n = st.clear_count;
        st.rows.clear();
        drop(st);

        self.write_snapshot(&hex, &snap_name, &phase, &rows)?;
        self.write_session_meta(&hex, &phase, false);
        self.write_peers_latest(&hex, &phase, &[]);

        Ok(json!({
            "ok": true,
            "message": format!("Saved {} peer(s) to snapshot, table cleared", rows.len()),
            "session_hex": hex,
            "snapshot": snap_name,
            "cleared_peers": rows.len(),
            "clear_count": clear_n,
        }))
    }

    pub fn end_session(&self) -> Option<String> {
        let mut st = self.inner.lock();
        let Some(hex) = st.session_hex.take() else {
            return None;
        };
        let rows: Vec<PeerRow> = st.rows.values().cloned().collect();
        let phase = st.phase.clone();
        let started = st.session_started;
        let snapshots = st.snapshot_files.clone();
        st.rows.clear();
        st.clear_count = 0;
        st.snapshot_files.clear();
        st.session_started = 0.0;
        st.phase.clear();
        drop(st);

        self.write_session_meta(&hex, &phase, true);
        if !rows.is_empty() {
            let _ = self.write_snapshot(&hex, "final.json", &phase, &rows);
        }
        let _ = self.write_peers_latest(&hex, "ended", &rows);
        tracing::info!("[peer-tracker] session {hex} ended — {} peer(s)", rows.len());
        Some(hex)
    }

    pub fn start_fresh_session(&self, phase: &str) -> String {
        let _ = self.end_session();
        self.ensure_session(phase)
    }

    fn write_session_meta(&self, hex: &str, phase: &str, ended: bool) {
        let st = self.inner.lock();
        let dir = self.session_dir(hex);
        let _ = fs::create_dir_all(&dir);
        let meta = SessionMeta {
            session_hex: hex.into(),
            started_at: st.session_started,
            ended_at: if ended { Some(now_secs()) } else { None },
            phase: phase.into(),
            clear_count: st.clear_count,
            snapshot_files: st.snapshot_files.clone(),
        };
        drop(st);
        let path = dir.join("session.meta.json");
        if let Ok(text) = serde_json::to_string_pretty(&meta) {
            let _ = fs::write(path, text);
        }
    }

    fn write_peers_latest(&self, hex: &str, phase: &str, rows: &[PeerRow]) {
        let dir = self.session_dir(hex);
        let _ = fs::create_dir_all(&dir);
        let body = json!({
            "session_hex": hex,
            "phase": phase,
            "updated_at": now_secs(),
            "peers": rows_sorted(rows, phase),
        });
        if let Ok(text) = serde_json::to_string_pretty(&body) {
            let _ = fs::write(dir.join("peers.latest.json"), text);
        }
    }

    fn write_snapshot(
        &self,
        hex: &str,
        name: &str,
        phase: &str,
        rows: &[PeerRow],
    ) -> Result<(), String> {
        let dir = self.session_dir(hex).join("snapshots");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let body = json!({
            "session_hex": hex,
            "phase": phase,
            "saved_at": now_secs(),
            "peers": rows_sorted(rows, phase),
        });
        fs::write(
            dir.join(name),
            serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        let st = self.inner.lock();
        let gaming = st.phase == "matchmaking" || st.phase == "in-match";
        let rows: Vec<PeerRow> = if gaming {
            st.rows.values().cloned().collect()
        } else {
            vec![]
        };
        json!({
            "session_hex": if gaming { st.session_hex.clone() } else { None },
            "session_started": st.session_started,
            "phase": st.phase,
            "clear_count": st.clear_count,
            "peer_count": rows.len(),
            "snapshots": st.snapshot_files,
            "storage_dir": st.session_hex.as_ref().map(|h| self.session_dir(h).display().to_string()),
            "peers": rows_sorted(&rows, &st.phase),
        })
    }

    pub fn list_sessions(&self) -> Value {
        let mut sessions = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for ent in entries.flatten() {
                let path = ent.path();
                if !path.is_dir() {
                    continue;
                }
                let hex = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if hex.len() != 16 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let meta_path = path.join("session.meta.json");
                if meta_path.is_file() {
                    if let Ok(text) = fs::read_to_string(&meta_path) {
                        if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
                            if let Some(obj) = v.as_object_mut() {
                                let peers_path = path.join("peers.latest.json");
                                if peers_path.is_file() {
                                    if let Ok(doc) = Self::read_json_path(&peers_path) {
                                        let n = doc
                                            .get("peers")
                                            .and_then(|p| p.as_array())
                                            .map(|a| a.len())
                                            .unwrap_or(0);
                                        obj.insert("peer_count".into(), json!(n));
                                    }
                                }
                                let snap_dir = path.join("snapshots");
                                let snap_n = fs::read_dir(&snap_dir)
                                    .map(|rd| {
                                        rd.flatten()
                                            .filter(|e| {
                                                e.path()
                                                    .extension()
                                                    .and_then(|s| s.to_str())
                                                    == Some("json")
                                            })
                                            .count()
                                    })
                                    .unwrap_or(0);
                                obj.insert("snapshot_count".into(), json!(snap_n));
                            }
                            sessions.push(v);
                            continue;
                        }
                    }
                }
                sessions.push(json!({ "session_hex": hex }));
            }
        }
        sessions.sort_by(|a, b| {
            let ta = a.get("started_at").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let tb = b.get("started_at").and_then(|v| v.as_f64()).unwrap_or(0.0);
            tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
        });
        json!({ "sessions": sessions, "base_dir": self.base_dir.display().to_string(), "count": sessions.len() })
    }

    pub fn read_session(&self, hex: &str) -> Result<Value, String> {
        if !Self::valid_session_hex(hex) {
            return Err("invalid session_hex".into());
        }
        let dir = self.session_dir(hex);
        if !dir.is_dir() {
            return Err("session not found".into());
        }
        let meta = Self::read_json_path(&dir.join("session.meta.json"))?;
        let peers_doc = Self::read_json_path(&dir.join("peers.latest.json")).unwrap_or(json!({}));
        let peers = peers_doc
            .get("peers")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let mut snapshots: Vec<Value> = Vec::new();
        let snap_dir = dir.join("snapshots");
        if snap_dir.is_dir() {
            for ent in fs::read_dir(&snap_dir).map_err(|e| e.to_string())?.flatten() {
                let path = ent.path();
                if !path.is_file() {
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if !name.ends_with(".json") {
                    continue;
                }
                let mut doc = Self::read_json_path(&path)?;
                if doc.get("filename").is_none() {
                    doc["filename"] = json!(name);
                }
                snapshots.push(doc);
            }
        }
        snapshots.sort_by(|a, b| {
            let fa = a.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            let fb = b.get("filename").and_then(|v| v.as_str()).unwrap_or("");
            fa.cmp(fb)
        });
        Ok(json!({
            "ok": true,
            "session_hex": hex,
            "meta": meta,
            "peers": peers,
            "peer_count": peers.as_array().map(|a| a.len()).unwrap_or(0),
            "snapshots": snapshots,
            "snapshot_count": snapshots.len(),
            "storage_dir": dir.display().to_string(),
        }))
    }

    pub fn export_session_bundle(&self, hex: &str) -> Result<Value, String> {
        let detail = self.read_session(hex)?;
        let dir = self.session_dir(hex);
        let mut files: Vec<Value> = Vec::new();
        for ent in fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
            let path = ent.path();
            if path.is_file() {
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                if name.ends_with(".json") {
                    files.push(json!({
                        "path": name,
                        "data": Self::read_json_path(&path)?,
                    }));
                }
            }
        }
        let snap_dir = dir.join("snapshots");
        if snap_dir.is_dir() {
            for ent in fs::read_dir(&snap_dir).map_err(|e| e.to_string())?.flatten() {
                let path = ent.path();
                if !path.is_file() {
                    continue;
                }
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                if name.ends_with(".json") {
                    files.push(json!({
                        "path": format!("snapshots/{name}"),
                        "data": Self::read_json_path(&path)?,
                    }));
                }
            }
        }
        Ok(json!({
            "exported_at": now_secs(),
            "format": "warzone-sentinel-session-v1",
            "session_hex": hex,
            "detail": detail,
            "files": files,
        }))
    }

    fn valid_session_hex(hex: &str) -> bool {
        hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn read_json_path(path: &std::path::Path) -> Result<Value, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
}

fn rows_sorted(rows: &[PeerRow], phase: &str) -> Vec<Value> {
    let mut out: Vec<PeerRow> = rows
        .iter()
        .filter(|p| should_show_in_peer_table(&p.role, phase))
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        b.identical_count
            .cmp(&a.identical_count)
            .then(b.total_packets.cmp(&a.total_packets))
            .then(a.ip.cmp(&b.ip))
    });
    out.into_iter()
        .map(|p| {
            json!({
                "ip": p.ip,
                "remote": p.remote,
                "label": p.label,
                "role": p.role,
                "identical_count": p.identical_count,
                "identical_size": p.identical_size,
                "packet_size_min": p.packet_size_min,
                "packet_size_max": p.packet_size_max,
                "fixed_size": p.packet_size_min > 0
                    && p.packet_size_min == p.packet_size_max
                    && p.identical_count >= 6,
                "total_packets": p.total_packets,
                "tiny_packets": p.tiny_packets,
                "poll_hits": p.poll_hits,
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "suspicious": p.suspicious,
                "vps_probe": p.vps_probe,
            })
        })
        .collect()
}

static TRACKER: OnceLock<PeerTracker> = OnceLock::new();

pub fn tracker() -> &'static PeerTracker {
    TRACKER.get_or_init(PeerTracker::from_env)
}
