//! Overwolf / Xbox companion game events — ground truth for kicks, playlist, player flags.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVENTS: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GameEvent {
    pub ts: f64,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(default)]
    pub player: String,
    #[serde(default)]
    pub playlist: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub source: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

pub struct GameStateStore {
    events: Mutex<Vec<GameEvent>>,
    playlist: Mutex<String>,
    last_kick_at: Mutex<f64>,
    player_flags: Mutex<HashMap<String, u32>>,
}

impl Default for GameStateStore {
    fn default() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            playlist: Mutex::new(String::new()),
            last_kick_at: Mutex::new(0.0),
            player_flags: Mutex::new(HashMap::new()),
        }
    }
}

impl GameStateStore {
    pub fn ingest(&self, raw: &Value) -> Value {
        let ts = now();
        let event_type = raw
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if let Some(pl) = raw.get("playlist").and_then(|v| v.as_str()) {
            if !pl.is_empty() {
                *self.playlist.lock() = pl.to_string();
            }
        }
        if event_type == "match" || event_type == "match_start" {
            if let Some(pl) = raw.get("mode").and_then(|v| v.as_str()) {
                *self.playlist.lock() = pl.to_string();
            }
        }

        let player = raw
            .get("player")
            .or(raw.get("victim"))
            .or(raw.get("killer"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut extra = HashMap::new();
        if let Some(obj) = raw.as_object() {
            for (k, v) in obj {
                if matches!(
                    k.as_str(),
                    "type" | "player" | "victim" | "killer" | "playlist" | "mode"
                ) {
                    continue;
                }
                extra.insert(k.clone(), v.clone());
            }
        }

        let ev = GameEvent {
            ts,
            event_type: event_type.clone(),
            player: player.clone(),
            playlist: self.playlist.lock().clone(),
            note: raw
                .get("note")
                .or(raw.get("detail"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            source: raw
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("api")
                .to_string(),
            extra,
        };

        if matches!(
            event_type.as_str(),
            "kick" | "kicked" | "disconnect" | "lobby_kick"
        ) || raw.get("kicked").and_then(|v| v.as_bool()) == Some(true)
        {
            *self.last_kick_at.lock() = ts;
        }

        if !player.is_empty()
            && matches!(
                event_type.as_str(),
                "prefire" | "killcam_result" | "snap" | "wallhack" | "cheater"
            )
        {
            *self.player_flags.lock().entry(player).or_default() += 1;
        }

        let mut events = self.events.lock();
        events.push(ev);
        if events.len() > MAX_EVENTS {
            let drop = events.len() - MAX_EVENTS;
            events.drain(0..drop);
        }

        json!({
            "ok": true,
            "accepted": 1,
            "type": event_type,
            "playlist": self.playlist.lock().clone(),
            "recent_kick": self.recent_kick(120.0),
        })
    }

    pub fn ingest_batch(&self, items: &[Value]) -> Value {
        let mut n = 0;
        for item in items {
            if item.is_object() {
                self.ingest(item);
                n += 1;
            }
        }
        json!({ "ok": true, "accepted": n })
    }

    pub fn playlist(&self) -> String {
        self.playlist.lock().clone()
    }

    pub fn recent_kick(&self, window_sec: f64) -> bool {
        let ts = *self.last_kick_at.lock();
        ts > 0.0 && now() - ts <= window_sec
    }

    pub fn kick_age_sec(&self) -> Option<f64> {
        let ts = *self.last_kick_at.lock();
        if ts <= 0.0 {
            return None;
        }
        Some(now() - ts)
    }

    pub fn to_json(&self) -> Value {
        let events = self.events.lock();
        let recent: Vec<Value> = events
            .iter()
            .rev()
            .take(24)
            .map(|e| {
                json!({
                    "ts": e.ts,
                    "type": e.event_type,
                    "player": e.player,
                    "playlist": e.playlist,
                    "source": e.source,
                    "note": e.note,
                })
            })
            .collect();
        json!({
            "playlist": self.playlist.lock().clone(),
            "recent_kick": self.recent_kick(180.0),
            "kick_age_sec": self.kick_age_sec(),
            "flagged_players": self.player_flags.lock().len(),
            "events": recent,
        })
    }

    pub fn clear_session(&self) {
        self.events.lock().clear();
        *self.last_kick_at.lock() = 0.0;
        self.player_flags.lock().clear();
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

static STORE: OnceLock<GameStateStore> = OnceLock::new();

pub fn store() -> &'static GameStateStore {
    STORE.get_or_init(GameStateStore::default)
}
