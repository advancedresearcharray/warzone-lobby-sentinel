use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout, Duration};
use tracing_subscriber::EnvFilter;
use warzone_sentinel::{
    dashboard, enrich::enrich_snapshot, firewalla::FirewallaClient, game_state,
    learning, learning::engine,
    network_guard::guard, network_session::NetworkSessionScorer, notify, packets, peer_tracker,
    traffic,
};

struct AppState {
    risk: Mutex<Option<Value>>,
    last_snapshot: Mutex<Option<Value>>,
    last_error: Mutex<Option<String>>,
    source: Mutex<String>,
    updated_at: Mutex<f64>,
    polls: Mutex<u64>,
    network_guard: Mutex<Option<Value>>,
    last_auto_alert: Mutex<Option<Value>>,
    last_packet_capture: Mutex<Option<Value>>,
    scorer: Mutex<NetworkSessionScorer>,
    peer_restrictions_cache: Mutex<Option<(f64, Value)>>,
    offender_ips_cache: Mutex<(f64, Vec<String>)>,
    vps_blocked_ips: Mutex<std::collections::HashSet<String>>,
    fw: FirewallaClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let fw = FirewallaClient::from_env().expect("array-firewall API config");
    let host = std::env::var("WZ_INGEST_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("WZ_INGEST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8098);
    let interval: f64 = std::env::var("WZ_POLL_INTERVAL_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4.0);
    let idle_interval: f64 = std::env::var("WZ_POLL_INTERVAL_IDLE_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12.0);

    let state = Arc::new(AppState {
        risk: Mutex::new(None),
        last_snapshot: Mutex::new(None),
        last_error: Mutex::new(None),
        source: Mutex::new(String::new()),
        updated_at: Mutex::new(0.0),
        polls: Mutex::new(0),
        network_guard: Mutex::new(None),
        last_auto_alert: Mutex::new(None),
        last_packet_capture: Mutex::new(None),
        scorer: Mutex::new(NetworkSessionScorer::default()),
        peer_restrictions_cache: Mutex::new(None),
        offender_ips_cache: Mutex::new((0.0, Vec::new())),
        vps_blocked_ips: Mutex::new(std::collections::HashSet::new()),
        fw,
    });

    let poll_state = state.clone();
    std::thread::Builder::new()
        .name("wz-poll".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("poll runtime");
            rt.block_on(run_poll_loop(poll_state, interval, idle_interval));
        })
        .expect("poll thread spawn");

    let app = Router::new()
        .route("/", get(dashboard_page))
        .route("/v1/dashboard", get(dashboard_page))
        .route("/dashboard", get(dashboard_page))
        .route("/v1/dashboard/data", get(dashboard_data))
        .route("/dashboard/data", get(dashboard_data))
        .route("/health", get(health))
        .route("/v1/health", get(health))
        .route("/v1/status", get(status))
        .route("/status", get(status))
        .route("/v1/feedback", get(feedback_help).post(feedback_post))
        .route("/feedback", get(feedback_help).post(feedback_post))
        .route("/v1/feedback/kicked", post(feedback_kicked))
        .route("/feedback/kicked", post(feedback_kicked))
        .route("/v1/session/end", post(session_end))
        .route("/session/end", post(session_end))
        .route("/v1/session/match", post(session_match))
        .route("/session/match", post(session_match))
        .route("/v1/events", post(events_post))
        .route("/events", post(events_post))
        .route("/v1/game-state", get(game_state_get).post(game_state_post))
        .route("/v1/intel/export", get(intel_export))
        .route("/v1/intel/import", post(intel_import))
        .route("/intel/export", get(intel_export))
        .route("/intel/import", post(intel_import))
        .route("/v1/network-guard/release", post(network_guard_release))
        .route("/network-guard/release", post(network_guard_release))
        .route("/v1/ai/calibration", get(ai_calibration))
        .route("/v1/ai/analyze", get(ai_analyze))
        .route("/v1/traffic", get(traffic_inspect))
        .route("/v1/traffic/outbound", get(traffic_outbound))
        .route("/v1/traffic/inbound", get(traffic_inbound))
        .route("/v1/traffic/inbound/analyze", get(traffic_inbound_analyze))
        .route("/v1/packets", get(packets_view))
        .route("/v1/packets/analyze", get(packets_analyze))
        .route("/v1/packets/capture", post(packets_capture))
        .route("/v1/peers/clear", post(peers_clear))
        .route("/v1/peers/sessions", get(peers_sessions))
        .route("/v1/sessions", get(sessions_list))
        .route("/v1/sessions/{hex}", get(session_detail))
        .route("/v1/sessions/{hex}/download", get(session_download))
        .route("/v1/peers/shield", post(peers_shield))
        .route("/v1/peers/restrict", post(peers_restrict))
        .route("/v1/peers/unrestrict", post(peers_unrestrict))
        .route("/v1/connections", get(connections_query))
        .route("/v1/connections/sessions", get(connections_sessions))
        .route("/v1/connections/offenders", get(connections_offenders))
        .route("/v1/connections/action", post(connections_action))
        .route("/v1/investigate/run", post(investigate_run))
        .route("/traffic", get(traffic_inspect))
        .route("/ai/calibration", get(ai_calibration))
        .route("/ai/analyze", get(ai_analyze))
        .route("/v1/alerts/setup", get(alerts_setup))
        .route("/alerts/setup", get(alerts_setup))
        .route("/v1/alerts/test", get(alerts_test))
        .route("/alerts/test", get(alerts_test))
        .route("/v1/xbox/setup", get(xbox_setup).post(xbox_setup_post))
        .route("/xbox/setup", get(xbox_setup).post(xbox_setup_post))
        .route("/v1/xbox/test", get(|| async { Redirect::temporary("/v1/alerts/test") }))
        .with_state(state.clone());

    let addr = format!("{host}:{port}");
    tracing::info!("Warzone Sentinel (Rust) listening on http://{addr}/v1/dashboard");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn run_poll_loop(state: Arc<AppState>, interval: f64, idle_interval: f64) {
    let api = state.fw.base.clone();
    let ok = state.fw.probe().await;
    *state.source.lock() = if ok {
        format!("array-firewall:{api}")
    } else {
        "unconfigured".into()
    };
    tracing::info!(
        "Autonomous Xbox mode — polling array-firewall {api} every {interval}s active / {idle_interval}s idle (Rust + 32D fold)"
    );
    if guard().release_now(&state.fw).await {
        tracing::info!("[network-guard] startup sync — cleared stale defense rules");
    }
    let st = notify::alert_status();
    if st["phone_push"].as_bool().unwrap_or(false) {
        tracing::info!("Phone alerts (auto on POSSIBLE/LIKELY): {}", st["phone_subscribe_url"]);
    }

    loop {
        let mut sleep_sec = idle_interval;
        match state.fw.fetch_snapshot().await {
            Ok(mut raw) => {
                let poll_n = *state.polls.lock() + 1;
                let xbox_online = raw
                    .pointer("/xbox/online")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if xbox_online && poll_n % 6 == 0 {
                    if let Ok(deep) = state.fw.fetch_packet_capture(400).await {
                        let deep_pc = deep.get("packetCapture");
                        let shallow = raw
                            .pointer("/packetCapture/records")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let deep_n = deep_pc
                            .and_then(|p| p.get("records"))
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        if deep_n > shallow {
                            if let Some(pc) = deep_pc {
                                raw["packetCapture"] = pc.clone();
                            }
                        }
                        *state.last_packet_capture.lock() =
                            Some(deep_pc.cloned().unwrap_or(deep));
                    }
                }
                let raw_for_enrich = raw.clone();
                let snapshot = tokio::task::spawn_blocking(move || enrich_snapshot(raw_for_enrich))
                    .await
                    .unwrap_or(raw);
                *state.last_snapshot.lock() = Some(dashboard::trim_snapshot(&snapshot));
                let insights = json!({});
                let (mut risk, alert_decision) = {
                    let mut scorer = state.scorer.lock();
                    let mut risk = scorer.score(&snapshot, &insights);
                    let conns = snapshot
                        .pointer("/connections/count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as i64;
                    let playlist = game_state::store().playlist();
                    let offender_ips = cached_offender_ips(&state, poll_n).await;
                    let reputation = engine().lobby_reputation(
                        &snapshot,
                        conns,
                        &risk.phase,
                        risk.cheater_lobby
                            .get("mm_delta")
                            .and_then(|v| v.as_f64()),
                        &playlist,
                        &offender_ips,
                    );
                    risk = risk.with_reputation(reputation, &offender_ips);
                    let decision = scorer.should_alert(&risk);
                    (risk, decision)
                };
                if risk.phase == "matchmaking" || risk.phase == "in-match" {
                    sleep_sec = interval;
                } else if xbox_online {
                    let conns = snapshot
                        .pointer("/connections/count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let game = snapshot
                        .pointer("/_enriched/game")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    if game == "warzone" && conns >= 20 {
                        sleep_sec = interval;
                    }
                }
                let ng = guard()
                    .evaluate(&state.fw, &risk, &snapshot)
                    .await;
                let desync_on = ng.get("mode").and_then(|v| v.as_str()) == Some("desync");
                let flood_on = ng
                    .pointer("/flood_guard/active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                engine().record_guard_activity(desync_on, flood_on);
                *state.network_guard.lock() = Some(ng.clone());
                let mut risk_json = risk.to_json();
                if let Some(obj) = risk_json.as_object_mut() {
                    obj.insert("network_guard".into(), ng.clone());
                    if let Some(m) = ng.get("mitigation") {
                        obj.insert("defense_status".into(), m.clone());
                    }
                }
                let pt = peer_tracker::tracker();
                pt.set_phase(&risk.phase);
                if let Some(peers) = risk
                    .packets
                    .get("metrics")
                    .and_then(|m| m.get("inbound_identical_peers"))
                    .and_then(|v| v.as_array())
                {
                    pt.ingest_identical_peers(&risk.phase, peers);
                }
                if risk.phase == "matchmaking" || risk.phase == "in-match" {
                    if let Some(vps_ips) = extract_vps_game_peer_ips(&risk.packets) {
                        let mut blocked = state.vps_blocked_ips.lock();
                        let new_ips: Vec<String> = vps_ips
                            .into_iter()
                            .filter(|ip| !blocked.contains(ip))
                            .collect();
                        if !new_ips.is_empty() {
                            let fw = state.fw.clone();
                            let phase = risk.phase.clone();
                            for ip in &new_ips {
                                blocked.insert(ip.clone());
                            }
                            drop(blocked);
                            let ips = new_ips.clone();
                            tokio::spawn(async move {
                                if let Ok(r) = fw
                                    .block_peers(&ips, "vultr_vps_game_peer", Some(604_800))
                                    .await
                                {
                                    tracing::info!(
                                        "[vps-block] auto-blocked {} Vultr/VPS game-peer(s) in {phase}: {:?}",
                                        ips.len(),
                                        r.get("added").or(r.get("total"))
                                    );
                                }
                                if let Ok(sr) = fw
                                    .block_subnets_from_ips(&ips, "vultr_vps_game_peer")
                                    .await
                                {
                                    tracing::info!(
                                        "[subnet-block] mesh /24 blocks in {phase}: {:?}",
                                        sr.get("results").and_then(|v| v.as_array()).map(|a| a.len())
                                    );
                                }
                                let _ = fw.sync_shield_peers("peer-strict", &ips).await;
                            });
                        }
                    }
                }
                if risk.phase == "matchmaking" || risk.phase == "in-match" {
                    let session_hex = pt.to_json().get("session_hex").and_then(|v| v.as_str()).map(str::to_string);
                    if let Some(hex) = session_hex {
                        let fw = state.fw.clone();
                        let phase = risk.phase.clone();
                        let xbox = fw.xbox_ip();
                        let peers_for_db = risk
                            .packets
                            .pointer("/metrics/inbound_identical_peers")
                            .cloned()
                            .unwrap_or(json!([]));
                        let slim_snap = json!({
                            "connections": snapshot.get("connections"),
                            "recentFlows": snapshot.get("recentFlows"),
                        });
                        tokio::spawn(async move {
                            let body = json!({
                                "session_hex": hex,
                                "phase": phase,
                                "xbox_ip": xbox,
                                "snapshot": slim_snap,
                                "peers": peers_for_db,
                            });
                            if let Err(e) = fw.ingest_connections(body).await {
                                tracing::debug!("[conn-lite] ingest: {e}");
                            }
                        });
                    }
                }
                if risk.phase == "matchmaking" || risk.phase == "in-match" {
                    let kick_spike = ng
                        .get("kick_spike")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let session_hex = pt
                        .to_json()
                        .get("session_hex")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    if let Some(obj) = risk_json.as_object_mut() {
                        if let Some(hex) = session_hex.clone() {
                            obj.insert("session_hex".into(), json!(hex));
                        }
                        obj.insert(
                            "offender_ips".into(),
                            json!(cached_offender_ips(&state, poll_n).await),
                        );
                    }
                    match state.fw.mitigate_session(&risk_json, kick_spike).await {
                        Ok(m) => {
                            if m.get("skipped").and_then(|v| v.as_bool()) != Some(true) {
                                if let Some(actions) = m.get("actions").and_then(|v| v.as_array()) {
                                    if !actions.is_empty() {
                                        tracing::info!("[mitigate] {:?}", actions);
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::debug!("[mitigate] {e}"),
                    }
                }
                *state.risk.lock() = Some(risk_json);
                *state.last_error.lock() = None;
                *state.updated_at.lock() = now_secs();
                *state.polls.lock() += 1;
                *state.source.lock() = format!("array-firewall:{api}");

                if alert_decision.send {
                    tracing::warn!(
                        "WZ ALERT [{}] score={:.0} phase={} ({}) — {}",
                        risk.level,
                        risk.score,
                        risk.phase,
                        alert_decision.reason,
                        risk.recommendation
                    );
                    let sent = notify::notify_session_alert(
                        &risk.level,
                        risk.score,
                        &risk.phase,
                        &risk.game,
                        &risk.recommendation,
                        &risk.anomalies,
                        &risk.cheater_lobby,
                        false,
                    )
                    .await;
                    *state.last_auto_alert.lock() = Some(json!({
                        "at": now_secs(),
                        "label": risk.cheater_lobby.get("label"),
                        "score": risk.score,
                        "phase": risk.phase,
                        "reason": alert_decision.reason,
                        "delivered": sent,
                    }));
                }
            }
            Err(e) => {
                let polls = *state.polls.lock();
                *state.last_error.lock() = Some(e.clone());
                if polls == 0 || polls % 20 == 0 {
                    tracing::warn!("[wz] poll error: {e}");
                }
            }
        }
        sleep(Duration::from_secs_f64(sleep_sec)).await;
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "ok": state.last_error.lock().is_none() || state.risk.lock().is_some(),
        "mode": "autonomous",
        "platform": "xbox",
        "runtime": "rust",
        "source": *state.source.lock(),
        "polls": *state.polls.lock(),
        "error": *state.last_error.lock(),
        "alerts": notify::alert_status(),
        "learning": engine().insights(),
        "network_guard": *state.network_guard.lock(),
        "last_auto_alert": *state.last_auto_alert.lock(),
    }))
}

async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "autonomous": true,
        "runtime": "rust",
        "source": *state.source.lock(),
        "updated_at": *state.updated_at.lock(),
        "alerts": {
            "mode": "automatic",
            "description": "Phone push fires on POSSIBLE/LIKELY during matchmaking or in-match — no feedback required",
            "phone": notify::alert_status(),
            "last_auto_alert": *state.last_auto_alert.lock(),
        },
        "session": *state.risk.lock(),
    }))
}

async fn ai_calibration() -> Json<Value> {
    Json(json!({
        "ok": true,
        "calibration": engine().calibration(),
        "insights": engine().insights(),
    }))
}

async fn ai_analyze(State(state): State<Arc<AppState>>) -> Json<Value> {
    let session = state.risk.lock().clone();
    Json(json!({
        "ok": true,
        "updated_at": *state.updated_at.lock(),
        "session": session,
        "ai": session.as_ref().and_then(|s| s.get("ai").cloned()),
    }))
}

async fn dashboard_page() -> Html<&'static str> {
    Html(dashboard::dashboard_page())
}

async fn cached_peer_restrictions(state: &AppState) -> Option<Value> {
    let now = now_secs();
    if let Some((at, cached)) = state.peer_restrictions_cache.lock().clone() {
        if now - at < 15.0 {
            return Some(cached);
        }
    }
    let fetched = timeout(Duration::from_secs(2), state.fw.peer_blocklist_status())
        .await
        .ok()
        .and_then(|r| r.ok());
    if let Some(v) = fetched.clone() {
        *state.peer_restrictions_cache.lock() = Some((now, v.clone()));
    }
    fetched
}

async fn dashboard_data(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    let session = state.risk.lock().clone();
    let scorer_meta = state.scorer.lock().dashboard_meta();
    let updated_at = *state.updated_at.lock();
    let polls = *state.polls.lock();
    let source = state.source.lock().clone();
    let error = state.last_error.lock().clone();
    let last_auto_alert = state.last_auto_alert.lock().clone();
    let network_guard = state.network_guard.lock().clone();
    let restrictions = cached_peer_restrictions(&state).await;
    let learning = tokio::task::spawn_blocking(|| engine().insights())
        .await
        .unwrap_or(json!({}));
    let mut peer_tracker = peer_tracker::tracker().to_json();
    merge_peer_restrictions(&mut peer_tracker, restrictions.as_ref());
    Json(json!({
        "updated_at": updated_at,
        "polls": polls,
        "source": source,
        "error": error,
        "session": session,
        "telemetry": snap.clone(),
        "traffic": traffic::inspect(&snap, "all"),
        "scorer": scorer_meta,
        "alerts": {
            "mode": "automatic",
            "phone": notify::alert_status(),
            "last_auto_alert": last_auto_alert.clone(),
        },
        "learning": learning,
        "network_guard": network_guard,
        "last_auto_alert": last_auto_alert,
        "peer_tracker": peer_tracker,
        "peer_restrictions": restrictions,
    }))
}

fn merge_peer_restrictions(peer_tracker: &mut Value, restrictions: Option<&Value>) {
    let Some(bl) = restrictions else {
        return;
    };
    let mut by_ip: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    if let Some(arr) = bl.get("peers").and_then(|v| v.as_array()) {
        for p in arr {
            if let Some(ip) = p.get("ip").and_then(|v| v.as_str()) {
                by_ip.insert(ip.into(), p.clone());
            }
        }
    }
    let Some(peers) = peer_tracker.get_mut("peers").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for row in peers.iter_mut() {
        let Some(ip) = row.get("ip").and_then(|v| v.as_str()) else {
            continue;
        };
        if let Some(meta) = by_ip.get(ip) {
            let reason = meta.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            row["restricted"] = json!(true);
            row["restriction_reason"] = json!(reason);
            row["repeat_offender"] = meta.get("repeat_offender").cloned().unwrap_or(json!(false));
            row["shielded"] = json!(reason.contains("shield") || reason.contains("restrict"));
        } else {
            row["restricted"] = json!(false);
            row["shielded"] = json!(false);
        }
    }
}

#[derive(Deserialize, Default)]
struct TrafficQuery {
    dir: Option<String>,
}

async fn traffic_inspect(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TrafficQuery>,
) -> Json<Value> {
    let dir = q.dir.as_deref().unwrap_or("out");
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    Json(json!({
        "ok": true,
        "updated_at": *state.updated_at.lock(),
        "polls": *state.polls.lock(),
        "traffic": traffic::inspect(&snap, dir),
    }))
}

async fn traffic_outbound(State(state): State<Arc<AppState>>) -> Json<Value> {
    traffic_inspect(
        State(state),
        Query(TrafficQuery {
            dir: Some("out".into()),
        }),
    )
    .await
}

async fn traffic_inbound(State(state): State<Arc<AppState>>) -> Json<Value> {
    traffic_inspect(
        State(state),
        Query(TrafficQuery {
            dir: Some("in".into()),
        }),
    )
    .await
}

async fn traffic_inbound_analyze(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    let session = state.risk.lock().clone().unwrap_or(json!({}));
    let phase = session
        .get("phase")
        .and_then(|v| v.as_str())
        .unwrap_or("idle");
    let eng = learning::engine();
    let th = eng.thresholds();
    let baseline = eng.inbound_baseline();
    let inbound = traffic::analyze_inbound(&snap, phase, baseline.as_ref(), &th);
    Json(json!({
        "ok": true,
        "updated_at": *state.updated_at.lock(),
        "phase": phase,
        "inbound_analysis": inbound.to_json(),
        "traffic": traffic::inspect(&snap, "in"),
    }))
}

async fn packets_view(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    let pc = snap.get("packetCapture").cloned().unwrap_or(json!({}));
    Json(json!({
        "ok": true,
        "updated_at": *state.updated_at.lock(),
        "packetCapture": pc,
        "topFlows": snap.get("topFlows"),
        "lastDeepCapture": *state.last_packet_capture.lock(),
    }))
}

async fn packets_analyze(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    let session = state.risk.lock().clone().unwrap_or(json!({}));
    let phase = session
        .get("phase")
        .and_then(|v| v.as_str())
        .unwrap_or("idle");
    let conns = snap
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as i64;
    let analysis = packets::analyze_packets(&snap, phase, conns);
    Json(json!({
        "ok": true,
        "updated_at": *state.updated_at.lock(),
        "phase": phase,
        "packet_analysis": analysis.to_json(),
        "records": snap.pointer("/packetCapture/records"),
        "stats": snap.pointer("/packetCapture/stats"),
    }))
}

async fn packets_capture(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.fw.fetch_packet_capture(500).await {
        Ok(deep) => {
            let pc = deep
                .get("packetCapture")
                .cloned()
                .unwrap_or(deep.clone());
            *state.last_packet_capture.lock() = Some(pc.clone());
            let session = state.risk.lock().clone().unwrap_or(json!({}));
            let phase = session
                .get("phase")
                .and_then(|v| v.as_str())
                .unwrap_or("idle");
            let conns = state
                .last_snapshot
                .lock()
                .as_ref()
                .and_then(|s| s.pointer("/connections/count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as i64;
            let mut inspect = json!({
                "records": pc.get("records"),
                "stats": pc.get("stats"),
                "captured": pc.pointer("/stats/total"),
            });
            let analysis = packets::analyze_packets(&json!({"packetCapture": pc}), phase, conns);
            inspect["analysis"] = analysis.to_json();
            Json(json!({
                "ok": true,
                "updated_at": now_secs(),
                "inspect": inspect,
            }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn network_guard_release(State(state): State<Arc<AppState>>) -> Json<Value> {
    let released = guard().release_and_pause(&state.fw, 180.0).await;
    let ng = guard().current_status();
    *state.network_guard.lock() = Some(ng.clone());
    Json(json!({
        "ok": true,
        "network_guard_released": released,
        "pause_sec": 180,
        "message": "Defenses stopped for this session — network path restored. Cheater detection still active.",
        "network_guard": ng,
    }))
}

async fn session_match(State(state): State<Arc<AppState>>) -> Json<Value> {
    let scorer_meta = {
        let mut scorer = state.scorer.lock();
        scorer.mark_in_match();
        scorer.dashboard_meta()
    };
    let tracker = peer_tracker::tracker();
    tracker.set_phase("in-match");
    let hex = tracker.ensure_session("in-match");
    Json(json!({
        "ok": true,
        "message": "In-match mode — scoring and alerts active.",
        "session_hex": hex,
        "scorer": scorer_meta,
    }))
}

async fn peers_clear() -> Json<Value> {
    match peer_tracker::tracker().clear_table() {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn peers_sessions() -> Json<Value> {
    Json(json!({
        "ok": true,
        "tracker": peer_tracker::tracker().to_json(),
        "history": peer_tracker::tracker().list_sessions(),
    }))
}

async fn sessions_list() -> Json<Value> {
    let mut out = peer_tracker::tracker().list_sessions();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("ok".into(), json!(true));
    }
    Json(out)
}

async fn session_detail(Path(hex): Path<String>) -> Result<Json<Value>, (StatusCode, String)> {
    peer_tracker::tracker()
        .read_session(&hex)
        .map(Json)
        .map_err(|e| (StatusCode::NOT_FOUND, e))
}

async fn session_download(Path(hex): Path<String>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let bundle = peer_tracker::tracker()
        .export_session_bundle(&hex)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    let body = serde_json::to_string_pretty(&bundle)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let filename = format!("warzone-session-{hex}.json");
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    ))
}

#[derive(Deserialize, Default)]
struct PeerIpsBody {
    #[serde(default)]
    ips: Vec<String>,
}

fn normalize_ips(ips: &[String]) -> Vec<String> {
    ips.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn peers_shield(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PeerIpsBody>,
) -> Json<Value> {
    let ips = normalize_ips(&body.ips);
    if ips.is_empty() {
        return Json(json!({ "ok": false, "error": "no IPs selected" }));
    }
    let session_hex = peer_tracker::tracker()
        .to_json()
        .get("session_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("manual")
        .to_string();
    let reason = format!("sentinel-shield:{session_hex}");
    match state
        .fw
        .block_peers(&ips, &reason, Some(86_400))
        .await
    {
        Ok(block) => match state.fw.sync_shield_peers("peer-strict", &ips).await {
            Ok(shield) => Json(json!({
                "ok": block.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
                    && shield.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                "action": "shield",
                "ips": ips,
                "blocklist": block,
                "shield": shield,
                "message": format!("Shield active for {} peer(s) — tiny probes dropped", ips.len()),
            })),
            Err(e) => Json(json!({ "ok": false, "error": e, "blocklist": block })),
        },
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn peers_restrict(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PeerIpsBody>,
) -> Json<Value> {
    let ips = normalize_ips(&body.ips);
    if ips.is_empty() {
        return Json(json!({ "ok": false, "error": "no IPs selected" }));
    }
    let session_hex = peer_tracker::tracker()
        .to_json()
        .get("session_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("manual")
        .to_string();
    let reason = format!("sentinel-restrict:{session_hex}");
    match state
        .fw
        .block_peers(&ips, &reason, Some(604_800))
        .await
    {
        Ok(block) => match state.fw.sync_shield_peers("peer-strict", &ips).await {
            Ok(shield) => Json(json!({
                "ok": block.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
                    && shield.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
                "action": "restrict",
                "ips": ips,
                "blocklist": block,
                "shield": shield,
                "message": format!("Restricted {} peer(s) for 7 days — full peer block + shield", ips.len()),
            })),
            Err(e) => Json(json!({ "ok": false, "error": e, "blocklist": block })),
        },
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn peers_unrestrict(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PeerIpsBody>,
) -> Json<Value> {
    let ips = normalize_ips(&body.ips);
    if ips.is_empty() {
        return Json(json!({ "ok": false, "error": "no IPs selected" }));
    }
    match state.fw.remove_peers(&ips).await {
        Ok(removed) => match state.fw.sync_shield_peers("peer-strict", &[]).await {
            Ok(shield) => Json(json!({
                "ok": true,
                "action": "unrestrict",
                "ips": ips,
                "removed": removed,
                "shield": shield,
                "message": format!("Removed restriction from {} peer(s)", ips.len()),
            })),
            Err(e) => Json(json!({ "ok": false, "error": e, "removed": removed })),
        },
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize, Default)]
struct ConnectionsQuery {
    session_hex: Option<String>,
    ip: Option<String>,
    #[serde(rename = "type")]
    conn_type: Option<String>,
    policy: Option<String>,
    offenders: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn connections_query(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ConnectionsQuery>,
) -> Json<Value> {
    let offenders_only = q.offenders.as_deref().map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(false);
    match state
        .fw
        .query_connections(
            q.session_hex.as_deref(),
            q.ip.as_deref(),
            q.conn_type.as_deref(),
            q.policy.as_deref(),
            offenders_only,
            q.limit.unwrap_or(25),
            q.offset.unwrap_or(0),
        )
        .await
    {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn connections_sessions(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.fw.list_connection_sessions(40).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize, Default)]
struct OffendersQuery {
    min_sessions: Option<u32>,
    limit: Option<u32>,
}

async fn connections_offenders(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OffendersQuery>,
) -> Json<Value> {
    match state
        .fw
        .connection_offenders(q.min_sessions.unwrap_or(2), q.limit.unwrap_or(50))
        .await
    {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize, Default)]
struct ConnectionActionBody {
    #[serde(default)]
    ips: Vec<String>,
    action: String,
    session_hex: Option<String>,
}

async fn connections_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConnectionActionBody>,
) -> Json<Value> {
    let ips = normalize_ips(&body.ips);
    if ips.is_empty() {
        return Json(json!({ "ok": false, "error": "no IPs selected" }));
    }
    match state
        .fw
        .connections_action(&ips, &body.action, body.session_hex.as_deref())
        .await
    {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize, Default)]
struct InvestigateRunBody {
    limit: Option<u32>,
}

async fn investigate_run(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InvestigateRunBody>,
) -> Json<Value> {
    match state.fw.investigate_unknowns(body.limit.unwrap_or(30)).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

async fn session_end(State(state): State<Arc<AppState>>) -> Json<Value> {
    let ended_hex = peer_tracker::tracker().end_session();
    if let Some(ref hex) = ended_hex {
        let _ = state.fw.end_connection_session(hex).await;
        let _ = state.fw.correlate_probe_sink(hex).await;
    }
    state.vps_blocked_ips.lock().clear();
    let ended = engine().end_active_session();
    if engine().should_decay_blocks() {
        let _ = state.fw.decay_peer_blocks().await;
    }
    game_state::store().clear_session();
    state.scorer.lock().mark_lobby_exit();
    let guard_released = guard().release_if_engaged(&state.fw).await;
    Json(json!({
        "ok": true,
        "session_ended": ended,
        "session_hex": ended_hex,
        "network_guard_released": guard_released,
        "message": "Left lobby — alerts and desync tuning stopped.",
        "learning": engine().insights(),
    }))
}

async fn feedback_help(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "message": "Send POST with {\"bad_lobby\": true|false, \"note\": \"optional\"} — or POST /v1/feedback/kicked when kicked from lobby",
        "last_verdict": state.risk.lock().as_ref().and_then(|r| r.get("cheater_lobby").cloned()),
        "learning": engine().insights(),
    }))
}

#[derive(Deserialize)]
struct FeedbackBody {
    bad_lobby: bool,
    #[serde(default)]
    note: String,
}

async fn feedback_kicked(State(state): State<Arc<AppState>>) -> Json<Value> {
    game_state::store().ingest(&json!({"type": "kick", "source": "user", "note": "kicked from lobby"}));
    let (verdict, score) = session_verdict(&state);
    engine().record_feedback(true, "kicked from lobby by hacker", &verdict, score);
    let ended_hex = peer_tracker::tracker().end_session();
    let ended = engine().end_active_session();
    state.scorer.lock().mark_lobby_exit();
    let guard_released = guard().release_if_engaged(&state.fw).await;
    notify::notify_session_alert(
        "LIKELY",
        score.max(90.0),
        "in-match",
        "Warzone",
        "Kicked from lobby — logged as cheater attack.",
        &["You reported being kicked by a hacker".into()],
        &json!({"label": "LIKELY", "reasons": ["User kicked from lobby — cheater attack confirmed"]}),
        true,
    )
    .await;
    Json(json!({
        "ok": true,
        "kicked": true,
        "bad_lobby": true,
        "session_ended": ended,
        "session_hex": ended_hex,
        "network_guard_released": guard_released,
        "message": "Kicked logged — session ended, defenses released.",
        "learning": engine().insights(),
    }))
}

fn session_verdict(state: &Arc<AppState>) -> (String, f64) {
    state
        .risk
        .lock()
        .as_ref()
        .and_then(|r| {
            let cl = r.get("cheater_lobby")?;
            Some((
                cl.get("label")?.as_str()?.to_string(),
                cl.get("confidence")?.as_f64().unwrap_or(0.0),
            ))
        })
        .unwrap_or_else(|| ("UNKNOWN".into(), 0.0))
}

async fn feedback_post(State(state): State<Arc<AppState>>, Json(body): Json<FeedbackBody>) -> Json<Value> {
    let (verdict, score) = session_verdict(&state);
    engine().record_feedback(body.bad_lobby, &body.note, &verdict, score);
    if body.bad_lobby {
        notify::notify_session_alert(
            "LIKELY",
            75.0,
            "in-match",
            "Warzone",
            "Cheater lobby confirmed — defenses hardened on array-firewall.",
            &["You reported cheaters in this lobby".into()],
            &json!({"label": "LIKELY", "reasons": ["User confirmed cheaters in session"]}),
            true,
        )
        .await;
    }
    Json(json!({
        "ok": true,
        "bad_lobby": body.bad_lobby,
        "message": if body.bad_lobby {
            "Marked as cheater lobby — logged for learning."
        } else {
            "Marked as clean lobby."
        },
        "note": body.note.chars().take(200).collect::<String>(),
        "learning": engine().insights(),
    }))
}

async fn alerts_setup() -> Html<String> {
    let st = notify::alert_status();
    let ntfy_url = st["phone_subscribe_url"]
        .as_str()
        .unwrap_or(&notify::subscribe_url())
        .to_string();
    let oauth = notify::xbox_authorize_url();
    Html(format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>WZ Sentinel</title></head><body>
<h1>Warzone Sentinel alerts (Rust)</h1>
<h2>Phone (recommended)</h2>
<p><a href="{ntfy_url}">Subscribe on this phone</a></p>
<p><a href="/v1/alerts/test">Send test alert</a></p>
<h2>Xbox Live (optional)</h2>
<p><a href="{oauth}">Link Microsoft account</a> or <a href="/v1/xbox/setup">setup form</a></p>
</body></html>"#
    ))
}

async fn alerts_test() -> Html<&'static str> {
    let ok = notify::notify_session_alert(
        "TEST",
        50.0,
        "matchmaking",
        "Warzone",
        "Test alert — Rust sentinel running.",
        &["Sentinel is working".into()],
        &json!({}),
        true,
    )
    .await;
    if ok {
        Html("<h1>Test sent</h1><p><a href='/v1/alerts/setup'>Back</a></p>")
    } else {
        Html("<h1>Send failed</h1><p><a href='/v1/alerts/setup'>Back</a></p>")
    }
}

async fn xbox_setup() -> Html<String> {
    let url = notify::xbox_authorize_url();
    Html(format!(
        r#"<!DOCTYPE html><html><body>
<h1>Xbox Live (optional)</h1>
<ol><li><a href="{url}">Sign in with Microsoft</a></li>
<li>Paste redirect URL below.</li></ol>
<form method="POST" action="/v1/xbox/setup">
<textarea name="redirect_url" rows="4" cols="60"></textarea><br>
<button type="submit">Save</button></form>
<p><a href="/v1/alerts/setup">Back</a></p></body></html>"#
    ))
}

#[derive(Deserialize)]
struct XboxForm {
    redirect_url: String,
}

async fn xbox_setup_post(Form(form): Form<XboxForm>) -> impl IntoResponse {
    if form.redirect_url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Missing redirect URL</h1>".to_string()),
        )
            .into_response();
    }
    match notify::xbox_exchange_redirect(form.redirect_url.trim()).await {
        Ok(()) => (
            StatusCode::OK,
            Html("<h1>Microsoft account linked</h1>".to_string()),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Html(format!("<h1>Setup failed</h1><p>{e}</p>")),
        )
            .into_response(),
    }
}

fn extract_vps_game_peer_ips(packets: &Value) -> Option<Vec<String>> {
    let rows = packets
        .pointer("/metrics/vps_game_peers")
        .or_else(|| packets.pointer("/metrics/inbound_identical_peers"))
        .and_then(|v| v.as_array())?;
    let mut ips = Vec::new();
    for row in rows {
        let vps = row.get("vps_probe").and_then(|v| v.as_bool()) == Some(true);
        let role = row.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if !vps && role != "vps-probe" && role != "game-peer" {
            continue;
        }
        if let Some(ip) = row.get("ip").and_then(|v| v.as_str()) {
            if !ip.is_empty() {
                ips.push(ip.to_string());
            }
        }
    }
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn cached_offender_ips(state: &Arc<AppState>, poll_n: u64) -> Vec<String> {
    let now = now_secs();
    {
        let cache = state.offender_ips_cache.lock();
        if now - cache.0 < 45.0 {
            return cache.1.clone();
        }
    }
    if poll_n % 8 != 0 {
        return state.offender_ips_cache.lock().1.clone();
    }
    match state.fw.connection_offenders(2, 32).await {
        Ok(v) => {
            let ips: Vec<String> = v
                .get("offenders")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| {
                            r.get("ip")
                                .and_then(|x| x.as_str())
                                .map(String::from)
                        })
                        .collect()
                })
                .unwrap_or_default();
            *state.offender_ips_cache.lock() = (now, ips.clone());
            ips
        }
        Err(_) => state.offender_ips_cache.lock().1.clone(),
    }
}

async fn events_post(Json(body): Json<Value>) -> Json<Value> {
    let store = game_state::store();
    if let Some(arr) = body.as_array() {
        Json(store.ingest_batch(arr))
    } else {
        Json(store.ingest(&body))
    }
}

async fn game_state_get() -> Json<Value> {
    Json(json!({
        "ok": true,
        "game_state": game_state::store().to_json(),
        "learning": engine().insights(),
    }))
}

#[derive(Deserialize, Default)]
struct GameStateBody {
    playlist: Option<String>,
    #[serde(default)]
    event: Option<Value>,
}

async fn game_state_post(Json(body): Json<GameStateBody>) -> Json<Value> {
    if let Some(pl) = body.playlist.filter(|s| !s.is_empty()) {
        game_state::store().ingest(&json!({"type": "playlist", "playlist": pl}));
    }
    if let Some(ev) = body.event {
        game_state::store().ingest(&ev);
    }
    Json(json!({
        "ok": true,
        "game_state": game_state::store().to_json(),
    }))
}

async fn intel_export() -> Json<Value> {
    Json(json!({
        "ok": true,
        "intel": engine().export_intel(),
    }))
}

async fn intel_import(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let learning = engine().import_intel(&body);
    let firewall = state.fw.import_lobby_intel(body).await.ok();
    Json(json!({
        "ok": true,
        "learning": learning,
        "firewall": firewall,
    }))
}
