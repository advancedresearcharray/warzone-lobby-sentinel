use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;
use warzone_sentinel::{
    dashboard, enrich::enrich_snapshot, firewalla::FirewallaClient, learning, learning::engine,
    network_guard::guard, network_session::NetworkSessionScorer, notify, packets, traffic,
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
        fw,
    });

    let poll_state = state.clone();
    tokio::spawn(async move {
        run_poll_loop(poll_state, interval, idle_interval).await;
    });

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
                let snapshot = enrich_snapshot(raw);
                *state.last_snapshot.lock() = Some(dashboard::trim_snapshot(&snapshot));
                let insights = json!({});
                let (risk, alert_decision) = {
                    let mut scorer = state.scorer.lock();
                    let risk = scorer.score(&snapshot, &insights);
                    let decision = scorer.should_alert(&risk);
                    (risk, decision)
                };
                if risk.phase == "matchmaking" || risk.phase == "in-match" {
                    sleep_sec = interval;
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

async fn dashboard_data(State(state): State<Arc<AppState>>) -> Json<Value> {
    let scorer = state.scorer.lock();
    let snap = state.last_snapshot.lock().clone().unwrap_or(json!({}));
    Json(json!({
        "updated_at": *state.updated_at.lock(),
        "polls": *state.polls.lock(),
        "source": *state.source.lock(),
        "error": *state.last_error.lock(),
        "session": *state.risk.lock(),
        "telemetry": snap.clone(),
        "traffic": traffic::inspect(&snap, "out"),
        "scorer": scorer.dashboard_meta(),
        "alerts": {
            "mode": "automatic",
            "phone": notify::alert_status(),
            "last_auto_alert": *state.last_auto_alert.lock(),
        },
        "learning": engine().insights(),
        "network_guard": *state.network_guard.lock(),
        "last_auto_alert": *state.last_auto_alert.lock(),
    }))
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
    state.scorer.lock().mark_in_match();
    Json(json!({
        "ok": true,
        "message": "In-match mode — scoring and alerts active.",
        "scorer": state.scorer.lock().dashboard_meta(),
    }))
}

async fn session_end(State(state): State<Arc<AppState>>) -> Json<Value> {
    let ended = engine().end_active_session();
    state.scorer.lock().mark_lobby_exit();
    let guard_released = guard().release_if_engaged(&state.fw).await;
    Json(json!({
        "ok": true,
        "session_ended": ended,
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
    let (verdict, score) = session_verdict(&state);
    engine().record_feedback(true, "kicked from lobby by hacker", &verdict, score);
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
            "Cheater lobby confirmed — defenses hardened on Firewalla.",
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

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
