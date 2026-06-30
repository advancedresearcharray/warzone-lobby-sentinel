use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_XBOX_NOTIFY: Mutex<f64> = Mutex::new(0.0);
static LAST_NTFY_COALESCE: Mutex<(String, f64)> = Mutex::new((String::new(), 0.0));

const NTFY_COALESCE_SEC: f64 = 120.0;

pub fn alert_status() -> Value {
    json!({
        "phone_push": ntfy_enabled(),
        "phone_subscribe_url": if ntfy_enabled() { Some(subscribe_url()) } else { None },
        "xbox_live": xbox_configured(),
    })
}

fn ntfy_enabled() -> bool {
    !matches!(
        std::env::var("WZ_NTFY_ENABLED").unwrap_or_else(|_| "1".into()).as_str(),
        "0" | "false" | "no"
    )
}

fn ntfy_config_path() -> String {
    std::env::var("WZ_NTFY_CONFIG_FILE")
        .unwrap_or_else(|_| "/etc/warzone-sentinel/ntfy.json".into())
}

fn ntfy_server() -> String {
    std::env::var("WZ_NTFY_SERVER")
        .unwrap_or_else(|_| "https://ntfy.sh".into())
        .trim_end_matches('/')
        .to_string()
}

pub fn topic() -> String {
    if let Ok(t) = std::env::var("WZ_NTFY_TOPIC") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    if let Ok(raw) = std::fs::read_to_string(ntfy_config_path()) {
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(t) = v.get("topic").and_then(|x| x.as_str()) {
                return t.into();
            }
        }
    }
    let generated = format!("warzone-sentinel-{:x}", rand::random::<u32>());
    let path = ntfy_config_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&json!({"topic": generated, "server": ntfy_server()})).unwrap(),
    );
    generated
}

pub fn subscribe_url() -> String {
    format!("{}/{}", ntfy_server(), topic())
}

fn header_safe(text: &str) -> String {
    text.replace('\u{2014}', "-")
        .replace('\u{2013}', "-")
        .chars()
        .filter(|c| c.is_ascii())
        .collect()
}

pub async fn ntfy_notify(title: &str, body: &str) -> bool {
    if !ntfy_enabled() {
        return false;
    }
    let client = match Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let resp = client
        .post(subscribe_url())
        .header("Title", header_safe(&title.chars().take(200).collect::<String>()))
        .header("Tags", "warning,video_game")
        .header("Priority", "high")
        .body(body.to_string())
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            tracing::info!("[ntfy] phone push sent: {title}");
            true
        }
        Ok(r) => {
            tracing::warn!("[ntfy] phone push rejected: HTTP {}", r.status());
            false
        }
        Err(e) => {
            tracing::warn!("[ntfy] failed: {e}");
            false
        }
    }
}

pub async fn notify_session_alert(
    level: &str,
    score: f64,
    phase: &str,
    game: &str,
    recommendation: &str,
    anomalies: &[String],
    cheater_lobby: &Value,
    force: bool,
) -> bool {
    let band = if score >= 0.75 {
        "high"
    } else if score >= 0.45 {
        "med"
    } else {
        "low"
    };
    let coalesce_key = format!("{phase}:{band}:{level}");
    if !force {
        let now = now_secs();
        if let Ok(guard) = LAST_NTFY_COALESCE.lock() {
            let last_key = guard.0.clone();
            let last_ts = guard.1;
            if last_key == coalesce_key && (now - last_ts) < NTFY_COALESCE_SEC {
                tracing::debug!("[ntfy] coalesced duplicate alert {coalesce_key}");
                return false;
            }
        }
    }
    let label = cheater_lobby
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or(level);
    let answer = crate::cheater_lobby::answer_json(cheater_lobby);
    let plain = answer
        .get("plain")
        .and_then(|v| v.as_str())
        .unwrap_or("Cheater lobby alert");
    let title = format!(
        "Warzone — {}",
        answer
            .get("headline")
            .and_then(|v| v.as_str())
            .unwrap_or(label)
    );
    let mut lines = vec![plain.to_string()];
    if let Some(reasons) = cheater_lobby.get("reasons").and_then(|v| v.as_array()) {
        for r in reasons.iter().take(3) {
            if let Some(s) = r.as_str() {
                lines.push(s.into());
            }
        }
    } else {
        lines.extend(anomalies.iter().take(3).cloned());
    }
    lines.push(recommendation.to_string());
    let body = lines.join("\n");
    let phone = ntfy_notify(&title, &body).await;
    let xbox = xbox_notify_session(level, score, phase, game, recommendation, anomalies, force).await;
    if phone || xbox {
        if let Ok(mut guard) = LAST_NTFY_COALESCE.lock() {
            *guard = (coalesce_key, now_secs());
        }
    }
    phone || xbox
}

fn xbox_token_path() -> String {
    std::env::var("WZ_XBOX_NOTIFY_TOKEN_FILE")
        .unwrap_or_else(|_| "/etc/warzone-sentinel/xbox_notify.json".into())
}

fn xbox_enabled() -> bool {
    !matches!(
        std::env::var("WZ_XBOX_NOTIFY_ENABLED").unwrap_or_else(|_| "1".into()).as_str(),
        "0" | "false" | "no"
    )
}

pub fn xbox_configured() -> bool {
    load_xbox_token()
        .ok()
        .and_then(|v| v.get("refresh_token").cloned())
        .is_some()
}

fn load_xbox_token() -> Result<Value, String> {
    let raw = std::fs::read_to_string(xbox_token_path()).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn save_xbox_token(data: &Value) -> Result<(), String> {
    let path = xbox_token_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, serde_json::to_string_pretty(data).unwrap()).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn xbox_authorize_url() -> String {
    let client_id = std::env::var("WZ_XBOX_CLIENT_ID").unwrap_or_else(|_| "000000004C12AE6F".into());
    let redirect = std::env::var("WZ_XBOX_REDIRECT_URI")
        .unwrap_or_else(|_| "https://login.live.com/oauth20_desktop.srf".into());
    let scopes = std::env::var("WZ_XBOX_SCOPES").unwrap_or_else(|_| "XboxLive.signin XboxLive.offline_access".into());
    format!(
        "https://login.live.com/oauth20_authorize.srf?client_id={}&response_type=code&redirect_uri={}&scope={}&state=wzsentinel",
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect),
        urlencoding::encode(&scopes),
    )
}

pub async fn xbox_exchange_redirect(redirect_url: &str) -> Result<(), String> {
    let code = extract_auth_code(redirect_url)?;
    let client_id = std::env::var("WZ_XBOX_CLIENT_ID").unwrap_or_else(|_| "000000004C12AE6F".into());
    let redirect = std::env::var("WZ_XBOX_REDIRECT_URI")
        .unwrap_or_else(|_| "https://login.live.com/oauth20_desktop.srf".into());
    let client = Client::new();
    let resp: Value = client
        .post("https://login.live.com/oauth20_token.srf")
        .form(&[
            ("client_id", client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let store = json!({
        "refresh_token": resp.get("refresh_token").and_then(|v| v.as_str()).ok_or("no refresh_token")?,
        "access_token": resp.get("access_token"),
        "updated_at": now_secs(),
    });
    save_xbox_token(&store)
}

fn extract_auth_code(redirect_url: &str) -> Result<String, String> {
    let url = url::Url::parse(redirect_url.trim()).map_err(|e| e.to_string())?;
    for (k, v) in url.query_pairs() {
        if k == "code" {
            return Ok(v.into_owned());
        }
    }
    if let Some(fragment) = redirect_url.split('#').nth(1) {
        for part in fragment.split('&') {
            if let Some(code) = part.strip_prefix("code=") {
                return Ok(code.into());
            }
        }
    }
    Err("No authorization code in redirect URL".into())
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

async fn xbox_notify_session(
    level: &str,
    score: f64,
    phase: &str,
    game: &str,
    recommendation: &str,
    anomalies: &[String],
    force: bool,
) -> bool {
    if !xbox_enabled() || !xbox_configured() {
        return false;
    }
    let cooldown: f64 = std::env::var("WZ_XBOX_NOTIFY_COOLDOWN_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120.0);
    let now = now_secs();
    {
        let last = LAST_XBOX_NOTIFY.lock().unwrap();
        if !force && now - *last < cooldown {
            return false;
        }
    }
    let title = format!("Warzone Sentinel — {level}");
    let mut lines = vec![
        recommendation.into(),
        format!("Integrity {score:.0}% · {phase} · {game}"),
    ];
    lines.extend(anomalies.iter().take(3).cloned());
    let mut body = format!("{title}\n{}", lines.join("\n"));
    if body.len() > 256 {
        body = truncate_utf8(&body, 256);
    }
    match send_xbox_message(&body).await {
        Ok(()) => {
            *LAST_XBOX_NOTIFY.lock().unwrap() = now;
            tracing::info!("[xbox-notify] message sent (self-chat muted — use phone push)");
            true
        }
        Err(e) => {
            tracing::warn!("[xbox-notify] failed: {e}");
            false
        }
    }
}

async fn send_xbox_message(text: &str) -> Result<(), String> {
    let (uhs, xsts, xuid) = xbox_auth_header().await?;
    let client = Client::new();
    let url = format!(
        "https://xblmessaging.xboxlive.com/network/Xbox/users/me/conversations/users/xuid({xuid})"
    );
    client
        .post(url)
        .header("Authorization", format!("XBL3.0 x={uhs};{xsts}"))
        .header("x-xbl-contract-version", "1")
        .json(&json!({"parts": [{"contentType": "text", "version": 0, "text": text}]}))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn xbox_auth_header() -> Result<(String, String, String), String> {
    let mut store = load_xbox_token()?;
    let refresh = store
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or("no refresh token")?
        .to_string();
    let client_id = std::env::var("WZ_XBOX_CLIENT_ID").unwrap_or_else(|_| "000000004C12AE6F".into());
    let redirect = std::env::var("WZ_XBOX_REDIRECT_URI")
        .unwrap_or_else(|_| "https://login.live.com/oauth20_desktop.srf".into());
    let client = Client::new();
    let tok: Value = client
        .post("https://login.live.com/oauth20_token.srf")
        .form(&[
            ("client_id", client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("redirect_uri", redirect.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if let Some(rt) = tok.get("refresh_token").and_then(|v| v.as_str()) {
        store["refresh_token"] = json!(rt);
    }
    store["access_token"] = tok.get("access_token").cloned().unwrap_or(json!(null));
    store["updated_at"] = json!(now_secs());
    let access = tok
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("no access_token")?;

    let user: Value = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .json(&json!({
            "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": format!("d={access}")},
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let user_token = user.get("Token").and_then(|v| v.as_str()).ok_or("no user token")?;
    let xsts: Value = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .json(&json!({
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
            "RelyingParty": "http://xboxlive.com",
            "TokenType": "JWT",
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let xui = xsts
        .pointer("/DisplayClaims/xui/0")
        .ok_or("no xui claims")?;
    let uhs = xui.get("uhs").and_then(|v| v.as_str()).ok_or("no uhs")?;
    let xuid = xui
        .get("xid")
        .or(xui.get("xuid"))
        .and_then(|v| v.as_str())
        .ok_or("no xuid")?;
    if store.get("xuid").is_none() {
        store["xuid"] = json!(xuid);
        let _ = save_xbox_token(&store);
    }
    let xsts_token = xsts.get("Token").and_then(|v| v.as_str()).ok_or("no xsts")?;
    Ok((uhs.into(), xsts_token.into(), xuid.into()))
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
