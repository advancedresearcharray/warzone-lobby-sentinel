use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone)]
pub struct FirewallaClient {
    http: Client,
    pub base: String,
    token: String,
    xbox_ip: String,
}

impl FirewallaClient {
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var("WZ_ARRAY_FW_API_URL")
            .or_else(|_| std::env::var("WZ_FIREWALLA_API_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:8090".into())
            .trim_end_matches('/')
            .to_string();
        let token = load_token()?;
        let xbox_ip = std::env::var("WZ_XBOX_IP").unwrap_or_else(|_| "203.0.113.11".into());
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            base,
            token,
            xbox_ip,
        })
    }

    pub fn xbox_ip(&self) -> String {
        self.xbox_ip.clone()
    }

    pub async fn probe(&self) -> bool {
        match self
            .http
            .get(format!("{}/api/health", self.base))
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            Ok(r) => r
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v.get("ok").and_then(|x| x.as_bool()))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    pub async fn run_script(
        &self,
        script: &str,
        args: &[&str],
        sudo: bool,
    ) -> Result<String, String> {
        let body = json!({
            "script": script,
            "args": args,
            "sudo": sudo,
        });
        let result = self.post_run(body).await?;
        if result.get("ok").and_then(|v| v.as_bool()) == Some(false) {
            return Err(result
                .get("error")
                .or(result.get("stderr"))
                .and_then(|v| v.as_str())
                .unwrap_or("script failed")
                .into());
        }
        Ok(result
            .get("stdout")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string())
    }

    pub async fn fetch_snapshot(&self) -> Result<Value, String> {
        self.fetch_snapshot_with_args(&[]).await
    }

    pub async fn fetch_packet_capture(&self, _count: u32) -> Result<Value, String> {
        self.run_script_json(
            "gaming-snapshot.sh",
            &[&self.xbox_ip, "--deep-packets"],
            false,
        )
        .await
    }

    async fn fetch_snapshot_with_args(&self, extra: &[&str]) -> Result<Value, String> {
        let mut args: Vec<String> = vec![self.xbox_ip.clone()];
        args.extend(extra.iter().map(|s| s.to_string()));
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_script_json("gaming-snapshot.sh", &arg_refs, false)
            .await
    }

    async fn run_script_json(&self, script: &str, args: &[&str], sudo: bool) -> Result<Value, String> {
        let body = json!({
            "script": script,
            "args": args,
            "sudo": sudo,
        });
        let result = self.post_run(body).await?;
        if !result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Err(result
                .get("stderr")
                .or(result.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("script failed")
                .into());
        }
        let stdout = result.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
        if stdout.trim().is_empty() {
            return Err(format!("empty output from {script}"));
        }
        serde_json::from_str(stdout).map_err(|e| e.to_string())
    }

    async fn post_run(&self, body: Value) -> Result<Value, String> {
        let resp = self
            .http
            .post(format!("{}/api/v1/run", self.base))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json().await.map_err(|e| e.to_string())
    }

    pub async fn mitigate_session(&self, risk: &Value, kick_spike: bool) -> Result<Value, String> {
        let mut body = risk.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.insert("kick_spike".into(), json!(kick_spike));
        }
        self.post_json_maybe_wire("/api/v1/gaming/mitigate", body, 2048).await
    }

    pub async fn ai_ops_outcome(&self, body: Value) -> Result<Value, String> {
        self.post_json("/api/v1/ai-ops/outcome", body).await
    }

    pub async fn peer_blocklist_status(&self) -> Result<Value, String> {
        self.get_json("/api/v1/gaming/peers").await
    }

    pub async fn block_peers(
        &self,
        ips: &[String],
        reason: &str,
        ttl_sec: Option<u64>,
    ) -> Result<Value, String> {
        let mut body = json!({
            "ips": ips,
            "reason": reason,
        });
        if let Some(ttl) = ttl_sec {
            body["ttl_sec"] = json!(ttl);
        }
        self.post_json("/api/v1/gaming/peers/block", body).await
    }

    pub async fn subnet_blocklist_status(&self) -> Result<Value, String> {
        self.get_json("/api/v1/subnets").await
    }

    pub async fn block_subnets_from_ips(
        &self,
        ips: &[String],
        reason: &str,
    ) -> Result<Value, String> {
        self.post_json(
            "/api/v1/subnets/block",
            json!({
                "ips": ips,
                "reason": reason,
            }),
        )
        .await
    }

    pub async fn refresh_subnet_providers(&self) -> Result<Value, String> {
        self.post_json("/api/v1/subnets/refresh-providers", json!({})).await
    }

    pub async fn remove_peers(&self, ips: &[String]) -> Result<Value, String> {
        self.post_json(
            "/api/v1/gaming/peers/remove",
            json!({ "ips": ips }),
        )
        .await
    }

    pub async fn sync_shield_peers(
        &self,
        level: &str,
        ips: &[String],
    ) -> Result<Value, String> {
        self.post_json(
            "/api/v1/gaming/peers/sync-shield",
            json!({
                "level": level,
                "ips": ips,
            }),
        )
        .await
    }

    pub async fn enable_shield_level(&self, level: &str) -> Result<Value, String> {
        self.post_json(
            "/api/v1/shield/enable",
            json!({ "level": level }),
        )
        .await
    }

    pub async fn ingest_connections(&self, body: Value) -> Result<Value, String> {
        self.post_json_maybe_wire("/api/v1/gaming/connections/ingest", body, 4096)
            .await
    }

    pub async fn end_connection_session(&self, session_hex: &str) -> Result<Value, String> {
        self.post_json(
            "/api/v1/gaming/connections/end-session",
            json!({ "session_hex": session_hex }),
        )
        .await
    }

    pub async fn query_connections(
        &self,
        session_hex: Option<&str>,
        ip: Option<&str>,
        conn_type: Option<&str>,
        policy: Option<&str>,
        offenders_only: bool,
        limit: u32,
        offset: u32,
    ) -> Result<Value, String> {
        let mut qs = vec![format!("limit={limit}"), format!("offset={offset}")];
        if let Some(s) = session_hex.filter(|s| !s.is_empty()) {
            qs.push(format!("session_hex={}", urlencoding::encode(s)));
        }
        if let Some(s) = ip.filter(|s| !s.is_empty()) {
            qs.push(format!("ip={}", urlencoding::encode(s)));
        }
        if let Some(s) = conn_type.filter(|s| !s.is_empty()) {
            qs.push(format!("type={}", urlencoding::encode(s)));
        }
        if let Some(s) = policy.filter(|s| !s.is_empty()) {
            qs.push(format!("policy={}", urlencoding::encode(s)));
        }
        if offenders_only {
            qs.push("offenders=1".into());
        }
        self.get_json(&format!("/api/v1/gaming/connections?{}", qs.join("&")))
            .await
    }

    pub async fn connection_offenders(&self, min_sessions: u32, limit: u32) -> Result<Value, String> {
        self.get_json(&format!(
            "/api/v1/gaming/connections/offenders?min_sessions={min_sessions}&limit={limit}"
        ))
        .await
    }

    pub async fn list_connection_sessions(&self, limit: u32) -> Result<Value, String> {
        self.get_json(&format!("/api/v1/gaming/connections/sessions?limit={limit}"))
            .await
    }

    pub async fn connections_action(
        &self,
        ips: &[String],
        action: &str,
        session_hex: Option<&str>,
    ) -> Result<Value, String> {
        let mut body = json!({ "ips": ips, "action": action });
        if let Some(hex) = session_hex.filter(|s| !s.is_empty()) {
            body["session_hex"] = json!(hex);
        }
        self.post_json("/api/v1/gaming/connections/action", body).await
    }

    pub async fn investigate_unknowns(&self, limit: u32) -> Result<Value, String> {
        self.post_json(
            "/api/v1/gaming/investigate/run",
            json!({ "limit": limit }),
        )
        .await
    }

    pub async fn import_lobby_intel(&self, body: Value) -> Result<Value, String> {
        self.post_json("/api/v1/gaming/intel/import", body).await
    }

    pub async fn decay_peer_blocks(&self) -> Result<Value, String> {
        self.post_json("/api/v1/gaming/peers/decay", json!({})).await
    }

    pub async fn correlate_probe_sink(&self, session_hex: &str) -> Result<Value, String> {
        self.post_json(
            "/api/v1/gaming/probe-sink/correlate",
            json!({ "session_hex": session_hex }),
        )
        .await
    }

    pub async fn sync_shield_fast(
        &self,
        level: &str,
        ips: &[String],
    ) -> Result<Value, String> {
        self.post_json(
            "/api/v1/shield/sync-fast",
            json!({ "level": level, "ips": ips }),
        )
        .await
    }

    pub async fn fetch_telemetry_queues(&self) -> Result<Value, String> {
        self.get_json("/api/v1/telemetry/queues").await
    }

    pub async fn upload_boost_status(&self) -> Result<Value, String> {
        self.get_json("/api/v1/qos/upload-boost").await
    }

    pub async fn apply_rqd_buffer_profile(&self, sample: Value) -> Result<Value, String> {
        self.post_json(
            "/api/v1/rqd/buffer-profile",
            json!({
                "apply": true,
                "sample": sample,
            }),
        )
        .await
    }

    pub async fn rqd_buffer_recommendation(&self, sample: Value) -> Result<Value, String> {
        self.post_json(
            "/api/v1/rqd/buffer-profile",
            json!({ "sample": sample }),
        )
        .await
    }

    pub async fn asvi_scan(&self, session_hex: Option<&str>, limit: u32) -> Result<Value, String> {
        let mut body = json!({ "limit": limit });
        if let Some(hex) = session_hex.filter(|s| !s.is_empty()) {
            body["session_hex"] = json!(hex);
        }
        self.post_json("/api/v1/asvi/scan", body).await
    }

    pub async fn wire_compress_bytes(&self, raw: &[u8]) -> Result<Value, String> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        self.post_json(
            "/api/v1/folding/wire/compress",
            json!({ "payload_b64": b64 }),
        )
        .await
    }

    async fn post_json_maybe_wire(
        &self,
        path: &str,
        body: Value,
        min_bytes: usize,
    ) -> Result<Value, String> {
        let raw = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        if raw.len() >= min_bytes {
            if let Ok(wire) = self.wire_compress_bytes(&raw).await {
                if wire.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let envelope = json!({
                        "_wire": true,
                        "encoding": wire.get("encoding").cloned().unwrap_or(json!("gzip+blsb")),
                        "orig_size": wire.get("orig_size"),
                        "compressed_size": wire.get("compressed_size"),
                        "ratio": wire.get("ratio"),
                        "effective_throughput_factor": wire.get("effective_throughput_factor"),
                        "preservation_ratio": wire.get("preservation_ratio"),
                        "payload_b64": wire.get("payload_b64"),
                        "fold_sidecar": wire.get("fold_sidecar"),
                    });
                    return self.post_json(path, envelope).await;
                }
            }
        }
        self.post_json(path, body).await
    }

    async fn get_json(&self, path: &str) -> Result<Value, String> {
        let resp = self
            .http
            .get(format!("{}{}", self.base, path))
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json().await.map_err(|e| e.to_string())
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, String> {
        let resp = self
            .http
            .post(format!("{}{}", self.base, path))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json().await.map_err(|e| e.to_string())
    }
}

fn load_token() -> Result<String, String> {
    for key in ["WZ_ARRAY_FW_API_TOKEN", "WZ_FIREWALLA_API_TOKEN", "ARRAY_FW_API_TOKEN"] {
        if let Ok(tok) = std::env::var(key) {
            let t = tok.trim();
            if !t.is_empty() {
                return Ok(t.into());
            }
        }
    }
    for path_key in ["WZ_ARRAY_FW_API_TOKEN_FILE", "WZ_FIREWALLA_API_TOKEN_FILE"] {
        if let Ok(path) = std::env::var(path_key) {
            if let Some(tok) = read_token_file(&path) {
                return Ok(tok);
            }
        }
    }
    for path in [
        "/etc/warzone-sentinel/array-firewall.token",
        "/etc/warzone-sentinel/firewalla.token",
        "/etc/array-firewall/api.token",
    ] {
        if let Some(tok) = read_token_file(path) {
            return Ok(tok);
        }
    }
    Err("array-firewall API token not configured".into())
}

fn read_token_file(path: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for prefix in [
            "ARRAY_FW_API_TOKEN=",
            "FIREWALLA_API_TOKEN=",
            "WZ_ARRAY_FW_API_TOKEN=",
            "WZ_FIREWALLA_API_TOKEN=",
        ] {
            if let Some(rest) = line.strip_prefix(prefix) {
                let tok = rest.trim().trim_matches('"');
                if !tok.is_empty() {
                    return Some(tok.into());
                }
            }
        }
        if !line.contains('=') && !line.is_empty() {
            return Some(line.into());
        }
    }
    None
}
