use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

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
            .unwrap_or_else(|_| "http://192.168.167.1:8090".into())
            .trim_end_matches('/')
            .to_string();
        let token = load_token()?;
        let xbox_ip = std::env::var("WZ_XBOX_IP").unwrap_or_else(|_| "192.168.167.65".into());
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
