//! Export saved session logs as JSON, CSV, TSV, TXT, NDJSON, or Markdown.

use serde_json::{json, Value};

const PEER_COLUMNS: &[&str] = &[
    "ip",
    "label",
    "role",
    "identical_count",
    "identical_size",
    "packet_size_min",
    "packet_size_max",
    "total_packets",
    "tiny_packets",
    "poll_hits",
    "suspicious",
    "vps_probe",
    "first_seen",
    "last_seen",
];

pub const FORMATS: &[(&str, &str, &str, &str)] = &[
    ("json", "json", "application/json", "Full session bundle (JSON)"),
    ("csv", "csv", "text/csv; charset=utf-8", "Peer table (CSV)"),
    ("tsv", "tsv", "text/tab-separated-values; charset=utf-8", "Peer table (TSV)"),
    ("txt", "txt", "text/plain; charset=utf-8", "Human-readable report"),
    ("ndjson", "ndjson", "application/x-ndjson; charset=utf-8", "One JSON object per peer"),
    ("md", "md", "text/markdown; charset=utf-8", "Markdown report with peer table"),
];

pub fn formats_json() -> Value {
    json!({
        "ok": true,
        "formats": FORMATS.iter().map(|(id, ext, mime, label)| json!({
            "id": id,
            "ext": ext,
            "mime": mime,
            "label": label,
        })).collect::<Vec<_>>(),
    })
}

pub fn normalize_format(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "" | "json" => "json".into(),
        "csv" => "csv".into(),
        "tsv" | "tab" => "tsv".into(),
        "txt" | "text" | "log" => "txt".into(),
        "ndjson" | "jsonl" | "jsonlines" => "ndjson".into(),
        "md" | "markdown" => "md".into(),
        other => other.to_string(),
    }
}

pub fn export_session(
    hex: &str,
    detail: &Value,
    bundle: Option<&Value>,
    format: &str,
) -> Result<(String, String, String), String> {
    let fmt = normalize_format(format);
    let (body, ext, mime) = match fmt.as_str() {
        "json" => {
            let bundle = bundle.ok_or("json export requires bundle")?;
            (
                serde_json::to_string_pretty(bundle).map_err(|e| e.to_string())?,
                "json".into(),
                "application/json".into(),
            )
        }
        "csv" => (export_peers_delimited(detail, ','), "csv".into(), "text/csv; charset=utf-8".into()),
        "tsv" => (
            export_peers_delimited(detail, '\t'),
            "tsv".into(),
            "text/tab-separated-values; charset=utf-8".into(),
        ),
        "txt" => (export_txt(hex, detail), "txt".into(), "text/plain; charset=utf-8".into()),
        "ndjson" => (
            export_ndjson(hex, detail),
            "ndjson".into(),
            "application/x-ndjson; charset=utf-8".into(),
        ),
        "md" => (
            export_markdown(hex, detail),
            "md".into(),
            "text/markdown; charset=utf-8".into(),
        ),
        _ => return Err(format!("unsupported format '{fmt}' — use json, csv, tsv, txt, ndjson, or md")),
    };
    Ok((body, ext, mime))
}

pub fn attachment_name(hex: &str, ext: &str) -> String {
    format!("warzone-session-{hex}.{ext}")
}

fn meta_val<'a>(detail: &'a Value, key: &str) -> Option<&'a Value> {
    detail.get("meta").and_then(|m| m.get(key))
}

fn peers(detail: &Value) -> &[Value] {
    detail
        .get("peers")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
}

fn peer_field(p: &Value, key: &str) -> String {
    match p.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn delimited_escape(s: &str, delim: char) -> String {
    let needs_quotes = s.contains(delim) || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs_quotes {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn export_peers_delimited(detail: &Value, delim: char) -> String {
    let mut out = String::new();
    out.push_str(&PEER_COLUMNS.join(&delim.to_string()));
    out.push('\n');
    for p in peers(detail) {
        let row: Vec<String> = PEER_COLUMNS
            .iter()
            .map(|col| delimited_escape(&peer_field(p, col), delim))
            .collect();
        out.push_str(&row.join(&delim.to_string()));
        out.push('\n');
    }
    out
}

fn fmt_ts(ts: f64) -> String {
    if ts <= 0.0 {
        return "—".into();
    }
    // Human-readable UTC without pulling in chrono.
    let secs = ts as i64;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{days}d {h:02}:{m:02}:{s:02} UTC (unix {secs})")
}

fn export_txt(hex: &str, detail: &Value) -> String {
    let phase = meta_val(detail, "phase")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let started = meta_val(detail, "started_at")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let clears = meta_val(detail, "clear_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let peer_list = peers(detail);
    let snaps = detail
        .get("snapshot_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut out = String::new();
    out.push_str("Warzone Lobby Sentinel — session export\n");
    out.push_str("========================================\n\n");
    out.push_str(&format!("Session:     {hex}\n"));
    out.push_str(&format!("Phase:       {phase}\n"));
    out.push_str(&format!("Started:     {}\n", fmt_ts(started)));
    out.push_str(&format!("Peer count:  {}\n", peer_list.len()));
    out.push_str(&format!("Snapshots:   {snaps}\n"));
    out.push_str(&format!("Table clears:{clears}\n\n"));
    out.push_str("Inbound IPs — identical packet count\n");
    out.push_str("------------------------------------\n");
    out.push_str(&format!(
        "{:<16} {:<28} {:>9} {:>6} {:>11} {:>8} {:>5} {:>6}\n",
        "IP", "Label / role", "Identical", "Peak", "Size spread", "Total in", "Tiny", "Polls"
    ));
    for p in peer_list {
        let ip = peer_field(p, "ip");
        let label = peer_field(p, "label");
        let role = peer_field(p, "role");
        let label_role = if role.is_empty() || role == label {
            label
        } else {
            format!("{label} · {role}")
        };
        let min = p.get("packet_size_min").and_then(|v| v.as_u64()).unwrap_or(0);
        let max = p.get("packet_size_max").and_then(|v| v.as_u64()).unwrap_or(0);
        let spread = if min == 0 && max == 0 {
            "—".into()
        } else if min == max {
            format!("{min} (fixed)")
        } else {
            format!("{min}-{max}")
        };
        out.push_str(&format!(
            "{:<16} {:<28} {:>9} {:>6} {:>11} {:>8} {:>5} {:>6}\n",
            ip,
            truncate(&label_role, 28),
            peer_field(p, "identical_count"),
            peer_field(p, "identical_size"),
            spread,
            peer_field(p, "total_packets"),
            peer_field(p, "tiny_packets"),
            peer_field(p, "poll_hits"),
        ));
    }
    out.push('\n');
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max.saturating_sub(1)).collect::<String>())
    }
}

fn export_ndjson(hex: &str, detail: &Value) -> String {
    let mut out = String::new();
    for p in peers(detail) {
        let mut row = p.clone();
        if let Some(obj) = row.as_object_mut() {
            obj.insert("session_hex".into(), json!(hex));
        }
        if let Ok(line) = serde_json::to_string(&row) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

fn export_markdown(hex: &str, detail: &Value) -> String {
    let phase = meta_val(detail, "phase")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let started = meta_val(detail, "started_at")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let peer_list = peers(detail);

    let mut out = String::new();
    out.push_str("# Warzone session export\n\n");
    out.push_str(&format!("- **Session:** `{hex}`\n"));
    out.push_str(&format!("- **Phase:** {phase}\n"));
    out.push_str(&format!("- **Started:** {}\n", fmt_ts(started)));
    out.push_str(&format!("- **Peers:** {}\n\n", peer_list.len()));
    out.push_str("## Inbound IPs — identical packet count\n\n");
    out.push_str("| IP | Label | Role | Identical | Peak (B) | Size spread | Total in | Tiny | Polls | VPS |\n");
    out.push_str("| --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | --- |\n");
    for p in peer_list {
        let min = p.get("packet_size_min").and_then(|v| v.as_u64()).unwrap_or(0);
        let max = p.get("packet_size_max").and_then(|v| v.as_u64()).unwrap_or(0);
        let spread = if min == 0 && max == 0 {
            "—".into()
        } else if min == max {
            format!("{min}")
        } else {
            format!("{min}–{max}")
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            peer_field(p, "ip"),
            peer_field(p, "label"),
            peer_field(p, "role"),
            peer_field(p, "identical_count"),
            peer_field(p, "identical_size"),
            spread,
            peer_field(p, "total_packets"),
            peer_field(p, "tiny_packets"),
            peer_field(p, "poll_hits"),
            peer_field(p, "vps_probe"),
        ));
    }
    out
}
