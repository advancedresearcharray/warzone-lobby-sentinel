use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;

static ROLES: OnceLock<Vec<RoleRule>> = OnceLock::new();
static PTR_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

#[derive(Clone)]
struct RoleRule {
    id: String,
    match_patterns: Vec<String>,
    cidrs: Vec<String>,
    exclude: Vec<String>,
}

fn load_roles() -> &'static Vec<RoleRule> {
    ROLES.get_or_init(|| {
        let path = std::env::var("WZ_ROLES_FILE")
            .unwrap_or_else(|_| "/opt/warzone-lobby-sentinel/data/server-roles.json".into());
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| include_str!("../../data/server-roles.json").into());
        let v: Value = serde_json::from_str(&raw).unwrap_or(json!({"rules": []}));
        v["rules"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|r| {
                Some(RoleRule {
                    id: r["id"].as_str()?.to_string(),
                    match_patterns: r["match"]
                        .as_array()?
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_lowercase))
                        .collect(),
                    cidrs: r
                        .get("cidrs")
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    exclude: r
                        .get("matchExclude")
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_lowercase))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect()
    })
}

fn ptr_cache() -> &'static Mutex<HashMap<String, String>> {
    PTR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn classify_host(hostname: &str) -> String {
    let host = hostname.to_lowercase();
    if host.is_empty() {
        return "unknown".into();
    }
    for rule in load_roles() {
        if rule.exclude.iter().any(|x| host.contains(x)) {
            continue;
        }
        if rule.match_patterns.iter().any(|p| host.contains(p)) {
            return rule.id.clone();
        }
    }
    "unknown".into()
}

pub fn extract_ip(remote: &str) -> String {
    let s = remote.trim();
    if s.is_empty() {
        return String::new();
    }
    let bare = s.trim_matches(|c| c == '[' || c == ']');
    if bare.contains(':') && bare.contains('.') {
        return bare.rsplit_once(':').map(|(ip, _)| ip.to_string()).unwrap_or_else(|| bare.to_string());
    }
    if bare.chars().filter(|c| *c == '.').count() == 3 {
        return bare.to_string();
    }
    String::new()
}

fn parse_ipv4(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    Some(
        ((parts[0] as u32) << 24)
            | ((parts[1] as u32) << 16)
            | ((parts[2] as u32) << 8)
            | parts[3] as u32,
    )
}

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Some(ip_n) = parse_ipv4(ip) else {
        return false;
    };
    let Some(net_n) = parse_ipv4(net) else {
        return false;
    };
    let Ok(p) = prefix.parse::<u32>() else {
        return false;
    };
    if p > 32 {
        return false;
    }
    let mask = if p == 0 {
        0
    } else {
        !0u32 << (32 - p)
    };
    (ip_n & mask) == (net_n & mask)
}

fn classify_cidr(ip: &str) -> Option<String> {
    if ip.is_empty() {
        return None;
    }
    for rule in load_roles() {
        if rule.cidrs.iter().any(|cidr| ip_in_cidr(ip, cidr)) {
            return Some(rule.id.clone());
        }
    }
    None
}

fn reverse_ptr(ip: &str) -> String {
    {
        let cache = ptr_cache().lock();
        if let Some(hit) = cache.get(ip) {
            return hit.clone();
        }
    }
    let ptr = Command::new("dig")
        .args(["+short", "+time=1", "+tries=1", "-x", ip, "@1.1.1.1"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok()
            } else {
                None
            }
        })
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_lowercase();
    ptr_cache().lock().insert(ip.to_string(), ptr.clone());
    ptr
}

fn is_private_ip(ip: &str) -> bool {
    let Some(n) = parse_ipv4(ip) else {
        return true;
    };
    let o = [
        (n >> 24) as u8,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
    ];
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] == 127
}

fn classify_local_ip(ip: &str) -> Option<String> {
    if !is_private_ip(ip) {
        return None;
    }
    if ip == "192.168.167.1" {
        return Some("lan-gateway".into());
    }
    Some("lan-local".into())
}

fn parse_port_value(v: &Value) -> Option<u16> {
    if let Some(n) = v.as_u64() {
        return Some(n as u16);
    }
    v.as_str()
        .and_then(|s| s.parse().ok())
}

fn parse_port_from(item: &Value, remote: &str) -> Option<u16> {
    for key in ["port", "remotePort"] {
        if let Some(v) = item.get(key) {
            if let Some(p) = parse_port_value(v) {
                return Some(p);
            }
        }
    }
    if remote.contains('.') && remote.contains(':') {
        return remote.rsplit_once(':').and_then(|(_, p)| p.parse().ok());
    }
    None
}

fn classify_peer_fallback(ip: &str, port: Option<u16>, proto: &str) -> Option<String> {
    if ip.is_empty() || is_private_ip(ip) {
        return None;
    }
    if proto.eq_ignore_ascii_case("udp") {
        match port {
            Some(3074 | 3075 | 3544) => return Some("game-peer".into()),
            Some(p) if p >= 1024 => return Some("game-peer".into()),
            _ => {}
        }
    }
    None
}

pub fn classify_endpoint(remote: &str, hostname_hint: &str) -> String {
    classify_endpoint_with_port(remote, hostname_hint, None, "")
}

pub fn classify_endpoint_with_port(
    remote: &str,
    hostname_hint: &str,
    port: Option<u16>,
    proto: &str,
) -> String {
    let ip = extract_ip(remote);
    if !ip.is_empty() {
        if let Some(role) = classify_local_ip(&ip) {
            return role;
        }
        if let Some(role) = classify_cidr(&ip) {
            return role;
        }
    }

    let hint = hostname_hint.trim();
    if !hint.is_empty() && !is_ipish(hint) {
        let role = classify_host(hint);
        if role != "unknown" {
            return role;
        }
    }

    if !ip.is_empty() {
        let ptr = reverse_ptr(&ip);
        if !ptr.is_empty() && ptr != ip {
            let role = classify_host(&ptr);
            if role != "unknown" {
                return role;
            }
        }
    }

    if let Some(role) = classify_peer_fallback(&ip, port, proto) {
        return role;
    }

    if !hint.is_empty() {
        let role = classify_host(hint);
        if role != "unknown" {
            return role;
        }
    }

    if !ip.is_empty() {
        return classify_host(&ip);
    }

    classify_host(remote)
}

pub fn classify_value(item: &Value) -> String {
    if let Some(rid) = item.get("roleId").and_then(|v| v.as_str()) {
        if !rid.is_empty() {
            return rid.to_string();
        }
    }
    let remote = item
        .get("remote")
        .or(item.get("ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let host = item
        .get("hostname")
        .or(item.get("label"))
        .or(item.get("host"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let port = parse_port_from(item, remote);
    let proto = item.get("proto").and_then(|v| v.as_str()).unwrap_or("");
    classify_endpoint_with_port(remote, host, port, proto)
}

fn is_ipish(h: &str) -> bool {
    !h.is_empty() && extract_ip(h) == h
}

fn flow_hosts(snapshot: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    for key in ["recentFlows", "recent_flows"] {
        if let Some(flows) = snapshot.get(key).and_then(|v| v.as_array()) {
            for flow in flows {
                let h = flow
                    .get("hostname")
                    .or(flow.get("host"))
                    .or(flow.get("label"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !h.is_empty() && !is_ipish(h) {
                    hosts.push(h.to_string());
                }
            }
        }
    }
    for key in ["dnsDestinations", "dns_destinations"] {
        if let Some(buckets) = snapshot.get(key).and_then(|v| v.as_array()) {
            for b in buckets {
                if let Some(h) = b.get("hostname").or(b.get("label")).and_then(|v| v.as_str()) {
                    if !h.is_empty() {
                        hosts.push(h.to_string());
                    }
                }
            }
        }
    }
    if let Some(items) = snapshot
        .pointer("/connections/items")
        .and_then(|v| v.as_array())
    {
        for item in items {
            let remote = item
                .get("remote")
                .or(item.get("ip"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let h = item
                .get("hostname")
                .or(item.get("host"))
                .or(item.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !h.is_empty() && !is_ipish(h) {
                hosts.push(h.to_string());
            } else if !remote.is_empty() {
                let role = classify_endpoint(remote, h);
                if role != "unknown" {
                    hosts.push(format!("{remote} ({role})"));
                }
            }
        }
    }
    hosts
}

pub fn enrich_snapshot(mut snapshot: Value) -> Value {
    if snapshot.get("error").is_some() || snapshot.is_null() {
        return snapshot;
    }

    let mut role_counts: HashMap<String, u32> = HashMap::new();
    let mut classified = Vec::new();
    for host in flow_hosts(&snapshot) {
        let rid = if host.contains(" (") {
            host.split(" (").nth(1).and_then(|s| s.strip_suffix(')')).unwrap_or("unknown").to_string()
        } else {
            classify_host(&host)
        };
        *role_counts.entry(rid.clone()).or_default() += 1;
        if rid != "unknown" && classified.len() < 20 {
            classified.push(json!({"hostname": host, "roleId": rid}));
        }
    }

    let xbox_online = snapshot
        .pointer("/xbox/online")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let conns = snapshot
        .pointer("/connections/count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let mut game = "unknown".to_string();
    if role_counts.contains_key("warzone-game")
        || role_counts.contains_key("game-assets")
        || role_counts.contains_key("telemetry")
    {
        game = "warzone".into();
    } else if role_counts.contains_key("xbox-live") && xbox_online {
        game = "warzone".into();
    }

    let phase = infer_phase(&role_counts, xbox_online, conns, &game);

    if let Some(obj) = snapshot.as_object_mut() {
        obj.insert(
            "_enriched".into(),
            json!({
                "roleCounts": role_counts,
                "classified": classified,
                "phase": phase,
                "game": game,
            }),
        );
    }
    snapshot
}

fn infer_phase(
    roles: &HashMap<String, u32>,
    xbox_online: bool,
    conns: u32,
    game: &str,
) -> &'static str {
    if roles.get("warzone-game").copied().unwrap_or(0) >= 1 {
        return "in-match";
    }
    if roles.get("matchmaking").copied().unwrap_or(0) >= 1 {
        return "matchmaking";
    }
    if roles.get("azure-qos").copied().unwrap_or(0) >= 2 && conns >= 80 {
        return "matchmaking";
    }
    if game == "warzone"
        && xbox_online
        && conns >= 65
        && roles.get("game-assets").copied().unwrap_or(0) >= 2
        && roles.get("telemetry").copied().unwrap_or(0) >= 2
    {
        return "in-match";
    }
    if xbox_online
        && conns >= 40
        && (roles.get("matchmaking").copied().unwrap_or(0) > 0
            || roles.get("azure-qos").copied().unwrap_or(0) >= 2)
    {
        return "matchmaking";
    }
    if xbox_online && conns >= 15 {
        return "background";
    }
    if !xbox_online && conns == 0 {
        return "idle";
    }
    "background"
}

pub fn role_index(role: &str) -> u8 {
    match role {
        "warzone-game" => 1,
        "matchmaking" => 2,
        "game-assets" => 3,
        "telemetry" => 4,
        "xbox-live" => 5,
        "azure-qos" => 6,
        "notifications" => 7,
        "game-peer" => 8,
        _ => 0,
    }
}

pub fn phase_code(phase: &str) -> u8 {
    match phase {
        "idle" => 0,
        "background" => 1,
        "matchmaking" => 2,
        "in-match" => 3,
        "post-match" => 4,
        _ => 1,
    }
}

pub fn is_game_peer(role: &str) -> bool {
    role == "game-peer"
}

pub fn is_infrastructure(role: &str) -> bool {
    matches!(
        role,
        "warzone-game"
            | "game-assets"
            | "matchmaking"
            | "xbox-live"
            | "azure-qos"
            | "telemetry"
            | "notifications"
    )
}

pub fn peer_display_label(ip: &str, hostname_hint: &str) -> String {
    let hint = hostname_hint.to_lowercase();
    if hint.contains("vultr") {
        return "Vultr VPS".into();
    }
    if hint.contains("linode") {
        return "Linode VPS".into();
    }
    if hint.contains("amazonaws") {
        return "AWS".into();
    }
    if ip.starts_with("34.") || ip.starts_with("35.") {
        return "Google Cloud".into();
    }
    if ip.starts_with("66.42.") || ip.starts_with("155.138.") {
        return "Vultr VPS".into();
    }
    "Player peer".into()
}

pub fn is_unknown_inbound(role: &str) -> bool {
    role == "unknown"
}

pub fn is_known_traffic(role: &str) -> bool {
    matches!(
        role,
        "warzone-game"
            | "game-assets"
            | "matchmaking"
            | "xbox-live"
            | "azure-qos"
            | "telemetry"
            | "notifications"
            | "game-peer"
            | "lan-local"
            | "lan-gateway"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demonware_ip_is_warzone_game() {
        assert_eq!(classify_endpoint("185.34.106.103:3074", ""), "warzone-game");
    }

    #[test]
    fn akamai_ip_is_game_assets() {
        assert_eq!(classify_endpoint("23.213.26.152:80", ""), "game-assets");
    }

    #[test]
    fn azure_ip_is_xbox_live() {
        assert_eq!(classify_endpoint("20.201.200.56:443", ""), "xbox-live");
    }

    #[test]
    fn akamai_23_66_is_game_assets() {
        assert_eq!(classify_endpoint("23.66.101.238:443", ""), "game-assets");
    }

    #[test]
    fn msft_4_x_is_xbox_live() {
        assert_eq!(classify_endpoint("4.155.94.229:443", ""), "xbox-live");
    }

    #[test]
    fn gateway_is_lan_not_unknown() {
        assert_eq!(classify_endpoint("192.168.167.1:52322", ""), "lan-gateway");
    }

    #[test]
    fn vultr_udp_peer() {
        assert_eq!(
            classify_endpoint_with_port("66.42.86.93:44998", "", Some(44998), "udp"),
            "game-peer"
        );
    }
}
