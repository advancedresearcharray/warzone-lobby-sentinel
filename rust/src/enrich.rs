use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

static ROLES: OnceLock<Vec<RoleRule>> = OnceLock::new();
static PTR_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static PTR_BUDGET: AtomicU32 = AtomicU32::new(0);

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
    if PTR_BUDGET.load(Ordering::Relaxed) == 0 {
        return String::new();
    }
    PTR_BUDGET.fetch_sub(1, Ordering::Relaxed);
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
    if ip == "192.0.2.1" {
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

fn classify_udp_game_role(ip: &str, port: Option<u16>, proto: &str) -> Option<String> {
    if ip.is_empty() || is_private_ip(ip) {
        return None;
    }
    if !proto.eq_ignore_ascii_case("udp") {
        return None;
    }
    match port {
        Some(3074 | 3075) => Some("dedicated-server".into()),
        Some(p) if p >= 1024 => Some("p2p-mesh".into()),
        _ => None,
    }
}

fn classify_peer_fallback(ip: &str, port: Option<u16>, proto: &str) -> Option<String> {
    classify_udp_game_role(ip, port, proto)
}

/// Inbound UDP on CoD game ports — used to detect mesh/server-shaped traffic.
pub fn is_inbound_player_peer_port(port: Option<u16>, proto: &str) -> bool {
    if !proto.eq_ignore_ascii_case("udp") {
        return false;
    }
    match port {
        Some(3074 | 3075) => true,
        Some(p) if p >= 1024 => true,
        _ => false,
    }
}

/// Classify inbound traffic — P2P-shaped ports stay unconfirmed until VPS identity or probe proof.
pub fn classify_inbound_endpoint(
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
        if role != "unknown" && role != "vps-probe-host" {
            return role;
        }
    }

    if is_inbound_player_peer_port(port, proto) {
        if let Some(role) = classify_udp_game_role(&ip, port, proto) {
            return role;
        }
    }

    classify_endpoint_with_port(remote, hostname_hint, port, proto)
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

    PTR_BUDGET.store(6, Ordering::Relaxed);

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
        || role_counts.contains_key("dedicated-server")
        || role_counts.contains_key("game-assets")
        || role_counts.contains_key("telemetry")
        || role_counts.contains_key("matchmaking")
    {
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
    if roles.get("warzone-game").copied().unwrap_or(0) >= 1
        || roles.get("dedicated-server").copied().unwrap_or(0) >= 1
    {
        return "in-match";
    }
    if roles.get("matchmaking").copied().unwrap_or(0) >= 1 {
        return "matchmaking";
    }
    if xbox_online
        && game == "warzone"
        && conns >= 22
        && (roles.get("game-assets").copied().unwrap_or(0) >= 1
            || roles.get("matchmaking").copied().unwrap_or(0) >= 1
            || roles.get("telemetry").copied().unwrap_or(0) >= 2)
    {
        return "matchmaking";
    }
    if roles.get("azure-qos").copied().unwrap_or(0) >= 2 && conns >= 45 {
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
        && conns >= 25
        && (roles.get("matchmaking").copied().unwrap_or(0) > 0
            || roles.get("azure-qos").copied().unwrap_or(0) >= 1)
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
        "dedicated-server" => 2,
        "matchmaking" => 3,
        "game-assets" => 4,
        "telemetry" => 5,
        "xbox-live" => 6,
        "azure-qos" => 7,
        "notifications" => 8,
        "vps-probe" | "game-peer" => 9,
        "p2p-mesh" | "p2p-unconfirmed" => 10,
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
    is_vps_probe_role(role)
}

pub fn is_p2p_unconfirmed(role: &str) -> bool {
    is_p2p_mesh_role(role)
}

pub fn is_vps_probe_role(role: &str) -> bool {
    matches!(role, "vps-probe" | "game-peer")
}

pub fn is_p2p_mesh_role(role: &str) -> bool {
    matches!(role, "p2p-mesh" | "p2p-unconfirmed")
}

/// VPS provider identity hint — does not confirm probe traffic by itself.
pub fn is_vps_provider_host(ip: &str, hostname_hint: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    if is_vultr_ip(ip) {
        return true;
    }
    let hint = hostname_hint.to_lowercase();
    if hint.contains("vultr")
        || hint.contains("choopa")
        || hint.contains("linode")
        || hint.contains("digitalocean")
        || hint.contains("your-server")
    {
        return true;
    }
    if !hostname_hint.is_empty() && classify_host(hostname_hint) == "vps-probe-host" {
        return true;
    }
    false
}

/// Legacy name — probe proof required before treating as hostile peer.
pub fn is_confirmed_player_peer_host(ip: &str, hostname_hint: &str) -> bool {
    is_vps_provider_host(ip, hostname_hint)
}

/// Promote to player peer only after repeated probe-shaped traffic (not port alone).
pub fn confirm_player_peer_from_probe_signals(
    identical_count: u32,
    tiny_packets: u64,
    total_packets: u64,
    packet_size_min: u64,
    packet_size_max: u64,
) -> bool {
    let fixed = packet_size_min > 0
        && packet_size_min == packet_size_max
        && identical_count >= 6;
    fixed || identical_count >= 6 || (tiny_packets >= 3 && total_packets >= 6)
}

pub fn resolve_inbound_peer_role(
    ip: &str,
    hostname_hint: &str,
    base_role: &str,
    identical_count: u32,
    tiny_packets: u64,
    total_packets: u64,
    packet_size_min: u64,
    packet_size_max: u64,
) -> String {
    if is_infrastructure(base_role) {
        return base_role.into();
    }
    let probe = confirm_player_peer_from_probe_signals(
        identical_count,
        tiny_packets,
        total_packets,
        packet_size_min,
        packet_size_max,
    );
    if probe && is_vps_provider_host(ip, hostname_hint) {
        return "vps-probe".into();
    }
    if base_role == "dedicated-server" {
        return "dedicated-server".into();
    }
    if base_role == "p2p-mesh" || base_role == "p2p-unconfirmed" {
        return "p2p-mesh".into();
    }
    if base_role == "vps-probe" || base_role == "game-peer" {
        return if probe && is_vps_provider_host(ip, hostname_hint) {
            "vps-probe".into()
        } else {
            "p2p-mesh".into()
        };
    }
    base_role.into()
}

/// Roles allowed to reach Xbox during in-match shield (Warzone + Xbox Live + LAN).
pub fn is_in_match_allowed(role: &str) -> bool {
    matches!(
        role,
        "warzone-game" | "dedicated-server" | "xbox-live" | "lan-local" | "lan-gateway"
    )
}

pub fn should_drop_inbound_role(role: &str, phase: &str) -> bool {
    if is_vps_probe_role(role) || is_p2p_mesh_role(role) {
        return true;
    }
    phase == "in-match" && !role.is_empty() && !is_in_match_allowed(role)
}

pub fn should_drop_inbound(role: &str, port: Option<u16>, proto: &str, phase: &str) -> bool {
    if is_game_peer(role) || is_p2p_unconfirmed(role) {
        return true;
    }
    if is_inbound_player_peer_port(port, proto) {
        return true;
    }
    should_drop_inbound_role(role, phase)
}

/// Peer table / identical-packet panel — show unconfirmed P2P, hide infrastructure.
pub fn should_show_in_peer_table(role: &str, phase: &str) -> bool {
    if is_infrastructure(role) {
        return false;
    }
    if is_game_peer(role) || is_p2p_unconfirmed(role) {
        return true;
    }
    !should_drop_inbound_role(role, phase)
}

pub fn is_infrastructure(role: &str) -> bool {
    matches!(
        role,
        "warzone-game"
            | "dedicated-server"
            | "game-assets"
            | "matchmaking"
            | "xbox-live"
            | "azure-qos"
            | "telemetry"
            | "notifications"
    )
}

const VULTR_IP_PREFIXES: &[&str] = &[
    "45.76.", "45.77.", "66.42.", "96.30.", "108.61.", "149.28.", "155.138.", "207.148.", "140.82.",
    "144.202.",
];

pub fn is_vultr_ip(ip: &str) -> bool {
    VULTR_IP_PREFIXES.iter().any(|pfx| ip.starts_with(pfx))
}

pub fn is_vps_host_label(label: &str) -> bool {
    matches!(
        label,
        "Vultr VPS" | "Linode VPS" | "AWS" | "Google Cloud" | "DigitalOcean"
    ) || label.ends_with(" VPS") || label.contains("Cloud")
}

/// VPS kick/probe host with packet proof — auto-block target.
pub fn is_vps_game_peer(label: &str, role: &str) -> bool {
    is_vps_probe_role(role) && (is_vps_host_label(label) || label.contains("VPS"))
}

pub fn peer_display_label(ip: &str, hostname_hint: &str) -> String {
    inbound_display_label(ip, hostname_hint, "p2p-mesh")
}

fn peer_vps_label(ip: &str, hostname_hint: &str) -> Option<String> {
    let hint = hostname_hint.to_lowercase();
    if hint.contains("vultr") || hint.contains("choopa") || is_vultr_ip(ip) {
        return Some("Vultr VPS".into());
    }
    if hint.contains("linode") {
        return Some("Linode VPS".into());
    }
    if hint.contains("amazonaws") {
        return Some("AWS".into());
    }
    if hint.contains("digitalocean") {
        return Some("DigitalOcean".into());
    }
    if ip.starts_with("34.") || ip.starts_with("35.") {
        return Some("Cloud host".into());
    }
    None
}

/// Human label for inbound identical-peer rows (infrastructure ≠ player peer).
pub fn inbound_display_label(ip: &str, hostname_hint: &str, role: &str) -> String {
    match role {
        "xbox-live" => return "Xbox Live".into(),
        "warzone-game" => return "CoD backend".into(),
        "dedicated-server" => return "Dedicated server".into(),
        "matchmaking" => return "Matchmaking".into(),
        "game-assets" => return "Game CDN".into(),
        "azure-qos" => return "Azure QoS".into(),
        "telemetry" => return "Telemetry".into(),
        "notifications" => return "Notifications".into(),
        "lan-local" | "lan-gateway" => return "LAN".into(),
        "p2p-mesh" | "p2p-unconfirmed" => return "P2P mesh (unconfirmed)".into(),
        "vps-probe" | "game-peer" => {
            return peer_vps_label(ip, hostname_hint).unwrap_or_else(|| "VPS probe".into());
        }
        _ => {}
    }
    peer_vps_label(ip, hostname_hint).unwrap_or_else(|| "Unconfirmed inbound".into())
}

pub fn is_unknown_inbound(role: &str) -> bool {
    role == "unknown"
}

pub fn is_known_traffic(role: &str) -> bool {
    matches!(
        role,
        "warzone-game"
            | "dedicated-server"
            | "game-assets"
            | "matchmaking"
            | "xbox-live"
            | "azure-qos"
            | "telemetry"
            | "notifications"
            | "vps-probe"
            | "game-peer"
            | "p2p-mesh"
            | "p2p-unconfirmed"
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
    fn azure_on_p2p_port_inbound_stays_xbox_live_not_player() {
        assert_eq!(
            classify_inbound_endpoint("20.201.200.56:3074", "", Some(3074), "udp"),
            "xbox-live"
        );
    }

    #[test]
    fn unknown_on_high_port_is_p2p_mesh_not_player() {
        assert_eq!(
            classify_inbound_endpoint("203.0.113.51:44998", "", Some(44998), "udp"),
            "p2p-mesh"
        );
    }

    #[test]
    fn idle_home_xbox_live_is_background_not_matchmaking() {
        let mut roles = HashMap::new();
        roles.insert("xbox-live".into(), 8);
        assert_eq!(infer_phase(&roles, true, 45, "unknown"), "background");
    }

    #[test]
    fn xbox_live_inbound_label_not_player_peer() {
        assert_eq!(
            inbound_display_label("20.201.200.49", "", "xbox-live"),
            "Xbox Live"
        );
    }

    #[test]
    fn demonware_on_p2p_port_stays_warzone_not_player() {
        assert_eq!(
            classify_inbound_endpoint("185.34.106.103:3074", "", Some(3074), "udp"),
            "warzone-game"
        );
    }

    #[test]
    fn vultr_on_high_port_is_p2p_mesh_without_probe_proof() {
        assert_eq!(
            classify_inbound_endpoint("66.42.86.93:44998", "", Some(44998), "udp"),
            "p2p-mesh"
        );
    }

    #[test]
    fn vultr_with_probe_signals_becomes_vps_probe() {
        assert_eq!(
            resolve_inbound_peer_role("66.42.86.93", "66.42.86.93.vultrusercontent.com", "p2p-mesh", 8, 0, 10, 64, 64),
            "vps-probe"
        );
    }

    #[test]
    fn unknown_on_game_port_is_dedicated_server() {
        assert_eq!(
            classify_inbound_endpoint("203.0.113.51:3074", "", Some(3074), "udp"),
            "dedicated-server"
        );
    }

    #[test]
    fn probe_signals_confirm_player_peer() {
        assert!(confirm_player_peer_from_probe_signals(8, 0, 10, 64, 64));
        assert!(!confirm_player_peer_from_probe_signals(2, 1, 3, 64, 128));
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
        assert_eq!(classify_endpoint("192.0.2.1:52322", ""), "lan-gateway");
    }

    #[test]
    fn vultr_udp_high_port_is_p2p_mesh() {
        assert_eq!(
            classify_endpoint_with_port("66.42.86.93:44998", "", Some(44998), "udp"),
            "p2p-mesh"
        );
    }
}
