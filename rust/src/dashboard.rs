use serde_json::{json, Value};

pub fn trim_snapshot(snapshot: &Value) -> Value {
    let flows = snapshot
        .get("recentFlows")
        .or(snapshot.get("recent_flows"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().take(32).collect::<Vec<_>>())
        .unwrap_or_default();
    let items = snapshot
        .pointer("/connections/items")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().take(48).collect::<Vec<_>>())
        .unwrap_or_default();
    let dns = snapshot
        .get("dnsDestinations")
        .or(snapshot.get("dns_destinations"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().take(16).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "xbox": snapshot.get("xbox"),
        "wan": snapshot.get("wan"),
        "sample": snapshot.get("sample"),
        "flowSource": snapshot.get("flowSource"),
        "connections": {
            "count": snapshot.pointer("/connections/count"),
            "items": items,
        },
        "_enriched": snapshot.get("_enriched"),
        "recentFlows": flows,
        "dnsDestinations": dns,
        "topFlows": snapshot
            .get("topFlows")
            .or(snapshot.get("top_flows"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().take(20).collect::<Vec<_>>())
            .unwrap_or_default(),
        "packetCapture": snapshot.get("packetCapture").or(snapshot.get("packet_capture")),
    })
}

pub fn dashboard_page() -> &'static str {
    include_str!("dashboard.html")
}
