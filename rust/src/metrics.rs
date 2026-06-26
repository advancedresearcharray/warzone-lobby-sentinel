#[derive(Clone, Debug, Default)]
pub struct InboundBaseline {
    pub inbound_mbps: f64,
    pub outbound_mbps: f64,
    pub total_kpps: f64,
    pub connections: f64,
    pub wan_latency_ms: f64,
}
