#[derive(Debug, Clone)]
pub struct TunConfig {
    pub tun_name: String,
    pub tun_addr: String,
    pub mtu: u16,
    pub dns_hijack: bool,
    pub intercept: InterceptStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptStrategy {
    KernelRedirect,
    UserspaceNat,
    IpStack,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tun_name: "mirage0".into(),
            tun_addr: "10.0.85.1/24".into(),
            // 1280 (IPv6 minimum) leaves headroom for onion+AEAD+camo per-hop
            // overhead. At 1500 the onion-wrapped segments exceed path MTU →
            // PMTUD blackhole: TCP connect succeeds but the onion handshake /
            // data-exchange stalls (verified on Mac edge — 1500 = 0% E2E,
            // 1280 = traffic flows). Tunable; compute from hop count later.
            mtu: 1280,
            dns_hijack: true,
            intercept: InterceptStrategy::IpStack,
        }
    }
}
