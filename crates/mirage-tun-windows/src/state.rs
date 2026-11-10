use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::AtomicU64,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunPhase {
    AdapterReady,
    TunActive,
    Transitioning,
}

pub struct ServiceState {
    pub wintun: Option<super::wintun::WintunHandle>,
    pub tun_phase: TunPhase,
    pub proxy_active: Option<String>,
    pub ipstack_cancel: Option<CancellationToken>,
    pub bypass_addrs: Vec<IpAddr>,
    /// The holes the person asked for: the prefixes whose route points at
    /// the real gateway, so their packets never reach the adapter.  Closed
    /// when the tunnel stops.
    pub bypass_holes: Vec<crate::routing::BypassHole>,
    pub original_gateway: Option<String>,
    pub tun_default_set: bool,
    pub socks5_addr: Option<SocketAddr>,
    pub tun_name: String,
    pub killswitch: Option<crate::firewall::WfpKillSwitch>,
    pub if_index: u32,
    pub dns_map: Arc<crate::dns_map::DnsMap>,
    pub chains: Arc<crate::chains::ChainRegistry>,
    /// Tracks active TCP/bypass connections for graceful drain on stop.
    pub active_conns: Option<Arc<AtomicU64>>,
    /// How long to wait for active connections to drain (seconds).
    pub drain_timeout_secs: u64,
    /// DNS upstream used for DNS-over-TCP SOCKS5 warmup.
    pub dns_upstream: SocketAddr,
}

impl ServiceState {
    pub fn new(tun_name: String) -> Self {
        Self {
            wintun: None,
            tun_phase: TunPhase::AdapterReady,
            proxy_active: None,
            ipstack_cancel: None,
            bypass_addrs: Vec::new(),
            bypass_holes: Vec::new(),
            original_gateway: None,
            tun_default_set: false,
            socks5_addr: None,
            tun_name,
            killswitch: None,
            if_index: 0,
            dns_map: Arc::new(crate::dns_map::DnsMap::new()),
            chains: Arc::new(crate::chains::ChainRegistry::empty()),
            active_conns: None,
            drain_timeout_secs: 5,
            dns_upstream: "8.8.8.8:53".parse().expect("static addr is valid"),
        }
    }
}
