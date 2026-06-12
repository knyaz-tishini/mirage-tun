use std::net::{IpAddr, SocketAddr};
use crate::policy::PolicyConfigRequest;

/// Config passed to `TunStack::start()` — platform-agnostic.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Adapter name (e.g. "mirage0").  Passed to WintunHandle::create on Windows.
    /// D9: propagated from TunConfig::tun_name so the adapter name is configurable.
    pub tun_name: String,
    /// Tunnel interface address + prefix (e.g. "10.0.85.1/24").
    pub tun_addr: String,
    /// Optional IPv6 address for the TUN interface (e.g. "fd00:7::2/64").
    /// None = v4-only TUN (backward-compat default).
    pub tun_addr_v6: Option<String>,
    pub mtu: u16,
    /// Chain registry: name → SOCKS5 addr.
    pub chains: Vec<ChainEntry>,
    /// Policy rules. Default: all → chain "default".
    pub policy: PolicyConfigRequest,
    /// DNS override pushed to chain N. None = use system DNS.
    pub chain_dns: Vec<ChainDnsConfig>,
    /// Relay/server addresses that must never route through TUN (v4 and v6).
    pub relay_addrs: Vec<IpAddr>,
    /// Per-chain DNS upstream for the DoT/DoH proxy inside the stack.
    pub dns_upstream: SocketAddr,
    /// DNS cache parameters.
    pub dns_cache_ttl_secs: u64,
    pub dns_cache_max: usize,
    pub dns_concurrency: usize,
    pub socks5_concurrency: usize,
    /// When true: each chain gets its own TUN interface (full isolation).
    /// When false: one shared TUN, policy engine routes per-connection.
    pub per_chain_tun: bool,
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub socks5_addr: SocketAddr,
    /// Optional failover group this chain belongs to.
    /// Chains in the same group are interchangeable for `FailurePolicy::Failover`.
    /// `None` = chain is not part of any group.
    pub group: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainDnsConfig {
    /// Chain name this DNS config belongs to.
    pub chain_name: String,
    /// DNS servers visible only to traffic on this chain.
    pub servers: Vec<IpAddr>,
}
