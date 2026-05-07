use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    #[serde(default = "default_api_bind")]
    pub api_bind: SocketAddr,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_addr")]
    pub tun_addr: String,
    /// Optional IPv6 address for the TUN interface (e.g. "fd00:7::2/64").
    /// None = v4-only (backward-compat default).
    #[serde(default)]
    pub tun_addr_v6: Option<String>,
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: SocketAddr,
    #[serde(default = "default_dns_cache_ttl_secs")]
    pub dns_cache_ttl_secs: u64,
    #[serde(default = "default_dns_cache_max")]
    pub dns_cache_max: usize,
    #[serde(default = "default_dns_concurrency")]
    pub dns_concurrency: usize,
    #[serde(default = "default_socks5_concurrency")]
    pub socks5_concurrency: usize,
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    /// Optional: URL of mirage2monitor to pull chain config from.
    /// When set, mirage2tun spawns an internal MonitorLink and updates the
    /// chain registry automatically — no mirage2app required.
    /// Example: `"http://127.0.0.1:19410"`
    #[serde(default)]
    pub monitor_url: Option<String>,
    /// Optional Bearer token sent to the monitor on every request.
    #[serde(default)]
    pub monitor_api_key: Option<String>,
    /// Per-connection TCP send buffer size inside smoltcp (bytes).
    /// Default: 524288 (512 KB).
    #[serde(default = "default_tcp_send_buffer_size")]
    pub tcp_send_buffer_size: u32,
    /// Per-connection TCP recv buffer size inside smoltcp (bytes).
    /// Default: 524288 (512 KB).
    #[serde(default = "default_tcp_recv_buffer_size")]
    pub tcp_recv_buffer_size: u32,
}

fn default_api_bind() -> SocketAddr {
    "127.0.0.1:19485".parse().expect("static addr is valid")
}

fn default_tun_name() -> String {
    "mirage0".to_owned()
}

fn default_tun_addr() -> String {
    "10.0.85.1/24".to_owned()
}

fn default_dns_upstream() -> SocketAddr {
    "8.8.8.8:53".parse().expect("static addr is valid")
}

fn default_dns_cache_ttl_secs() -> u64 {
    60
}

fn default_dns_cache_max() -> usize {
    1024
}

fn default_dns_concurrency() -> usize {
    8
}

fn default_socks5_concurrency() -> usize {
    100
}

fn default_drain_timeout_secs() -> u64 {
    5
}

fn default_tcp_send_buffer_size() -> u32 {
    mirage_tcpip_stack::tcp::DEFAULT_TCP_SEND_BUFFER_SIZE
}

fn default_tcp_recv_buffer_size() -> u32 {
    mirage_tcpip_stack::tcp::DEFAULT_TCP_RECV_BUFFER_SIZE
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            api_bind: default_api_bind(),
            tun_name: default_tun_name(),
            tun_addr: default_tun_addr(),
            tun_addr_v6: None,
            dns_upstream: default_dns_upstream(),
            dns_cache_ttl_secs: default_dns_cache_ttl_secs(),
            dns_cache_max: default_dns_cache_max(),
            dns_concurrency: default_dns_concurrency(),
            socks5_concurrency: default_socks5_concurrency(),
            drain_timeout_secs: default_drain_timeout_secs(),
            monitor_url: None,
            monitor_api_key: None,
            tcp_send_buffer_size: default_tcp_send_buffer_size(),
            tcp_recv_buffer_size: default_tcp_recv_buffer_size(),
        }
    }
}

impl TunConfig {
    /// Load from a JSON object that may contain a `"config"` key.
    /// If the file is absent or the key is missing, defaults are used.
    pub fn load_from_tun_json(path: &std::path::Path) -> Self {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(&contents) else {
            return Self::default();
        };
        // Support both top-level config fields and a nested `"config"` object.
        let cfg_value = obj.get("config").cloned().unwrap_or(obj);
        serde_json::from_value(cfg_value).unwrap_or_default()
    }
}
