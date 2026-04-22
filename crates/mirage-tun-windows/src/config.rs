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

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            api_bind: default_api_bind(),
            tun_name: default_tun_name(),
            tun_addr: default_tun_addr(),
            dns_upstream: default_dns_upstream(),
            dns_cache_ttl_secs: default_dns_cache_ttl_secs(),
            dns_cache_max: default_dns_cache_max(),
            dns_concurrency: default_dns_concurrency(),
            socks5_concurrency: default_socks5_concurrency(),
            drain_timeout_secs: default_drain_timeout_secs(),
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
