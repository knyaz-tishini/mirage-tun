use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Transport protocol used by a chain.
///
/// Only `Socks5` is implemented; other variants are recognised in config
/// but will return an error at connection time.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChainProtocol {
    #[default]
    Socks5,
}

/// Single chain configuration as sent in JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    pub socks5_addr: String,
    #[serde(default)]
    pub protocol: ChainProtocol,
    /// Per-chain DNS upstream. Falls back to global TunConfig.dns_upstream if None.
    #[serde(default)]
    pub dns_upstream: Option<String>,
}

/// Resolved entry for a single chain.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub socks5_addr: SocketAddr,
    /// Per-chain DNS upstream. None means use the global fallback.
    pub dns_upstream: Option<SocketAddr>,
}

/// Resolved map: chain name → ChainEntry.
pub type ChainMap = HashMap<String, ChainEntry>;

/// Hot-reloadable registry of SOCKS5 chains.
pub struct ChainRegistry {
    map: RwLock<Arc<ChainMap>>,
}

impl ChainRegistry {
    /// Build registry from a list of configs, resolving addresses at construction time.
    /// Invalid addresses are skipped with a warning.
    pub fn new(configs: Vec<ChainConfig>) -> Self {
        let mut map = ChainMap::new();
        for cfg in configs {
            match cfg.socks5_addr.parse::<SocketAddr>() {
                Ok(socks5_addr) => {
                    let dns_upstream = cfg.dns_upstream.as_ref().and_then(|d| {
                        d.parse::<SocketAddr>().map_err(|e| {
                            tracing::warn!(
                                "chains: invalid dns_upstream '{}' for chain '{}': {e}",
                                d,
                                cfg.name
                            );
                        }).ok()
                    });
                    map.insert(cfg.name, ChainEntry { socks5_addr, dns_upstream });
                }
                Err(e) => {
                    tracing::warn!(
                        "chains: invalid socks5_addr '{}' for chain '{}': {e}",
                        cfg.socks5_addr,
                        cfg.name
                    );
                }
            }
        }
        Self { map: RwLock::new(Arc::new(map)) }
    }

    /// Empty registry — no chains configured.
    pub fn empty() -> Self {
        Self { map: RwLock::new(Arc::new(ChainMap::new())) }
    }

    /// Snapshot of current map — cheap Arc clone, no allocation.
    pub async fn snapshot(&self) -> Arc<ChainMap> {
        self.map.read().await.clone()
    }

    /// Replace the entire map atomically.
    pub async fn update(&self, new_map: ChainMap) {
        let mut guard = self.map.write().await;
        *guard = Arc::new(new_map);
    }

    /// Reconstruct Vec<ChainConfig> from current map (for API responses).
    pub async fn to_configs(&self) -> Vec<ChainConfig> {
        self.map
            .read()
            .await
            .iter()
            .map(|(name, entry)| ChainConfig {
                name: name.clone(),
                socks5_addr: entry.socks5_addr.to_string(),
                protocol: ChainProtocol::Socks5,
                dns_upstream: entry.dns_upstream.map(|a| a.to_string()),
            })
            .collect()
    }
}
