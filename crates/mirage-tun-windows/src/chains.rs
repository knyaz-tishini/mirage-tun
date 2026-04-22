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
}

/// Resolved map: chain name → SOCKS5 SocketAddr.
pub type ChainMap = HashMap<String, SocketAddr>;

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
                Ok(addr) => {
                    map.insert(cfg.name, addr);
                }
                Err(e) => {
                    tracing::warn!("chains: invalid socks5_addr '{}' for chain '{}': {e}", cfg.socks5_addr, cfg.name);
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
        self.map.read().await
            .iter()
            .map(|(name, addr)| ChainConfig {
                name: name.clone(),
                socks5_addr: addr.to_string(),
                protocol: ChainProtocol::Socks5,
            })
            .collect()
    }
}
