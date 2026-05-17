use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
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
    /// Chain name/ID — mirrors `ChainConfig::name`.
    ///
    /// Injected at the DNS dispatch point (ipstack `udp_dns_loop`) so the
    /// `DnsRoutingHint` can tag which chain owns each intercepted DNS query.
    pub chain_id: String,
    pub socks5_addr: SocketAddr,
    /// Per-chain DNS upstream. None means use the global fallback.
    pub dns_upstream: Option<SocketAddr>,
}

/// Resolved map: chain name → ChainEntry.
pub type ChainMap = HashMap<String, ChainEntry>;

/// Hot-reloadable registry of SOCKS5 chains.
///
/// The registry stores a `HashMap` for O(1) name lookup and an ordered
/// `Vec` for round-robin failover. The ordered vec preserves insertion order
/// from the supervisor's `/chains/update` push (which sends chains in config
/// priority order).
pub struct ChainRegistry {
    map: RwLock<Arc<ChainMap>>,
    /// Ordered chain names (insertion order from `/chains/update`).
    ordered: RwLock<Vec<String>>,
}

impl ChainRegistry {
    /// Build registry from a list of configs, resolving addresses at construction time.
    /// Invalid addresses are skipped with a warning.
    pub fn new(configs: Vec<ChainConfig>) -> Self {
        let mut map = ChainMap::new();
        let mut ordered = Vec::with_capacity(configs.len());
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
                    ordered.push(cfg.name.clone());
                    map.insert(cfg.name.clone(), ChainEntry { chain_id: cfg.name, socks5_addr, dns_upstream });
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
        Self {
            map: RwLock::new(Arc::new(map)),
            ordered: RwLock::new(ordered),
        }
    }

    /// Empty registry — no chains configured.
    pub fn empty() -> Self {
        Self {
            map: RwLock::new(Arc::new(ChainMap::new())),
            ordered: RwLock::new(Vec::new()),
        }
    }

    /// Snapshot of current map — cheap Arc clone, no allocation.
    pub async fn snapshot(&self) -> Arc<ChainMap> {
        self.map.read().await.clone()
    }

    /// Snapshot of ordered chain names (insertion order from supervisor push).
    pub async fn ordered_names(&self) -> Vec<String> {
        self.ordered.read().await.clone()
    }

    /// Replace the entire map atomically, preserving insertion order.
    ///
    /// `new_map` keys are reordered to match the original insertion order
    /// of `new_ordered`. Any key in `new_map` not present in `new_ordered`
    /// is appended at the end.
    pub async fn update(&self, new_map: ChainMap) {
        // Derive ordering from current map's insertion order, extended with
        // any new keys.
        let mut new_ordered: Vec<String> = Vec::with_capacity(new_map.len());
        // First pass: preserve existing ordering for keys that still exist.
        {
            let old_ordered = self.ordered.read().await;
            for name in old_ordered.iter() {
                if new_map.contains_key(name) {
                    new_ordered.push(name.clone());
                }
            }
        }
        // Second pass: append new keys not yet in ordered.
        for name in new_map.keys() {
            if !new_ordered.contains(name) {
                new_ordered.push(name.clone());
            }
        }

        let mut map_guard = self.map.write().await;
        let mut ord_guard = self.ordered.write().await;
        *map_guard = Arc::new(new_map);
        *ord_guard = new_ordered;
    }

    /// Update from an ordered list of configs (preserves config-file order).
    pub async fn update_ordered(&self, configs: Vec<ChainConfig>) {
        let mut map = ChainMap::new();
        let mut ordered = Vec::with_capacity(configs.len());
        for cfg in configs {
            match cfg.socks5_addr.parse::<SocketAddr>() {
                Ok(socks5_addr) => {
                    let dns_upstream = cfg.dns_upstream.as_ref().and_then(|d| {
                        d.parse::<SocketAddr>().ok()
                    });
                    ordered.push(cfg.name.clone());
                    map.insert(cfg.name.clone(), ChainEntry { chain_id: cfg.name, socks5_addr, dns_upstream });
                }
                Err(_) => {}
            }
        }
        let mut map_guard = self.map.write().await;
        let mut ord_guard = self.ordered.write().await;
        *map_guard = Arc::new(map);
        *ord_guard = ordered;
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

// ── TunRouter ─────────────────────────────────────────────────────────────────

/// Lightweight TUN-side router.
///
/// Holds an ordered snapshot of chains and does round-robin selection with
/// ordered failover. This mirrors `RouterImpl::pick_round_robin` but operates
/// over SOCKS5 addresses instead of TunnelPool objects — TUN never owns pools.
///
/// Build via `TunRouter::from_registry` after each `/chains/update` push.
pub struct TunRouter {
    /// Chains in priority order.
    chains: Vec<(String, SocketAddr)>,
    /// Round-robin cursor.
    cursor: AtomicU64,
}

impl TunRouter {
    /// Build from current registry state.
    pub async fn from_registry(registry: &ChainRegistry) -> Arc<Self> {
        let snap = registry.snapshot().await;
        let ordered = registry.ordered_names().await;

        // Build ordered list: ordered names first, then any leftover.
        let mut chains: Vec<(String, SocketAddr)> = Vec::with_capacity(snap.len());
        for name in &ordered {
            if let Some(e) = snap.get(name) {
                chains.push((name.clone(), e.socks5_addr));
            }
        }
        // Append any keys not in ordered (shouldn't normally happen).
        for (name, entry) in snap.iter() {
            if !ordered.contains(name) {
                chains.push((name.clone(), entry.socks5_addr));
            }
        }

        Arc::new(Self {
            chains,
            cursor: AtomicU64::new(0),
        })
    }

    /// Return ordered `Vec<(chain_name, socks5_addr)>` for this flow.
    ///
    /// The primary chain is at index 0. If `preferred_chain` is provided and
    /// exists in the registry, it is moved to index 0. On exhaustion, the
    /// "default" chain (if present) is tried before first-available.
    ///
    /// Returns an empty vec when no chains are configured.
    pub fn pick(&self, preferred_chain: Option<&str>, five_tuple_hash: u64) -> Vec<(String, SocketAddr)> {
        if self.chains.is_empty() {
            return Vec::new();
        }

        let n = self.chains.len();

        // If a preferred chain is specified and found, put it first.
        if let Some(name) = preferred_chain {
            if let Some(pos) = self.chains.iter().position(|(id, _)| id == name) {
                let mut result = Vec::with_capacity(n);
                result.push(self.chains[pos].clone());
                for (i, c) in self.chains.iter().enumerate() {
                    if i != pos {
                        result.push(c.clone());
                    }
                }
                return result;
            }
        }

        // Round-robin with five_tuple_hash mixing for sticky-ish per-flow assignment.
        let start = (self.cursor.fetch_add(1, Ordering::Relaxed)
            ^ five_tuple_hash) as usize
            % n;

        let mut result = Vec::with_capacity(n);
        for i in 0..n {
            result.push(self.chains[(start + i) % n].clone());
        }

        // Ensure "default" chain is last (if not already primary).
        if result.len() > 1 && result[0].0 != "default" {
            if let Some(def_pos) = result.iter().position(|(id, _)| id == "default") {
                let def = result.remove(def_pos);
                result.push(def);
            }
        }

        result
    }
}
