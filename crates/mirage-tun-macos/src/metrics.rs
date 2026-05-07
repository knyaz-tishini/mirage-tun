use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use serde::Serialize;

#[derive(Default)]
pub struct ChainMetrics {
    pub connections: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Serialize)]
pub struct ChainMetricsSnapshot {
    pub connections: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub errors: u64,
}

#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub chains: HashMap<String, ChainMetricsSnapshot>,
}

pub struct MetricsRegistry {
    chains: RwLock<HashMap<String, Arc<ChainMetrics>>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
        }
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get existing chain metrics or create a new entry.
    pub fn get_or_create(&self, chain_name: &str) -> Arc<ChainMetrics> {
        {
            let map = self.chains.read().expect("metrics read lock poisoned");
            if let Some(m) = map.get(chain_name) {
                return m.clone();
            }
        }
        let mut map = self.chains.write().expect("metrics write lock poisoned");
        map.entry(chain_name.to_owned())
            .or_insert_with(|| Arc::new(ChainMetrics::default()))
            .clone()
    }

    pub fn record_connection(&self, chain: &str) {
        self.get_or_create(chain).connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes(&self, chain: &str, tx: u64, rx: u64) {
        let m = self.get_or_create(chain);
        m.bytes_tx.fetch_add(tx, Ordering::Relaxed);
        m.bytes_rx.fetch_add(rx, Ordering::Relaxed);
    }

    pub fn record_error(&self, chain: &str) {
        self.get_or_create(chain).errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Build a serializable snapshot — called only on the `/metrics` API path.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let map = self.chains.read().expect("metrics read lock poisoned");
        let chains = map
            .iter()
            .map(|(name, m)| {
                (
                    name.clone(),
                    ChainMetricsSnapshot {
                        connections: m.connections.load(Ordering::Relaxed),
                        bytes_tx: m.bytes_tx.load(Ordering::Relaxed),
                        bytes_rx: m.bytes_rx.load(Ordering::Relaxed),
                        errors: m.errors.load(Ordering::Relaxed),
                    },
                )
            })
            .collect();

        MetricsSnapshot { chains }
    }
}
