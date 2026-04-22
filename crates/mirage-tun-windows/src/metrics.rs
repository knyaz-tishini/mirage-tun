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
pub struct RuleHitSnapshot {
    pub index: usize,
    pub hits: u64,
}

#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub chains: HashMap<String, ChainMetricsSnapshot>,
    pub bypass: ChainMetricsSnapshot,
    pub rules: Vec<RuleHitSnapshot>,
}

pub struct MetricsRegistry {
    chains: RwLock<HashMap<String, Arc<ChainMetrics>>>,
    bypass: ChainMetrics,
    /// Rule hit counters — replaced atomically when policy is swapped.
    rule_hits: RwLock<Arc<Vec<AtomicU64>>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            bypass: ChainMetrics::default(),
            rule_hits: RwLock::new(Arc::new(Vec::new())),
        }
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get existing chain metrics or create a new entry.
    pub fn get_or_create(&self, chain_name: &str) -> Arc<ChainMetrics> {
        // Fast path: read lock.
        {
            let map = self.chains.read().expect("metrics read lock poisoned");
            if let Some(m) = map.get(chain_name) {
                return m.clone();
            }
        }
        // Slow path: write lock — may race, that's fine.
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

    pub fn record_bypass_connection(&self) {
        self.bypass.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bypass_bytes(&self, tx: u64, rx: u64) {
        self.bypass.bytes_tx.fetch_add(tx, Ordering::Relaxed);
        self.bypass.bytes_rx.fetch_add(rx, Ordering::Relaxed);
    }

    pub fn record_bypass_error(&self) {
        self.bypass.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Replace rule hit counters when policy is updated. Returns the new Arc so
    /// PolicyEngine can hold a reference to the same counters.
    pub fn reset_rule_hits(&self, rule_count: usize) -> Arc<Vec<AtomicU64>> {
        let new_hits: Arc<Vec<AtomicU64>> =
            Arc::new((0..rule_count).map(|_| AtomicU64::new(0)).collect());
        let mut guard = self.rule_hits.write().expect("rule_hits write lock poisoned");
        *guard = new_hits.clone();
        new_hits
    }

    /// Borrow the current rule hit counters Arc (cheap clone).
    pub fn rule_hits(&self) -> Arc<Vec<AtomicU64>> {
        self.rule_hits.read().expect("rule_hits read lock poisoned").clone()
    }

    /// Build a serializable snapshot — called only on the `/metrics` API path.
    pub fn snapshot(&self, rule_hits: &Arc<Vec<AtomicU64>>) -> MetricsSnapshot {
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

        let bypass = ChainMetricsSnapshot {
            connections: self.bypass.connections.load(Ordering::Relaxed),
            bytes_tx: self.bypass.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bypass.bytes_rx.load(Ordering::Relaxed),
            errors: self.bypass.errors.load(Ordering::Relaxed),
        };

        let rules = rule_hits
            .iter()
            .enumerate()
            .map(|(index, h)| RuleHitSnapshot {
                index,
                hits: h.load(Ordering::Relaxed),
            })
            .collect();

        MetricsSnapshot { chains, bypass, rules }
    }
}
