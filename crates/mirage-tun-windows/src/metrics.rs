use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
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

// ── ConnectionRegistry ───────────────────────────────────────────────────────
//
// Tracks each individual TCP destination so a UI can render the routing tree
// (centre → L1 → L2 → external destinations) instead of just chain-level
// totals.  Entries auto-expire when no traffic has been observed for
// `IDLE_GC_AFTER`.

/// How long a connection stays in the registry after its last byte event
/// before the GC sweeps it out.
const IDLE_GC_AFTER: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct ConnState {
    pub chain: String,
    pub dest: SocketAddr,
    pub domain: Option<String>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub started_at: Instant,
    pub last_active: Instant,
    /// Transport protocol: `"tcp"` or `"udp"`.
    pub proto: &'static str,
    /// PID of the attributed process, if attribution succeeded.
    pub pid: Option<u32>,
    /// Full normalized exe path of the attributed process.
    pub exe_path: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ConnSnapshot {
    pub chain: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub domain: Option<String>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    /// Milliseconds since the connection was first observed.
    pub age_ms: u128,
    /// Milliseconds since the last byte was recorded — `0` for currently active.
    pub idle_ms: u128,
    /// Transport protocol: `"tcp"` or `"udp"`.
    pub proto: &'static str,
    /// PID of the attributed process, `null` when attribution missed.
    pub pid: Option<u32>,
    /// Full normalized exe path, `null` when attribution missed.
    pub exe_path: Option<String>,
}

/// Live per-destination connection registry.
///
/// Keyed by `(dest, chain)` because the same destination may legitimately be
/// served by multiple chains (e.g. one TCP stream on the default chain and
/// another on a backup chain) — we track them as distinct rows.
pub struct ConnectionRegistry {
    inner: RwLock<HashMap<(SocketAddr, String), ConnState>>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self { Self::new() }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }

    /// Record a new connection (or refresh the timestamp on an existing one).
    ///
    /// `proto` is `"tcp"` or `"udp"`.  `app_info` carries the attributed process
    /// (PID + exe path); pass `None` when attribution missed — the ledger records
    /// that explicitly so attribution-miss flows are observable via `/connections`.
    pub fn record_open(
        &self,
        chain: &str,
        dest: SocketAddr,
        domain: Option<String>,
        proto: &'static str,
        app_info: Option<&crate::process_info::ProcessInfo>,
    ) {
        let now = Instant::now();
        let pid = app_info.map(|i| i.pid);
        let exe_path = app_info.map(|i| i.exe_path.clone());
        let mut map = self.inner.write().expect("conn registry write lock poisoned");
        let key = (dest, chain.to_string());
        match map.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let v = e.get_mut();
                v.last_active = now;
                if v.domain.is_none() && domain.is_some() {
                    v.domain = domain;
                }
                // Update attribution if we now have it and didn't before.
                if v.pid.is_none() {
                    v.pid = pid;
                    v.exe_path = exe_path;
                }
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ConnState {
                    chain: chain.to_string(),
                    dest,
                    domain,
                    bytes_tx: 0,
                    bytes_rx: 0,
                    started_at: now,
                    last_active: now,
                    proto,
                    pid,
                    exe_path,
                });
            }
        }
    }

    /// Update byte counters when a flow finishes (or periodically).
    pub fn record_bytes(&self, chain: &str, dest: SocketAddr, tx: u64, rx: u64) {
        let now = Instant::now();
        let mut map = self.inner.write().expect("conn registry write lock poisoned");
        if let Some(v) = map.get_mut(&(dest, chain.to_string())) {
            v.bytes_tx = v.bytes_tx.saturating_add(tx);
            v.bytes_rx = v.bytes_rx.saturating_add(rx);
            v.last_active = now;
        } else {
            // Late record without a prior open — synthesize an entry.
            map.insert(
                (dest, chain.to_string()),
                ConnState {
                    chain: chain.to_string(),
                    dest,
                    domain: None,
                    bytes_tx: tx,
                    bytes_rx: rx,
                    started_at: now,
                    last_active: now,
                    proto: "tcp",
                    pid: None,
                    exe_path: None,
                },
            );
        }
    }

    /// Drop entries that have been silent for longer than `IDLE_GC_AFTER`.
    /// Returns the number of entries removed (handy for debug logs).
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let mut map = self.inner.write().expect("conn registry write lock poisoned");
        let before = map.len();
        map.retain(|_, v| now.duration_since(v.last_active) < IDLE_GC_AFTER);
        before - map.len()
    }

    /// Build a serializable snapshot for the `/connections` API.
    pub fn snapshot(&self) -> Vec<ConnSnapshot> {
        let now = Instant::now();
        let map = self.inner.read().expect("conn registry read lock poisoned");
        let mut out: Vec<ConnSnapshot> = map
            .values()
            .map(|v| ConnSnapshot {
                chain: v.chain.clone(),
                dest_ip: v.dest.ip().to_string(),
                dest_port: v.dest.port(),
                domain: v.domain.clone(),
                bytes_tx: v.bytes_tx,
                bytes_rx: v.bytes_rx,
                age_ms: now.duration_since(v.started_at).as_millis(),
                idle_ms: now.duration_since(v.last_active).as_millis(),
                proto: v.proto,
                pid: v.pid,
                exe_path: v.exe_path.clone(),
            })
            .collect();
        // Stable order — by total bytes desc — so heavy hitters appear first.
        out.sort_by_key(|c| std::cmp::Reverse(c.bytes_tx + c.bytes_rx));
        out
    }
}

/// Spawn a periodic GC task.  Idempotent — caller may safely spawn once at
/// service startup.
pub fn spawn_gc(reg: Arc<ConnectionRegistry>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let _ = reg.gc();
        }
    });
}
