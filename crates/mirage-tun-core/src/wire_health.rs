use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const FAIL_STREAK_THRESHOLD: u32 = 2;
const RECOVER_AFTER_SECS: u64 = 30;

/// Per-wire liveness tracked by consecutive connect failures.
/// Shared via `Arc`; clone-cheap. Thread-safe via `std::sync::RwLock`
/// (held only for the duration of a single map lookup — never across `.await`).
pub struct WireHealthMap {
    inner: RwLock<HashMap<String, WireState>>,
}

#[derive(Clone)]
struct WireState {
    healthy: bool,
    fail_streak: u32,
    last_changed: Instant,
}

impl WireHealthMap {
    /// Construct a new, empty map wrapped in `Arc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
        })
    }

    /// Record a successful SOCKS5 connect. Resets `fail_streak` and marks healthy.
    pub fn record_success(&self, wire: &str) {
        let mut map = match self.inner.write() {
            Ok(m) => m,
            Err(_) => return,
        };
        let state = map.entry(wire.to_owned()).or_insert_with(|| WireState {
            healthy: true,
            fail_streak: 0,
            last_changed: Instant::now(),
        });
        let was_unhealthy = !state.healthy || state.fail_streak > 0;
        state.fail_streak = 0;
        state.healthy = true;
        if was_unhealthy {
            state.last_changed = Instant::now();
        }
    }

    /// Record a failed SOCKS5 connect (`ConnectionRefused` / timeout).
    /// Marks unhealthy after `FAIL_STREAK_THRESHOLD` consecutive failures.
    pub fn record_failure(&self, wire: &str) {
        let mut map = match self.inner.write() {
            Ok(m) => m,
            Err(_) => return,
        };
        let state = map.entry(wire.to_owned()).or_insert_with(|| WireState {
            healthy: true,
            fail_streak: 0,
            last_changed: Instant::now(),
        });
        state.fail_streak += 1;
        if state.fail_streak >= FAIL_STREAK_THRESHOLD && state.healthy {
            state.healthy = false;
            state.last_changed = Instant::now();
        }
    }

    /// Fast health check. Absent entry → `true` (assume healthy on first use).
    /// Poisoned lock → `true` (fail-open for liveness).
    ///
    /// Auto-recover: an unhealthy wire that has been unhealthy for longer than
    /// `RECOVER_AFTER_SECS` returns `true` (allow one probe attempt). The next
    /// `record_success` / `record_failure` will update state accordingly.
    #[inline]
    pub fn is_healthy(&self, wire: &str) -> bool {
        let map = match self.inner.read() {
            Ok(m) => m,
            Err(_) => return true,
        };
        match map.get(wire) {
            None => true,
            Some(state) if state.healthy => true,
            Some(state) => {
                // Unhealthy — check cooldown: allow retry probe after RECOVER_AFTER_SECS.
                state.last_changed.elapsed() >= Duration::from_secs(RECOVER_AFTER_SECS)
            }
        }
    }

    /// Return the first candidate (ordered preference) whose wire name is healthy.
    pub fn first_healthy<'a>(
        &self,
        candidates: &'a [(String, SocketAddr)],
    ) -> Option<&'a (String, SocketAddr)> {
        candidates.iter().find(|(name, _)| self.is_healthy(name))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn sa(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn absent_wire_is_healthy() {
        let m = WireHealthMap::new();
        assert!(m.is_healthy("wire_a"));
    }

    #[test]
    fn two_failures_mark_unhealthy() {
        let m = WireHealthMap::new();
        m.record_failure("wire_a");
        assert!(m.is_healthy("wire_a"), "one failure must not mark unhealthy yet");
        m.record_failure("wire_a");
        assert!(!m.is_healthy("wire_a"), "two consecutive failures must mark unhealthy");
    }

    #[test]
    fn success_after_failures_resets_to_healthy() {
        let m = WireHealthMap::new();
        m.record_failure("wire_a");
        m.record_failure("wire_a");
        assert!(!m.is_healthy("wire_a"));
        m.record_success("wire_a");
        assert!(m.is_healthy("wire_a"), "success must restore health");
    }

    #[test]
    fn first_healthy_skips_unhealthy_first_candidate() {
        let m = WireHealthMap::new();
        // Mark wire_a unhealthy.
        m.record_failure("wire_a");
        m.record_failure("wire_a");
        assert!(!m.is_healthy("wire_a"));

        let candidates = vec![
            ("wire_a".to_owned(), sa(1080)),
            ("wire_b".to_owned(), sa(1081)),
        ];
        let result = m.first_healthy(&candidates);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "wire_b");
    }

    #[test]
    fn first_healthy_returns_first_when_all_healthy() {
        let m = WireHealthMap::new();
        let candidates = vec![
            ("wire_a".to_owned(), sa(1080)),
            ("wire_b".to_owned(), sa(1081)),
        ];
        let result = m.first_healthy(&candidates);
        assert_eq!(result.unwrap().0, "wire_a");
    }

    #[test]
    fn first_healthy_returns_none_when_all_unhealthy() {
        let m = WireHealthMap::new();
        for _ in 0..FAIL_STREAK_THRESHOLD {
            m.record_failure("wire_a");
            m.record_failure("wire_b");
        }
        let candidates = vec![
            ("wire_a".to_owned(), sa(1080)),
            ("wire_b".to_owned(), sa(1081)),
        ];
        // Neither has passed the cooldown yet so both unhealthy.
        assert!(m.first_healthy(&candidates).is_none());
    }

    /// Test cooldown path without sleeping 30 s.
    /// We manipulate a WireState directly via the internal map to backdating
    /// `last_changed`, then verify is_healthy returns true.
    #[test]
    fn cooldown_allows_probe_after_recover_period() {
        let m = WireHealthMap::new();
        // Drive wire_a to unhealthy.
        for _ in 0..FAIL_STREAK_THRESHOLD {
            m.record_failure("wire_a");
        }
        assert!(!m.is_healthy("wire_a"), "must be unhealthy before cooldown");

        // Backdating: write directly into the inner map.
        {
            let mut map = m.inner.write().unwrap();
            let state = map.get_mut("wire_a").unwrap();
            // Simulate time passing by setting last_changed to well in the past.
            state.last_changed =
                Instant::now() - Duration::from_secs(RECOVER_AFTER_SECS + 1);
        }

        assert!(
            m.is_healthy("wire_a"),
            "after cooldown the wire should report healthy (allow retry probe)"
        );
    }
}
