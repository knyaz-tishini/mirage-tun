/// Per-flow connection registry exposed through the `GET /connections` API.
///
/// `record_open` is called from the TCP accept loop at flow-creation time.
/// `record_close` is called when the forward task finishes (bytes counters
/// are written then too).  Both operations are lock-gated writes; reads only
/// happen on the `/connections` API path, so contention is minimal.
///
/// The registry is bounded: when `MAX_CONNECTIONS` is reached the oldest
/// *closed* entry is evicted first; if all are open the oldest open entry is
/// removed to prevent unbounded growth under a connection-flood.
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

/// Maximum number of entries (open + closed) kept in memory.
const MAX_CONNECTIONS: usize = 2048;

/// Serializable snapshot of a single flow.
#[derive(Clone, Serialize)]
pub struct ConnSnapshot {
    /// Internal flow identifier (monotonically increasing).
    pub id: u64,
    /// Chain name used to forward this flow.
    pub chain: String,
    /// Destination IP address.
    pub dest_ip: IpAddr,
    /// Destination port.
    pub dest_port: u16,
    /// Forward DNS query name that resolved to `dest_ip`, if known.
    ///
    /// Set from the TUN's own DNS-intercept log (forward query name wins over
    /// any reverse-PTR fallback).  `None` for direct-IP flows whose DNS query
    /// did not pass through the TUN intercept (rare in practice when the TUN
    /// redirects all DNS traffic).
    pub domain: Option<String>,
    /// L4 protocol: `"tcp"` or `"udp"`.
    pub proto: &'static str,
    /// Flow state.
    pub state: ConnState,
    /// Epoch-seconds timestamp of flow open.
    pub opened_at_secs: u64,
    /// Bytes sent (populated on close; 0 while open).
    pub bytes_tx: u64,
    /// Bytes received (populated on close; 0 while open).
    pub bytes_rx: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    Open,
    Closed,
}

struct Entry {
    snap: ConnSnapshot,
}

struct Inner {
    entries: VecDeque<Entry>,
    next_id: u64,
}

/// Shared connection registry.
pub struct ConnectionRegistry {
    inner: Mutex<Inner>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        ConnectionRegistry {
            inner: Mutex::new(Inner {
                entries: VecDeque::new(),
                next_id: 1,
            }),
        }
    }

    /// Record a new flow opening.  Returns the assigned flow `id` so the
    /// caller can pass it to `record_close`.
    ///
    /// `domain` should be the result of `DnsQueryLog::lookup(dest_ip)`;
    /// pass `None` if no forward name is known.
    pub fn record_open(
        &self,
        chain: String,
        dest: SocketAddr,
        domain: Option<String>,
        proto: &'static str,
    ) -> u64 {
        let mut g = self.inner.lock().expect("ConnectionRegistry lock poisoned");
        let id = g.next_id;
        g.next_id += 1;

        // Evict when at capacity: prefer oldest closed entry, then oldest open.
        if g.entries.len() >= MAX_CONNECTIONS {
            let closed_pos = g
                .entries
                .iter()
                .position(|e| e.snap.state == ConnState::Closed);
            if let Some(pos) = closed_pos {
                g.entries.remove(pos);
            } else {
                g.entries.pop_front();
            }
        }

        let opened_at_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        g.entries.push_back(Entry {
            snap: ConnSnapshot {
                id,
                chain,
                dest_ip: dest.ip(),
                dest_port: dest.port(),
                domain,
                proto,
                state: ConnState::Open,
                opened_at_secs,
                bytes_tx: 0,
                bytes_rx: 0,
            },
        });

        id
    }

    /// Mark a flow as closed and record final byte counters.
    ///
    /// If `id` is not found (e.g. evicted under load), this is a no-op.
    pub fn record_close(&self, id: u64, bytes_tx: u64, bytes_rx: u64) {
        let mut g = self.inner.lock().expect("ConnectionRegistry lock poisoned");
        if let Some(e) = g.entries.iter_mut().rev().find(|e| e.snap.id == id) {
            e.snap.state = ConnState::Closed;
            e.snap.bytes_tx = bytes_tx;
            e.snap.bytes_rx = bytes_rx;
        }
    }

    /// Return a snapshot of all current entries (open and recently closed).
    pub fn snapshot(&self) -> Vec<ConnSnapshot> {
        let g = self.inner.lock().expect("ConnectionRegistry lock poisoned");
        g.entries.iter().map(|e| e.snap.clone()).collect()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience wrapper so callers can hold an `Arc<ConnectionRegistry>`.
pub type SharedConnRegistry = Arc<ConnectionRegistry>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port)
    }

    #[test]
    fn record_open_close_roundtrip() {
        let r = ConnectionRegistry::new();
        let id = r.record_open("chain-a".to_owned(), addr(443), Some("example.com".to_owned()), "tcp");
        let snaps = r.snapshot();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, id);
        assert_eq!(snaps[0].state, ConnState::Open);
        assert_eq!(snaps[0].domain.as_deref(), Some("example.com"));

        r.record_close(id, 1024, 4096);
        let snaps = r.snapshot();
        assert_eq!(snaps[0].state, ConnState::Closed);
        assert_eq!(snaps[0].bytes_tx, 1024);
        assert_eq!(snaps[0].bytes_rx, 4096);
    }

    #[test]
    fn domain_none_for_direct_ip() {
        let r = ConnectionRegistry::new();
        let id = r.record_open("chain-b".to_owned(), addr(80), None, "tcp");
        let snaps = r.snapshot();
        assert_eq!(snaps[0].id, id);
        assert!(snaps[0].domain.is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let r = ConnectionRegistry::new();
        // Fill to capacity
        for i in 0..MAX_CONNECTIONS {
            let id = r.record_open("c".to_owned(), addr(i as u16 + 1), None, "tcp");
            // Close every other one so eviction can prefer closed entries.
            if i % 2 == 0 {
                r.record_close(id, 0, 0);
            }
        }
        // Insert one more — should not panic and capacity stays bounded.
        r.record_open("c".to_owned(), addr(9999), None, "tcp");
        let g = r.inner.lock().unwrap();
        assert!(g.entries.len() <= MAX_CONNECTIONS);
    }
}
