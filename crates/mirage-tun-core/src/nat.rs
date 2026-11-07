//! Connection-tracking table for the userspace NAT path.
//!
//! Maps (src_addr, dst_addr, protocol) 5-tuple flows to tunnel pool slots.
//! Used by the [`InterceptStrategy::UserspaceNat`] path on Windows, macOS,
//! and mobile platforms where kernel-level `REDIRECT` is unavailable.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Identifies one bidirectional flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
}

/// State associated with a tracked flow.
#[derive(Debug, Clone)]
pub struct FlowState {
    /// Index into the tunnel pool that this flow is spliced to.
    pub tunnel_id: usize,
    /// When the flow was first seen.
    pub created: Instant,
    /// Last time a packet was seen on this flow.
    pub last_active: Instant,
}

/// Per-protocol connection tracking tables.
pub struct NatTable {
    tcp_flows: HashMap<FlowKey, FlowState>,
    udp_flows: HashMap<FlowKey, FlowState>,
}

impl NatTable {
    /// Create an empty NAT table.
    pub fn new() -> Self {
        Self {
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
        }
    }

    /// Record a new flow and associate it with `tunnel_id`.
    ///
    /// If an entry for the same key already exists it is replaced (the new
    /// tunnel assignment wins).
    pub fn track_new_flow(&mut self, key: FlowKey, tunnel_id: usize) {
        let now = Instant::now();
        let state = FlowState { tunnel_id, created: now, last_active: now };
        self.table_for_protocol_mut(key.protocol).insert(key, state);
    }

    /// Look up an existing flow.
    ///
    /// Updates [`FlowState::last_active`] on a hit and returns the tunnel id.
    /// Returns `None` when the flow is unknown.
    pub fn lookup_flow(&mut self, key: &FlowKey) -> Option<usize> {
        let table = self.table_for_protocol_mut(key.protocol);
        let state = table.get_mut(key)?;
        state.last_active = Instant::now();
        Some(state.tunnel_id)
    }

    /// Remove all flows that have been idle for longer than `timeout`.
    ///
    /// Returns the number of entries removed.
    pub fn expire_idle(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let before_tcp = self.tcp_flows.len();
        let before_udp = self.udp_flows.len();

        self.tcp_flows.retain(|_, s| now.duration_since(s.last_active) < timeout);
        self.udp_flows.retain(|_, s| now.duration_since(s.last_active) < timeout);

        (before_tcp - self.tcp_flows.len()) + (before_udp - self.udp_flows.len())
    }

    /// Total number of tracked flows (TCP + UDP).
    pub fn len(&self) -> usize {
        self.tcp_flows.len() + self.udp_flows.len()
    }

    /// Returns `true` when no flows are tracked.
    pub fn is_empty(&self) -> bool {
        self.tcp_flows.is_empty() && self.udp_flows.is_empty()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn table_for_protocol_mut(&mut self, protocol: u8) -> &mut HashMap<FlowKey, FlowState> {
        if protocol == 6 {
            &mut self.tcp_flows
        } else {
            // All non-TCP protocols (including UDP) share the udp_flows table.
            &mut self.udp_flows
        }
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src: &str, dst: &str, proto: u8) -> FlowKey {
        FlowKey {
            src_addr: src.parse().unwrap(),
            dst_addr: dst.parse().unwrap(),
            protocol: proto,
        }
    }

    #[test]
    fn track_and_lookup() {
        let mut table = NatTable::new();
        let k = key("10.0.85.2:12345", "8.8.8.8:53", 17);
        table.track_new_flow(k.clone(), 42);
        assert_eq!(table.lookup_flow(&k), Some(42));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn lookup_missing() {
        let mut table = NatTable::new();
        let k = key("10.0.85.2:1234", "1.1.1.1:443", 6);
        assert_eq!(table.lookup_flow(&k), None);
    }

    #[test]
    fn expire_idle_removes_stale() {
        let mut table = NatTable::new();
        let k = key("10.0.85.2:9999", "8.8.8.8:53", 17);
        table.track_new_flow(k.clone(), 0);
        // Expire immediately with zero timeout — every entry is stale.
        let removed = table.expire_idle(Duration::ZERO);
        assert_eq!(removed, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn replace_existing_flow() {
        let mut table = NatTable::new();
        let k = key("10.0.85.3:8080", "93.184.216.34:80", 6);
        table.track_new_flow(k.clone(), 1);
        table.track_new_flow(k.clone(), 7);
        assert_eq!(table.lookup_flow(&k), Some(7));
        assert_eq!(table.len(), 1);
    }
}
