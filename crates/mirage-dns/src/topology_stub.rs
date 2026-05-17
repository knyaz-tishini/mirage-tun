//! Wave 3 Step 3.3-partial — TUN DNS topology wire-in stub.
//!
//! **Wired in V8 (Wave 4, sub-item 4.5).**
//!
//! The per-flow `DnsRoutingHint.chain_id` is now populated at the DNS dispatch
//! point in `mirage2tun/crates/mirage-tun-windows/src/ipstack.rs`
//! (`udp_dns_loop`).  The DNS forwarding path has been replaced with
//! `mirage_core::dns::dns_forward_via_socks5` — a shared helper that both TUN
//! and the client-core `TopologyForwarder` can use without a cross-workspace dep.
//!
//! The `DnsRoutingHint` struct is retained here as a logging + observability
//! type.  Its `log_intent` method now records the chain_id-tagged dispatch
//! rather than a "pending" stub warning.

use tracing::debug;

/// Hint about which chain should handle DNS for a given intercepted packet.
///
/// Populated at packet-intercept time from the `PolicyEngine` decision.
/// In V8 this is always `Some(chain_id)` for proxied flows; `None` means
/// the bypass tier (no chain).
pub struct DnsRoutingHint {
    /// Chain that owns the intercepted flow.
    ///
    /// `None` → bypass tier (uses native/direct DNS).
    /// `Some(id)` → routed through the named chain's SOCKS5 port.
    pub chain_id: Option<String>,
    /// Hostname being resolved.
    pub name: String,
}

impl DnsRoutingHint {
    /// Log the chain-tagged DNS dispatch for observability.
    pub fn log_intent(&self) {
        match &self.chain_id {
            Some(id) => debug!(
                chain_id = %id,
                name = %self.name,
                "DNS dispatch: per-chain SOCKS5 (V8 wire-in active)"
            ),
            None => debug!(
                name = %self.name,
                "DNS dispatch: bypass tier (native DNS)"
            ),
        }
    }
}
