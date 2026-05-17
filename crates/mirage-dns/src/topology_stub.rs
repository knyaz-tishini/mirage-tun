//! Wave 3 Step 3.3-partial — TUN DNS topology wire-in stub.
//!
//! The full per-flow `DnsTopology::resolve(name, chain_id, cache)` call
//! requires knowing which chain owns a given intercepted flow at packet-capture
//! time.  In Wave 3 the TUN router does not yet expose the chain_id for each
//! flow to the DNS layer.
//!
//! This stub records the integration point and logs intent.  Wave 4 will
//! replace it with a real `DnsTopology` dispatch by:
//! 1. Adding `mirage-core` as a workspace dep in `mirage2tun/Cargo.toml`.
//! 2. Passing the active `DnsTopology` down from the TUN manager into the
//!    DNS intercept path (mirage-tcpip-stack → mirage-dns).
//! 3. Replacing `DnsResolver::resolve` calls with
//!    `DnsTopology::resolve(name, Some(chain_id), &dns_cache)`.
//!
//! Callsites to update in Wave 4 (found during Wave 3 audit):
//! - `mirage2tun/crates/mirage-tcpip-stack/src/` — TCP/UDP intercept loop
//!   that dispatches to `DnsResolver`.  Exact file confirmed by audit below.
//! - `mirage2tun/crates/mirage-tun-windows/src/` — Windows-specific TUN
//!   manager that initialises `DnsResolver` from `DnsConfig`.

use tracing::warn;

/// Hint about which chain should handle DNS for a given intercepted packet.
///
/// Wave 3 only: the TUN layer does not yet propagate chain_id per-flow, so
/// `chain_id` is always `None` here and queries fall through to the existing
/// `DnsResolver` (which uses a single shared DoH backend).
pub struct DnsRoutingHint {
    /// Chain that owns the intercepted flow, if known.
    ///
    /// `None` means "not yet determined" — caller MUST fall back to the
    /// existing `DnsResolver` until Wave 4 wires this in.
    pub chain_id: Option<String>,
    /// Hostname being resolved.
    pub name: String,
}

impl DnsRoutingHint {
    /// Log the routing intent for observability.  In Wave 4 this becomes the
    /// actual `DnsTopology::resolve` dispatch.
    pub fn log_intent(&self) {
        match &self.chain_id {
            Some(id) => warn!(
                chain_id = %id,
                name = %self.name,
                "DNS topology stub: would resolve via per-chain DoH backend (Wave 4 wire-in pending)"
            ),
            None => warn!(
                name = %self.name,
                "DNS topology stub: chain_id unknown, using shared DnsResolver (Wave 4 pending)"
            ),
        }
    }
}
