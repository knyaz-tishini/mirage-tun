/// macOS pf firewall — leak-proof traffic-adoption floor.
///
/// Rules are loaded into the `mirage` pf anchor to avoid interfering with
/// system rules in `/etc/pf.conf`. The anchor is flushed on deactivation.
///
/// This is the macOS equivalent of the Windows WFP block-all floor: route
/// priority (`0/1 + 128/1` via the utun peer, set up in routing.rs) CAPTURES
/// traffic into the tun, and this pf anchor ENFORCES that capture — any egress
/// that escaped the tun (stale more-specific route, IPv6 with no tun_peer_v6,
/// the route install/teardown window) is DROPPED by the floor instead of
/// leaking the real NIC IP. Loaded BEFORE routing (activate precedes
/// set_default_route) and flushed AFTER route restore (deactivate follows
/// restore_routes), so the floor guards every transition.
///
/// It is NOT a global `block drop all`: tun, relay egress, the bypass plane,
/// LAN/control link, link-local, multicast, DHCP and exempt ports are all
/// `pass quick` exempted, so the bypass plane, the opbox↔Mac control link and
/// any OTHER tun cluster's local traffic stay fully alive.
///
/// TCP is handled by mirage-tcpip-stack (smoltcp) — no rdr rule needed.
use crate::error::MacosTunError;
use mirage_tun_core::traits::{PlatformFirewall, PlatformExecutor, FlowProto, FlowKey, private::Sealed};
use mirage_tun_core::plane::{Plane, ProcessIdentity};
use std::net::IpAddr;
use tracing::{debug, info, warn};

const ANCHOR: &str = "mirage";
const PF_CONF_PATH: &str = "/tmp/mirage-pf.conf";

/// macOS pf firewall manager.
pub struct MacosFirewall {
    active: bool,
    /// Bypass-plane CIDRs that must `pass out` the real NIC even under the
    /// kill-switch (mirrors the per-relay pass rules). Set before `activate`.
    bypass_nets: Vec<String>,
    /// Full mode drops public egress that escaped the tun. Split mode leaves
    /// it alone: only the selected prefixes are routed into the tun.
    leak_floor: bool,
}

impl MacosFirewall {
    pub fn new() -> Self {
        MacosFirewall { active: false, bypass_nets: Vec::new(), leak_floor: true }
    }

    /// `false` is split mode: public traffic that is not routed into the tun
    /// must leave on the physical NIC, not die on the leak floor.
    pub fn set_leak_floor(&mut self, enabled: bool) {
        self.leak_floor = enabled;
    }

    /// Seed bypass-plane CIDRs (e.g. "1.0.0.1/32") — call before `activate` so
    /// the bypass plane gets unconditional `pass out` rules. These CIDRs egress the
    /// real NIC directly; all other non-relay traffic routes into the tun.
    pub fn set_bypass_nets(&mut self, nets: Vec<String>) {
        self.bypass_nets = nets;
    }

    /// Live update of bypass-plane CIDRs while the TUN is active.
    ///
    /// Replaces `self.bypass_nets` with `new_nets` then reloads the pf anchor via
    /// `pfctl -f` (the same mechanism as `activate()`). The reload is atomic at
    /// the kernel level — the old ruleset is replaced in one shot.
    ///
    /// `relay_addrs` and `tun_name` must be the values currently in use so the
    /// reload preserves relay and tun-interface exemptions already in the anchor.
    pub fn reload_bypass_nets(
        &mut self,
        new_nets: Vec<String>,
        relay_addrs: &[IpAddr],
        tun_name: &str,
    ) -> Result<(), MacosTunError> {
        self.bypass_nets = new_nets;
        self.activate(relay_addrs, tun_name, &[53])?;
        info!("pf anchor reloaded with updated bypass nets ({} CIDRs)", self.bypass_nets.len());
        Ok(())
    }

    /// Load the leak-floor WITHOUT the tun-interface exemption — the floor-first
    /// PRE-floor brought up BEFORE the utun device exists (Windows-WFP parity).
    /// Wire egress is already blocked here; bypass plane + relays + LAN/control +
    /// loopback stay alive, so a failure during utun open / ifconfig fails CLOSED
    /// (no real-NIC leak) and the bootstrap path survives. `activate` reloads the
    /// same anchor WITH the tun exemption once the device is up. Call
    /// `set_bypass_nets` before this.
    pub fn activate_prefloor(
        &mut self,
        relay_addrs: &[IpAddr],
        exempt_ports: &[u16],
    ) -> Result<(), MacosTunError> {
        let conf = build_pf_rules(relay_addrs, "", exempt_ports, &self.bypass_nets, self.leak_floor);
        debug!("pf pre-floor rules:\n{}", conf);
        std::fs::write(PF_CONF_PATH, &conf).map_err(MacosTunError::Io)?;
        run_pfctl_sync(&["-a", ANCHOR, "-f", PF_CONF_PATH])?;
        let _ = run_pfctl_sync(&["-e"]); // ok if already enabled
        self.active = true;
        info!("pf pre-floor activated (anchor: {}) — fail-closed before utun up", ANCHOR);
        Ok(())
    }
}

impl Default for MacosFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealed for MacosFirewall {}

impl PlatformFirewall for MacosFirewall {
    type Error = MacosTunError;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), Self::Error> {
        let conf = build_pf_rules(relay_addrs, tun_name, exempt_ports, &self.bypass_nets, self.leak_floor);
        debug!("pf rules:\n{}", conf);

        std::fs::write(PF_CONF_PATH, &conf).map_err(MacosTunError::Io)?;
        run_pfctl_sync(&["-a", ANCHOR, "-f", PF_CONF_PATH])?;
        let _ = run_pfctl_sync(&["-e"]); // ok if already enabled
        self.active = true;
        info!("pf firewall activated (anchor: {})", ANCHOR);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), Self::Error> {
        if !self.active {
            return Ok(());
        }
        if let Err(e) = run_pfctl_sync(&["-a", ANCHOR, "-F", "all"]) {
            warn!("pfctl flush anchor failed: {}", e);
        }
        let _ = std::fs::remove_file(PF_CONF_PATH);
        self.active = false;
        info!("pf firewall deactivated (anchor: {})", ANCHOR);
        Ok(())
    }
}

fn run_pfctl_sync(args: &[&str]) -> Result<(), MacosTunError> {
    let out = std::process::Command::new("pfctl")
        .args(args)
        .output()
        .map_err(MacosTunError::Io)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let code = out.status.code().unwrap_or(-1);
        return Err(MacosTunError::Pfctl { code, stderr });
    }
    Ok(())
}

fn build_pf_rules(
    relay_addrs: &[IpAddr],
    tun_name: &str,
    exempt_ports: &[u16],
    bypass_nets: &[String],
    leak_floor: bool,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "# Mirage VPN pf anchor — loaded into anchor \"{ANCHOR}\""
    ));
    // Bypass-safe posture — NO global block (the kill-switch is selective,
    // enforced at the accept loop). Bypass + relay pass rules are unconditional.
    lines.push(String::new());

    lines.push("set skip on lo0".to_string());
    lines.push(String::new());

    // The tun-interface exemption is skipped when tun_name is empty (the
    // floor-first PRE-floor loaded before the utun device exists).
    if !tun_name.is_empty() {
        lines.push(format!("pass quick on {tun_name} inet all keep state"));
        lines.push(format!("pass quick on {tun_name} inet6 all keep state"));
        lines.push(String::new());
    }

    for relay in relay_addrs {
        if relay.is_ipv6() {
            lines.push(format!("pass out quick inet6 proto {{tcp, udp}} to {relay} keep state"));
            lines.push(format!("pass in quick inet6 proto {{tcp, udp}} from {relay} keep state"));
        } else {
            lines.push(format!("pass out quick proto {{tcp, udp}} to {relay} keep state"));
            lines.push(format!("pass in quick proto {{tcp, udp}} from {relay} keep state"));
        }
    }
    lines.push(String::new());

    // Bypass-PLANE pass rules — these CIDRs egress the real NIC directly (their
    // routes go via the original gateway, set up in routing.rs). Unconditional:
    // bypass flows bypass the proxy entirely; wire flows still go through the tun.
    for cidr in bypass_nets {
        let is_v6 = cidr
            .split('/')
            .next()
            .and_then(|a| a.parse::<IpAddr>().ok())
            .map(|ip| ip.is_ipv6())
            .unwrap_or(false);
        if is_v6 {
            lines.push(format!("pass out quick inet6 proto {{tcp, udp}} to {cidr} keep state"));
        } else {
            lines.push(format!("pass out quick proto {{tcp, udp}} to {cidr} keep state"));
        }
    }
    if !bypass_nets.is_empty() {
        lines.push(String::new());
    }

    // ── Control / LAN / link-local / multicast — NEVER severed by the floor ──
    // Keeps the bypass plane (incl. the opbox↔Mac control link over the LAN),
    // DHCP, mDNS/ND, and ANY OTHER tun cluster's local traffic alive. RFC1918 +
    // link-local + multicast egress the real NIC unconditionally; the floor
    // below only drops escaped PUBLIC-internet wire traffic.
    lines.push("pass out quick to 10.0.0.0/8 keep state".to_string());
    lines.push("pass out quick to 172.16.0.0/12 keep state".to_string());
    lines.push("pass out quick to 192.168.0.0/16 keep state".to_string());
    lines.push("pass out quick to 169.254.0.0/16 keep state".to_string());
    lines.push("pass out quick to 224.0.0.0/4 keep state".to_string());
    lines.push("pass out quick inet6 to fe80::/10 keep state".to_string());
    lines.push("pass out quick inet6 to ff00::/8 keep state".to_string());
    lines.push(String::new());

    lines.push(
        "pass quick on egress proto {tcp,udp} from any port 67:68 to any port 67:68 keep state"
            .to_string(),
    );
    if !exempt_ports.is_empty() {
        let ports: Vec<String> = exempt_ports.iter().map(|p| p.to_string()).collect();
        let ports_str = ports.join(", ");
        lines.push(format!(
            "pass out quick proto {{tcp, udp}} to any port {{{ports_str}}} keep state"
        ));
    }
    lines.push(String::new());

    // ── LEAK-FLOOR (kernel-enforced fail-closed) ──────────────────────────────
    // Any egress NOT matched by an exempt `pass quick` above — i.e. wire traffic
    // that escaped capture into the tun (stale route, IPv6 with no tun_peer_v6,
    // route install/teardown window) — is DROPPED here, never leaked to the real
    // NIC. macOS equivalent of the Windows WFP block-all floor. `out inet/inet6
    // all` (NOT `on egress`, which would resolve to the utun once routes flip);
    // the `pass quick on {tun}` above exempts the captured path. The `inet6`
    // floor also closes the IPv6 capture gap: when tun_peer_v6 is unset and v6 is
    // not routed into the tun, v6 egress fails CLOSED instead of leaking.
    if leak_floor {
        lines.push("block drop out inet all".to_string());
        lines.push("block drop out inet6 all".to_string());
    }

    lines.join("\n") + "\n"
}

// ── T2: PlatformExecutor stub ─────────────────────────────────────────────────

impl PlatformExecutor for MacosFirewall {
    type Error = MacosTunError;

    /// Attribution is not available on macOS at T2 — returns None.
    /// T3 will attach NEAppProxyFlow source app signing IDs here.
    fn attribute(
        &self,
        _src_port: u16,
        _dst: std::net::SocketAddr,
        _proto: FlowProto,
    ) -> Option<ProcessIdentity> {
        None
    }

    /// T2: no-op — pf anchor handles coarse enforcement via activate().
    /// Per-process enforcement (NE framework app containers) is T3.
    /// `Plane::Group` must not reach here — caller resolves group first.
    fn enforce(
        &mut self,
        plane: &Plane,
        _identity: Option<&ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), MacosTunError> {
        if let Plane::Group(_) = plane {
            warn!(?flow, "enforce called with unresolved Group plane — bug in caller");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn pf_rules_have_leak_floor_with_exemptions() {
        let relay: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let rules = build_pf_rules(&[relay], "utun3", &[53], &[], true);
        // Kernel-enforced leak-floor: wire egress that escaped the tun is dropped,
        // never leaked to the real NIC (macOS equivalent of Windows WFP block-all).
        assert!(rules.contains("block drop out inet all"));
        assert!(rules.contains("block drop out inet6 all"));
        // NOT a global block-everything — that would sever the bypass plane.
        assert!(!rules.contains("block drop all"));
        // Exemptions must be `pass quick` so they win over the floor.
        assert!(rules.contains("pass quick on utun3 inet all"));
        assert!(rules.contains("pass quick on utun3 inet6 all"));
        assert!(rules.contains("pass out quick proto {tcp, udp} to 1.2.3.4 keep state")); // relay
        assert!(rules.contains("pass out quick to 192.168.0.0/16 keep state"));            // LAN/control
        assert!(rules.contains("pass out quick to 10.0.0.0/8 keep state"));
        assert!(rules.contains("pass out quick inet6 to fe80::/10 keep state"));           // v6 ND
        assert!(rules.contains("53")); // exempt port
        // lo0 skipped so loopback (control IPC) is never touched.
        assert!(rules.contains("set skip on lo0"));
    }

    #[test]
    fn pf_rules_v6_relay() {
        use std::net::Ipv6Addr;
        let relay_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let rules = build_pf_rules(&[relay_v6], "utun3", &[], &[], true);
        assert!(rules.contains("inet6 proto {tcp, udp} to 2001:db8::1"));
    }

    #[test]
    fn no_rdr_in_rules() {
        let relay: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let rules = build_pf_rules(&[relay], "utun3", &[53], &[], true);
        assert!(!rules.contains("rdr"));
    }

    #[test]
    fn bypass_cidrs_get_pass_out() {
        let relay: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let bypass = vec!["1.0.0.1/32".to_string(), "2001:db8::/32".to_string()];
        let rules = build_pf_rules(&[relay], "utun3", &[53], &bypass, true);
        // v4 bypass passes out (quick, above the floor); v6 bypass uses inet6.
        assert!(rules.contains("pass out quick proto {tcp, udp} to 1.0.0.1/32 keep state"));
        assert!(rules.contains("pass out quick inet6 proto {tcp, udp} to 2001:db8::/32 keep state"));
        // Floor present, but bypass exemptions sit above it (quick) — never severed.
        assert!(rules.contains("block drop out inet all"));
        assert!(!rules.contains("block drop all"));
    }
}
