/// macOS routing management.
///
/// Uses the `route` command (BSD routing socket API) to:
/// - Save the original default gateway before tunnel is active.
/// - Override the default route via two /1 routes through the TUN interface.
/// - Add host routes for relay addresses through the original gateway.
/// - Restore all routes on teardown.
use crate::error::MacosTunError;
use async_trait::async_trait;
use mirage_tun_core::traits::{PlatformRouting, private::Sealed};
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// macOS routing state.
pub struct MacosRouting {
    /// Original IPv4 default gateway saved before we override it.
    original_gateway: Option<IpAddr>,
    /// Original IPv6 default gateway.
    original_v6_gateway: Option<IpAddr>,
    /// Relay (VPN server) addresses added as bypass host routes (v4 + v6).
    bypassed_hosts: Vec<IpAddr>,
    /// Bypass-PLANE CIDRs (e.g. "1.0.0.1/32", "10.0.0.0/8") routed via the
    /// original gateway so the operator's "байпас канал" egresses the real NIC
    /// instead of the TUN. Installed as `route add -net <cidr> <gw>` before the
    /// /1 default-via-tun overrides. Distinct from `bypassed_hosts` (exact relay
    /// IPs) — these are operator-configured network ranges from Bypass policy rules.
    bypassed_nets: Vec<String>,
    /// TUN interface name (set when `set_default_route` is called).
    tun_name: Option<String>,
    /// TUN IPv4 peer IP (gateway to use for IPv4 default route).
    tun_peer: Option<IpAddr>,
    /// TUN IPv6 peer IP (gateway to use for IPv6 default route).
    tun_peer_v6: Option<IpAddr>,
    /// Whether IPv6 /1 default routes have been installed.
    v6_default_set: bool,
}

impl MacosRouting {
    pub fn new() -> Self {
        MacosRouting {
            original_gateway: None,
            original_v6_gateway: None,
            bypassed_hosts: Vec::new(),
            bypassed_nets: Vec::new(),
            tun_name: None,
            tun_peer: None,
            tun_peer_v6: None,
            v6_default_set: false,
        }
    }

    /// Set the TUN IPv4 peer IP — must be called before `set_default_route`.
    pub fn set_tun_peer(&mut self, peer: IpAddr) {
        self.tun_peer = Some(peer);
    }

    /// Seed the bypass-plane CIDRs — must be called before `set_default_route`
    /// so they're installed (via the original gateway) ahead of the /1 overrides.
    pub fn set_bypass_nets(&mut self, nets: Vec<String>) {
        self.bypassed_nets = nets;
    }

    /// Set the TUN IPv6 address (the address assigned to the utun interface, not a peer).
    /// Used as the nexthop for the v6 /1 default routes.
    pub fn set_tun_peer_v6(&mut self, peer: IpAddr) {
        self.tun_peer_v6 = Some(peer);
    }
}

impl Default for MacosRouting {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealed for MacosRouting {}

#[async_trait]
impl PlatformRouting for MacosRouting {
    type Error = MacosTunError;

    async fn set_default_route(&mut self, tun_name: &str) -> Result<(), Self::Error> {
        // ── IPv4 ──────────────────────────────────────────────────────────────
        let gw = get_default_gateway_v4().await?;
        info!("original IPv4 gateway: {}", gw);
        self.original_gateway = Some(gw);
        self.tun_name = Some(tun_name.to_string());

        // Bypass routes for relay addresses through the original gateway —
        // must be installed BEFORE we add the /1 overrides.
        for relay in self.bypassed_hosts.clone() {
            if relay.is_ipv4() {
                if let Err(e) = add_host_route_v4(relay, gw).await {
                    warn!("bypass host route v4 {} failed: {}", relay, e);
                }
            }
        }

        // Bypass-PLANE v4 CIDRs via the original gateway — installed BEFORE the
        // /1 overrides so they're more-specific than default-via-tun → egress NIC.
        for cidr in self.bypassed_nets.clone() {
            if cidr_is_v6(&cidr) {
                continue;
            }
            if let Err(e) = add_net_route(&cidr, gw, false).await {
                warn!("bypass net route v4 {} failed: {}", cidr, e);
            } else {
                info!("bypass-plane v4 net {} via {}", cidr, gw);
            }
        }

        let peer = self.tun_peer.ok_or_else(|| MacosTunError::GatewayParse(
            "tun_peer must be set before set_default_route on macOS".into()
        ))?;
        run_route(&["add", "-net", "0.0.0.0/1", &peer.to_string()]).await?;
        run_route(&["add", "-net", "128.0.0.0/1", &peer.to_string()]).await?;
        info!("IPv4 default route via {} peer={} (0/1 + 128/1 trick)", tun_name, peer);

        // ── IPv6 (best-effort) ────────────────────────────────────────────────
        // Save host's original IPv6 gateway if any (for bypass + restore).
        match get_default_gateway_v6().await {
            Ok(gw6) => {
                info!("original IPv6 gateway: {}", gw6);
                self.original_v6_gateway = Some(gw6);
                for relay in self.bypassed_hosts.clone() {
                    if relay.is_ipv6() {
                        if let Err(e) = add_host_route_v6(relay, gw6).await {
                            warn!("bypass host route v6 {} failed: {}", relay, e);
                        }
                    }
                }
                // Bypass-PLANE v6 CIDRs via the original v6 gateway.
                for cidr in self.bypassed_nets.clone() {
                    if !cidr_is_v6(&cidr) {
                        continue;
                    }
                    if let Err(e) = add_net_route(&cidr, gw6, true).await {
                        warn!("bypass net route v6 {} failed: {}", cidr, e);
                    } else {
                        info!("bypass-plane v6 net {} via {}", cidr, gw6);
                    }
                }
            }
            Err(e) => {
                info!("no native IPv6 default gateway ({}); v6 traffic will only flow through tun", e);
            }
        }

        // Install ::/1 + 8000::/1 via tun even when host has no native v6 —
        // exit node may have v6 and clients should reach v6 destinations
        // through the tunnel regardless of local-network capability.
        if let Some(peer6) = self.tun_peer_v6 {
            let peer6_str = peer6.to_string();
            let r1 = run_route(&["add", "-inet6", "-net", "::/1", &peer6_str]).await;
            let r2 = run_route(&["add", "-inet6", "-net", "8000::/1", &peer6_str]).await;
            match (r1, r2) {
                (Ok(_), Ok(_)) => {
                    self.v6_default_set = true;
                    info!("IPv6 default route via {} peer={} (::/1 + 8000::/1)", tun_name, peer6);
                }
                (Err(e), _) | (_, Err(e)) => warn!("IPv6 default route failed (non-fatal): {}", e),
            }
        } else {
            info!("no tun_peer_v6 configured; skipping IPv6 default route override");
        }

        Ok(())
    }

    async fn restore_routes(&mut self) -> Result<(), Self::Error> {
        let tun_name = match &self.tun_name {
            Some(n) => n.clone(),
            None => return Ok(()),
        };

        // Delete IPv4 /1 override routes
        for net in &["0.0.0.0/1", "128.0.0.0/1"] {
            match run_route(&["delete", "-net", net]).await {
                Ok(()) => {}
                Err(e) => warn!("delete route {} failed: {}", net, e),
            }
        }

        // Delete IPv6 /1 override routes
        if self.v6_default_set {
            for net in &["::/1", "8000::/1"] {
                match run_route(&["delete", "-inet6", "-net", net]).await {
                    Ok(()) => {}
                    Err(e) => warn!("delete inet6 route {} failed: {}", net, e),
                }
            }
            self.v6_default_set = false;
        }

        let _ = tun_name;

        // Remove bypass host routes
        for relay in self.bypassed_hosts.drain(..) {
            if relay.is_ipv4() {
                if let Some(gw) = self.original_gateway {
                    match run_route(&["delete", "-host", &relay.to_string(), &gw.to_string()]).await {
                        Ok(()) => {}
                        Err(e) => warn!("delete host route v4 {} failed: {}", relay, e),
                    }
                }
            } else if relay.is_ipv6() {
                if let Some(gw6) = self.original_v6_gateway {
                    match run_route(&["delete", "-inet6", "-host", &relay.to_string(), &gw6.to_string()]).await {
                        Ok(()) => {}
                        Err(e) => warn!("delete host route v6 {} failed: {}", relay, e),
                    }
                }
            }
        }

        // Remove bypass-plane net routes
        for cidr in self.bypassed_nets.drain(..) {
            let v6 = cidr_is_v6(&cidr);
            if let Err(e) = del_net_route(&cidr, v6).await {
                warn!("delete bypass net route {} failed: {}", cidr, e);
            }
        }

        self.original_gateway = None;
        self.original_v6_gateway = None;
        self.tun_name = None;
        info!("routes restored");
        Ok(())
    }

    async fn add_bypass_host(&mut self, addr: IpAddr) -> Result<(), Self::Error> {
        self.bypassed_hosts.push(addr);

        // If the default route is already overridden, install the bypass route now.
        if addr.is_ipv4() {
            if let Some(gw) = self.original_gateway {
                add_host_route_v4(addr, gw).await?;
            }
        } else if addr.is_ipv6() {
            if let Some(gw6) = self.original_v6_gateway {
                add_host_route_v6(addr, gw6).await?;
            }
        }
        Ok(())
    }

    fn original_gateway(&self) -> Option<IpAddr> {
        self.original_gateway
    }
}

/// Read the IPv4 default gateway IP from `route -n get default`.
async fn get_default_gateway_v4() -> Result<IpAddr, MacosTunError> {
    use tokio::process::Command;

    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .await
        .map_err(MacosTunError::Io)?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    debug!("route get default output:\n{}", stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            let gw_str = line["gateway:".len()..].trim();
            return gw_str
                .parse::<IpAddr>()
                .map_err(|_| MacosTunError::GatewayParse(gw_str.to_string()));
        }
    }

    Err(MacosTunError::GatewayParse(
        "gateway line not found in route output".to_string(),
    ))
}

/// Read the IPv6 default gateway IP from `route -n get -inet6 default`.
async fn get_default_gateway_v6() -> Result<IpAddr, MacosTunError> {
    use tokio::process::Command;

    let out = Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output()
        .await
        .map_err(MacosTunError::Io)?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    debug!("route -inet6 get default output:\n{}", stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            let gw_str = line["gateway:".len()..].trim();
            return gw_str
                .parse::<IpAddr>()
                .map_err(|_| MacosTunError::GatewayParse(format!("v6 gateway: {gw_str}")));
        }
    }

    Err(MacosTunError::GatewayParse(
        "no IPv6 default gateway found".to_string(),
    ))
}

/// True if the network part of `cidr` ("addr/prefix") parses as IPv6.
fn cidr_is_v6(cidr: &str) -> bool {
    cidr.split('/')
        .next()
        .and_then(|a| a.parse::<IpAddr>().ok())
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
}

/// Decide route form for a CIDR: a /32 (v4) or /128 (v6) MUST use the `-host`
/// form, otherwise `-net`. macOS stores a `route add -net 1.2.3.4/32` AS a host
/// route, but `route delete -net 1.2.3.4/32` then does NOT match it → the route
/// leaks on teardown (the stale-1.1.1.1 bug). Using host form symmetrically on
/// add+delete fixes it. Returns (route_kind_flag, target_string).
fn route_form(cidr: &str) -> (&'static str, String) {
    if let Some((addr, prefix)) = cidr.split_once('/') {
        if let Ok(p) = prefix.parse::<u32>() {
            let is_v6 = addr.parse::<IpAddr>().map(|i| i.is_ipv6()).unwrap_or(false);
            let host_prefix = if is_v6 { 128 } else { 32 };
            if p == host_prefix {
                return ("-host", addr.to_string());
            }
        }
        ("-net", cidr.to_string())
    } else {
        ("-host", cidr.to_string())
    }
}

/// Add a route for `cidr` (e.g. "1.0.0.1/32", "10.0.0.0/8") via `gateway`.
/// `v6` selects the `-inet6` family. /32 + /128 use `-host` (see `route_form`).
async fn add_net_route(cidr: &str, gateway: IpAddr, v6: bool) -> Result<(), MacosTunError> {
    let (kind, target) = route_form(cidr);
    if v6 {
        run_route(&["add", "-inet6", kind, &target, &gateway.to_string()]).await
    } else {
        run_route(&["add", kind, &target, &gateway.to_string()]).await
    }
}

/// Delete a previously-installed bypass route (symmetric host/net form).
async fn del_net_route(cidr: &str, v6: bool) -> Result<(), MacosTunError> {
    let (kind, target) = route_form(cidr);
    if v6 {
        run_route(&["delete", "-inet6", kind, &target]).await
    } else {
        run_route(&["delete", kind, &target]).await
    }
}

/// Add an IPv4 host route for `addr` via `gateway`.
async fn add_host_route_v4(addr: IpAddr, gateway: IpAddr) -> Result<(), MacosTunError> {
    run_route(&["add", "-host", &addr.to_string(), &gateway.to_string()]).await
}

/// Add an IPv6 host route for `addr` via `gateway`.
async fn add_host_route_v6(addr: IpAddr, gateway: IpAddr) -> Result<(), MacosTunError> {
    run_route(&["add", "-inet6", "-host", &addr.to_string(), &gateway.to_string()]).await
}

/// Run `route` with the given arguments, capturing output.
async fn run_route(args: &[&str]) -> Result<(), MacosTunError> {
    use tokio::process::Command;

    let out = Command::new("route")
        .args(args)
        .output()
        .await
        .map_err(MacosTunError::Io)?;

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    debug!("route {:?}: stdout={} stderr={}", args, stdout.trim(), stderr.trim());

    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        return Err(MacosTunError::Route { code, stderr });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_initial_state() {
        let r = MacosRouting::new();
        assert!(r.original_gateway().is_none());
    }
}
