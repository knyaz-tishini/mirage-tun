use std::net::{IpAddr, Ipv6Addr};
use tracing::{debug, info, warn};
use crate::error::{Result, TunError};

/// A hole in the routing: a prefix that leaves the machine the way it
/// always did, while the tunnel holds the default route.
///
/// The hole is a route, not a rule: the prefix points at the gateway the
/// machine had before the tunnel took the default, so the packets of that
/// prefix never reach the adapter at all.
#[derive(Debug, Clone)]
pub struct BypassHole {
    /// The prefix, in CIDR form.
    pub cidr: String,
    /// The interface the hole points at.
    pub if_index: u32,
    /// The gateway the hole points at, when there is one.
    pub gateway: Option<String>,
}

pub struct Routing {
    original_gateway: Option<String>,
    original_interface_idx: Option<u32>,
    original_v6_gateway: Option<String>,
    original_v6_interface_idx: Option<u32>,
    bypass_routes: Vec<String>,
    bypass_v6_routes: Vec<String>,
    /// The holes the person asked for: the prefixes whose route points at
    /// the real gateway.
    bypass_holes: Vec<BypassHole>,
    tun_default_set: bool,
    tun_v6_default_set: bool,
    /// Whether the adapter carries an IPv6 address of its own.
    ///
    /// The IPv6 half-routes point the host's IPv6 into the adapter, so
    /// they belong only to an adapter that has an IPv6 address: a route
    /// into an adapter without one would black-hole that traffic.
    ipv6_enabled: bool,
    tun_name: String,
}

impl Routing {
    pub fn new(tun_name: impl Into<String>) -> Self {
        Self {
            original_gateway: None,
            original_interface_idx: None,
            original_v6_gateway: None,
            original_v6_interface_idx: None,
            bypass_routes: Vec::new(),
            bypass_v6_routes: Vec::new(),
            bypass_holes: Vec::new(),
            tun_default_set: false,
            tun_v6_default_set: false,
            ipv6_enabled: false,
            tun_name: tun_name.into(),
        }
    }

    /// Say whether the adapter carries an IPv6 address.
    pub fn set_ipv6_enabled(&mut self, enabled: bool) {
        self.ipv6_enabled = enabled;
    }

    pub fn original_gateway(&self) -> Option<&str> {
        self.original_gateway.as_deref()
    }

    pub fn original_interface_idx(&self) -> Option<u32> {
        self.original_interface_idx
    }

    pub async fn set_default_route(&mut self) -> Result<()> {
        // IPv4
        if let Some((gw, idx)) = read_default_gateway_v4().await {
            self.original_interface_idx = Some(idx);
            self.original_gateway = Some(gw);
        }
        info!(
            gateway = ?self.original_gateway,
            if_idx = ?self.original_interface_idx,
            "Routing: saved original IPv4 default gateway"
        );
        if self.original_gateway.is_none() {
            warn!("Routing: could not detect original IPv4 gateway — bypass routes will NOT work");
        }

        // IPv6
        if let Some((gw6, idx6)) = read_default_gateway_v6().await {
            self.original_v6_interface_idx = Some(idx6);
            self.original_v6_gateway = Some(gw6);
        }
        info!(
            v6_gateway = ?self.original_v6_gateway,
            v6_if_idx = ?self.original_v6_interface_idx,
            "Routing: saved original IPv6 default gateway"
        );

        let tun_name = self.tun_name.clone();

        // Set interface metric to 1 so total metric (route + iface) beats amnezia
        if let Err(e) = run_netsh_route(&[
            "interface", "ipv4", "set", "interface",
            &tun_name,
            "metric=1",
        ]).await {
            warn!("failed to set IPv4 interface metric (non-fatal): {e}");
        }

        let iface = format!("interface={tun_name}");

        // IPv4 half-routes
        let args0 = ["interface", "ipv4", "add", "route", "0.0.0.0/1", iface.as_str(), "metric=1", "store=active"];
        let args1 = ["interface", "ipv4", "add", "route", "128.0.0.0/1", iface.as_str(), "metric=1", "store=active"];
        tokio::try_join!(
            run_netsh_route(&args0),
            run_netsh_route(&args1)
        )?;
        self.tun_default_set = true;
        info!(tun_name, "Routing: IPv4 default route set via TUN");

        // IPv6 half-routes (best-effort - the host may have no IPv6 at all).
        // They go in only when the adapter carries an IPv6 address: a
        // route into an adapter without one would black-hole the host's
        // IPv6.  route.exe has no IPv6 mode, so netsh is the only way.
        if self.ipv6_enabled {
            let args2 = ["interface", "ipv6", "add", "route", "::/1", iface.as_str(), "metric=1", "store=active"];
            let args3 = ["interface", "ipv6", "add", "route", "8000::/1", iface.as_str(), "metric=1", "store=active"];
            match tokio::try_join!(run_netsh_route(&args2), run_netsh_route(&args3)) {
                Ok(_) => {
                    self.tun_v6_default_set = true;
                    info!(tun_name, "Routing: IPv6 default route set via TUN");
                }
                Err(e) => warn!(
                    "Routing: IPv6 default route via TUN failed (non-fatal, the host keeps its native IPv6 routes): {e}"
                ),
            }
        } else {
            debug!("Routing: IPv6 half-routes skipped - the adapter carries no IPv6 address");
        }

        Ok(())
    }

    pub fn restore_routes_sync(&mut self) {
        // Close the holes: the prefixes the person excluded go back to the
        // tunnel.  The hole was drilled through the real interface, so it is
        // closed the same way.
        for hole in self.bypass_holes.drain(..) {
            close_hole_sync(&hole);
        }

        // Remove IPv4 bypass host routes
        for addr in self.bypass_routes.drain(..) {
            let _ = std::process::Command::new("route")
                .args(["delete", &addr, "mask", "255.255.255.255"])
                .output();
        }

        // Remove IPv6 bypass host routes
        let name = &self.tun_name;
        for addr in self.bypass_v6_routes.drain(..) {
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route",
                       &format!("{addr}/128"),
                       &format!("interface={name}"),
                       "store=active"])
                .output();
        }

        if self.tun_default_set {
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "0.0.0.0/1",
                       &format!("interface={name}"), "store=active"])
                .output();
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "128.0.0.0/1",
                       &format!("interface={name}"), "store=active"])
                .output();
            self.tun_default_set = false;
        }

        if self.tun_v6_default_set {
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", "::/1",
                       &format!("interface={name}"), "store=active"])
                .output();
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", "8000::/1",
                       &format!("interface={name}"), "store=active"])
                .output();
            self.tun_v6_default_set = false;
        }

        info!("Routing: routes restored (sync)");
    }

    pub async fn add_bypass(&mut self, addr: IpAddr) -> Result<()> {        match addr {
            IpAddr::V4(_) => self.add_bypass_v4(addr).await,
            IpAddr::V6(_) => self.add_bypass_v6(addr).await,
        }
    }

    /// A hole for a whole network: every address in the prefix leaves the
    /// machine the way it always did.
    ///
    /// The adapter takes every packet when the tunnel is up, so the only way
    /// out for the destinations the person excluded is a ROUTE — the prefix
    /// points at the gateway the machine had before the tunnel took the
    /// default, and those packets never reach the adapter at all.
    ///
    /// A bare address is a host route: the same hole, one address wide.
    pub async fn add_bypass_cidr(&mut self, cidr: &str) -> Result<()> {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            return Ok(());
        }
        let gateway = match self.original_gateway.clone() {
            Some(gw) => gw,
            None => {
                warn!(cidr, "Routing: no original IPv4 gateway; bypass hole NOT added");
                return Ok(());
            }
        };
        let if_index = self.original_interface_idx.unwrap_or(0);
        let hole = drill_hole(cidr, Some(&gateway), if_index).await?;
        info!(cidr = %hole.cidr, gateway = %gateway, if_index, "Routing: IPv4 bypass hole added");
        self.bypass_holes.push(hole);
        Ok(())
    }

    /// The holes that were drilled, as they stand.
    pub fn bypass_holes(&self) -> Vec<BypassHole> {
        self.bypass_holes.clone()
    }

    async fn add_bypass_v4(&mut self, addr: IpAddr) -> Result<()> {
        let addr_str = addr.to_string();
        let prefix = format!("{addr_str}/32");
        let if_idx = self.original_interface_idx.unwrap_or(0);

        info!(
            %addr,
            gateway = ?self.original_gateway,
            if_idx,
            "Routing: adding IPv4 bypass route for relay addr"
        );

        if let Some(ref gw) = self.original_gateway.clone() {
            if if_idx > 0 {
                let if_idx_str = if_idx.to_string();
                let result = run_netsh_route(&[
                    "interface", "ipv4", "add", "route",
                    &prefix,
                    &format!("interface={if_idx_str}"),
                    &format!("nexthop={gw}"),
                    "metric=1",
                    "store=active",
                ]).await;
                match &result {
                    Ok(()) => info!(%addr, gateway = %gw, if_idx, "Routing: IPv4 bypass route added via netsh"),
                    Err(e) => {
                        warn!(%addr, gateway = %gw, if_idx, "Routing: netsh IPv4 bypass failed ({e}), falling back to route.exe");
                        let idx_str = if_idx.to_string();
                        run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1", "IF", &idx_str]).await?;
                        info!(%addr, gateway = %gw, if_idx, "Routing: IPv4 bypass route added via route.exe fallback");
                    }
                }
            } else {
                warn!(%addr, gateway = %gw, "Routing: no interface index, using route.exe without IF");
                run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1"]).await?;
                info!(%addr, gateway = %gw, "Routing: IPv4 bypass route added via route.exe (no IF)");
            }
        } else {
            warn!(%addr, "Routing: no original IPv4 gateway saved; bypass route NOT added");
        }
        self.bypass_routes.push(addr_str);
        Ok(())
    }

    async fn add_bypass_v6(&mut self, addr: IpAddr) -> Result<()> {
        let addr_str = addr.to_string();
        let prefix = format!("{addr_str}/128");
        let if_idx = self.original_v6_interface_idx.unwrap_or(0);

        info!(
            %addr,
            v6_gateway = ?self.original_v6_gateway,
            if_idx,
            "Routing: adding IPv6 bypass route for relay addr"
        );

        if let Some(ref gw) = self.original_v6_gateway.clone() {
            if if_idx > 0 {
                let if_idx_str = if_idx.to_string();
                match run_netsh_route(&[
                    "interface", "ipv6", "add", "route",
                    &prefix,
                    &format!("interface={if_idx_str}"),
                    &format!("nexthop={gw}"),
                    "metric=1",
                    "store=active",
                ]).await {
                    Ok(()) => info!(%addr, gateway = %gw, if_idx, "Routing: IPv6 bypass route added"),
                    Err(e) => warn!(%addr, "Routing: IPv6 bypass route failed: {e}"),
                }
            } else {
                warn!(%addr, "Routing: no IPv6 interface index");
            }
        } else {
            warn!(%addr, "Routing: no original IPv6 gateway; IPv6 bypass NOT added — relay may loop through TUN");
        }
        self.bypass_v6_routes.push(addr_str);
        Ok(())
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        if self.tun_default_set || self.tun_v6_default_set
            || !self.bypass_routes.is_empty() || !self.bypass_v6_routes.is_empty()
        {
            self.restore_routes_sync();
        }
    }
}

/// The address and the prefix length of a CIDR.
///
/// A bare address is a host route: its prefix is the whole address space.
pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let cidr = cidr.trim();
    let (addr, prefix) = match cidr.split_once('/') {
        Some((addr, prefix)) => {
            let prefix = prefix.trim().parse::<u8>().map_err(|e| {
                TunError::Routing(format!("bad prefix length in '{cidr}': {e}"))
            })?;
            (addr.trim(), prefix)
        }
        None => {
            let ip = cidr.parse::<IpAddr>().map_err(|e| {
                TunError::Routing(format!("bad address in '{cidr}': {e}"))
            })?;
            let length = if ip.is_ipv4() { 32 } else { 128 };
            return Ok((ip, length));
        }
    };
    let ip = addr.parse::<IpAddr>().map_err(|e| {
        TunError::Routing(format!("bad address in '{cidr}': {e}"))
    })?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(TunError::Routing(format!(
            "prefix length {prefix} does not fit '{cidr}'"
        )));
    }
    Ok((ip, prefix))
}

/// The mask of a prefix length, as route.exe wants it.
fn v4_mask(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

/// The route is already there: the hole is drilled, whoever drilled it.
///
/// A device that was killed instead of stopped leaves its holes in the
/// routing.  The next device must take them over -- otherwise the hole is
/// never tracked, never permitted by the kill-switch and never closed.
fn already_exists(err: &TunError) -> bool {
    let text = err.to_string().to_lowercase();
    text.contains("already exists") || text.contains("object already exists")
}

/// Drill a hole: the prefix leaves the machine through the real gateway.
///
/// This is the whole bypass: a route that is more specific than the
/// tunnel's default, so the packets of that prefix never reach the
/// adapter.  The application sees the machine it has always seen, and the
/// destination sees the application itself.
pub async fn drill_hole(
    cidr: &str,
    gateway: Option<&str>,
    if_index: u32,
) -> Result<BypassHole> {
    let (addr, prefix) = parse_cidr(cidr)?;
    match addr {
        IpAddr::V4(_) => {
            let Some(gw) = gateway else {
                warn!(cidr, "Routing: no IPv4 gateway; the hole was NOT drilled");
                return Err(TunError::Routing(format!(
                    "no IPv4 gateway for the hole of {cidr}"
                )));
            };
            let prefix_text = format!("{addr}/{prefix}");
            if if_index > 0 {
                let idx = if_index.to_string();
                let result = run_netsh_route(&[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &prefix_text,
                    &format!("interface={idx}"),
                    &format!("nexthop={gw}"),
                    "metric=1",
                    "store=active",
                ])
                .await;
                if let Err(e) = result {
                    if already_exists(&e) {
                        info!(cidr = %prefix_text, "Routing: the hole was already there");
                    } else {
                        warn!(cidr, error = %e, "Routing: netsh refused the hole; trying route.exe");
                        let mask = v4_mask(prefix);
                        let fallback = run_route(&[
                            "add",
                            &addr.to_string(),
                            "mask",
                            &mask,
                            gw,
                            "METRIC",
                            "1",
                            "IF",
                            &idx,
                        ])
                        .await;
                        if let Err(e) = fallback {
                            if already_exists(&e) {
                                info!(cidr = %prefix_text, "Routing: the hole was already there");
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }
            } else {
                let mask = v4_mask(prefix);
                let result = run_route(&[
                    "add",
                    &addr.to_string(),
                    "mask",
                    &mask,
                    gw,
                    "METRIC",
                    "1",
                ])
                .await;
                if let Err(e) = result {
                    if !already_exists(&e) {
                        return Err(e);
                    }
                    info!(cidr = %prefix_text, "Routing: the hole was already there");
                }
            }
            info!(cidr = %prefix_text, gateway = %gw, if_index, "Routing: the hole is drilled");
            Ok(BypassHole {
                cidr: prefix_text,
                if_index,
                gateway: Some(gw.to_owned()),
            })
        }
        IpAddr::V6(_) => {
            let prefix_text = format!("{addr}/{prefix}");
            let Some(gw) = gateway else {
                warn!(cidr, "Routing: no IPv6 gateway; the hole was NOT drilled");
                return Err(TunError::Routing(format!(
                    "no IPv6 gateway for the hole of {cidr}"
                )));
            };
            let idx = if_index.to_string();
            let result = run_netsh_route(&[
                "interface",
                "ipv6",
                "add",
                "route",
                &prefix_text,
                &format!("interface={idx}"),
                &format!("nexthop={gw}"),
                "metric=1",
                "store=active",
            ])
            .await;
            if let Err(e) = result {
                if !already_exists(&e) {
                    return Err(e);
                }
                info!(cidr = %prefix_text, "Routing: the hole was already there");
            }
            info!(cidr = %prefix_text, gateway = %gw, if_index, "Routing: the IPv6 hole is drilled");
            Ok(BypassHole {
                cidr: prefix_text,
                if_index,
                gateway: Some(gw.to_owned()),
            })
        }
    }
}

/// Close a hole: the prefix goes back to the tunnel.
pub fn close_hole(hole: &BypassHole) {
    close_hole_sync(hole);
}

/// Close a hole without the async runtime.
pub fn close_hole_sync(hole: &BypassHole) {
    let Ok((addr, prefix)) = parse_cidr(&hole.cidr) else {
        return;
    };
    let idx = hole.if_index.to_string();
    let interface = format!("interface={idx}");
    match addr {
        IpAddr::V4(_) => {
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &hole.cidr,
                    &interface,
                    "store=active",
                ])
                .output();
            let mask = v4_mask(prefix);
            let _ = std::process::Command::new("route")
                .args(["delete", &addr.to_string(), "mask", &mask])
                .output();
        }
        IpAddr::V6(_) => {
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "delete",
                    "route",
                    &hole.cidr,
                    &interface,
                    "store=active",
                ])
                .output();
        }
    }
    info!(cidr = %hole.cidr, "Routing: the hole is closed");
}

/// Stateless host-route bypass — used by the peer-LM watcher to additively
/// extend the bypass set without owning a `Routing` instance.  Mirrors
/// `Routing::add_bypass_*` but uses the gateway / interface_index passed by
/// the caller (`ServiceState`).
///
/// `gateway` may be `None`, in which case a route.exe fallback (no IF) is
/// attempted; if the OS is unable to resolve a gateway, the call returns Ok
/// without doing anything (matches existing v4 fallback behaviour).
pub async fn add_runtime_bypass(
    addr: IpAddr,
    gateway: Option<&str>,
    if_index: u32,
) -> Result<()> {
    match addr {
        IpAddr::V4(_) => add_runtime_bypass_v4(addr, gateway, if_index).await,
        IpAddr::V6(_) => add_runtime_bypass_v6(addr, gateway, if_index).await,
    }
}

async fn add_runtime_bypass_v4(addr: IpAddr, gateway: Option<&str>, if_index: u32) -> Result<()> {
    let addr_str = addr.to_string();
    let prefix = format!("{addr_str}/32");
    info!(%addr, gateway, if_index, "Routing(runtime): adding IPv4 bypass route");

    let Some(gw) = gateway else {
        warn!(%addr, "Routing(runtime): no IPv4 gateway; bypass NOT added");
        return Ok(());
    };

    if if_index > 0 {
        let if_idx_str = if_index.to_string();
        let result = run_netsh_route(&[
            "interface", "ipv4", "add", "route",
            &prefix,
            &format!("interface={if_idx_str}"),
            &format!("nexthop={gw}"),
            "metric=1",
            "store=active",
        ])
        .await;
        match &result {
            Ok(()) => info!(%addr, gateway = %gw, if_index, "Routing(runtime): IPv4 bypass added via netsh"),
            Err(e) => {
                warn!(%addr, gateway = %gw, if_index, "Routing(runtime): netsh failed ({e}), falling back to route.exe");
                run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1", "IF", &if_idx_str]).await?;
                info!(%addr, gateway = %gw, "Routing(runtime): IPv4 bypass added via route.exe fallback");
            }
        }
    } else {
        run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1"]).await?;
        info!(%addr, gateway = %gw, "Routing(runtime): IPv4 bypass added via route.exe (no IF)");
    }
    Ok(())
}

async fn add_runtime_bypass_v6(addr: IpAddr, gateway: Option<&str>, if_index: u32) -> Result<()> {
    let addr_str = addr.to_string();
    let prefix = format!("{addr_str}/128");
    info!(%addr, gateway, if_index, "Routing(runtime): adding IPv6 bypass route");

    let Some(gw) = gateway else {
        warn!(%addr, "Routing(runtime): no IPv6 gateway; bypass NOT added");
        return Ok(());
    };

    if if_index > 0 {
        let if_idx_str = if_index.to_string();
        match run_netsh_route(&[
            "interface", "ipv6", "add", "route",
            &prefix,
            &format!("interface={if_idx_str}"),
            &format!("nexthop={gw}"),
            "metric=1",
            "store=active",
        ])
        .await
        {
            Ok(()) => info!(%addr, gateway = %gw, if_index, "Routing(runtime): IPv6 bypass added"),
            Err(e) => warn!(%addr, "Routing(runtime): IPv6 bypass failed: {e}"),
        }
    } else {
        warn!(%addr, "Routing(runtime): no IPv6 interface index; skipping");
    }
    Ok(())
}

pub async fn cleanup_stale_routes(tun_name: &str) {
    let iface = format!("interface={tun_name}");
    let args0 = ["interface", "ipv4", "delete", "route", "0.0.0.0/1", iface.as_str(), "store=active"];
    let args1 = ["interface", "ipv4", "delete", "route", "128.0.0.0/1", iface.as_str(), "store=active"];
    let args2 = ["interface", "ipv6", "delete", "route", "::/1", iface.as_str(), "store=active"];
    let args3 = ["interface", "ipv6", "delete", "route", "8000::/1", iface.as_str(), "store=active"];
    let (_, _, _, _) = tokio::join!(
        run_netsh_route(&args0),
        run_netsh_route(&args1),
        run_netsh_route(&args2),
        run_netsh_route(&args3),
    );
    debug!("Routing: stale route cleanup done");
}

async fn run_route(args: &[&str]) -> Result<()> {
    let label = format!("route {}", args.join(" "));
    debug!(cmd = %label, "Routing: running");
    let out = tokio::process::Command::new("route")
        .args(args)
        .output()
        .await
        .map_err(|e| TunError::Io { source: e })?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Err(TunError::Routing(format!("route command failed ({label}): {stdout}{stderr}")))
}

async fn run_netsh_route(args: &[&str]) -> Result<()> {
    let label = format!("netsh {}", args.join(" "));
    debug!(cmd = %label, "Routing: running");
    let out = tokio::process::Command::new("netsh")
        .args(args)
        .output()
        .await
        .map_err(|e| TunError::Io { source: e })?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Err(TunError::Routing(format!("netsh command failed ({label}): {stdout}{stderr}")))
}

/// Returns (gateway_ip, interface_index) for the lowest-metric IPv4 default route.
async fn read_default_gateway_v4() -> Option<(String, u32)> {
    read_default_gateway_v4_win32()
}

#[cfg(windows)]
fn read_default_gateway_v4_win32() -> Option<(String, u32)> {
    use std::net::Ipv4Addr;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    unsafe {
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let ret = GetIpForwardTable2(AF_INET, &mut table_ptr);
        if ret != NO_ERROR {
            warn!("GetIpForwardTable2(AF_INET) failed: {ret}");
            return None;
        }

        let table = &*table_ptr;
        let num = table.NumEntries as usize;
        let rows_ptr = table.Table.as_ptr();

        let mut best: Option<(String, u32)> = None;
        let mut best_metric: u32 = u32::MAX;

        for i in 0..num {
            let row: &MIB_IPFORWARD_ROW2 = &*rows_ptr.add(i);

            let family = row.DestinationPrefix.Prefix.si_family;
            let prefix_len = row.DestinationPrefix.PrefixLength;

            if family == AF_INET && prefix_len == 0 {
                let metric = row.Metric;
                if metric < best_metric {
                    best_metric = metric;
                    let sin = row.NextHop.Ipv4;
                    let addr_u32 = sin.sin_addr.S_un.S_addr;
                    let ip = Ipv4Addr::from(addr_u32.to_ne_bytes());
                    best = Some((ip.to_string(), row.InterfaceIndex));
                }
            }
        }

        FreeMibTable(table_ptr as *const _);
        best
    }
}

#[cfg(not(windows))]
fn read_default_gateway_v4_win32() -> Option<(String, u32)> {
    None
}

/// Returns (gateway_ip, interface_index) for the lowest-metric IPv6 default route.
async fn read_default_gateway_v6() -> Option<(String, u32)> {
    read_default_gateway_v6_win32()
}

#[cfg(windows)]
fn read_default_gateway_v6_win32() -> Option<(String, u32)> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    unsafe {
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let ret = GetIpForwardTable2(AF_INET6, &mut table_ptr);
        if ret != NO_ERROR {
            warn!("GetIpForwardTable2(AF_INET6) failed: {ret}");
            return None;
        }

        let table = &*table_ptr;
        let num = table.NumEntries as usize;
        let rows_ptr = table.Table.as_ptr();

        let mut best: Option<(String, u32)> = None;
        let mut best_metric: u32 = u32::MAX;

        for i in 0..num {
            let row: &MIB_IPFORWARD_ROW2 = &*rows_ptr.add(i);

            let family = row.DestinationPrefix.Prefix.si_family;
            let prefix_len = row.DestinationPrefix.PrefixLength;

            if family == AF_INET6 && prefix_len == 0 {
                let metric = row.Metric;
                if metric < best_metric {
                    best_metric = metric;
                    let sin6 = row.NextHop.Ipv6;
                    let ip = Ipv6Addr::from(sin6.sin6_addr.u.Byte);
                    // Skip unspecified (all-zeros) gateway — link-local routes use InterfaceIndex only
                    if ip == Ipv6Addr::UNSPECIFIED {
                        continue;
                    }
                    best = Some((ip.to_string(), row.InterfaceIndex));
                }
            }
        }

        FreeMibTable(table_ptr as *const _);
        best
    }
}

#[cfg(not(windows))]
fn read_default_gateway_v6_win32() -> Option<(String, u32)> {
    None
}
