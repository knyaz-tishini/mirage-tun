use std::net::IpAddr;
use tracing::{debug, info, warn};
use crate::error::{Result, TunError};

pub struct Routing {
    original_gateway: Option<String>,
    original_interface_idx: Option<u32>,
    bypass_routes: Vec<String>,
    tun_default_set: bool,
    tun_name: String,
}

impl Routing {
    pub fn new(tun_name: impl Into<String>) -> Self {
        Self {
            original_gateway: None,
            original_interface_idx: None,
            bypass_routes: Vec::new(),
            tun_default_set: false,
            tun_name: tun_name.into(),
        }
    }

    pub fn original_gateway(&self) -> Option<&str> {
        self.original_gateway.as_deref()
    }

    pub fn original_interface_idx(&self) -> Option<u32> {
        self.original_interface_idx
    }

    pub async fn set_default_route(&mut self) -> Result<()> {
        if let Some((gw, idx)) = read_default_gateway().await {
            self.original_interface_idx = Some(idx);
            self.original_gateway = Some(gw);
        }
        info!(
            gateway = ?self.original_gateway,
            if_idx = ?self.original_interface_idx,
            "Routing: saved original default gateway (will be used for bypass routes)"
        );
        if self.original_gateway.is_none() {
            warn!("Routing: could not detect original gateway — bypass routes will NOT work");
        }

        let tun_name = self.tun_name.clone();

        // Set interface metric to 1 so total metric (route + iface) beats amnezia
        if let Err(e) = run_netsh_route(&[
            "interface", "ipv4", "set", "interface",
            &tun_name,
            "metric=1",
        ]).await {
            warn!("failed to set interface metric (non-fatal): {e}");
        }

        let iface = format!("interface={tun_name}");
        // Run both half-route additions in parallel
        let args0 = ["interface", "ipv4", "add", "route", "0.0.0.0/1", iface.as_str(), "metric=1", "store=active"];
        let args1 = ["interface", "ipv4", "add", "route", "128.0.0.0/1", iface.as_str(), "metric=1", "store=active"];
        tokio::try_join!(
            run_netsh_route(&args0),
            run_netsh_route(&args1)
        )?;
        self.tun_default_set = true;
        info!(tun_name, "Routing: default route set via TUN (metric=1+1=2)");
        Ok(())
    }

    pub fn restore_routes_sync(&mut self) {
        for addr in self.bypass_routes.drain(..) {
            let _ = std::process::Command::new("route")
                .args(["delete", &addr, "mask", "255.255.255.255"])
                .output();
        }
        if self.tun_default_set {
            let name = &self.tun_name;
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
        info!("Routing: routes restored (sync)");
    }

    pub async fn add_bypass(&mut self, addr: IpAddr) -> Result<()> {
        let addr_str = addr.to_string();
        let prefix = format!("{addr_str}/32");
        let if_idx = self.original_interface_idx.unwrap_or(0);

        info!(
            %addr,
            gateway = ?self.original_gateway,
            if_idx,
            "Routing: adding bypass route for relay addr"
        );

        if let Some(ref gw) = self.original_gateway.clone() {
            if if_idx > 0 {
                // Prefer netsh with explicit interface index — more reliable on modern Windows
                // than route.exe which can pick a different interface when TUN is active.
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
                    Ok(()) => info!(%addr, gateway = %gw, if_idx, "Routing: bypass route added via netsh"),
                    Err(e) => {
                        warn!(%addr, gateway = %gw, if_idx, "Routing: netsh bypass failed ({e}), falling back to route.exe");
                        let idx_str = if_idx.to_string();
                        run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1", "IF", &idx_str]).await?;
                        info!(%addr, gateway = %gw, if_idx, "Routing: bypass route added via route.exe fallback");
                    }
                }
            } else {
                // No interface index — fall back to route.exe with just gateway
                warn!(%addr, gateway = %gw, "Routing: no interface index, using route.exe without IF");
                run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1"]).await?;
                info!(%addr, gateway = %gw, "Routing: bypass route added via route.exe (no IF)");
            }
        } else {
            warn!(%addr, "Routing: no original gateway saved; bypass route NOT added — relay traffic will go through TUN");
        }
        self.bypass_routes.push(addr_str);
        Ok(())
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        if self.tun_default_set || !self.bypass_routes.is_empty() {
            self.restore_routes_sync();
        }
    }
}

pub async fn cleanup_stale_routes(tun_name: &str) {
    let iface = format!("interface={tun_name}");
    let args0 = ["interface", "ipv4", "delete", "route", "0.0.0.0/1", iface.as_str(), "store=active"];
    let args1 = ["interface", "ipv4", "delete", "route", "128.0.0.0/1", iface.as_str(), "store=active"];
    let (_, _) = tokio::join!(
        run_netsh_route(&args0),
        run_netsh_route(&args1)
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

/// Returns (gateway_ip, interface_index) via Win32 GetIpForwardTable2.
/// Finds the lowest-metric IPv4 default route (0.0.0.0/0).
/// Instant — no subprocess, no netsh.
async fn read_default_gateway() -> Option<(String, u32)> {
    read_default_gateway_win32()
}

#[cfg(windows)]
fn read_default_gateway_win32() -> Option<(String, u32)> {
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
            warn!("GetIpForwardTable2 failed: {ret}");
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
fn read_default_gateway_win32() -> Option<(String, u32)> {
    None
}
