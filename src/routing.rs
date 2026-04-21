use std::{net::IpAddr, process::Command};
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

    pub fn set_default_route(&mut self) -> Result<()> {
        cleanup_stale_routes(&self.tun_name);
        if let Some((gw, idx)) = read_default_gateway() {
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

        let tun_name = &self.tun_name;

        // Set interface metric to 1 so total metric (route + iface) beats amnezia
        if let Err(e) = run_netsh_route(&[
            "interface", "ipv4", "set", "interface",
            tun_name,
            "metric=1",
        ]) {
            warn!("failed to set interface metric (non-fatal): {e}");
        }

        run_netsh_route(&[
            "interface", "ipv4", "add", "route",
            "0.0.0.0/1",
            &format!("interface={tun_name}"),
            "metric=1",
            "store=active",
        ])?;
        run_netsh_route(&[
            "interface", "ipv4", "add", "route",
            "128.0.0.0/1",
            &format!("interface={tun_name}"),
            "metric=1",
            "store=active",
        ])?;
        self.tun_default_set = true;
        info!(tun_name, "Routing: default route set via TUN (metric=1+1=2)");
        Ok(())
    }

    pub fn restore_routes(&mut self) -> Result<()> {
        for addr in self.bypass_routes.drain(..) {
            if let Err(e) = run_route(&["delete", &addr, "mask", "255.255.255.255"]) {
                warn!("Routing: failed to remove bypass route {addr}: {e}");
            }
        }
        if self.tun_default_set {
            let name = &self.tun_name;
            if let Err(e) = run_netsh_route(&[
                "interface", "ipv4", "delete", "route",
                "0.0.0.0/1",
                &format!("interface={name}"),
                "store=active",
            ]) {
                warn!("Routing: failed to remove TUN route 0.0.0.0/1: {e}");
            }
            if let Err(e) = run_netsh_route(&[
                "interface", "ipv4", "delete", "route",
                "128.0.0.0/1",
                &format!("interface={name}"),
                "store=active",
            ]) {
                warn!("Routing: failed to remove TUN route 128.0.0.0/1: {e}");
            }
            self.tun_default_set = false;
        }
        info!("Routing: routes restored");
        Ok(())
    }

    pub fn add_bypass(&mut self, addr: IpAddr) -> Result<()> {
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
                ]);
                match &result {
                    Ok(()) => info!(%addr, gateway = %gw, if_idx, "Routing: bypass route added via netsh"),
                    Err(e) => {
                        warn!(%addr, gateway = %gw, if_idx, "Routing: netsh bypass failed ({e}), falling back to route.exe");
                        let idx_str = if_idx.to_string();
                        run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1", "IF", &idx_str])?;
                        info!(%addr, gateway = %gw, if_idx, "Routing: bypass route added via route.exe fallback");
                    }
                }
            } else {
                // No interface index — fall back to route.exe with just gateway
                warn!(%addr, gateway = %gw, "Routing: no interface index, using route.exe without IF");
                run_route(&["add", &addr_str, "mask", "255.255.255.255", gw, "METRIC", "1"])?;
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
            if let Err(e) = self.restore_routes() {
                warn!("Routing::drop: failed to restore routes: {e}");
            }
        }
    }
}

pub fn cleanup_stale_routes(tun_name: &str) {
    let _ = run_netsh_route(&[
        "interface", "ipv4", "delete", "route",
        "0.0.0.0/1",
        &format!("interface={tun_name}"),
        "store=active",
    ]);
    let _ = run_netsh_route(&[
        "interface", "ipv4", "delete", "route",
        "128.0.0.0/1",
        &format!("interface={tun_name}"),
        "store=active",
    ]);
    debug!("Routing: stale route cleanup done");
}

fn run_route(args: &[&str]) -> Result<()> {
    let label = format!("route {}", args.join(" "));
    debug!(cmd = %label, "Routing: running");
    let out = Command::new("route").args(args).output().map_err(|e| TunError::Io { source: e })?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Err(TunError::Routing(format!("route command failed ({label}): {stdout}{stderr}")))
}

fn run_netsh_route(args: &[&str]) -> Result<()> {
    let label = format!("netsh {}", args.join(" "));
    debug!(cmd = %label, "Routing: running");
    let out = Command::new("netsh").args(args).output().map_err(|e| TunError::Io { source: e })?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Err(TunError::Routing(format!("netsh command failed ({label}): {stdout}{stderr}")))
}

/// Returns (gateway_ip, interface_index).
/// Tries `netsh interface ipv4 show route` first for exact interface index,
/// falls back to `route print 0.0.0.0` with index=0 when netsh parsing fails.
fn read_default_gateway() -> Option<(String, u32)> {
    // `netsh interface ipv4 show route` — no filter arg (Windows rejects it).
    // Output columns: Publish Type Met Prefix Idx Gateway/InterfaceName
    // Example: No  Manual  0  0.0.0.0/0  19  192.168.1.1
    let netsh_out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "route"])
        .output()
        .ok();
    if let Some(out) = netsh_out {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|t| *t == "0.0.0.0/0") {
                if let (Some(idx_str), Some(gw)) = (tokens.get(pos + 1), tokens.get(pos + 2)) {
                    // Only accept entries where gateway is a valid IP (skip "AmneziaVPN" etc.)
                    if gw.parse::<std::net::IpAddr>().is_ok() {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            return Some((gw.to_string(), idx));
                        }
                    }
                }
            }
        }
    }

    // Fallback: route print — columns: Network Netmask Gateway Interface Metric
    let out = Command::new("route").args(["print", "0.0.0.0"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 3 && tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
            return Some((tokens[2].to_owned(), 0));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_gateway_line_fallback() {
        // Simulates `route print 0.0.0.0` fallback path
        let fake_output = "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n";
        let mut found: Option<(String, u32)> = None;
        for line in fake_output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 3 && tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
                found = Some((tokens[2].to_owned(), 0));
            }
        }
        assert_eq!(found.as_ref().map(|(gw, _)| gw.as_str()), Some("192.168.1.1"));
        assert_eq!(found.as_ref().map(|(_, idx)| *idx), Some(0u32));
    }

    #[test]
    fn parse_gateway_line_netsh() {
        // Simulates `netsh interface ipv4 show route` output (no filter arg)
        let fake_output = "No       Manual    0   0.0.0.0/0                  19  192.168.1.1\nNo       Manual    0   0.0.0.0/0                  44  AmneziaVPN\n";
        let mut found: Option<(String, u32)> = None;
        for line in fake_output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|t| *t == "0.0.0.0/0") {
                if let (Some(idx_str), Some(gw)) = (tokens.get(pos + 1), tokens.get(pos + 2)) {
                    if gw.parse::<std::net::IpAddr>().is_ok() {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            found = Some((gw.to_string(), idx));
                            break;
                        }
                    }
                }
            }
        }
        assert_eq!(found.as_ref().map(|(gw, _)| gw.as_str()), Some("192.168.1.1"));
        assert_eq!(found.as_ref().map(|(_, idx)| *idx), Some(19u32));
    }
}
