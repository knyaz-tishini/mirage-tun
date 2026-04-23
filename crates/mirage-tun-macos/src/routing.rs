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
    /// Original default gateway saved before we override it.
    original_gateway: Option<IpAddr>,
    /// Relay (VPN server) addresses added as bypass host routes.
    bypassed_hosts: Vec<IpAddr>,
    /// TUN interface name (set when `set_default_route` is called).
    tun_name: Option<String>,
}

impl MacosRouting {
    pub fn new() -> Self {
        MacosRouting {
            original_gateway: None,
            bypassed_hosts: Vec::new(),
            tun_name: None,
        }
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
        // 1. Save original gateway
        let gw = get_default_gateway().await?;
        info!("original gateway: {}", gw);
        self.original_gateway = Some(gw);
        self.tun_name = Some(tun_name.to_string());

        // 2. Add bypass routes for already-registered relay addresses using the
        //    original gateway (must happen before we override the default route).
        for relay in self.bypassed_hosts.clone() {
            add_host_route(relay, gw).await?;
        }

        // 3. Override default route with two /1 routes through TUN
        //    (0.0.0.0/1 + 128.0.0.0/1 are more specific than /0 default).
        run_route(&["add", "-net", "0.0.0.0/1", "-interface", tun_name]).await?;
        run_route(&["add", "-net", "128.0.0.0/1", "-interface", tun_name]).await?;

        info!("default route via {} (0/1 + 128/1 trick)", tun_name);
        Ok(())
    }

    async fn restore_routes(&mut self) -> Result<(), Self::Error> {
        let tun_name = match &self.tun_name {
            Some(n) => n.clone(),
            None => return Ok(()), // never activated
        };

        // Delete /1 override routes
        for net in &["0.0.0.0/1", "128.0.0.0/1"] {
            match run_route(&["delete", "-net", net, "-interface", &tun_name]).await {
                Ok(()) => {}
                Err(e) => warn!("delete route {} failed: {}", net, e),
            }
        }

        // Remove bypass host routes
        if let Some(gw) = self.original_gateway {
            for relay in self.bypassed_hosts.drain(..) {
                match run_route(&["delete", "-host", &relay.to_string(), &gw.to_string()]).await {
                    Ok(()) => {}
                    Err(e) => warn!("delete host route {} failed: {}", relay, e),
                }
            }
        }

        self.original_gateway = None;
        self.tun_name = None;
        info!("routes restored");
        Ok(())
    }

    async fn add_bypass_host(&mut self, addr: IpAddr) -> Result<(), Self::Error> {
        self.bypassed_hosts.push(addr);

        // If the default route is already overridden, install the bypass route now.
        if let Some(gw) = self.original_gateway {
            add_host_route(addr, gw).await?;
        }
        // Otherwise it will be added when set_default_route is called.
        Ok(())
    }

    fn original_gateway(&self) -> Option<IpAddr> {
        self.original_gateway
    }
}

/// Read the default gateway IP from `route -n get default`.
async fn get_default_gateway() -> Result<IpAddr, MacosTunError> {
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

/// Add a host route for `addr` via `gateway`.
async fn add_host_route(addr: IpAddr, gateway: IpAddr) -> Result<(), MacosTunError> {
    run_route(&["add", "-host", &addr.to_string(), &gateway.to_string()]).await
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
