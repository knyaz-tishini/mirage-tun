use std::net::IpAddr;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use mirage_tun_core::traits::{PlatformRouting, private};
use crate::error::LinuxTunError;
use crate::tun_device::run_ip;

/// fwmark used for bypass sockets (bypasses policy routing table).
pub const BYPASS_FWMARK: u32 = 51820;
/// Custom routing table id for VPN traffic.
pub const VPN_TABLE: u32 = 51820;
/// ip rule priority for "lookup main, suppress default".
const RULE_MAIN_PRIORITY: u32 = 32764;
/// ip rule priority for "not fwmark → VPN table".
const RULE_VPN_PRIORITY: u32 = 32765;

/// Linux routing manager using wg-quick-style policy routing.
pub struct LinuxRouting {
    original_gateway: Option<IpAddr>,
    tun_name: String,
    bypass_hosts: Vec<IpAddr>,
    rules_installed: bool,
}

impl LinuxRouting {
    pub fn new() -> Self {
        Self {
            original_gateway: None,
            tun_name: String::new(),
            bypass_hosts: Vec::new(),
            rules_installed: false,
        }
    }

    /// Detect the current default IPv4 gateway from `ip route show default`.
    async fn detect_gateway() -> Option<IpAddr> {
        use tokio::process::Command;
        let out = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        debug!("ip route show default: {text}");
        // Format: "default via X.X.X.X dev eth0 ..."
        for token in text.split_whitespace().collect::<Vec<_>>().windows(2) {
            if token[0] == "via" {
                if let Ok(ip) = token[1].parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        None
    }
}

impl private::Sealed for LinuxRouting {}

#[async_trait]
impl PlatformRouting for LinuxRouting {
    type Error = LinuxTunError;

    async fn set_default_route(&mut self, tun_name: &str) -> Result<(), Self::Error> {
        self.tun_name = tun_name.to_owned();

        // Save original gateway before installing policy routing.
        self.original_gateway = Self::detect_gateway().await;
        info!(
            "Original gateway: {:?}",
            self.original_gateway
        );

        // Add bypass routes for already-registered relay addrs via original gw.
        if let Some(gw) = self.original_gateway {
            for &addr in &self.bypass_hosts.clone() {
                add_bypass_route(addr, gw).await?;
            }
        }

        // Policy routing (wg-quick style):
        //   table VPN_TABLE: default → tun_name
        //   rule RULE_MAIN_PRIORITY: lookup main suppress_prefixlength 0
        //   rule RULE_VPN_PRIORITY:  not fwmark BYPASS_FWMARK → table VPN_TABLE

        run_ip(&[
            "route", "add", "default",
            "dev", tun_name,
            "table", &VPN_TABLE.to_string(),
        ]).await?;

        run_ip(&[
            "rule", "add",
            "priority", &RULE_MAIN_PRIORITY.to_string(),
            "lookup", "main",
            "suppress_prefixlength", "0",
        ]).await?;

        run_ip(&[
            "rule", "add",
            "priority", &RULE_VPN_PRIORITY.to_string(),
            "not", "fwmark", &BYPASS_FWMARK.to_string(),
            "lookup", &VPN_TABLE.to_string(),
        ]).await?;

        self.rules_installed = true;
        info!("Policy routing installed for {tun_name} (table={VPN_TABLE})");
        Ok(())
    }

    async fn restore_routes(&mut self) -> Result<(), Self::Error> {
        if !self.rules_installed {
            return Ok(());
        }

        // Remove policy rules — ignore individual errors (may already be gone).
        let _ = run_ip(&[
            "rule", "del",
            "priority", &RULE_MAIN_PRIORITY.to_string(),
        ]).await;

        let _ = run_ip(&[
            "rule", "del",
            "priority", &RULE_VPN_PRIORITY.to_string(),
        ]).await;

        // Flush custom routing table.
        let _ = run_ip(&[
            "route", "flush",
            "table", &VPN_TABLE.to_string(),
        ]).await;

        // Remove bypass host routes.
        if let Some(gw) = self.original_gateway {
            for &addr in &self.bypass_hosts {
                let _ = remove_bypass_route(addr, gw).await;
            }
        }

        self.rules_installed = false;
        info!("Policy routing restored");
        Ok(())
    }

    async fn add_bypass_host(&mut self, addr: IpAddr) -> Result<(), Self::Error> {
        self.bypass_hosts.push(addr);
        if let Some(gw) = self.original_gateway {
            add_bypass_route(addr, gw).await?;
        }
        // If gateway not yet known routes will be added in set_default_route.
        Ok(())
    }

    fn original_gateway(&self) -> Option<IpAddr> {
        self.original_gateway
    }
}

async fn add_bypass_route(addr: IpAddr, gw: IpAddr) -> Result<(), LinuxTunError> {
    match run_ip(&[
        "route", "add",
        &addr.to_string(),
        "via", &gw.to_string(),
    ]).await {
        Ok(()) => {
            info!("Bypass route added: {addr} via {gw}");
            Ok(())
        }
        Err(e) => {
            // EEXIST is fine — route already present.
            warn!("add_bypass_route {addr}: {e}");
            Ok(())
        }
    }
}

async fn remove_bypass_route(addr: IpAddr, gw: IpAddr) -> Result<(), LinuxTunError> {
    let result = run_ip(&[
        "route", "del",
        &addr.to_string(),
        "via", &gw.to_string(),
    ]).await;
    if let Err(e) = &result {
        warn!("remove_bypass_route {addr}: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_routing_has_no_gateway() {
        let r = LinuxRouting::new();
        assert!(r.original_gateway().is_none());
        assert!(!r.rules_installed);
    }

    #[test]
    fn bypass_hosts_accumulate() {
        let mut r = LinuxRouting::new();
        // Can't await in sync test — just verify field mutation.
        r.bypass_hosts.push("1.2.3.4".parse().unwrap());
        assert_eq!(r.bypass_hosts.len(), 1);
    }
}
