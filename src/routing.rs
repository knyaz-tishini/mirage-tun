use std::{net::IpAddr, process::Command};
use tracing::{debug, info, warn};
use crate::error::{Result, TunError};

pub struct Routing {
    original_gateway: Option<String>,
    bypass_routes: Vec<String>,
    tun_default_set: bool,
    tun_name: String,
}

impl Routing {
    pub fn new(tun_name: impl Into<String>) -> Self {
        Self {
            original_gateway: None,
            bypass_routes: Vec::new(),
            tun_default_set: false,
            tun_name: tun_name.into(),
        }
    }

    pub fn original_gateway(&self) -> Option<&str> {
        self.original_gateway.as_deref()
    }

    pub fn set_default_route(&mut self) -> Result<()> {
        cleanup_stale_routes(&self.tun_name);
        self.original_gateway = read_default_gateway();
        debug!(gateway = ?self.original_gateway, "Routing: saved original gateway");

        let tun_name = &self.tun_name;
        run_netsh_route(&[
            "interface", "ipv4", "add", "route",
            "0.0.0.0/1",
            &format!("interface={tun_name}"),
            "metric=10",
            "store=active",
        ])?;
        run_netsh_route(&[
            "interface", "ipv4", "add", "route",
            "128.0.0.0/1",
            &format!("interface={tun_name}"),
            "metric=10",
            "store=active",
        ])?;
        self.tun_default_set = true;
        info!(tun_name, "Routing: default route set via TUN");
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
        if let Some(ref gw) = self.original_gateway.clone() {
            run_route(&["add", &addr_str, "mask", "255.255.255.255", gw])?;
            debug!(%addr, gateway = %gw, "Routing: bypass route added");
        } else {
            warn!(%addr, "Routing: no original gateway saved; bypass may be incomplete");
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

fn read_default_gateway() -> Option<String> {
    let out = Command::new("route").args(["print", "0.0.0.0"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 3 && tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
            return Some(tokens[2].to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_gateway_line() {
        let fake_output = "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n";
        let mut found: Option<String> = None;
        for line in fake_output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 3 && tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
                found = Some(tokens[2].to_owned());
            }
        }
        assert_eq!(found.as_deref(), Some("192.168.1.1"));
    }
}
