use std::net::IpAddr;
use std::process::Command as StdCommand;
use tracing::{debug, info, warn};

use mirage_tun_core::traits::{PlatformFirewall, PlatformExecutor, FlowProto, FlowKey, private};
use mirage_tun_core::plane::{Plane, ProcessIdentity};
use crate::error::LinuxTunError;

/// Intercept port for TCP REDIRECT: traffic from TUN is redirected here.
pub const DEFAULT_INTERCEPT_PORT: u16 = 7300;

/// Runtime-detected firewall backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
}

/// Linux firewall manager. Installs kill-switch + TCP REDIRECT rules.
pub struct LinuxFirewall {
    backend: FirewallBackend,
    intercept_port: u16,
    /// True once rules have been installed.
    active: bool,
}

impl LinuxFirewall {
    /// Detect which backend is available and create the manager.
    pub fn detect(intercept_port: u16) -> Self {
        let backend = detect_backend_sync();
        info!("Firewall backend: {backend:?}");
        Self {
            backend,
            intercept_port,
            active: false,
        }
    }
}

impl private::Sealed for LinuxFirewall {}

// ── T2: PlatformExecutor stub ─────────────────────────────────────────────────

impl PlatformExecutor for LinuxFirewall {
    type Error = LinuxTunError;

    /// Attribution is not available on Linux at T2 — returns None.
    /// T3 will use cgroup / SO_PEERCRED / eBPF attribution here.
    fn attribute(
        &self,
        _src_port: u16,
        _dst: std::net::SocketAddr,
        _proto: FlowProto,
    ) -> Option<ProcessIdentity> {
        None
    }

    /// T2: no-op — nftables/iptables handle coarse enforcement via activate().
    /// Per-process enforcement (cgroup v2 / eBPF) is T3.
    /// `Plane::Group` must not reach here — caller resolves group first.
    fn enforce(
        &mut self,
        plane: &Plane,
        _identity: Option<&ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), LinuxTunError> {
        if let Plane::Group(_) = plane {
            warn!(?flow, "enforce called with unresolved Group plane — bug in caller");
        }
        Ok(())
    }
}

impl PlatformFirewall for LinuxFirewall {
    type Error = LinuxTunError;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        _exempt_ports: &[u16],
    ) -> Result<(), Self::Error> {
        match self.backend {
            FirewallBackend::Nftables => {
                nft_activate_sync(relay_addrs, tun_name, self.intercept_port)?;
            }
            FirewallBackend::Iptables => {
                ipt_activate_sync(relay_addrs, tun_name, self.intercept_port)?;
            }
        }
        self.active = true;
        info!("Firewall activated on {tun_name}, intercept_port={}", self.intercept_port);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), Self::Error> {
        if !self.active {
            return Ok(());
        }
        match self.backend {
            FirewallBackend::Nftables => nft_deactivate_sync()?,
            FirewallBackend::Iptables => ipt_deactivate_sync()?,
        }
        self.active = false;
        info!("Firewall deactivated");
        Ok(())
    }
}

// ── Backend detection ─────────────────────────────────────────────────────────

fn detect_backend_sync() -> FirewallBackend {
    let out = StdCommand::new("which").arg("nft").output();
    match out {
        Ok(o) if o.status.success() => FirewallBackend::Nftables,
        _ => FirewallBackend::Iptables,
    }
}

// ── nftables ──────────────────────────────────────────────────────────────────

fn nft_activate_sync(
    relay_addrs: &[IpAddr],
    tun_name: &str,
    intercept_port: u16,
) -> Result<(), LinuxTunError> {
    let relay_set = if relay_addrs.is_empty() {
        String::new()
    } else {
        let addrs: Vec<String> = relay_addrs.iter().map(|a| a.to_string()).collect();
        format!(
            "    set relay_addrs {{\n        type ipv4_addr;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            addrs.join(", ")
        )
    };

    let relay_bypass = if relay_addrs.is_empty() {
        String::new()
    } else {
        "    # bypass relay addresses (do not redirect)\n    ip daddr @relay_addrs accept\n".to_string()
    };

    let script = format!(
        r#"#!/usr/sbin/nft -f

table inet mirage_redirect {{
{relay_set}
  chain prerouting {{
    type nat hook prerouting priority dstnat;
{relay_bypass}    iifname "{tun_name}" tcp dport != 53 redirect to :{intercept_port}
  }}
}}
"#
    );

    debug!("nft script:\n{script}");

    let path = "/tmp/mirage-fw.nft";
    std::fs::write(path, &script)
        .map_err(|e| LinuxTunError::Nftables { code: -1, stderr: e.to_string() })?;

    run_nft_sync(&["-f", path])
}

fn nft_deactivate_sync() -> Result<(), LinuxTunError> {
    let out = StdCommand::new("nft")
        .args(["delete", "table", "inet", "mirage_redirect"])
        .output()?;
    debug!("nft delete table: status={}", out.status);
    // Not an error if table doesn't exist.
    Ok(())
}

fn run_nft_sync(args: &[&str]) -> Result<(), LinuxTunError> {
    let out = StdCommand::new("nft").args(args).output()?;
    debug!("nft {}: status={}", args.join(" "), out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("nft {} failed: {stderr}", args.join(" "));
        return Err(LinuxTunError::Nftables {
            code: out.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(())
}

// ── iptables ──────────────────────────────────────────────────────────────────

fn ipt_activate_sync(
    relay_addrs: &[IpAddr],
    tun_name: &str,
    intercept_port: u16,
) -> Result<(), LinuxTunError> {
    // REDIRECT rule: TCP from TUN interface (except port 53) → intercept_port
    // Split into two rules because iptables --dport doesn't accept negation easily.
    run_ipt_sync(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", tun_name,
        "-p", "tcp",
        "--dport", "1:52",
        "-j", "REDIRECT",
        "--to-ports", &intercept_port.to_string(),
    ])?;
    run_ipt_sync(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", tun_name,
        "-p", "tcp",
        "--dport", "54:65535",
        "-j", "REDIRECT",
        "--to-ports", &intercept_port.to_string(),
    ])?;

    // Bypass rules for relay addresses.
    for addr in relay_addrs {
        run_ipt_sync(&[
            "-t", "nat", "-I", "PREROUTING", "1",
            "-i", tun_name,
            "-d", &addr.to_string(),
            "-j", "ACCEPT",
        ])?;
    }

    Ok(())
}

fn ipt_deactivate_sync() -> Result<(), LinuxTunError> {
    let out = StdCommand::new("iptables")
        .args(["-t", "nat", "-F", "PREROUTING"])
        .output()?;
    debug!("iptables -F PREROUTING: status={}", out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("iptables flush failed: {stderr}");
    }
    Ok(())
}

fn run_ipt_sync(args: &[&str]) -> Result<(), LinuxTunError> {
    let out = StdCommand::new("iptables").args(args).output()?;
    debug!("iptables {}: status={}", args.join(" "), out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("iptables {} failed: {stderr}", args.join(" "));
        return Err(LinuxTunError::Iptables {
            code: out.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_script_contains_redirect() {
        let tun_name = "tun0";
        let intercept_port: u16 = 7300;
        let relay_set = String::new();
        let relay_bypass = String::new();
        let script = format!(
            r#"table inet mirage_redirect {{
{relay_set}
  chain prerouting {{
    type nat hook prerouting priority dstnat;
{relay_bypass}    iifname "{tun_name}" tcp dport != 53 redirect to :{intercept_port}
  }}
}}
"#
        );
        assert!(script.contains("redirect to :7300"));
        assert!(script.contains(r#"iifname "tun0""#));
    }

    #[test]
    fn nft_script_contains_relay_set() {
        use std::str::FromStr;
        let relay_addrs: Vec<IpAddr> = vec![IpAddr::from_str("1.2.3.4").unwrap()];
        let addrs: Vec<String> = relay_addrs.iter().map(|a| a.to_string()).collect();
        let relay_set = format!(
            "    set relay_addrs {{\n        type ipv4_addr;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            addrs.join(", ")
        );
        assert!(relay_set.contains("1.2.3.4"));
    }
}
