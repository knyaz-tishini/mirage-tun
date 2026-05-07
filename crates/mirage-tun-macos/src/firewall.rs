/// macOS pf-based kill-switch firewall.
///
/// Rules are loaded into the `mirage` pf anchor to avoid interfering with
/// system rules in `/etc/pf.conf`. The anchor is flushed on deactivation.
///
/// TCP is handled by mirage-tcpip-stack (smoltcp) — no rdr rule needed.
use crate::error::MacosTunError;
use mirage_tun_core::traits::{PlatformFirewall, private::Sealed};
use std::net::IpAddr;
use tracing::{debug, info, warn};

const ANCHOR: &str = "mirage";
const PF_CONF_PATH: &str = "/tmp/mirage-pf.conf";

/// macOS pf firewall manager.
pub struct MacosFirewall {
    active: bool,
}

impl MacosFirewall {
    pub fn new() -> Self {
        MacosFirewall { active: false }
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
        let conf = build_pf_rules(relay_addrs, tun_name, exempt_ports);
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

fn build_pf_rules(relay_addrs: &[IpAddr], tun_name: &str, exempt_ports: &[u16]) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "# Mirage VPN pf anchor — loaded into anchor \"{ANCHOR}\""
    ));
    lines.push(String::new());

    lines.push("set skip on lo0".to_string());
    lines.push(String::new());

    // PF rule order: pass quick first wins, then block-all default catches the rest.
    lines.push(format!("pass quick on {tun_name} inet all keep state"));
    lines.push(format!("pass quick on {tun_name} inet6 all keep state"));
    lines.push(String::new());
    lines.push("block drop all".to_string());
    lines.push("block drop out inet6 from any to any".to_string());
    lines.push(String::new());

    for relay in relay_addrs {
        if relay.is_ipv6() {
            lines.push(format!("pass out inet6 proto {{tcp, udp}} to {relay} keep state"));
            lines.push(format!("pass in inet6 proto {{tcp, udp}} from {relay} keep state"));
        } else {
            lines.push(format!("pass out proto {{tcp, udp}} to {relay} keep state"));
            lines.push(format!("pass in proto {{tcp, udp}} from {relay} keep state"));
        }
    }
    lines.push(String::new());

    lines.push(
        "pass on egress proto {tcp,udp} from any port 67:68 to any port 67:68 keep state"
            .to_string(),
    );
    if !exempt_ports.is_empty() {
        let ports: Vec<String> = exempt_ports.iter().map(|p| p.to_string()).collect();
        let ports_str = ports.join(", ");
        lines.push(format!(
            "pass out proto {{tcp, udp}} to any port {{{ports_str}}} keep state"
        ));
    }

    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn pf_rules_contain_block_all() {
        let relay: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let rules = build_pf_rules(&[relay], "utun3", &[53]);
        assert!(rules.contains("block drop all"));
        assert!(rules.contains("block drop out inet6 on egress all"));
        assert!(rules.contains("pass on utun3 inet all"));
        assert!(rules.contains("pass on utun3 inet6 all"));
        assert!(rules.contains("1.2.3.4"));
        assert!(rules.contains("53"));
    }

    #[test]
    fn pf_rules_v6_relay() {
        use std::net::Ipv6Addr;
        let relay_v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let rules = build_pf_rules(&[relay_v6], "utun3", &[]);
        assert!(rules.contains("inet6 proto {tcp, udp} to 2001:db8::1"));
    }

    #[test]
    fn no_rdr_in_rules() {
        let relay: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let rules = build_pf_rules(&[relay], "utun3", &[53]);
        assert!(!rules.contains("rdr"));
    }
}
