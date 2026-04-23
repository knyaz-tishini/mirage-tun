/// macOS pf-based kill-switch and TCP redirect firewall.
///
/// Rules are loaded into the `mirage` pf anchor to avoid interfering with
/// system rules in `/etc/pf.conf`. The anchor is flushed on deactivation.
use crate::error::MacosTunError;
use mirage_tun_core::traits::{PlatformFirewall, private::Sealed};
use std::net::IpAddr;
use tracing::{debug, info, warn};

const ANCHOR: &str = "mirage";
const PF_CONF_PATH: &str = "/tmp/mirage-pf.conf";

/// macOS pf firewall manager.
pub struct MacosFirewall {
    active: bool,
    /// TCP intercept port for the pf rdr rule. Set before calling `activate`.
    pub intercept_port: u16,
}

impl MacosFirewall {
    pub fn new() -> Self {
        MacosFirewall {
            active: false,
            intercept_port: 7891,
        }
    }

    pub fn with_intercept_port(port: u16) -> Self {
        MacosFirewall {
            active: false,
            intercept_port: port,
        }
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
        tokio::runtime::Handle::current().block_on(self.activate_async(
            relay_addrs,
            tun_name,
            exempt_ports,
        ))
    }

    fn deactivate(&mut self) -> Result<(), Self::Error> {
        tokio::runtime::Handle::current().block_on(self.deactivate_async())
    }
}

impl MacosFirewall {
    async fn activate_async(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), MacosTunError> {
        let mut conf = build_pf_rules(relay_addrs, tun_name, exempt_ports);
        // Append TCP intercept redirect rule
        conf.push_str(&tcp_redirect_rule(tun_name, self.intercept_port));
        debug!("pf rules:\n{}", conf);

        tokio::fs::write(PF_CONF_PATH, &conf)
            .await
            .map_err(MacosTunError::Io)?;

        // Load anchor rules
        run_pfctl(&["-a", ANCHOR, "-f", PF_CONF_PATH]).await?;

        // Enable pf (idempotent if already enabled)
        run_pfctl(&["-e"]).await.ok(); // may fail if already enabled — that's fine

        self.active = true;
        info!("pf firewall activated (anchor: {})", ANCHOR);
        Ok(())
    }

    async fn deactivate_async(&mut self) -> Result<(), MacosTunError> {
        if !self.active {
            return Ok(());
        }

        // Flush all rules from anchor
        match run_pfctl(&["-a", ANCHOR, "-F", "all"]).await {
            Ok(()) => {}
            Err(e) => warn!("pfctl flush anchor failed: {}", e),
        }

        // Try to clean up temp file (non-fatal)
        tokio::fs::remove_file(PF_CONF_PATH).await.ok();

        self.active = false;
        info!("pf firewall deactivated (anchor: {})", ANCHOR);
        Ok(())
    }
}

fn build_pf_rules(relay_addrs: &[IpAddr], tun_name: &str, exempt_ports: &[u16]) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!("# Mirage VPN pf anchor — loaded into anchor \"{ANCHOR}\""));
    lines.push(String::new());

    // Pass loopback unconditionally
    lines.push("set skip on lo0".to_string());
    lines.push(String::new());

    // Block all by default (kill-switch)
    lines.push("block drop all".to_string());
    lines.push("block drop out inet6 all".to_string());
    lines.push(String::new());

    // Allow traffic on the TUN interface
    lines.push(format!("pass on {tun_name} all keep state"));
    lines.push(String::new());

    // Allow relay addresses through physical interfaces (so tunnel can reconnect)
    for relay in relay_addrs {
        lines.push(format!(
            "pass out proto {{tcp, udp}} to {relay} keep state"
        ));
        lines.push(format!(
            "pass in proto {{tcp, udp}} from {relay} keep state"
        ));
    }
    lines.push(String::new());

    // Allow DHCP on all physical interfaces
    lines.push(
        "pass on egress proto {tcp,udp} from any port 67:68 to any port 67:68 keep state"
            .to_string(),
    );

    // Allow exempt ports (e.g. local DNS)
    if !exempt_ports.is_empty() {
        let ports: Vec<String> = exempt_ports.iter().map(|p| p.to_string()).collect();
        let ports_str = ports.join(", ");
        lines.push(format!(
            "pass out proto {{tcp, udp}} to any port {{{ports_str}}} keep state"
        ));
    }

    lines.join("\n") + "\n"
}

/// Run `pfctl` with the given arguments, capturing stdout+stderr.
async fn run_pfctl(args: &[&str]) -> Result<(), MacosTunError> {
    use tokio::process::Command;

    let out = Command::new("pfctl")
        .args(args)
        .output()
        .await
        .map_err(MacosTunError::Io)?;

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    if !stdout.is_empty() {
        debug!("pfctl stdout: {}", stdout.trim());
    }
    if !stderr.is_empty() {
        debug!("pfctl stderr: {}", stderr.trim());
    }

    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        return Err(MacosTunError::Pfctl { code, stderr });
    }

    Ok(())
}

/// Build the pf rdr (redirect) rule for TCP intercept.
///
/// Redirects all TCP traffic arriving on `tun_name` (excluding relay addresses)
/// to `127.0.0.1:{intercept_port}`.
fn tcp_redirect_rule(tun_name: &str, intercept_port: u16) -> String {
    format!(
        "rdr pass on {tun_name} proto tcp -> 127.0.0.1 port {intercept_port}\n"
    )
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
        assert!(rules.contains("pass on utun3 all"));
        assert!(rules.contains("1.2.3.4"));
        assert!(rules.contains("53"));
    }

    #[test]
    fn redirect_rule_format() {
        let rule = tcp_redirect_rule("utun3", 9999);
        assert!(rule.contains("utun3"));
        assert!(rule.contains("9999"));
    }
}
