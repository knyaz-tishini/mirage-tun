/// macOS DNS configuration.
///
/// Primary strategy: write resolver files to `/etc/resolver/mirage`.
/// mDNSResponder picks these up automatically — no reboot required.
///
/// Secondary strategy: `networksetup -setdnsservers` for the active
/// network service (Wi-Fi / Ethernet).
///
/// Revert: delete the resolver file and restore original DNS via networksetup.
use crate::error::MacosTunError;
use async_trait::async_trait;
use mirage_tun_core::traits::{PlatformDns, private::Sealed};
use std::net::IpAddr;
use tracing::{debug, info, warn};

const RESOLVER_DIR: &str = "/etc/resolver";
const RESOLVER_FILE: &str = "/etc/resolver/mirage";

/// macOS DNS manager.
pub struct MacosDns {
    /// Original DNS servers per active network service, saved before override.
    original_dns: Vec<(String, Vec<String>)>,
    /// Whether we wrote the resolver file.
    resolver_written: bool,
}

impl MacosDns {
    pub fn new() -> Self {
        MacosDns {
            original_dns: Vec::new(),
            resolver_written: false,
        }
    }
}

impl Default for MacosDns {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealed for MacosDns {}

#[async_trait]
impl PlatformDns for MacosDns {
    type Error = MacosTunError;

    async fn set_dns(
        &mut self,
        _tun_name: &str,
        servers: &[IpAddr],
    ) -> Result<(), Self::Error> {
        if servers.is_empty() {
            return Ok(());
        }

        let server_strs: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();

        // 1. Save current DNS for all active network services
        self.original_dns = get_all_service_dns().await;

        // 2. Write /etc/resolver/mirage (domain-specific wildcard resolver)
        write_resolver_file(servers).await?;
        self.resolver_written = true;

        // 3. Override DNS for each active network service via networksetup
        for (service, _) in &self.original_dns {
            match set_service_dns(service, &server_strs).await {
                Ok(()) => debug!("set DNS on service '{}': {:?}", service, server_strs),
                Err(e) => warn!("set DNS on service '{}' failed: {}", service, e),
            }
        }

        info!("DNS set to {:?}", server_strs);
        Ok(())
    }

    async fn revert_dns(&mut self) -> Result<(), Self::Error> {
        // 1. Remove resolver file
        if self.resolver_written {
            match tokio::fs::remove_file(RESOLVER_FILE).await {
                Ok(()) => debug!("removed resolver file {}", RESOLVER_FILE),
                Err(e) => warn!("remove resolver file failed: {}", e),
            }
            self.resolver_written = false;
        }

        // 2. Restore original DNS for each service
        for (service, original_servers) in self.original_dns.drain(..) {
            match restore_service_dns(&service, &original_servers).await {
                Ok(()) => debug!("restored DNS on service '{}'", service),
                Err(e) => warn!("restore DNS on service '{}' failed: {}", service, e),
            }
        }

        info!("DNS reverted");
        Ok(())
    }
}

/// Write `/etc/resolver/mirage` with the given DNS servers.
async fn write_resolver_file(servers: &[IpAddr]) -> Result<(), MacosTunError> {
    let mut content = String::new();
    for server in servers {
        content.push_str(&format!("nameserver {}\n", server));
    }

    // Ensure directory exists
    tokio::fs::create_dir_all(RESOLVER_DIR)
        .await
        .map_err(MacosTunError::Io)?;

    tokio::fs::write(RESOLVER_FILE, &content)
        .await
        .map_err(MacosTunError::Io)?;

    debug!("wrote resolver file {}:\n{}", RESOLVER_FILE, content.trim());
    Ok(())
}

/// Get list of active network services via `networksetup -listallnetworkservices`.
async fn get_active_services() -> Vec<String> {
    use tokio::process::Command;

    let out = match Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!("networksetup -listallnetworkservices failed: {}", e);
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    // First line is a header ("An asterisk (*) denotes that a network service is disabled.")
    stdout
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// Get current DNS servers for a network service. Returns empty vec if none / error.
async fn get_service_dns(service: &str) -> Vec<String> {
    use tokio::process::Command;

    let out = match Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    // Output is either "There aren't any DNS Servers set on ..." or one IP per line
    if stdout.contains("aren't any DNS") || stdout.contains("aren't any") {
        return Vec::new();
    }

    stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Get DNS for all active network services.
async fn get_all_service_dns() -> Vec<(String, Vec<String>)> {
    let services = get_active_services().await;
    let mut result = Vec::new();
    for svc in services {
        let dns = get_service_dns(&svc).await;
        result.push((svc, dns));
    }
    result
}

/// Set DNS servers for a network service.
async fn set_service_dns(service: &str, servers: &[String]) -> Result<(), MacosTunError> {
    use tokio::process::Command;

    let mut args = vec!["networksetup", "-setdnsservers", service];
    let server_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
    args.extend_from_slice(&server_refs);

    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .await
        .map_err(MacosTunError::Io)?;

    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(MacosTunError::Networksetup { code, stderr });
    }

    Ok(())
}

/// Restore original DNS for a network service.
async fn restore_service_dns(service: &str, original: &[String]) -> Result<(), MacosTunError> {
    if original.is_empty() {
        // Restore to "empty" (no custom DNS)
        set_service_dns(service, &["Empty".to_string()]).await
    } else {
        set_service_dns(service, original).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_initial_state() {
        let dns = MacosDns::new();
        assert!(!dns.resolver_written);
        assert!(dns.original_dns.is_empty());
    }
}
