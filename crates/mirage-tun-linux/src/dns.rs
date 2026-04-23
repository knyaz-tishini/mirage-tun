use std::net::IpAddr;
use std::path::Path;
use async_trait::async_trait;
use tokio::process::Command;
use tracing::{debug, info, warn};

use mirage_tun_core::traits::{PlatformDns, private};
use crate::error::LinuxTunError;

/// DNS backend detected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBackend {
    /// systemd-resolved: use `resolvectl dns` + `resolvectl domain`.
    SystemdResolved,
    /// Plain /etc/resolv.conf: backup and overwrite.
    ResolvConf,
}

const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP: &str = "/tmp/mirage-resolv.conf.bak";

pub struct LinuxDns {
    backend: DnsBackend,
    tun_name: Option<String>,
    resolv_conf_backed_up: bool,
}

impl LinuxDns {
    pub async fn detect() -> Self {
        let backend = detect_dns_backend().await;
        info!("DNS backend: {backend:?}");
        Self {
            backend,
            tun_name: None,
            resolv_conf_backed_up: false,
        }
    }
}

impl private::Sealed for LinuxDns {}

#[async_trait]
impl PlatformDns for LinuxDns {
    type Error = LinuxTunError;

    async fn set_dns(
        &mut self,
        tun_name: &str,
        servers: &[IpAddr],
    ) -> Result<(), Self::Error> {
        if servers.is_empty() {
            return Ok(());
        }
        self.tun_name = Some(tun_name.to_owned());

        match self.backend {
            DnsBackend::SystemdResolved => {
                set_dns_resolvectl(tun_name, servers).await?;
            }
            DnsBackend::ResolvConf => {
                set_dns_resolv_conf(servers, &mut self.resolv_conf_backed_up).await?;
            }
        }

        info!("DNS set for {tun_name}: {:?}", servers);
        Ok(())
    }

    async fn revert_dns(&mut self) -> Result<(), Self::Error> {
        match self.backend {
            DnsBackend::SystemdResolved => {
                if let Some(ref tun_name) = self.tun_name {
                    revert_dns_resolvectl(tun_name).await?;
                }
            }
            DnsBackend::ResolvConf => {
                if self.resolv_conf_backed_up {
                    revert_dns_resolv_conf().await?;
                    self.resolv_conf_backed_up = false;
                }
            }
        }
        self.tun_name = None;
        info!("DNS reverted");
        Ok(())
    }
}

// ── Detection ─────────────────────────────────────────────────────────────────

async fn detect_dns_backend() -> DnsBackend {
    // Check if /etc/resolv.conf is a symlink pointing to systemd/resolved.
    match tokio::fs::read_link(RESOLV_CONF).await {
        Ok(target) => {
            let target_str = target.to_string_lossy();
            if target_str.contains("systemd") || target_str.contains("resolved") {
                return DnsBackend::SystemdResolved;
            }
        }
        Err(_) => {
            // Not a symlink — plain resolv.conf
        }
    }
    // Check if resolvectl binary exists.
    let out = Command::new("which").arg("resolvectl").output().await;
    if matches!(out, Ok(o) if o.status.success()) {
        return DnsBackend::SystemdResolved;
    }
    DnsBackend::ResolvConf
}

// ── systemd-resolved ──────────────────────────────────────────────────────────

async fn set_dns_resolvectl(tun_name: &str, servers: &[IpAddr]) -> Result<(), LinuxTunError> {
    let server_args: Vec<String> = servers.iter().map(|s| s.to_string()).collect();

    let mut cmd_args = vec!["dns".to_string(), tun_name.to_string()];
    cmd_args.extend(server_args);

    let out = Command::new("resolvectl")
        .args(&cmd_args)
        .output()
        .await?;
    debug!("resolvectl dns: status={}", out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(LinuxTunError::Dns(format!(
            "resolvectl dns failed (exit {}): {stderr}",
            out.status.code().unwrap_or(-1)
        )));
    }

    // Set catch-all routing domain so all queries go through this interface.
    let out = Command::new("resolvectl")
        .args(["domain", tun_name, "~."])
        .output()
        .await?;
    debug!("resolvectl domain: status={}", out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("resolvectl domain failed: {stderr}");
    }

    // Make tun0 the default DNS interface.
    let out = Command::new("resolvectl")
        .args(["default-route", tun_name, "true"])
        .output()
        .await?;
    debug!("resolvectl default-route: status={}", out.status);

    Ok(())
}

async fn revert_dns_resolvectl(tun_name: &str) -> Result<(), LinuxTunError> {
    let out = Command::new("resolvectl")
        .args(["revert", tun_name])
        .output()
        .await?;
    debug!("resolvectl revert: status={}", out.status);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        warn!("resolvectl revert failed: {stderr}");
    }
    Ok(())
}

// ── /etc/resolv.conf ──────────────────────────────────────────────────────────

async fn set_dns_resolv_conf(
    servers: &[IpAddr],
    backed_up: &mut bool,
) -> Result<(), LinuxTunError> {
    // Backup current file.
    if Path::new(RESOLV_CONF).exists() {
        tokio::fs::copy(RESOLV_CONF, RESOLV_CONF_BACKUP).await?;
        *backed_up = true;
        debug!("Backed up {RESOLV_CONF} → {RESOLV_CONF_BACKUP}");
    }

    // Write new file.
    let content: String = servers
        .iter()
        .map(|s| format!("nameserver {s}\n"))
        .collect();
    tokio::fs::write(RESOLV_CONF, content).await?;
    debug!("Wrote {RESOLV_CONF}");
    Ok(())
}

async fn revert_dns_resolv_conf() -> Result<(), LinuxTunError> {
    if Path::new(RESOLV_CONF_BACKUP).exists() {
        tokio::fs::copy(RESOLV_CONF_BACKUP, RESOLV_CONF).await?;
        let _ = tokio::fs::remove_file(RESOLV_CONF_BACKUP).await;
        debug!("Restored {RESOLV_CONF}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_content_format() {
        use std::str::FromStr;
        let servers: Vec<IpAddr> = vec![
            IpAddr::from_str("10.8.0.1").unwrap(),
            IpAddr::from_str("1.1.1.1").unwrap(),
        ];
        let content: String = servers
            .iter()
            .map(|s| format!("nameserver {s}\n"))
            .collect();
        assert!(content.contains("nameserver 10.8.0.1\n"));
        assert!(content.contains("nameserver 1.1.1.1\n"));
    }
}
