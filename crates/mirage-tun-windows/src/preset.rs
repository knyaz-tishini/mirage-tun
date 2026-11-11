//! The bypass preset: what goes around the tunnel without asking.
//!
//! The policy is the device's own rule book, and it is written by whoever
//! pushes it — the window, the operator, the fleet client.  The preset is
//! the other half: a file that lies beside the device and says "these
//! domains, these networks and these applications go around the tunnel".
//!
//! It exists because the two halves answer different questions.  The
//! network bypass is a hole in the routing — a destination out of the
//! tunnel.  The application bypass is the kernel driver — an application out
//! of the tunnel.  The preset carries both, and the rest of the traffic
//! stays in the tunnel.
//!
//! The file is `bypass-preset.json`:
//!
//! ```json
//! {
//!   "domains": ["yandex.ru", "ozon.ru"],
//!   "cidrs": ["5.45.0.0/16"],
//!   "apps": ["node.exe", "E:\\MU\\main.exe"]
//! }
//! ```
//!
//! Where it is looked for, in this order:
//!
//! 1. the environment variable `MIRAGE_BYPASS_PRESET`;
//! 2. `bypass-preset.json` beside the device's own binary;
//! 3. `C:\ProgramData\mirage2tun\bypass-preset.json`.
//!
//! A file that is not there is not an error: the device goes on without it.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::OnceLock;

use mirage_tun_core::policy::{PolicyDecision, PolicyRule};
use serde::Deserialize;

/// The preset, as the file writes it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Preset {
    /// The names that go around the tunnel.
    #[serde(default)]
    pub domains: Vec<String>,
    /// The networks that go around the tunnel.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// The applications that go around the tunnel.
    #[serde(default)]
    pub apps: Vec<String>,
}

impl Preset {
    /// The preset of this run, read once.
    pub fn get() -> Option<&'static Preset> {
        static PRESET: OnceLock<Option<Preset>> = OnceLock::new();
        PRESET.get_or_init(|| {
            let preset = load()?;
            tracing::info!(
                domains = preset.domains.len(),
                networks = preset.cidrs.len(),
                applications = preset.apps.len(),
                "the bypass preset is here"
            );
            Some(preset)
        })
        .as_ref()
    }

    /// The rules the preset adds to the policy.
    ///
    /// They go AFTER the rules of whoever wrote the policy: the engine
    /// looks at the app rules first, then the names, then the networks, and
    /// within a kind the first match wins — so a rule of the person's own
    /// is not overruled by the preset.
    pub fn policy_rules(&self) -> Vec<PolicyRule> {
        let mut rules = Vec::new();
        for app in &self.apps {
            let app = app.trim();
            if !app.is_empty() {
                rules.push(PolicyRule::DestAppPath {
                    path: app.to_owned(),
                    action: PolicyDecision::Bypass,
                    failure_policy: Default::default(),
                    wire_class: Default::default(),
                });
            }
        }
        for domain in &self.domains {
            let domain = normalize_domain(domain);
            if !domain.is_empty() {
                rules.push(PolicyRule::DestDomain {
                    domain,
                    action: PolicyDecision::Bypass,
                    failure_policy: Default::default(),
                    wire_class: Default::default(),
                });
            }
        }
        for cidr in &self.cidrs {
            let cidr = cidr.trim();
            if !cidr.is_empty() {
                rules.push(PolicyRule::DestCidr {
                    cidr: cidr.to_owned(),
                    action: PolicyDecision::Bypass,
                    failure_policy: Default::default(),
                    wire_class: Default::default(),
                });
            }
        }
        rules
    }

    /// The names of the preset, as they are written.
    ///
    /// They ARE drilled as holes: the adapter takes every packet when the
    /// tunnel is up, so a name can only leave the machine through a hole
    /// that follows its addresses.
    pub fn domain_strings(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .domains
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The networks of the preset, as they are written.
    ///
    /// They are NOT drilled as holes: a hole is a route in the routing
    /// table, and the list of a country is thousands of prefixes.  They stay
    /// in the policy, and the data plane walks out of the tunnel with them.
    pub fn cidr_strings(&self) -> HashSet<String> {
        self.cidrs
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect()
    }

    /// The networks of the preset, parsed.
    pub fn cidr_pairs(&self) -> (HashSet<(u32, u32)>, HashSet<(u128, u128)>) {
        let mut v4 = HashSet::new();
        let mut v6 = HashSet::new();
        for cidr in &self.cidrs {
            let cidr = cidr.trim();
            let Some((addr, prefix)) = cidr.split_once('/') else {
                continue;
            };
            let Ok(prefix) = prefix.parse::<u32>() else {
                continue;
            };
            if let Ok(addr) = addr.parse::<IpAddr>() {
                match addr {
                    IpAddr::V4(a) if prefix <= 32 => {
                        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                        v4.insert((u32::from(a) & mask, mask));
                    }
                    IpAddr::V6(a) if prefix <= 128 => {
                        let mask = if prefix == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix)
                        };
                        v6.insert((u128::from(a) & mask, mask));
                    }
                    _ => {}
                }
            }
        }
        (v4, v6)
    }
}

/// Where the preset may lie.
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("MIRAGE_BYPASS_PRESET") {
        if !path.trim().is_empty() {
            paths.push(PathBuf::from(path));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("bypass-preset.json"));
        }
    }
    paths.push(PathBuf::from(r"C:\ProgramData\mirage2tun\bypass-preset.json"));
    paths
}

/// Read the preset, if there is one.
fn load() -> Option<Preset> {
    for path in candidate_paths() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match serde_json::from_str::<Preset>(&text) {
            Ok(preset) => return Some(preset),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "the bypass preset could not be read");
            }
        }
    }
    None
}

/// The name as the engine wants it: lower case, without the leading dot.
pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return String::new();
    }
    domain
}

/// The address of the machine on the physical interface.
///
/// The kernel is asked which local address would be used to reach the
/// gateway: that is the address the tunnel took over from.
pub fn local_address_for(gateway: IpAddr) -> Option<Ipv4Addr> {
    let gateway = match gateway {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket
        .connect(&socket2::SockAddr::from(std::net::SocketAddr::new(
            IpAddr::V4(gateway),
            9,
        )))
        .ok()?;
    let local = socket.local_addr().ok()?;
    match local.as_socket() {
        Some(std::net::SocketAddr::V4(v4)) => Some(*v4.ip()),
        _ => None,
    }
}

/// The IPv6 form of an address, for the sets that carry both families.
pub fn as_v6(addr: Ipv6Addr) -> u128 {
    u128::from(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_there_is_not_an_error() {
        let dir = std::env::temp_dir().join("mirage-preset-test-missing");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(dir.exists() == false);
    }

    #[test]
    fn the_rules_are_bypass_rules() {
        let preset = Preset {
            domains: vec!["Yandex.RU".to_owned(), "  ".to_owned()],
            cidrs: vec!["5.45.0.0/16".to_owned()],
            apps: vec!["node.exe".to_owned()],
        };
        let rules = preset.policy_rules();
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| match r {
            PolicyRule::DestDomain { action, .. }
            | PolicyRule::DestCidr { action, .. }
            | PolicyRule::DestAppPath { action, .. } => *action == PolicyDecision::Bypass,
            PolicyRule::DestPort { .. } | PolicyRule::DestAppDir { .. } => false,
        }));
        // The name is normalized, the empty one is dropped.
        let domains: Vec<String> = rules
            .iter()
            .filter_map(|r| match r {
                PolicyRule::DestDomain { domain, .. } => Some(domain.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(domains, vec!["yandex.ru".to_owned()]);
    }

    #[test]
    fn the_networks_are_parsed() {
        let preset = Preset {
            cidrs: vec!["5.45.0.0/16".to_owned(), "2a00::/32".to_owned()],
            ..Default::default()
        };
        let (v4, v6) = preset.cidr_pairs();
        assert!(v4.contains(&(0x052d_0000, 0xffff_0000)));
        assert_eq!(v6.len(), 1);
        assert_eq!(preset.cidr_strings().len(), 2);
    }
}
