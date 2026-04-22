use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Mirage,
    Bypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    DestCidr { cidr: String, action: PolicyDecision },
    DestDomain { domain: String, action: PolicyDecision },
    DestPort { port: u16, action: PolicyDecision },
    /// Exact exe path match (case-insensitive, slash-normalized).
    DestAppPath { path: String, action: PolicyDecision },
    /// Directory prefix match — any exe whose normalized path starts with this dir prefix.
    DestAppDir { dir: String, action: PolicyDecision },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfigRequest {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default = "default_mirage")]
    pub default_action: PolicyDecision,
}

fn default_mirage() -> PolicyDecision { PolicyDecision::Mirage }

/// Parsed CIDR — either IPv4 (network_u32, mask_u32) or IPv6 (network_u128, mask_u128).
enum ParsedCidr {
    V4(u32, u32),
    V6(u128, u128),
}

fn parse_cidr(cidr: &str) -> Option<ParsedCidr> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
        let prefix_len: u32 = prefix_str.parse().ok()?;
        if prefix_len > 32 { return None; }
        let mask = if prefix_len == 0 { 0u32 } else { !0u32 << (32 - prefix_len) };
        return Some(ParsedCidr::V4(u32::from(v4), mask));
    }
    if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
        let prefix_len: u32 = prefix_str.parse().ok()?;
        if prefix_len > 128 { return None; }
        let mask: u128 = if prefix_len == 0 { 0u128 } else { !0u128 << (128 - prefix_len) };
        return Some(ParsedCidr::V6(u128::from(v6), mask));
    }
    None
}

/// Compiled policy — fast lookup structures.
pub struct CompiledPolicy {
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyDecision,
    cidr_table_v4: Vec<(u32, u32, PolicyDecision)>,    // (network_addr, mask, decision)
    cidr_table_v6: Vec<(u128, u128, PolicyDecision)>,  // (network_addr, mask, decision)
    domain_table: Vec<(String, PolicyDecision)>,        // (lowercase suffix, decision)
    port_table: HashMap<u16, PolicyDecision>,
    app_path_table: Vec<(String, PolicyDecision)>, // normalized exact exe paths
    app_dir_table: Vec<(String, PolicyDecision)>,  // normalized dir prefixes (trailing /)
}

impl CompiledPolicy {
    pub fn compile(rules: Vec<PolicyRule>, default_action: PolicyDecision) -> Self {
        let mut cidr_table_v4 = Vec::new();
        let mut cidr_table_v6 = Vec::new();
        let mut domain_table = Vec::new();
        let mut port_table = HashMap::new();
        let mut app_path_table = Vec::new();
        let mut app_dir_table = Vec::new();

        for rule in &rules {
            match rule {
                PolicyRule::DestCidr { cidr, action } => {
                    match parse_cidr(cidr) {
                        Some(ParsedCidr::V4(addr, mask)) => {
                            cidr_table_v4.push((addr, mask, *action));
                        }
                        Some(ParsedCidr::V6(addr, mask)) => {
                            cidr_table_v6.push((addr, mask, *action));
                        }
                        None => {}
                    }
                }
                PolicyRule::DestDomain { domain, action } => {
                    domain_table.push((domain.to_lowercase(), *action));
                }
                PolicyRule::DestPort { port, action } => {
                    port_table.insert(*port, *action);
                }
                PolicyRule::DestAppPath { path, action } => {
                    app_path_table.push((normalize_app_path(path), *action));
                }
                PolicyRule::DestAppDir { dir, action } => {
                    let mut normalized = normalize_app_path(dir);
                    if !normalized.ends_with('/') {
                        normalized.push('/');
                    }
                    app_dir_table.push((normalized, *action));
                }
            }
        }

        Self {
            rules,
            default_action,
            cidr_table_v4,
            cidr_table_v6,
            domain_table,
            port_table,
            app_path_table,
            app_dir_table,
        }
    }

    pub fn mirage_only() -> Self {
        Self::compile(vec![], PolicyDecision::Mirage)
    }

    pub fn decide(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        app_info: Option<&crate::process_info::ProcessInfo>,
    ) -> PolicyDecision {
        // App-based checks first (most specific — overrides domain/port/CIDR)
        if let Some(info) = app_info {
            let paths: Vec<&str> = std::iter::once(info.exe_path.as_str())
                .chain(info.ancestor_paths.iter().map(|s| s.as_str()))
                .collect();

            // Exact path match
            for (rule_path, decision) in &self.app_path_table {
                for &p in &paths {
                    if p == rule_path.as_str() {
                        return *decision;
                    }
                }
            }

            // Directory prefix match
            for (rule_dir, decision) in &self.app_dir_table {
                for &p in &paths {
                    if p.starts_with(rule_dir.as_str()) {
                        return *decision;
                    }
                }
            }
        }

        // Check domain (most specific among network rules)
        if let Some(domain) = domain_hint {
            let domain_lower = domain.to_lowercase();
            for (suffix, decision) in &self.domain_table {
                if suffix.starts_with('.') {
                    if domain_lower.ends_with(suffix.as_str()) || domain_lower == &suffix[1..] {
                        return *decision;
                    }
                } else if domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}")) {
                    return *decision;
                }
            }
        }

        // Check port
        if let Some(decision) = self.port_table.get(&dst_port) {
            return *decision;
        }

        // Check CIDR — IPv4
        if let IpAddr::V4(v4) = dst_ip {
            let ip_u32 = u32::from(v4);
            for &(network, mask, decision) in &self.cidr_table_v4 {
                if ip_u32 & mask == network & mask {
                    return decision;
                }
            }
        }

        // Check CIDR — IPv6
        if let IpAddr::V6(v6) = dst_ip {
            let ip_u128 = u128::from(v6);
            for &(network, mask, decision) in &self.cidr_table_v6 {
                if ip_u128 & mask == network & mask {
                    return decision;
                }
            }
        }

        self.default_action
    }

    pub fn domain_decision(&self, domain: &str) -> PolicyDecision {
        let domain_lower = domain.to_lowercase();
        for (suffix, decision) in &self.domain_table {
            if suffix.starts_with('.') {
                if domain_lower.ends_with(suffix.as_str()) || domain_lower == &suffix[1..] {
                    return *decision;
                }
            } else if domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}")) {
                return *decision;
            }
        }
        self.default_action
    }

    pub fn bypass_cidrs(&self) -> Vec<(u32, u32)> {
        self.cidr_table_v4.iter()
            .filter(|(_, _, d)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _)| (*addr, *mask))
            .collect()
    }

    /// Bypass CIDRs for IPv6.
    pub fn bypass_cidrs_v6(&self) -> Vec<(u128, u128)> {
        self.cidr_table_v6.iter()
            .filter(|(_, _, d)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _)| (*addr, *mask))
            .collect()
    }
}

fn normalize_app_path(p: &str) -> String {
    p.to_lowercase().replace('\\', "/")
}

pub struct PolicyEngine {
    config: RwLock<Arc<CompiledPolicy>>,
}

impl PolicyEngine {
    pub fn new(config: CompiledPolicy) -> Self {
        Self { config: RwLock::new(Arc::new(config)) }
    }

    pub fn mirage_only() -> Self {
        Self::new(CompiledPolicy::mirage_only())
    }

    pub async fn decide(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        app_info: Option<&crate::process_info::ProcessInfo>,
    ) -> PolicyDecision {
        let config = self.config.read().await;
        config.decide(dst_ip, dst_port, domain_hint, app_info)
    }

    pub async fn domain_decision(&self, domain: &str) -> PolicyDecision {
        let config = self.config.read().await;
        config.domain_decision(domain)
    }

    pub async fn update(&self, new_config: CompiledPolicy) {
        let mut config = self.config.write().await;
        *config = Arc::new(new_config);
    }

    pub async fn get_config(&self) -> Arc<CompiledPolicy> {
        self.config.read().await.clone()
    }

    pub async fn bypass_cidrs(&self) -> Vec<(u32, u32)> {
        let config = self.config.read().await;
        config.bypass_cidrs()
    }

    pub async fn bypass_cidrs_v6(&self) -> Vec<(u128, u128)> {
        let config = self.config.read().await;
        config.bypass_cidrs_v6()
    }
}
