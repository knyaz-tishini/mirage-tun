use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Runtime routing decision — which chain to use, or bypass entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Route through the named SOCKS5 chain. "default" = legacy mirage path.
    Chain(String),
    /// Connect directly via the native interface (bypass the proxy).
    Bypass,
}

impl PolicyDecision {
    pub fn default_chain() -> Self {
        PolicyDecision::Chain("default".to_owned())
    }
}

impl Serialize for PolicyDecision {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            PolicyDecision::Bypass => s.serialize_str("bypass"),
            PolicyDecision::Chain(name) if name == "default" => s.serialize_str("mirage"),
            PolicyDecision::Chain(name) => s.serialize_str(&format!("chain:{name}")),
        }
    }
}

impl<'de> Deserialize<'de> for PolicyDecision {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "bypass" => PolicyDecision::Bypass,
            "mirage" => PolicyDecision::Chain("default".to_owned()),
            other => {
                if let Some(name) = other.strip_prefix("chain:") {
                    PolicyDecision::Chain(name.to_owned())
                } else {
                    // Treat any unknown string as a named chain for forward compat.
                    PolicyDecision::Chain(other.to_owned())
                }
            }
        })
    }
}

fn default_mirage() -> PolicyDecision {
    PolicyDecision::Chain("default".to_owned())
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
    cidr_table_v4: Vec<(u32, u32, PolicyDecision, usize)>,    // (network_addr, mask, decision, rule_idx)
    cidr_table_v6: Vec<(u128, u128, PolicyDecision, usize)>,  // (network_addr, mask, decision, rule_idx)
    domain_table: Vec<(String, PolicyDecision, usize)>,        // (lowercase suffix, decision, rule_idx)
    port_table: HashMap<u16, (PolicyDecision, usize)>,
    app_path_table: Vec<(String, PolicyDecision, usize)>, // normalized exact exe paths
    app_dir_table: Vec<(String, PolicyDecision, usize)>,  // normalized dir prefixes (trailing /)
    /// Per-rule hit counters shared with MetricsRegistry. Index matches `rules` vec.
    pub rule_hits: Arc<Vec<AtomicU64>>,
}

impl CompiledPolicy {
    pub fn compile(rules: Vec<PolicyRule>, default_action: PolicyDecision) -> Self {
        Self::compile_with_hits(rules, default_action, None)
    }

    /// Compile with an externally provided hit counter vec (from MetricsRegistry).
    pub fn compile_with_hits(
        rules: Vec<PolicyRule>,
        default_action: PolicyDecision,
        rule_hits: Option<Arc<Vec<AtomicU64>>>,
    ) -> Self {
        // Each table entry stores (key, decision, rule_index) so we can increment
        // the correct counter when a rule fires.
        let mut cidr_table_v4: Vec<(u32, u32, PolicyDecision, usize)> = Vec::new();
        let mut cidr_table_v6: Vec<(u128, u128, PolicyDecision, usize)> = Vec::new();
        let mut domain_table: Vec<(String, PolicyDecision, usize)> = Vec::new();
        let mut port_table: HashMap<u16, (PolicyDecision, usize)> = HashMap::new();
        let mut app_path_table: Vec<(String, PolicyDecision, usize)> = Vec::new();
        let mut app_dir_table: Vec<(String, PolicyDecision, usize)> = Vec::new();

        for (idx, rule) in rules.iter().enumerate() {
            match rule {
                PolicyRule::DestCidr { cidr, action } => {
                    match parse_cidr(cidr) {
                        Some(ParsedCidr::V4(addr, mask)) => {
                            cidr_table_v4.push((addr, mask, action.clone(), idx));
                        }
                        Some(ParsedCidr::V6(addr, mask)) => {
                            cidr_table_v6.push((addr, mask, action.clone(), idx));
                        }
                        None => {}
                    }
                }
                PolicyRule::DestDomain { domain, action } => {
                    domain_table.push((domain.to_lowercase(), action.clone(), idx));
                }
                PolicyRule::DestPort { port, action } => {
                    port_table.insert(*port, (action.clone(), idx));
                }
                PolicyRule::DestAppPath { path, action } => {
                    app_path_table.push((normalize_app_path(path), action.clone(), idx));
                }
                PolicyRule::DestAppDir { dir, action } => {
                    let mut normalized = normalize_app_path(dir);
                    if !normalized.ends_with('/') {
                        normalized.push('/');
                    }
                    app_dir_table.push((normalized, action.clone(), idx));
                }
            }
        }

        let hits = rule_hits.unwrap_or_else(|| {
            Arc::new((0..rules.len()).map(|_| AtomicU64::new(0)).collect())
        });

        Self {
            rule_hits: hits,
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
        Self::compile(vec![], PolicyDecision::default_chain())
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
            for (rule_path, decision, rule_idx) in &self.app_path_table {
                for &p in &paths {
                    if p == rule_path.as_str() {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return decision.clone();
                    }
                }
            }

            // Directory prefix match
            for (rule_dir, decision, rule_idx) in &self.app_dir_table {
                for &p in &paths {
                    if p.starts_with(rule_dir.as_str()) {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return decision.clone();
                    }
                }
            }
        }

        // Check domain (most specific among network rules)
        if let Some(domain) = domain_hint {
            let domain_lower = domain.to_lowercase();
            for (suffix, decision, rule_idx) in &self.domain_table {
                let matched = if suffix.starts_with('.') {
                    domain_lower.ends_with(suffix.as_str()) || domain_lower == &suffix[1..]
                } else {
                    domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}"))
                };
                if matched {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return decision.clone();
                }
            }
        }

        // Check port
        if let Some((decision, rule_idx)) = self.port_table.get(&dst_port) {
            if let Some(counter) = self.rule_hits.get(*rule_idx) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            return decision.clone();
        }

        // Check CIDR — IPv4
        if let IpAddr::V4(v4) = dst_ip {
            let ip_u32 = u32::from(v4);
            for (network, mask, decision, rule_idx) in &self.cidr_table_v4 {
                if ip_u32 & mask == network & mask {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return decision.clone();
                }
            }
        }

        // Check CIDR — IPv6
        if let IpAddr::V6(v6) = dst_ip {
            let ip_u128 = u128::from(v6);
            for (network, mask, decision, rule_idx) in &self.cidr_table_v6 {
                if ip_u128 & mask == network & mask {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return decision.clone();
                }
            }
        }

        self.default_action.clone()
    }

    /// DNS routing decision for `domain`.
    ///
    /// When `app_info` is provided the app-path / app-dir tables are checked
    /// FIRST, mirroring the precedence in `decide()` (app > domain > port >
    /// CIDR > default).  A Bypass-app's DNS query goes `dns_via_native` even
    /// for unlisted domains; a chain-marked app routes via its chain.
    /// Unattributed queries (app_info = None) fall through to existing domain
    /// logic unchanged.
    pub fn domain_decision(
        &self,
        domain: &str,
        app_info: Option<&crate::process_info::ProcessInfo>,
    ) -> PolicyDecision {
        // App-based checks first — same precedence as decide().
        if let Some(info) = app_info {
            let paths: Vec<&str> = std::iter::once(info.exe_path.as_str())
                .chain(info.ancestor_paths.iter().map(|s| s.as_str()))
                .collect();

            // Exact path match.
            for (rule_path, decision, rule_idx) in &self.app_path_table {
                for &p in &paths {
                    if p == rule_path.as_str() {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return decision.clone();
                    }
                }
            }

            // Directory prefix match.
            for (rule_dir, decision, rule_idx) in &self.app_dir_table {
                for &p in &paths {
                    if p.starts_with(rule_dir.as_str()) {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return decision.clone();
                    }
                }
            }
        }

        // Domain check (unattributed queries + attributed queries whose app
        // has no app-level rule fall through to here).
        let domain_lower = domain.to_lowercase();
        for (suffix, decision, rule_idx) in &self.domain_table {
            let matched = if suffix.starts_with('.') {
                domain_lower.ends_with(suffix.as_str()) || domain_lower == &suffix[1..]
            } else {
                domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}"))
            };
            if matched {
                if let Some(counter) = self.rule_hits.get(*rule_idx) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                return decision.clone();
            }
        }
        self.default_action.clone()
    }

    pub fn bypass_cidrs(&self) -> Vec<(u32, u32)> {
        self.cidr_table_v4.iter()
            .filter(|(_, _, d, _)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _, _)| (*addr, *mask))
            .collect()
    }

    /// Bypass CIDRs for IPv6.
    pub fn bypass_cidrs_v6(&self) -> Vec<(u128, u128)> {
        self.cidr_table_v6.iter()
            .filter(|(_, _, d, _)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _, _)| (*addr, *mask))
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

    pub async fn domain_decision(
        &self,
        domain: &str,
        app_info: Option<&crate::process_info::ProcessInfo>,
    ) -> PolicyDecision {
        let config = self.config.read().await;
        config.domain_decision(domain, app_info)
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
