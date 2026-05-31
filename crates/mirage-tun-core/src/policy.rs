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

// ── Failure-policy types (Wave 1 — additive, all serde-defaulted) ─────────────

/// What to do when the preferred wire for a flow is unhealthy.
/// Absent in config → `FailClosed` (today's implicit behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum FailurePolicy {
    /// Fail the flow closed immediately on wire-down (RST, no egress).
    /// No reroute ever — containment case (e.g. Tor-pinned flows).
    #[default]
    FailClosed,
    /// Reroute to another healthy wire in the named group.
    /// If no healthy wire in group: fail closed (RST). NEVER bypass-as-fallback.
    Failover { group: String },
}

/// A wire class label — opaque string used for containment identity.
/// Default = empty string (treated as "default" class downstream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WireClass(pub String);

/// Full routing decision returned by `CompiledPolicy::decide_full`.
/// Contains everything the accept loop needs: the action, the failure policy,
/// and the wire class.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub action: PolicyDecision,
    pub failure_policy: FailurePolicy,
    pub wire_class: WireClass,
}

// ── Policy rules ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    DestCidr {
        cidr: String,
        action: PolicyDecision,
        #[serde(default)]
        failure_policy: FailurePolicy,
        #[serde(default)]
        wire_class: WireClass,
    },
    DestDomain {
        domain: String,
        action: PolicyDecision,
        #[serde(default)]
        failure_policy: FailurePolicy,
        #[serde(default)]
        wire_class: WireClass,
    },
    DestPort {
        port: u16,
        action: PolicyDecision,
        #[serde(default)]
        failure_policy: FailurePolicy,
        #[serde(default)]
        wire_class: WireClass,
    },
    /// Exact exe path match (case-insensitive, slash-normalized).
    DestAppPath {
        path: String,
        action: PolicyDecision,
        #[serde(default)]
        failure_policy: FailurePolicy,
        #[serde(default)]
        wire_class: WireClass,
    },
    /// Directory prefix match — any exe whose normalized path starts with this dir prefix.
    DestAppDir {
        dir: String,
        action: PolicyDecision,
        #[serde(default)]
        failure_policy: FailurePolicy,
        #[serde(default)]
        wire_class: WireClass,
    },
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

/// Normalized (lowercase, forward-slash) exe path of a process and its ancestors.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full path, lowercased, backslashes replaced with forward slashes.
    pub exe_path: String,
    /// Parent chain, up to 5 levels, same normalization.
    pub ancestor_paths: Vec<String>,
}

// ── Compiled policy ────────────────────────────────────────────────────────────

/// Compiled policy — fast lookup structures.
pub struct CompiledPolicy {
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyDecision,
    pub default_failure_policy: FailurePolicy,
    pub default_wire_class: WireClass,
    cidr_table_v4: Vec<(u32, u32, PolicyDecision, FailurePolicy, WireClass, usize)>,
    cidr_table_v6: Vec<(u128, u128, PolicyDecision, FailurePolicy, WireClass, usize)>,
    domain_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)>,
    port_table: HashMap<u16, (PolicyDecision, FailurePolicy, WireClass, usize)>,
    app_path_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)>,
    app_dir_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)>,
    /// Per-rule hit counters. Index matches `rules` vec.
    pub rule_hits: Arc<Vec<AtomicU64>>,
}

impl CompiledPolicy {
    pub fn compile(rules: Vec<PolicyRule>, default_action: PolicyDecision) -> Self {
        Self::compile_with_hits(rules, default_action, None)
    }

    /// Compile with an externally provided hit counter vec.
    /// The default `FailurePolicy` and `WireClass` for unmatched flows are
    /// always `FailClosed` / empty — additive defaults, no config surface.
    pub fn compile_with_hits(
        rules: Vec<PolicyRule>,
        default_action: PolicyDecision,
        rule_hits: Option<Arc<Vec<AtomicU64>>>,
    ) -> Self {
        let mut cidr_table_v4: Vec<(u32, u32, PolicyDecision, FailurePolicy, WireClass, usize)> = Vec::new();
        let mut cidr_table_v6: Vec<(u128, u128, PolicyDecision, FailurePolicy, WireClass, usize)> = Vec::new();
        let mut domain_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)> = Vec::new();
        let mut port_table: HashMap<u16, (PolicyDecision, FailurePolicy, WireClass, usize)> = HashMap::new();
        let mut app_path_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)> = Vec::new();
        let mut app_dir_table: Vec<(String, PolicyDecision, FailurePolicy, WireClass, usize)> = Vec::new();

        for (idx, rule) in rules.iter().enumerate() {
            match rule {
                PolicyRule::DestCidr { cidr, action, failure_policy, wire_class } => {
                    match parse_cidr(cidr) {
                        Some(ParsedCidr::V4(addr, mask)) => {
                            cidr_table_v4.push((addr, mask, action.clone(), failure_policy.clone(), wire_class.clone(), idx));
                        }
                        Some(ParsedCidr::V6(addr, mask)) => {
                            cidr_table_v6.push((addr, mask, action.clone(), failure_policy.clone(), wire_class.clone(), idx));
                        }
                        None => {}
                    }
                }
                PolicyRule::DestDomain { domain, action, failure_policy, wire_class } => {
                    domain_table.push((domain.to_lowercase(), action.clone(), failure_policy.clone(), wire_class.clone(), idx));
                }
                PolicyRule::DestPort { port, action, failure_policy, wire_class } => {
                    port_table.insert(*port, (action.clone(), failure_policy.clone(), wire_class.clone(), idx));
                }
                PolicyRule::DestAppPath { path, action, failure_policy, wire_class } => {
                    app_path_table.push((normalize_app_path(path), action.clone(), failure_policy.clone(), wire_class.clone(), idx));
                }
                PolicyRule::DestAppDir { dir, action, failure_policy, wire_class } => {
                    let mut normalized = normalize_app_path(dir);
                    if !normalized.ends_with('/') {
                        normalized.push('/');
                    }
                    app_dir_table.push((normalized, action.clone(), failure_policy.clone(), wire_class.clone(), idx));
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
            default_failure_policy: FailurePolicy::default(),
            default_wire_class: WireClass::default(),
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

    /// Existing single-wire API — unchanged. All callers continue to work.
    pub fn decide(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        app_info: Option<&ProcessInfo>,
    ) -> PolicyDecision {
        self.decide_full(dst_ip, dst_port, domain_hint, app_info).action
    }

    /// Full routing decision including failure policy and wire class.
    /// Implements the same lookup order as the former `decide()`.
    pub fn decide_full(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        app_info: Option<&ProcessInfo>,
    ) -> RoutingDecision {
        // App-based checks first (most specific — overrides domain/port/CIDR)
        if let Some(info) = app_info {
            let paths: Vec<&str> = std::iter::once(info.exe_path.as_str())
                .chain(info.ancestor_paths.iter().map(|s| s.as_str()))
                .collect();

            for (rule_path, decision, fp, wc, rule_idx) in &self.app_path_table {
                for &p in &paths {
                    if p == rule_path.as_str() {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return RoutingDecision {
                            action: decision.clone(),
                            failure_policy: fp.clone(),
                            wire_class: wc.clone(),
                        };
                    }
                }
            }

            for (rule_dir, decision, fp, wc, rule_idx) in &self.app_dir_table {
                for &p in &paths {
                    if p.starts_with(rule_dir.as_str()) {
                        if let Some(counter) = self.rule_hits.get(*rule_idx) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return RoutingDecision {
                            action: decision.clone(),
                            failure_policy: fp.clone(),
                            wire_class: wc.clone(),
                        };
                    }
                }
            }
        }

        // Check domain (most specific among network rules)
        if let Some(domain) = domain_hint {
            let domain_lower = domain.to_lowercase();
            for (suffix, decision, fp, wc, rule_idx) in &self.domain_table {
                let matched = if suffix.starts_with('.') {
                    domain_lower.ends_with(suffix.as_str()) || domain_lower == &suffix[1..]
                } else {
                    domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}"))
                };
                if matched {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return RoutingDecision {
                        action: decision.clone(),
                        failure_policy: fp.clone(),
                        wire_class: wc.clone(),
                    };
                }
            }
        }

        // Check port
        if let Some((decision, fp, wc, rule_idx)) = self.port_table.get(&dst_port) {
            if let Some(counter) = self.rule_hits.get(*rule_idx) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            return RoutingDecision {
                action: decision.clone(),
                failure_policy: fp.clone(),
                wire_class: wc.clone(),
            };
        }

        // Check CIDR — IPv4
        if let IpAddr::V4(v4) = dst_ip {
            let ip_u32 = u32::from(v4);
            for (network, mask, decision, fp, wc, rule_idx) in &self.cidr_table_v4 {
                if ip_u32 & mask == network & mask {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return RoutingDecision {
                        action: decision.clone(),
                        failure_policy: fp.clone(),
                        wire_class: wc.clone(),
                    };
                }
            }
        }

        // Check CIDR — IPv6
        if let IpAddr::V6(v6) = dst_ip {
            let ip_u128 = u128::from(v6);
            for (network, mask, decision, fp, wc, rule_idx) in &self.cidr_table_v6 {
                if ip_u128 & mask == network & mask {
                    if let Some(counter) = self.rule_hits.get(*rule_idx) {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    return RoutingDecision {
                        action: decision.clone(),
                        failure_policy: fp.clone(),
                        wire_class: wc.clone(),
                    };
                }
            }
        }

        RoutingDecision {
            action: self.default_action.clone(),
            failure_policy: self.default_failure_policy.clone(),
            wire_class: self.default_wire_class.clone(),
        }
    }

    pub fn domain_decision(&self, domain: &str) -> PolicyDecision {
        let domain_lower = domain.to_lowercase();
        for (suffix, decision, _fp, _wc, rule_idx) in &self.domain_table {
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
            .filter(|(_, _, d, _, _, _)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _, _, _, _)| (*addr, *mask))
            .collect()
    }

    pub fn bypass_cidrs_v6(&self) -> Vec<(u128, u128)> {
        self.cidr_table_v6.iter()
            .filter(|(_, _, d, _, _, _)| *d == PolicyDecision::Bypass)
            .map(|(addr, mask, _, _, _, _)| (*addr, *mask))
            .collect()
    }

    /// Raw CIDR strings (as written in the rules) of every `DestCidr` rule whose
    /// action is `Bypass`. Used by the platform routing layer to install
    /// `route add -net <cidr> <gw>` so bypass-plane traffic egresses the real NIC
    /// instead of the TUN — the macOS/Win parity for the operator's "байпас канал".
    /// Domains are NOT included (can't be pre-routed without resolution).
    pub fn bypass_cidr_strings(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                PolicyRule::DestCidr { cidr, action, .. } if *action == PolicyDecision::Bypass => {
                    Some(cidr.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Domains (as written) of every `DestDomain` rule whose action is `Bypass`.
    /// The DNS path uses these to resolve+egress direct for bypass-plane domains.
    pub fn bypass_domains(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                PolicyRule::DestDomain { domain, action, .. } if *action == PolicyDecision::Bypass => {
                    Some(domain.to_lowercase())
                }
                _ => None,
            })
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
        app_info: Option<&ProcessInfo>,
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

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn cidr_rule(cidr: &str, action: PolicyDecision) -> PolicyRule {
        PolicyRule::DestCidr {
            cidr: cidr.to_owned(),
            action,
            failure_policy: FailurePolicy::default(),
            wire_class: WireClass::default(),
        }
    }

    fn cidr_rule_with_fp(cidr: &str, action: PolicyDecision, fp: FailurePolicy) -> PolicyRule {
        PolicyRule::DestCidr {
            cidr: cidr.to_owned(),
            action,
            failure_policy: fp,
            wire_class: WireClass::default(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ── FailurePolicy serde ────────────────────────────────────────────────────

    #[test]
    fn failure_policy_default_is_fail_closed() {
        let fp = FailurePolicy::default();
        assert_eq!(fp, FailurePolicy::FailClosed);
    }

    #[test]
    fn failure_policy_serde_round_trip_fail_closed() {
        let json = r#"{"mode":"fail_closed"}"#;
        let fp: FailurePolicy = serde_json::from_str(json).unwrap();
        assert_eq!(fp, FailurePolicy::FailClosed);
        let out = serde_json::to_string(&fp).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn failure_policy_serde_round_trip_failover() {
        let json = r#"{"mode":"failover","group":"primary"}"#;
        let fp: FailurePolicy = serde_json::from_str(json).unwrap();
        assert_eq!(fp, FailurePolicy::Failover { group: "primary".to_owned() });
        let out = serde_json::to_string(&fp).unwrap();
        assert_eq!(out, json);
    }

    #[test]
    fn failure_policy_absent_in_rule_defaults_to_fail_closed() {
        // JSON with no failure_policy field — serde(default) must kick in.
        let json = r#"{"type":"dest_cidr","cidr":"10.0.0.0/8","action":"mirage"}"#;
        let rule: PolicyRule = serde_json::from_str(json).unwrap();
        match rule {
            PolicyRule::DestCidr { failure_policy, .. } => {
                assert_eq!(failure_policy, FailurePolicy::FailClosed);
            }
            _ => panic!("unexpected variant"),
        }
    }

    // ── decide() backward compat ───────────────────────────────────────────────

    #[test]
    fn decide_default_action_unchanged() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        assert_eq!(
            policy.decide(ip("8.8.8.8"), 443, None, None),
            PolicyDecision::Chain("default".to_owned()),
        );
    }

    #[test]
    fn decide_cidr_match() {
        let rules = vec![cidr_rule("10.0.0.0/8", PolicyDecision::Bypass)];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        assert_eq!(policy.decide(ip("10.1.2.3"), 80, None, None), PolicyDecision::Bypass);
        assert_eq!(policy.decide(ip("8.8.8.8"), 80, None, None), PolicyDecision::Chain("default".to_owned()));
    }

    // ── decide_full ────────────────────────────────────────────────────────────

    #[test]
    fn decide_full_no_failure_policy_returns_fail_closed() {
        let rules = vec![cidr_rule("10.0.0.0/8", PolicyDecision::Bypass)];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        let rd = policy.decide_full(ip("10.1.2.3"), 80, None, None);
        assert_eq!(rd.action, PolicyDecision::Bypass);
        assert_eq!(rd.failure_policy, FailurePolicy::FailClosed);
        assert_eq!(rd.wire_class, WireClass::default());
    }

    #[test]
    fn decide_full_with_failover_policy_round_trips() {
        let fp = FailurePolicy::Failover { group: "g".to_owned() };
        let rules = vec![cidr_rule_with_fp("10.0.0.0/8", PolicyDecision::Chain("nl".to_owned()), fp.clone())];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        let rd = policy.decide_full(ip("10.1.2.3"), 80, None, None);
        assert_eq!(rd.action, PolicyDecision::Chain("nl".to_owned()));
        assert_eq!(rd.failure_policy, fp);
    }

    #[test]
    fn decide_full_no_match_returns_defaults() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let rd = policy.decide_full(ip("1.2.3.4"), 80, None, None);
        assert_eq!(rd.action, PolicyDecision::Chain("default".to_owned()));
        assert_eq!(rd.failure_policy, FailurePolicy::FailClosed);
        assert_eq!(rd.wire_class, WireClass::default());
    }

    #[test]
    fn decide_full_action_matches_decide() {
        let rules = vec![
            cidr_rule("8.8.8.0/24", PolicyDecision::Chain("tr".to_owned())),
            cidr_rule("1.0.0.0/8", PolicyDecision::Bypass),
        ];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        for (addr_str, port) in &[("8.8.8.8", 443u16), ("1.0.0.1", 80), ("9.9.9.9", 53)] {
            let addr = ip(addr_str);
            assert_eq!(
                policy.decide(addr, *port, None, None),
                policy.decide_full(addr, *port, None, None).action,
                "decide and decide_full.action must agree for {addr_str}"
            );
        }
    }
}
