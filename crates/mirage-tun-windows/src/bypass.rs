//! The holes the bypass punches into the routing.
//!
//! The tunnel takes every packet: while it is up the adapter holds the
//! default route, so a destination the person excluded has no way out
//! except a HOLE -- a route that points at the gateway the machine had
//! before the tunnel took the default.  Those packets never reach the
//! adapter at all, and the destination sees the machine it has always seen.
//!
//! A network is a hole right away.  A NAME is a hole that follows the
//! name: the addresses of a CDN change under it, so the name is resolved
//! again while the tunnel is up and the holes follow.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use tracing::{debug, info, warn};

use mirage_tun_core::policy::CompiledPolicy;

/// The destinations the person kept out of the tunnel.
#[derive(Debug, Default, Clone)]
pub struct BypassPlan {
    /// Networks, in CIDR form.
    pub cidrs: Vec<String>,
    /// Names.
    pub domains: Vec<String>,
    /// Local programs.
    pub apps: Vec<String>,
}

impl BypassPlan {
    /// The networks and the names the policy excluded.
    ///
    /// The policy is the device's own rule book: the GUI writes the
    /// person's choice into it, and a rule that says "bypass" is a hole
    /// waiting to be drilled.
    pub fn from_policy(policy: Option<&CompiledPolicy>) -> Self {
        let Some(policy) = policy else {
            return Self::default();
        };
        let mut apps = Vec::new();
        for rule in &policy.rules {
            if let mirage_tun_core::policy::PolicyRule::DestAppPath { path, action, .. } = rule {
                if *action == mirage_tun_core::policy::PolicyDecision::Bypass {
                    apps.push(path.clone());
                }
            }
        }
        Self {
            cidrs: policy.bypass_cidr_strings(),
            domains: policy.bypass_domains(),
            apps,
        }
    }

    /// The networks and the names the device config excluded.
    pub fn from_config(config: &crate::config::BypassConfig) -> Self {
        Self {
            cidrs: config
                .cidrs
                .iter()
                .map(|cidr| cidr.trim().to_owned())
                .filter(|cidr| !cidr.is_empty())
                .collect(),
            domains: config
                .domains
                .iter()
                .map(|domain| normalize_domain(domain))
                .filter(|domain| !domain.is_empty())
                .collect(),
            apps: Vec::new(),
        }
    }

    /// Take everything another plan holds.
    pub fn merge(&mut self, other: BypassPlan) {
        for cidr in other.cidrs {
            if !self.cidrs.contains(&cidr) {
                self.cidrs.push(cidr);
            }
        }
        for domain in other.domains {
            if !self.domains.contains(&domain) {
                self.domains.push(domain);
            }
        }
        for app in other.apps {
            if !self.apps.contains(&app) {
                self.apps.push(app);
            }
        }
    }

    /// True when the person excluded nothing.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty() && self.apps.is_empty()
    }
}

/// The name as a resolver wants it: without the wildcard, without the
/// leading dot, in lower case.
fn normalize_domain(domain: &str) -> String {
    let mut name = domain.trim().to_ascii_lowercase();
    if let Some(rest) = name.strip_prefix("*.") {
        name = rest.to_owned();
    }
    name.trim_start_matches('.').to_owned()
}

/// Ask a resolver for the addresses of a name.
///
/// The resolver is a plain UDP server.  The bypass must know the addresses
/// the machine itself would talk to -- the ones the application will use
/// when the tunnel is off -- so the hole covers the right addresses.
pub async fn resolve(server: SocketAddr, name: &str, timeout: Duration) -> Vec<IpAddr> {
    // The two kinds of address are asked at the same time: a resolver that
    // stays silent costs the same as the slowest of them, not twice that.
    let (v4, v6) = futures::join!(
        resolve_one(server, name, 1, timeout),
        resolve_one(server, name, 28, timeout)
    );
    let mut addresses = Vec::new();
    if let Some(ips) = v4 {
        addresses.extend(ips);
    }
    if let Some(ips) = v6 {
        addresses.extend(ips);
    }
    addresses
}

/// One question, one answer.
async fn resolve_one(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Option<Vec<IpAddr>> {
    let id = transaction_id();
    let query = build_query(id, name, qtype);
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.send_to(&query, server).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let read = match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((read, _))) => read,
        Ok(Err(e)) => {
            warn!(%server, name, error = %e, "bypass: the resolver refused the question");
            return None;
        }
        Err(_) => {
            debug!(%server, name, "bypass: the resolver did not answer in time");
            return None;
        }
    };
    // The answer must carry the id of the question: another question may
    // have been answered in the meantime.
    if read < 2 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    let ips = mirage_dns::parse_answer_ips(&buf[..read]);
    if ips.is_empty() {
        debug!(%server, name, "bypass: the name has no address");
    }
    Some(ips)
}

/// The id of a question.  It only has to differ between two questions that
/// are open at the same time.
fn transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0x4d47);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The wire form of a question.
fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + name.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes()); // one question
    buf.extend_from_slice(&0u16.to_be_bytes()); // no answer
    buf.extend_from_slice(&0u16.to_be_bytes()); // no authority
    buf.extend_from_slice(&0u16.to_be_bytes()); // no additional
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            continue;
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // the root
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
    buf
}

/// The addresses of a name, as the holes need them.
///
/// Two answers are collected: the one the machine's own resolver gives
/// (the addresses the application sees with the tunnel off) and the one
/// the tunnel's resolver gives (the addresses the application sees with
/// the tunnel on).  The hole covers both, so the traffic leaves the
/// machine whichever answer the application took.
pub async fn resolve_both(
    native: Option<SocketAddr>,
    tunnel: Option<SocketAddr>,
    name: &str,
    timeout: Duration,
) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    if let Some(server) = native {
        addresses.extend(resolve(server, name, timeout).await);
    }
    if let Some(server) = tunnel {
        if Some(server) != native {
            addresses.extend(resolve(server, name, timeout).await);
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

/// The addresses of a name, from every resolver that answers.
///
/// A resolver that stays silent is the rule on a line where the provider
/// filters the questions: the names of the country are asked of the router
/// and of the provider's own resolver, and the answers of every one of them
/// are taken.  The questions go out together, so a silent resolver costs no
/// more time than the slowest of them.
pub async fn resolve_any(servers: &[SocketAddr], name: &str, timeout: Duration) -> Vec<IpAddr> {
    resolve_with(servers, name, timeout).await.addresses
}

/// What the machine's own resolvers answered.
///
/// The addresses are the ones the machine itself would talk to -- the ones
/// the application will use when the tunnel is off -- so the hole covers the
/// right addresses.  The counts say who answered: a resolver that stays
/// silent is the rule on a line where the provider filters the questions, and
/// a silent resolver must never become the adapter's own.
#[derive(Debug, Default)]
pub struct ResolverAnswers {
    /// Every address the resolvers gave.
    pub addresses: Vec<IpAddr>,
    /// The resolver that answered the most: the one the adapter is given.
    pub best: Option<SocketAddr>,
    /// How many names each resolver answered.
    pub counts: Vec<(SocketAddr, usize)>,
}

/// The addresses of a name, and the resolver that answered.
///
/// The resolver that answered is the one the machine can ask: it becomes the
/// adapter's own resolver, so the names of the machine keep working.  A
/// resolver that stays silent must never become the adapter's: the machine
/// would lose its names altogether.
pub async fn resolve_with(
    servers: &[SocketAddr],
    name: &str,
    timeout: Duration,
) -> ResolverAnswers {
    if servers.is_empty() {
        return ResolverAnswers::default();
    }
    let mut questions: Vec<_> = Vec::with_capacity(servers.len());
    for server in servers {
        let server = *server;
        questions.push(async move {
            let ips = resolve(server, name, timeout).await;
            (server, ips)
        });
    }
    let pairs: Vec<(SocketAddr, Vec<IpAddr>)> = futures::stream::iter(questions)
        .buffer_unordered(4)
        .collect()
        .await;

    let mut answers = ResolverAnswers::default();
    let mut counts: Vec<(SocketAddr, usize)> = Vec::with_capacity(pairs.len());
    let mut addresses: Vec<IpAddr> = Vec::new();
    for (server, ips) in pairs {
        counts.push((server, ips.len()));
        addresses.extend(ips);
    }
    // The resolver that answered the most speaks for the machine.  The order
    // of the list breaks a tie: the one the interface names comes first.
    counts.sort_by_key(|(server, count)| {
        let order = servers.iter().position(|s| s == server).unwrap_or(usize::MAX);
        (std::cmp::Reverse(*count), order)
    });
    answers.best = counts
        .iter()
        .find(|(_, count)| *count > 0)
        .map(|(server, _)| *server);
    answers.counts = counts;
    addresses.sort();
    addresses.dedup();
    answers.addresses = addresses;
    answers
}

/// The IPv4 form of a prefix, the way the firewall wants it:
/// the network address and the mask.
pub fn cidr_to_wfp(cidr: &str) -> Option<(u32, u32)> {
    let (ip, prefix) = crate::routing::parse_cidr(cidr).ok()?;
    let IpAddr::V4(v4) = ip else {
        return None;
    };
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((u32::from(v4) & mask, mask))
}

/// The IPv6 form of a prefix, the way the firewall wants it.
pub fn cidr_to_wfp_v6(cidr: &str) -> Option<(u128, u128)> {
    let (ip, prefix) = crate::routing::parse_cidr(cidr).ok()?;
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    if prefix > 128 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Some((u128::from(v6) & mask, mask))
}

/// True when a hole for this prefix is safe to drill.
///
/// A hole that covers the loopback, the tunnel's own address or the whole
/// address space would break the machine itself: the tunnel talks to
/// itself over the loopback, and its own address must stay inside the
/// adapter.
pub fn hole_is_safe(cidr: &str, tunnel_addr: Option<IpAddr>) -> bool {
    let Ok((ip, prefix)) = crate::routing::parse_cidr(cidr) else {
        return false;
    };
    // The whole address space: the tunnel already holds the default route.
    if prefix == 0 {
        return false;
    }
    let IpAddr::V4(v4) = ip else {
        return true;
    };
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = u32::from(v4) & mask;
    // 127.0.0.0/8 -- the machine talks to itself.
    if net & 0xff00_0000 == 0x7f00_0000 {
        return false;
    }
    // The tunnel's own address.
    if let Some(IpAddr::V4(tun)) = tunnel_addr {
        if (u32::from(tun) & mask) == net {
            return false;
        }
    }
    true
}

/// Log the plan once, so the person can see what was excluded.
pub fn log_plan(plan: &BypassPlan) {
    if plan.is_empty() {
        return;
    }
    info!(
        networks = plan.cidrs.len(),
        names = plan.domains.len(),
        "bypass: the plan is ready"
    );
    for cidr in &plan.cidrs {
        info!(cidr, "bypass: the network leaves the machine the way it always did");
    }
    for domain in &plan.domains {
        info!(domain, "bypass: the name leaves the machine the way it always did");
    }
    for app in &plan.apps {
        warn!(
            app,
            "bypass: the local program cannot be routed out of the tunnel by a route; name the destination instead"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_loses_its_wildcard_and_its_case() {
        assert_eq!(normalize_domain("*.Example.COM"), "example.com");
        assert_eq!(normalize_domain("agent.minimax.io"), "agent.minimax.io");
        assert_eq!(normalize_domain("  .example.com "), "example.com");
    }

    #[test]
    fn the_plan_keeps_one_copy_of_everything() {
        let mut plan = BypassPlan {
            cidrs: vec!["10.0.0.0/8".into()],
            domains: vec!["a.example".into()],
            apps: Vec::new(),
        };
        plan.merge(BypassPlan {
            cidrs: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            domains: vec!["a.example".into(), "b.example".into()],
            apps: vec!["node.exe".into()],
        });
        assert_eq!(plan.cidrs.len(), 2);
        assert_eq!(plan.domains.len(), 2);
        assert_eq!(plan.apps.len(), 1);
    }

    #[test]
    fn a_question_names_its_type() {        let query = build_query(0x1234, "example.com", 1);
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        // qdcount = 1
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        assert!(query.windows(7).any(|w| w == b"example"));
        // the tail: type A, class IN
        assert_eq!(&query[query.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn a_hole_that_would_break_the_machine_is_refused() {
        let tun: IpAddr = "10.77.0.2".parse().unwrap();
        // the loopback: the tunnel talks to itself over it
        assert!(!hole_is_safe("127.0.0.0/8", Some(tun)));
        assert!(!hole_is_safe("127.0.0.1/32", Some(tun)));
        // the tunnel's own address
        assert!(!hole_is_safe("10.0.0.0/8", Some(tun)));
        // the whole address space
        assert!(!hole_is_safe("0.0.0.0/0", Some(tun)));
        // ordinary exclusions are fine
        assert!(hole_is_safe("192.168.0.0/16", Some(tun)));
        assert!(hole_is_safe("2.17.251.112/32", Some(tun)));
    }
}
