/// macOS TUN stack — userspace TCP via mirage-tcpip-stack (smoltcp).
///
/// Architecture:
///   utun fd → read loop → smoltcp Stack (Sink) → TcpListener / UdpSocket
///   TcpListener → per-conn forward task → SOCKS5 → chain exit
///   UdpSocket → udp_forward loop → SOCKS5 UDP ASSOCIATE → chain exit
///   smoltcp Stack (Stream) → write loop → utun fd
use crate::{
    dns::MacosDns,
    dns_route::dns_via_socks5,
    error::MacosTunError,
    firewall::MacosFirewall,
    metrics::MetricsRegistry,
    route_monitor::spawn_route_monitor,
    routing::MacosRouting,
    runtime_guard::{MemoryGuard, MemoryGuardConfig},
    smoltcp_acceptor::{SmoltcpTcpAcceptor, SmoltcpUdpSocket},
    tun_device::{MacosTunDevice, configure_interface_with_v6},
    udp_forward::{UdpProxySessionMap, udp_proxy_forward},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{udp::UdpMsg, StackBuilder};
use mirage_tun_core::{
    chains::{ChainConfig, ChainRegistry},
    metrics::StackMetrics,
    stack_config::StackConfig,
    traits::{
        private::Sealed, PlatformDns, PlatformFirewall, PlatformRouting, StackHandle,
        TunStack,
    },
    wire_health::WireHealthMap,
};
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// macOS TUN stack. Implements `TunStack` from mirage-tun-core.
pub struct MacosTunStack;

impl Sealed for MacosTunStack {}

impl MacosTunStack {
    /// Start the stack and return the `StackHandle` (for trait compat), the
    /// per-chain `MetricsRegistry`, and the hot-reloadable `ChainRegistry`
    /// (both for the API server).
    pub async fn start_with_metrics(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<(StackHandle<SmoltcpTcpAcceptor, SmoltcpUdpSocket>, Arc<MetricsRegistry>, Arc<ChainRegistry>), MacosTunError> {
        // Phase 2b: multiple chains are now routed per-flow by policy (TCP path).
        // The first chain remains the default (used when no policy rule matches,
        // and for the DNS/UDP paths until those gain per-flow routing too).
        let chain_entry = cfg
            .chains
            .first()
            .ok_or_else(|| MacosTunError::Other("no chains configured".to_string()))?;

        let socks5_addr = chain_entry.socks5_addr;
        let chain_name = chain_entry.name.clone();

        // Build ChainRegistry seeded from config — exposed via /chains/list and
        // updated at runtime via /chains/update.
        let chain_registry: Arc<ChainRegistry> = Arc::new(ChainRegistry::new(
            cfg.chains
                .iter()
                .map(|c| ChainConfig {
                    name: c.name.clone(),
                    socks5_addr: c.socks5_addr.to_string(),
                    protocol: Default::default(),
                    dns_upstream: None,
                })
                .collect(),
        ));

        // Build per-chain DNS upstream map: chain_name → first server IP as SocketAddr :53.
        // Falls back to cfg.dns_upstream when chain has no entry.
        let chain_dns_map: HashMap<String, SocketAddr> = cfg
            .chain_dns
            .iter()
            .filter_map(|c| {
                c.servers.first().map(|ip| {
                    let sa = match ip {
                        IpAddr::V4(v4) => SocketAddr::from((*v4, 53)),
                        IpAddr::V6(v6) => SocketAddr::from((*v6, 53)),
                    };
                    (c.chain_name.clone(), sa)
                })
            })
            .collect();
        let global_dns_upstream = cfg.dns_upstream;
        // For the single-chain macOS stack, pick the first chain's DNS upstream.
        let dns_upstream_for_chain: SocketAddr = cfg
            .chains
            .first()
            .and_then(|c| chain_dns_map.get(&c.name).copied())
            .unwrap_or(global_dns_upstream);

        // Phase 2a — bypass plane. Compile the policy and extract Bypass CIDRs.
        // These egress the real NIC directly (route via original gw + pf pass +
        // smoltcp ip_filter exclude) — the operator's "байпас канал", plane-pure:
        // wire flows still traverse the tun, only bypass CIDRs go direct.
        let compiled_policy = mirage_tun_core::policy::CompiledPolicy::compile(
            cfg.policy.rules.clone(),
            cfg.policy.default_action.clone(),
        );
        let bypass_cidr_strings = compiled_policy.bypass_cidr_strings();
        let bypass_v4: Vec<(u32, u32)> = compiled_policy.bypass_cidrs();
        let bypass_v6: Vec<(u128, u128)> = compiled_policy.bypass_cidrs_v6();
        if !bypass_cidr_strings.is_empty() {
            info!(bypass_cidrs = ?bypass_cidr_strings, "Phase 2a: bypass-plane CIDRs configured");
        }

        // Phase 2b — per-flow WIRE selection. The policy decides which wire (chain)
        // a flow uses; `chain_socks_map` maps the chosen chain name → its SOCKS5
        // addr. With a single chain + the default Chain("default") action the
        // lookup misses → fallback to the first chain (byte-identical to today).
        // Bypass dsts never reach the TCP accept loop (ip_filter excludes them).
        let chain_socks_map: HashMap<String, SocketAddr> = cfg
            .chains
            .iter()
            .map(|c| (c.name.clone(), c.socks5_addr))
            .collect();
        let policy_arc = Arc::new(compiled_policy);
        let chain_socks_arc = Arc::new(chain_socks_map);
        if cfg.chains.len() > 1 {
            info!(wires = cfg.chains.len(), "Phase 2b: multi-wire routing (policy → chain)");
        }

        // Wave 3 — per-wire liveness + failover groups.
        // WireHealthMap: shared between the accept loop and each forward_tcp task.
        // Updated on each SOCKS5 connect success/failure; consulted at accept time
        // to enforce fail-closed / failover semantics before spawning a task.
        let wire_health = WireHealthMap::new();

        // WireGroupMap: group_name → ordered Vec<(chain_name, socks5_addr)>.
        // Built once at startup. Chains without a group do not appear here;
        // a Failover rule naming an unknown/empty group degrades to fail-closed.
        let wire_group_map: HashMap<String, Vec<(String, SocketAddr)>> = {
            let mut m: HashMap<String, Vec<(String, SocketAddr)>> = HashMap::new();
            for c in &cfg.chains {
                if let Some(ref g) = c.group {
                    m.entry(g.clone())
                        .or_default()
                        .push((c.name.clone(), c.socks5_addr));
                }
            }
            m
        };
        let wire_groups_arc = Arc::new(wire_group_map);

        // 1. Open utun device
        let device = MacosTunDevice::open(0)?;
        let tun_name = device.interface_name().to_string();

        // 2. Configure IPv4 (and optional IPv6) on the same interface in one
        //    ifconfig pass — calling configure() then configure_interface_with_v6()
        //    runs ifconfig twice on the v4 args and clobbers the P2P peer.
        configure_interface_with_v6(
            &tun_name,
            &cfg.tun_addr,
            cfg.tun_addr_v6.as_deref(),
            cfg.mtu,
        )
        .await?;
        info!(
            "utun interface: {} addr={} v6={:?} mtu={}",
            tun_name, cfg.tun_addr, cfg.tun_addr_v6, cfg.mtu
        );

        // 3. Set up firewall — bypass-safe pf posture is ALWAYS on.
        // No global block, no kill-switch toggle. The posture only passes the tun +
        // relays + bypass plane + DHCP/53; selective fail-closed for dead wires is
        // enforced at the accept loop (routing layer), not pf.
        let mut firewall = MacosFirewall::new();
        // Bypass-plane CIDRs get `pass out` rules so they egress the real NIC
        // via their original-gw routes (plane-pure: wire flows still go through tun).
        firewall.set_bypass_nets(bypass_cidr_strings.clone());
        firewall.activate(&cfg.relay_addrs, &tun_name, &[53])?;

        // 4. Add bypass routes for relay addresses
        let routing = Arc::new(Mutex::new(MacosRouting::new()));
        {
            let mut r = routing.lock().await;
            let local_addr = cfg.tun_addr.split('/').next().unwrap_or(&cfg.tun_addr);
            let peer_addr = derive_peer_ip(local_addr);
            if let Ok(p) = peer_addr.parse::<std::net::IpAddr>() {
                r.set_tun_peer(p);
            }
            // Set the v6 "peer" — for utun on macOS the TUN addr itself is used
            // as the nexthop for the ::/1 + 8000::/1 half-default routes.
            if let Some(ref v6_cidr) = cfg.tun_addr_v6 {
                let v6_addr_str = v6_cidr.split('/').next().unwrap_or(v6_cidr);
                if let Ok(v6_addr) = v6_addr_str.parse::<std::net::IpAddr>() {
                    r.set_tun_peer_v6(v6_addr);
                }
            }
            for relay in &cfg.relay_addrs {
                r.add_bypass_host(*relay).await?;
            }
            // Bypass-plane CIDRs routed via the original gateway (before the /1
            // overrides inside set_default_route) → they egress the real NIC.
            r.set_bypass_nets(bypass_cidr_strings.clone());
            // 5. Set default route AFTER stack read loop is about to start
            r.set_default_route(&tun_name).await?;
        }

        // 6. Set DNS
        let mut dns = MacosDns::new();
        if !cfg.chain_dns.is_empty() {
            let servers: Vec<std::net::IpAddr> = cfg
                .chain_dns
                .iter()
                .flat_map(|c| c.servers.iter().copied())
                .collect();
            dns.set_dns(&tun_name, &servers).await?;
        }

        // 7. Build smoltcp stack
        let relay_set: Arc<std::collections::HashSet<std::net::IpAddr>> =
            Arc::new(cfg.relay_addrs.iter().copied().collect());
        let relay_set2 = relay_set.clone();
        // Bypass CIDRs excluded from smoltcp interception too (they route direct
        // via the original gw). Belt-and-suspenders parity with relay handling:
        // even if a bypass packet reaches the tun before its route lands, smoltcp
        // must not grab it.
        let bypass_v4_filter = Arc::new(bypass_v4.clone());
        let bypass_v6_filter = Arc::new(bypass_v6.clone());

        let (stack, runner, udp_socket_opt, tcp_listener_opt) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(cfg.mtu as usize)
            .add_ip_filter_fn(move |_src, dst| {
                if relay_set2.contains(dst) {
                    return false;
                }
                let bypassed = match dst {
                    IpAddr::V4(v4) => {
                        let u = u32::from(*v4);
                        bypass_v4_filter.iter().any(|(net, mask)| u & mask == net & mask)
                    }
                    IpAddr::V6(v6) => {
                        let u = u128::from(*v6);
                        bypass_v6_filter.iter().any(|(net, mask)| u & mask == net & mask)
                    }
                };
                !bypassed
            })
            .build()
            .map_err(|e| MacosTunError::Other(format!("smoltcp build: {e}")))?;

        let tcp_listener = tcp_listener_opt
            .ok_or_else(|| MacosTunError::Other("TCP listener not returned".to_string()))?;
        let udp_socket = udp_socket_opt
            .ok_or_else(|| MacosTunError::Other("UDP socket not returned".to_string()))?;

        if let Some(r) = runner {
            tokio::spawn(r);
        }

        let (mut stack_sink, mut stack_stream) = stack.split();

        // Per-chain metrics registry — returned to the caller for the API server.
        let chain_metrics_registry = Arc::new(MetricsRegistry::new());
        // Pre-register the single chain so it appears in /metrics even before
        // any connection is made.
        chain_metrics_registry.get_or_create(&chain_name);

        // Flat StackMetrics kept for StackHandle trait compat (unused by mac api).
        let flat_metrics = Arc::new(StackMetrics::default());

        let device = Arc::new(device);
        let device_writer = Arc::clone(&device);

        // 8. Read loop: utun fd → smoltcp stack
        let read_cancel = cancel.clone();
        let routing_teardown = Arc::clone(&routing);
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(1504);
            loop {
                tokio::select! {
                    biased;
                    _ = read_cancel.cancelled() => {
                        info!("TUN read loop cancelled");
                        break;
                    }
                    result = device.read_packet(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                let pkt = buf.clone();
                                if let Err(e) = stack_sink.feed(pkt).await {
                                    warn!("stack sink error: {e}");
                                }
                                let _ = stack_sink.flush().await;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!("TUN read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            {
                let mut r = routing_teardown.lock().await;
                if let Err(e) = r.restore_routes().await {
                    error!("restore routes failed: {}", e);
                }
            }
            if let Err(e) = dns.revert_dns().await {
                error!("revert DNS failed: {}", e);
            }
            if let Err(e) = firewall.deactivate() {
                error!("firewall deactivate failed: {}", e);
            }
        });

        // 9. Write loop: smoltcp stack → utun fd
        let write_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = write_cancel.cancelled() => break,
                    pkt = stack_stream.next() => match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = device_writer.write_packet(&pkt).await {
                                error!("TUN write error: {}", e);
                            }
                        }
                        _ => break,
                    }
                }
            }
        });

        // 10. TCP accept loop: smoltcp TcpListener → policy → per-wire SOCKS5 forward
        let tcp_cancel = cancel.clone();
        let tcp_metrics = Arc::clone(&chain_metrics_registry);
        let tcp_default_chain = chain_name.clone();
        let tcp_policy = Arc::clone(&policy_arc);
        let tcp_chain_socks = Arc::clone(&chain_socks_arc);
        let tcp_wire_health = Arc::clone(&wire_health);
        let tcp_wire_groups = Arc::clone(&wire_groups_arc);
        tokio::spawn(async move {
            tcp_accept_loop(
                tcp_listener,
                tcp_policy,
                tcp_chain_socks,
                socks5_addr,
                tcp_default_chain,
                tcp_cancel,
                tcp_metrics,
                tcp_wire_health,
                tcp_wire_groups,
            )
            .await;
        });

        // 11. UDP forward loop: smoltcp UdpSocket → SOCKS5 UDP ASSOCIATE → chain
        let (udp_read, mut udp_write) = udp_socket.split();
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<UdpMsg>();

        // Writer half: inject SOCKS5 replies back into the smoltcp stack
        tokio::spawn(async move {
            while let Some(msg) = resp_rx.recv().await {
                if let Err(e) = udp_write.send(msg).await {
                    warn!("UDP forward: write into stack failed: {e}");
                    break;
                }
            }
        });

        // Reader half: receive from smoltcp, dispatch per-flow SOCKS5 sessions.
        // Port 53 → DNS-via-SOCKS5 TCP CONNECT (intercept before UDP ASSOCIATE).
        // All other UDP → SOCKS5 UDP ASSOCIATE.
        let udp_sessions: UdpProxySessionMap = Arc::new(Mutex::new(HashMap::new()));

        // Phase 2c: per-channel DNS routing.
        // One ForwardCache per wire (keyed by chain name) so cached answers for
        // wire A are never served to a query routed through wire B (split-DNS
        // correctness). The map is lazily populated; the default chain is seeded
        // eagerly so the common single-chain case allocates no extra lock traffic.
        let dns_caches: Arc<Mutex<HashMap<String, Arc<mirage_dns::ForwardCache>>>> = {
            let mut m: HashMap<String, Arc<mirage_dns::ForwardCache>> = HashMap::new();
            m.insert(chain_name.clone(), Arc::new(mirage_dns::ForwardCache::new(4096)));
            Arc::new(Mutex::new(m))
        };

        let udp_cancel = cancel.clone();
        let udp_metrics = Arc::clone(&chain_metrics_registry);
        let udp_chain_name = chain_name.clone();
        // Phase 2c captures
        let dns_policy = Arc::clone(&policy_arc);
        let dns_chain_socks = Arc::clone(&chain_socks_arc);
        // Wrap chain_dns_map in an Arc so it can be moved into the spawn closure.
        let dns_chain_dns: Arc<HashMap<String, SocketAddr>> = Arc::new(chain_dns_map);
        let default_chain_name = chain_name.clone();
        tokio::spawn(async move {
            let mut udp_read = udp_read;
            loop {
                tokio::select! {
                    biased;
                    _ = udp_cancel.cancelled() => break,
                    item = futures::StreamExt::next(&mut udp_read) => match item {
                        None => break,
                        Some((payload, src_addr, dst_addr)) => {
                            if dst_addr.port() == 53 {
                                // Phase 2c: per-channel DNS routing.
                                // Route each DNS query to the wire selected by the query's
                                // domain (policy), using that wire's SOCKS5 + DNS upstream.
                                // dst_addr.ip() from the guest is ignored — chain DNS
                                // overrides whatever the app asked (matches Windows semantics).
                                use mirage_tun_core::policy::PolicyDecision;

                                let domain = mirage_dns::protocol::parse_question(&payload)
                                    .map(|(q, _)| q.qname);

                                let (wire_name, dns_socks, dns_upstream) = match domain.as_deref() {
                                    Some(d) => match dns_policy.domain_decision(d) {
                                        PolicyDecision::Chain(name) => {
                                            let socks = dns_chain_socks.get(&name).copied()
                                                .unwrap_or(socks5_addr);
                                            let up = dns_chain_dns.get(&name).copied()
                                                .unwrap_or(global_dns_upstream);
                                            (name, socks, up)
                                        }
                                        // Bypass-domain: no direct-resolver path yet (bypass
                                        // plane is CIDR-based today). Resolve via the default
                                        // chain + global upstream — still tunneled, never a
                                        // plaintext DNS leak. A true direct-NIC bypass resolver
                                        // is a follow-up.
                                        PolicyDecision::Bypass => {
                                            (default_chain_name.clone(), socks5_addr, global_dns_upstream)
                                        }
                                    },
                                    // Malformed / EDNS-only packet: fall back to default chain.
                                    None => (default_chain_name.clone(), socks5_addr, dns_upstream_for_chain),
                                };

                                // Lazily create per-wire ForwardCache so a cached answer for
                                // wire A is never served to a query routed through wire B.
                                let fc = {
                                    let mut caches = dns_caches.lock().await;
                                    caches.entry(wire_name.clone())
                                        .or_insert_with(|| Arc::new(mirage_dns::ForwardCache::new(4096)))
                                        .clone()
                                };

                                tracing::debug!(
                                    domain = domain.as_deref().unwrap_or("<unknown>"),
                                    wire = %wire_name,
                                    upstream = %dns_upstream,
                                    "DNS routed per-channel (Phase 2c)"
                                );

                                let tx = resp_tx.clone();
                                let q = payload.clone();
                                let q2 = q.clone();
                                tokio::spawn(async move {
                                    let res = fc.resolve(&q, move || async move {
                                        dns_via_socks5(&q2, dns_socks, dns_upstream).await
                                    }).await;
                                    match res {
                                        Ok(response) => {
                                            let _ = tx.send((response, dst_addr, src_addr));
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                wire = %wire_name,
                                                upstream = %dns_upstream,
                                                "DNS resolve via SOCKS5 failed: {e}"
                                            );
                                        }
                                    }
                                });
                            } else {
                                let chain_m = udp_metrics.get_or_create(&udp_chain_name);
                                udp_proxy_forward(
                                    payload,
                                    src_addr,
                                    dst_addr,
                                    resp_tx.clone(),
                                    udp_sessions.clone(),
                                    socks5_addr,
                                    chain_m,
                                ).await;
                            }
                        }
                    }
                }
            }
        });

        // 12. Memory guard + route monitor
        let _memory_guard = MemoryGuard::spawn(
            MemoryGuardConfig::default(),
            Box::new(|| {
                tracing::error!("memory guard fatal — exiting");
                std::process::exit(1);
            }),
        );

        spawn_route_monitor(tun_name, Arc::clone(&routing), cancel.clone());

        // UDP socket consumed by forward loop above; expose noop for StackHandle.
        let udp = SmoltcpUdpSocket::noop();

        // TCP forwarding is self-contained in tcp_accept_loop; expose noop for StackHandle.
        let tcp = SmoltcpTcpAcceptor::noop();

        Ok((StackHandle { tcp, udp, metrics: flat_metrics }, chain_metrics_registry, chain_registry))
    }
}

#[async_trait]
impl TunStack for MacosTunStack {
    type Device = MacosTunDevice;
    type Tcp = SmoltcpTcpAcceptor;
    type Udp = SmoltcpUdpSocket;
    type Error = MacosTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        let (handle, _chain_metrics, _chain_registry) = Self::start_with_metrics(cfg, cancel).await?;
        Ok(handle)
    }
}

// ── SOCKS5 TCP forward ────────────────────────────────────────────────────────

async fn tcp_accept_loop(
    mut listener: mirage_tcpip_stack::TcpListener,
    policy: Arc<mirage_tun_core::policy::CompiledPolicy>,
    chain_socks: Arc<HashMap<String, SocketAddr>>,
    default_socks: SocketAddr,
    default_chain: String,
    cancel: CancellationToken,
    metrics: Arc<MetricsRegistry>,
    wire_health: Arc<WireHealthMap>,
    wire_groups: Arc<HashMap<String, Vec<(String, SocketAddr)>>>,
) {
    use mirage_tun_core::policy::{FailurePolicy, PolicyDecision};
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            conn = listener.next() => match conn {
                None => break,
                Some((stream, _local, remote)) => {
                    // Wave 3: full routing decision — includes failure policy.
                    // Bypass dsts never arrive here (ip_filter excludes them).
                    let decision = policy.decide_full(remote.ip(), remote.port(), None, None);

                    // Resolve the (wire_name, socks5_addr) to use, or None → fail-closed.
                    let chosen: Option<(String, SocketAddr)> = match decision.action {
                        // Bypass should never reach here, but if it does (domain-bypass
                        // without a pre-installed route): fall back to default chain.
                        // Bypass is unconditional and never affected by wire health.
                        PolicyDecision::Bypass => Some((default_chain.clone(), default_socks)),

                        PolicyDecision::Chain(name) => {
                            // Resolve preferred wire's socks addr.
                            // Unknown chain name → fall back to default chain.
                            let (pref_name, pref_socks) = if chain_socks.contains_key(&name) {
                                let s = *chain_socks.get(&name).expect("checked above");
                                (name, s)
                            } else {
                                (default_chain.clone(), default_socks)
                            };

                            match decision.failure_policy {
                                FailurePolicy::FailClosed => {
                                    // No reroute ever. Fail closed if wire is unhealthy.
                                    if wire_health.is_healthy(&pref_name) {
                                        Some((pref_name, pref_socks))
                                    } else {
                                        None
                                    }
                                }
                                FailurePolicy::Failover { ref group } => {
                                    // Try group members in order. Unknown/empty group →
                                    // degrade to fail-closed on the preferred wire.
                                    match wire_groups.get(group) {
                                        Some(cands) if !cands.is_empty() => {
                                            match wire_health.first_healthy(cands) {
                                                Some(pair) => {
                                                    if pair.0 != pref_name {
                                                        info!(
                                                            dst = %remote,
                                                            preferred = %pref_name,
                                                            chosen = %pair.0,
                                                            group = %group,
                                                            "failover: preferred wire down, rerouting"
                                                        );
                                                    }
                                                    Some(pair.clone())
                                                }
                                                // All group members unhealthy → fail closed.
                                                None => None,
                                            }
                                        }
                                        _ => {
                                            // Unknown or empty group → fall back to
                                            // fail-closed semantics on preferred wire.
                                            if wire_health.is_healthy(&pref_name) {
                                                Some((pref_name, pref_socks))
                                            } else {
                                                None
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    };

                    match chosen {
                        Some((chain_name, socks5_addr)) => {
                            metrics.record_connection(&chain_name);
                            let chain_m = metrics.get_or_create(&chain_name);
                            tokio::spawn(forward_tcp(
                                stream,
                                remote,
                                socks5_addr,
                                chain_name,
                                Arc::clone(&wire_health),
                                chain_m,
                            ));
                        }
                        None => {
                            // Fail-closed: drop the accepted stream → smoltcp RST.
                            // Zero egress. No reroute. Bypass plane is untouched.
                            warn!(dst = %remote, "wire fail-closed (unhealthy, no healthy failover) — RST");
                            drop(stream);
                        }
                    }
                }
            }
        }
    }
}

/// Open a SOCKS5 connection to `socks5_addr`, CONNECT to `target`, then
/// bidirectionally pipe `stream` to the SOCKS5 channel.
///
/// SOCKS5 no-auth CONNECT per RFC 1928.
///
/// Wave 3: `wire_name` and `wire_health` are used to record success/failure
/// so the accept loop can make health-aware routing decisions for future flows.
async fn forward_tcp(
    mut stream: mirage_tcpip_stack::TcpStream,
    target: SocketAddr,
    socks5_addr: SocketAddr,
    wire_name: String,
    wire_health: Arc<WireHealthMap>,
    chain_metrics: Arc<crate::metrics::ChainMetrics>,
) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut socks = match tokio::net::TcpStream::connect(socks5_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("SOCKS5 connect to {} failed: {}", socks5_addr, e);
            wire_health.record_failure(&wire_name);
            chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    if let Err(e) = socks.write_all(&[0x05, 0x01, 0x00]).await {
        warn!("SOCKS5 greeting write failed: {e}");
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let mut resp = [0u8; 2];
    if let Err(e) = socks.read_exact(&mut resp).await {
        warn!("SOCKS5 greeting read failed: {e}");
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if resp[0] != 0x05 || resp[1] != 0x00 {
        warn!("SOCKS5 auth method rejected: {:?}", resp);
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // CONNECT request
    let req = build_socks5_connect(target);
    if let Err(e) = socks.write_all(&req).await {
        warn!("SOCKS5 CONNECT write failed: {e}");
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Response: VER RSP RSV ATYP ... (min 10 bytes for IPv4)
    let mut hdr = [0u8; 4];
    if let Err(e) = socks.read_exact(&mut hdr).await {
        warn!("SOCKS5 CONNECT response read failed: {e}");
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if hdr[1] != 0x00 {
        warn!("SOCKS5 CONNECT failed, reply code: 0x{:02x}", hdr[1]);
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Drain bound address from response
    let skip = match hdr[3] {
        0x01 => 4 + 2,          // IPv4 + port
        0x04 => 16 + 2,         // IPv6 + port
        0x03 => {
            let mut len = [0u8; 1];
            if socks.read_exact(&mut len).await.is_err() {
                wire_health.record_failure(&wire_name);
                chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            len[0] as usize + 2
        }
        _ => {
            warn!("SOCKS5 unknown atyp: 0x{:02x}", hdr[3]);
            wire_health.record_failure(&wire_name);
            chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let mut tail = vec![0u8; skip];
    if let Err(e) = socks.read_exact(&mut tail).await {
        warn!("SOCKS5 bound addr read failed: {e}");
        wire_health.record_failure(&wire_name);
        chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // SOCKS5 handshake succeeded — wire proved it can carry this flow.
    wire_health.record_success(&wire_name);

    match tokio::io::copy_bidirectional(&mut stream, &mut socks).await {
        Ok((tx, rx)) => {
            chain_metrics.bytes_tx.fetch_add(tx, Ordering::Relaxed);
            chain_metrics.bytes_rx.fetch_add(rx, Ordering::Relaxed);
        }
        Err(e) => {
            warn!("TCP forward {target} error: {e}");
            chain_metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn build_socks5_connect(target: SocketAddr) -> Vec<u8> {
    let mut req = Vec::with_capacity(10);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV
    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    req
}

fn derive_peer_ip(local: &str) -> String {
    let parts: Vec<&str> = local.split('.').collect();
    if parts.len() == 4 {
        if let Ok(last) = parts[3].parse::<u8>() {
            let peer_last = if last == 1 { 2 } else { 1 };
            return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], peer_last);
        }
    }
    local.to_string()
}
