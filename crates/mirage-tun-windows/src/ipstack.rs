use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::Instant,
};

use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{
    udp::UdpMsg, AnyIpPktFrame, StackBuilder, TcpListener, UdpSocket,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, Mutex, Semaphore},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_core::dns::dns_forward_via_socks5;
use mirage_dns::topology_stub::DnsRoutingHint;

use crate::chains::{ChainEntry, ChainMap, ChainRegistry, TunRouter};
use crate::config::TunConfig;
use crate::dns_map::DnsMap;
use crate::error::{Result, TunError};
use crate::metrics::MetricsRegistry;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::process_info::ProcessResolver;
use crate::wintun::WintunDevice;

pub struct IpStackRunner {
    /// Number of active TCP/bypass connections — used for graceful drain.
    pub active_conns: Arc<AtomicU64>,
}

impl IpStackRunner {
    pub async fn start(
        device: WintunDevice,
        chain_registry: Arc<ChainRegistry>,
        cancel: CancellationToken,
        relay_addrs: Vec<IpAddr>,
        if_index: u32,
        policy: Arc<PolicyEngine>,
        dns_map: Arc<DnsMap>,
        native_dns: Option<SocketAddr>,
        process_resolver: Arc<ProcessResolver>,
        metrics: Arc<MetricsRegistry>,
        connections: Arc<crate::metrics::ConnectionRegistry>,
        cfg: &TunConfig,
    ) -> Result<Self> {
        // Snapshot for logging only — not used in the hot path.
        let snap = chain_registry.snapshot().await;
        let default_socks5 = snap.get("default").map(|e| e.socks5_addr)
            .or_else(|| snap.values().next().map(|e| e.socks5_addr));

        info!(
            "IpStackRunner: started, default_socks5={default_socks5:?}, chains={}, \
             relay_bypass={relay_addrs:?}, if_index={if_index}",
            snap.len(),
        );

        if native_dns.is_none() {
            warn!(
                "IpStackRunner: bypass rules active but native_dns not configured, \
                 using 8.8.8.8 as fallback for bypass DNS"
            );
        }

        let relay_set: Arc<HashSet<IpAddr>> =
            Arc::new(relay_addrs.into_iter().collect());
        let relay_set2 = relay_set.clone();

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(1500)
            .tcp_send_buffer_size(cfg.tcp_send_buffer_size)
            .tcp_recv_buffer_size(cfg.tcp_recv_buffer_size)
            .add_ip_filter_fn(move |_src, dst| !relay_set2.contains(dst))
            .build()
            .map_err(TunError::SmoltcpBuild)?;

        let tcp_listener = tcp_listener.expect("tcp enabled in StackBuilder");
        let udp_socket = udp_socket.expect("udp enabled in StackBuilder");

        if let Some(r) = runner {
            tokio::spawn(r);
        }

        let (stack_sink, stack_stream) = stack.split();
        let (wintun_rx, wintun_tx) = device.take_channels();

        let socks5_semaphore = Arc::new(Semaphore::new(cfg.socks5_concurrency));

        let stats = Arc::new(PumpStats::default());
        let active_conns = Arc::new(AtomicU64::new(0));

        let dns_upstream = cfg.dns_upstream;
        let dns_cache_ttl = std::time::Duration::from_secs(cfg.dns_cache_ttl_secs);
        let dns_cache_max = cfg.dns_cache_max;
        let dns_concurrency = cfg.dns_concurrency;

        tokio::spawn(pump_wintun_to_stack(
            wintun_rx,
            stack_sink,
            cancel.clone(),
            stats.clone(),
        ));
        tokio::spawn(pump_stack_to_wintun(
            stack_stream,
            wintun_tx,
            cancel.clone(),
            stats.clone(),
        ));
        let process_resolver2 = process_resolver.clone();
        let connections2 = connections.clone();
        tokio::spawn(tcp_accept_loop(
            tcp_listener,
            chain_registry.clone(),
            socks5_semaphore,
            if_index,
            cancel.clone(),
            stats.clone(),
            policy.clone(),
            dns_map.clone(),
            process_resolver,
            metrics,
            connections,
            active_conns.clone(),
        ));
        let udp_proxy_sessions: crate::udp_socks5::UdpProxySessionMap =
            Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(udp_dns_loop(
            udp_socket,
            chain_registry,
            if_index,
            cancel.clone(),
            policy,
            dns_map,
            native_dns,
            dns_upstream,
            dns_cache_ttl,
            dns_cache_max,
            dns_concurrency,
            udp_proxy_sessions,
            process_resolver2,
            connections2,
        ));

        // Stats printer
        let stats2 = stats.clone();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel2.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                        let s = &stats2;
                        info!(
                            "TUN stats: wintun→stack={} stack→wintun={} tcp_accept={} socks5_ok={} socks5_fail={} bypass_ok={} bypass_fail={} sink_err={}",
                            s.wintun_to_stack.load(Ordering::Relaxed),
                            s.stack_to_wintun.load(Ordering::Relaxed),
                            s.tcp_accepted.load(Ordering::Relaxed),
                            s.socks5_ok.load(Ordering::Relaxed),
                            s.socks5_fail.load(Ordering::Relaxed),
                            s.bypass_ok.load(Ordering::Relaxed),
                            s.bypass_fail.load(Ordering::Relaxed),
                            s.sink_errors.load(Ordering::Relaxed),
                        );
                    }
                }
            }
        });

        Ok(Self { active_conns })
    }
}

// ── Stats ────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct PumpStats {
    wintun_to_stack: AtomicU64,
    stack_to_wintun: AtomicU64,
    tcp_accepted: AtomicU64,
    socks5_ok: AtomicU64,
    socks5_fail: AtomicU64,
    sink_errors: AtomicU64,
    bypass_ok: AtomicU64,
    bypass_fail: AtomicU64,
}

/// RAII guard that decrements `active_conns` when the connection task completes.
struct ConnGuard(Arc<AtomicU64>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── Wintun ↔ Stack pumps ──────────────────────────────────────────────────────

async fn pump_wintun_to_stack(
    mut wintun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut stack_sink: futures::stream::SplitSink<mirage_tcpip_stack::Stack, AnyIpPktFrame>,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
) {
    use futures::SinkExt;
    info!("pump_wintun_to_stack: pump started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = wintun_rx.recv() => match pkt {
                None => break,
                Some(pkt) => {
                    stats.wintun_to_stack.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = stack_sink.feed(pkt).await {
                        stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                        warn!("pump wintun→stack: sink error: {e}");
                        continue;
                    }
                    // Drain any additional packets already in the channel before flushing.
                    while let Ok(pkt) = wintun_rx.try_recv() {
                        stats.wintun_to_stack.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = stack_sink.feed(pkt).await {
                            stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                            warn!("pump wintun→stack: sink error: {e}");
                            break;
                        }
                    }
                    // Single flush for the whole batch.
                    let _ = stack_sink.flush().await;
                }
            }
        }
    }
}

async fn pump_stack_to_wintun(
    mut stack_stream: futures::stream::SplitStream<mirage_tcpip_stack::Stack>,
    wintun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
) {
    info!("pump_stack_to_wintun: pump started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = stack_stream.next() => match pkt {
                Some(Ok(pkt)) => {
                    stats.stack_to_wintun.fetch_add(1, Ordering::Relaxed);
                    if wintun_tx.send(pkt).await.is_err() {
                        warn!("pump stack→wintun: channel closed");
                        break;
                    }
                }
                _ => break,
            }
        }
    }
}

// ── TCP accept loop ───────────────────────────────────────────────────────────

async fn tcp_accept_loop(
    mut tcp_listener: TcpListener,
    chain_registry: Arc<ChainRegistry>,
    socks5_semaphore: Arc<Semaphore>,
    if_index: u32,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
    policy: Arc<PolicyEngine>,
    dns_map: Arc<DnsMap>,
    process_resolver: Arc<ProcessResolver>,
    metrics: Arc<MetricsRegistry>,
    connections: Arc<crate::metrics::ConnectionRegistry>,
    active_conns: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("IpStackRunner: cancelled, exiting TCP accept loop");
                break;
            }
            item = tcp_listener.next() => match item {
                None => break,
                Some((stream, local_addr, remote_addr)) => {
                    let dst = remote_addr;
                    let src_port = local_addr.port();
                    stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);

                    // App-based process lookup (spawn_blocking — sync Win32 calls)
                    let resolver = process_resolver.clone();
                    let app_info = tokio::task::spawn_blocking(move || {
                        resolver.resolve(src_port, dst)
                    })
                    .await
                    .ok()
                    .flatten();

                    // Policy decision
                    let domain_hint = dns_map.get(&dst.ip());
                    let decision = policy
                        .decide(dst.ip(), dst.port(), domain_hint.as_deref(), app_info.as_ref())
                        .await;

                    let exe_short = app_info.as_ref().map(|i| {
                        i.exe_path.rsplit_once('\\')
                            .map(|(_, name)| name)
                            .unwrap_or(&i.exe_path)
                            .to_owned()
                    });

                    let cancel2 = cancel.clone();
                    let stats2 = stats.clone();

                    match decision {
                        PolicyDecision::Bypass => {
                            info!("TCP {dst}: BYPASS app={} domain={domain_hint:?}",
                                exe_short.as_deref().unwrap_or("?"));
                            let metrics2 = metrics.clone();
                            metrics2.record_bypass_connection();
                            let conns = connections.clone();
                            conns.record_open("__bypass__", dst, domain_hint.clone(), "tcp", app_info.as_ref());
                            let ac = active_conns.clone();
                            ac.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _guard = ConnGuard(ac);
                                tokio::select! {
                                    _ = cancel2.cancelled() => {}
                                    r = handle_bypass_tcp(stream, dst, if_index) => {
                                        match r {
                                            Ok((tx, rx)) => {
                                                stats2.bypass_ok.fetch_add(1, Ordering::Relaxed);
                                                metrics2.record_bypass_bytes(tx, rx);
                                                conns.record_bytes("__bypass__", dst, tx, rx);
                                            }
                                            Err(e) => {
                                                stats2.bypass_fail.fetch_add(1, Ordering::Relaxed);
                                                metrics2.record_bypass_error();
                                                warn!("IpStackRunner: TCP {dst} bypass error: {e}");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        PolicyDecision::Chain(chain_name) => {
                            // Build TunRouter from current registry snapshot.
                            // TunRouter::pick() returns chains ordered by priority:
                            // preferred chain first, others as failover, "default" last.
                            let tun_router = TunRouter::from_registry(&chain_registry).await;
                            let five_tuple_hash = {
                                use std::hash::{Hash, Hasher};
                                let mut h = std::collections::hash_map::DefaultHasher::new();
                                local_addr.hash(&mut h);
                                dst.hash(&mut h);
                                h.finish()
                            };
                            let candidates = tun_router.pick(Some(&chain_name), five_tuple_hash);
                            if candidates.is_empty() {
                                warn!("TCP {dst}: no chains available — dropping");
                                continue;
                            }

                            // Use the primary (index 0) chain for this connection.
                            // Additional candidates are fallbacks for future connections
                            // via round-robin; per-connection failover over SOCKS5 would
                            // require retrying which is deferred to Wave 3.
                            let (primary_chain_id, socks5_addr) = candidates.into_iter().next()
                                .expect("candidates non-empty checked above");

                            let sem = socks5_semaphore.clone();
                            let metrics2 = metrics.clone();
                            metrics2.record_connection(&primary_chain_id);
                            let conns = connections.clone();
                            conns.record_open(&primary_chain_id, dst, domain_hint.clone(), "tcp", app_info.as_ref());
                            let chain_for_task = primary_chain_id.clone();
                            let ac = active_conns.clone();
                            ac.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _guard = ConnGuard(ac);
                                tokio::select! {
                                    _ = cancel2.cancelled() => {}
                                    r = handle_tcp(stream, socks5_addr, dst, sem, if_index) => {
                                        match r {
                                            Ok((tx, rx)) => {
                                                stats2.socks5_ok.fetch_add(1, Ordering::Relaxed);
                                                metrics2.record_bytes(&chain_for_task, tx, rx);
                                                conns.record_bytes(&chain_for_task, dst, tx, rx);
                                            }
                                            Err(e) => {
                                                stats2.socks5_fail.fetch_add(1, Ordering::Relaxed);
                                                metrics2.record_error(&chain_for_task);
                                                warn!("IpStackRunner: TCP {dst} chain '{chain_for_task}' error: {e}");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }
}

// ── UDP / DNS loop ────────────────────────────────────────────────────────────

struct DnsCache {
    entries: HashMap<Vec<u8>, (Vec<u8>, Instant)>,
    ttl: std::time::Duration,
    max: usize,
}

impl DnsCache {
    fn new(ttl: std::time::Duration, max: usize) -> Self {
        Self { entries: HashMap::new(), ttl, max }
    }

    fn get(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let key = Self::cache_key(query);
        if let Some((resp, ts)) = self.entries.get(&key) {
            if ts.elapsed() < self.ttl {
                let mut cached = resp.clone();
                // Patch transaction ID in response to match query
                if query.len() >= 2 && cached.len() >= 2 {
                    cached[0] = query[0];
                    cached[1] = query[1];
                }
                return Some(cached);
            }
            self.entries.remove(&key);
        }
        None
    }

    fn put(&mut self, query: &[u8], response: &[u8]) {
        if self.entries.len() >= self.max {
            // Evict oldest
            let oldest = self.entries.iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        let key = Self::cache_key(query);
        self.entries.insert(key, (response.to_vec(), Instant::now()));
    }

    // Cache key = query minus transaction ID (first 2 bytes)
    fn cache_key(query: &[u8]) -> Vec<u8> {
        if query.len() > 2 { query[2..].to_vec() } else { query.to_vec() }
    }
}

// ── UDP bypass session map ───────────────────────────────────────────────────

/// Per-session state for a UDP bypass session.
///
/// The verdict is decided ONCE at session-open (D1); subsequent packets reuse
/// the forwarding channel without re-calling Win32 or policy.
struct UdpBypassSession {
    fwd_tx: mpsc::Sender<Vec<u8>>,
}

/// Key: (client_src, original_dst) — one entry per active UDP bypass session.
type UdpSessionMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpBypassSession>>>;

async fn udp_bypass_forward(
    payload: Vec<u8>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    resp_tx: mpsc::UnboundedSender<UdpMsg>,
    sessions: UdpSessionMap,
    if_index: u32,
    app_info: Option<crate::process_info::ProcessInfo>,
    connections: Arc<crate::metrics::ConnectionRegistry>,
    domain_hint: Option<String>,
) {
    // Check if session already exists — reuse stored verdict, no Win32 re-call.
    {
        let map = sessions.lock().await;
        if let Some(session) = map.get(&(src_addr, dst_addr)) {
            let _ = session.fwd_tx.send(payload);
            return;
        }
    }

    // No session — create one, record ledger entry at session-open.
    connections.record_open("__bypass__", dst_addr, domain_hint, "udp", app_info.as_ref());

    let (fwd_tx, mut fwd_rx) = mpsc::channel::<Vec<u8>>(64);

    {
        let mut map = sessions.lock().await;
        // Insert; send initial payload.
        map.insert((src_addr, dst_addr), UdpBypassSession { fwd_tx: fwd_tx.clone() });
    }
    let _ = fwd_tx.send(payload).await;

    let sessions2 = sessions.clone();
    tokio::spawn(async move {
        const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        // Create a native UDP socket bound via IP_UNICAST_IF.
        let sock = match create_udp_bypass_socket(if_index) {
            Ok(s) => s,
            Err(e) => {
                warn!("UDP bypass: socket create failed for {dst_addr}: {e}");
                sessions2.lock().await.remove(&(src_addr, dst_addr));
                return;
            }
        };

        let mut recv_buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                // Forward inbound datagrams to dst.
                msg = tokio::time::timeout(UDP_IDLE_TIMEOUT, fwd_rx.recv()) => {
                    match msg {
                        Ok(Some(data)) => {
                            if let Err(e) = sock.send_to(&data, dst_addr).await {
                                warn!("UDP bypass: send to {dst_addr} failed: {e}");
                                break;
                            }
                        }
                        Ok(None) | Err(_) => {
                            // Channel closed or idle timeout.
                            break;
                        }
                    }
                }
                // Receive responses and push back into TUN.
                result = tokio::time::timeout(UDP_IDLE_TIMEOUT, sock.recv_from(&mut recv_buf)) => {
                    match result {
                        Ok(Ok((n, _from))) => {
                            let response = recv_buf[..n].to_vec();
                            // src/dst are swapped: TUN sees response as coming from dst.
                            let _ = resp_tx.send((response, dst_addr, src_addr));
                        }
                        Ok(Err(e)) => {
                            warn!("UDP bypass: recv from {dst_addr} failed: {e}");
                            break;
                        }
                        Err(_) => {
                            // Idle timeout.
                            break;
                        }
                    }
                }
            }
        }

        sessions2.lock().await.remove(&(src_addr, dst_addr));
    });
}

/// Bind a socket to a specific interface via `IP_UNICAST_IF` / `IPV6_UNICAST_IF` setsockopt.
///
/// For IPv4, the index is passed in big-endian (network byte order) as required by
/// `IP_UNICAST_IF` on Windows. For IPv6, it is passed in native byte order as required by
/// `IPV6_UNICAST_IF`. No-op when `if_index == 0`.
#[cfg(windows)]
fn bind_to_interface(sock: &socket2::Socket, if_index: u32, is_ipv4: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    if if_index == 0 {
        return Ok(());
    }

    let (level, optname, index_val) = if is_ipv4 {
        (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
            31i32, // IP_UNICAST_IF
            u32::to_be(if_index),
        )
    } else {
        (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
            31i32, // IPV6_UNICAST_IF
            if_index, // native byte order for IPv6
        )
    };

    unsafe {
        let ret = windows_sys::Win32::Networking::WinSock::setsockopt(
            sock.as_raw_socket() as usize,
            level,
            optname,
            &index_val as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        );
        if ret == windows_sys::Win32::Networking::WinSock::SOCKET_ERROR {
            return Err(std::io::Error::from_raw_os_error(
                windows_sys::Win32::Networking::WinSock::WSAGetLastError(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn create_udp_bypass_socket(if_index: u32) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().expect("static addr is valid");
    sock.bind(&bind_addr.into())?;
    bind_to_interface(&sock, if_index, true)?;
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_udp)
}

#[cfg(not(windows))]
fn create_udp_bypass_socket(_if_index: u32) -> std::io::Result<tokio::net::UdpSocket> {
    // Blocking bind, but only on non-Windows (test/dev builds).
    let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    std_sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_sock)
}

/// pub(crate) wrapper for use by udp_socks5.
/// For SOCKS5 relay on localhost, always pass if_index=0.
pub(crate) fn create_udp_bypass_socket_for_proxy(if_index: u32) -> std::io::Result<tokio::net::UdpSocket> {
    create_udp_bypass_socket(if_index)
}

/// pub(crate) wrapper for use by udp_socks5.
pub(crate) async fn connect_via_interface_pub(
    remote: SocketAddr,
    if_index: u32,
) -> std::io::Result<TcpStream> {
    connect_via_interface(remote, if_index).await
}

/// Per-session verdict for non-DNS UDP flows.
///
/// Keyed by `(src_addr, dst_addr)`.  Created once at session-open and removed
/// when either `UdpSessionMap` (bypass) or `UdpProxySessionMap` (chain) reaps
/// the corresponding session.  We keep this map in sync with the session maps by
/// inserting on first packet and cleaning up when sessions are reaped (the
/// session maps own the lifecycle; this map is consulted for routing on subsequent
/// packets and then dropped if the session map entry is absent — no explicit
/// removal needed here because lookups are cheap and entries are small).
type UdpVerdictMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), (PolicyDecision, Option<crate::process_info::ProcessInfo>)>>>;

async fn udp_dns_loop(
    udp_socket: UdpSocket,
    chain_registry: Arc<ChainRegistry>,
    if_index: u32,
    cancel: CancellationToken,
    policy: Arc<PolicyEngine>,
    dns_map: Arc<DnsMap>,
    native_dns: Option<SocketAddr>,
    dns_upstream: SocketAddr,
    dns_cache_ttl: std::time::Duration,
    dns_cache_max: usize,
    dns_concurrency: usize,
    udp_proxy_sessions: crate::udp_socks5::UdpProxySessionMap,
    process_resolver: Arc<ProcessResolver>,
    connections: Arc<crate::metrics::ConnectionRegistry>,
) {
    let (mut read_half, write_half) = udp_socket.split();
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<UdpMsg>();

    let mut write_half = write_half;
    tokio::spawn(async move {
        while let Some(msg) = resp_rx.recv().await {
            if let Err(e) = write_half.send(msg).await {
                warn!("IpStackRunner: UDP DNS write error: {e}");
                break;
            }
        }
    });

    let dns_sem = Arc::new(Semaphore::new(dns_concurrency));
    let cache = Arc::new(Mutex::new(DnsCache::new(dns_cache_ttl, dns_cache_max)));
    let udp_sessions: UdpSessionMap = Arc::new(Mutex::new(HashMap::new()));
    // Per-session verdict cache (D1): verdict + attribution decided once at session-open,
    // reused for all subsequent packets of the same (src, dst) — no per-packet Win32 cost,
    // no mid-session flip.
    let udp_verdicts: UdpVerdictMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            item = read_half.next() => match item {
                None => break,
                Some((payload, src_addr, dst_addr)) => {
                    if dst_addr.port() != 53 {
                        let dst_ip = dst_addr.ip();

                        // D1: look up per-session verdict.  On session-open (first packet
                        // for this (src, dst) pair) run attribution + policy.decide ONCE and
                        // store.  Subsequent packets reuse the stored entry.
                        let session_key = (src_addr, dst_addr);
                        let is_new_session = {
                            let map = udp_verdicts.lock().await;
                            !map.contains_key(&session_key)
                        };

                        let (decision, app_info_for_session) = if is_new_session {
                            // Attribution: resolve UDP src_port → PID → exe.
                            // spawn_blocking because find_pid_in_udp_table is a sync Win32 call.
                            let resolver = process_resolver.clone();
                            let src_port = src_addr.port();
                            let app_info: Option<crate::process_info::ProcessInfo> =
                                tokio::task::spawn_blocking(move || {
                                    resolver.resolve_udp(src_port)
                                })
                                .await
                                .ok()
                                .flatten();

                            let domain_hint = dns_map.get(&dst_ip);
                            let decision = policy
                                .decide(dst_ip, dst_addr.port(), domain_hint.as_deref(), app_info.as_ref())
                                .await;

                            // Store verdict for subsequent packets.
                            {
                                let mut map = udp_verdicts.lock().await;
                                map.insert(session_key, (decision.clone(), app_info.clone()));
                            }

                            (decision, app_info)
                        } else {
                            // Reuse stored verdict — no Win32 call, no policy re-eval.
                            let map = udp_verdicts.lock().await;
                            let (d, a) = map.get(&session_key)
                                .expect("is_new_session=false means entry exists");
                            (d.clone(), a.clone())
                        };

                        let domain_hint = dns_map.get(&dst_ip);

                        if decision == PolicyDecision::Bypass {
                            udp_bypass_forward(
                                payload,
                                src_addr,
                                dst_addr,
                                resp_tx.clone(),
                                udp_sessions.clone(),
                                if_index,
                                app_info_for_session,
                                connections.clone(),
                                domain_hint,
                            )
                            .await;
                        } else {
                            // Proxy non-DNS UDP through SOCKS5 UDP ASSOCIATE
                            let chain_snap = chain_registry.snapshot().await;
                            let socks5_addr = match &decision {
                                PolicyDecision::Chain(name) => {
                                    chain_snap.get(name.as_str())
                                        .or_else(|| chain_snap.get("default"))
                                        .or_else(|| chain_snap.values().next())
                                        .map(|e| e.socks5_addr)
                                }
                                PolicyDecision::Bypass => unreachable!("bypass handled above"),
                            };
                            if let Some(socks5_addr) = socks5_addr {
                                // Record ledger entry for chain-routed UDP sessions at session-open.
                                if is_new_session {
                                    if let PolicyDecision::Chain(ref chain_name) = decision {
                                        connections.record_open(
                                            chain_name,
                                            dst_addr,
                                            domain_hint,
                                            "udp",
                                            app_info_for_session.as_ref(),
                                        );
                                    }
                                }
                                crate::udp_socks5::udp_proxy_forward(
                                    payload,
                                    src_addr,
                                    dst_addr,
                                    resp_tx.clone(),
                                    udp_proxy_sessions.clone(),
                                    socks5_addr,
                                    if_index,
                                )
                                .await;
                            } else {
                                warn!("UDP {dst_addr}: no chain available — dropped");
                            }
                        }

                        // Reap verdict entry when the underlying session is gone.
                        // Both UdpSessionMap (bypass) and UdpProxySessionMap (chain) remove their
                        // entries on idle timeout/close.  We mirror that here so stale verdict
                        // entries don't accumulate.
                        {
                            let bypass_alive = udp_sessions.lock().await.contains_key(&session_key);
                            let chain_alive = udp_proxy_sessions.lock().await.contains_key(&session_key);
                            if !bypass_alive && !chain_alive {
                                udp_verdicts.lock().await.remove(&session_key);
                            }
                        }

                        continue;
                    }
                    // Check cache first (no upstream query needed)
                    {
                        let mut c = cache.lock().await;
                        if let Some(cached) = c.get(&payload) {
                            let _ = resp_tx.send((cached, dst_addr, src_addr));
                            continue;
                        }
                    }

                    // Extract domain and check policy BEFORE spawning (no locks held)
                    let domain = extract_dns_domain(&payload);
                    let decision = if let Some(ref dom) = domain {
                        policy.domain_decision(dom).await
                    } else {
                        PolicyDecision::default_chain()
                    };

                    let tx = resp_tx.clone();
                    let sem = dns_sem.clone();
                    let cache2 = cache.clone();
                    let dns_map2 = dns_map.clone();

                    if decision == PolicyDecision::Bypass {
                        const FALLBACK_DNS: SocketAddr = SocketAddr::new(
                            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                            53,
                        );
                        let ndns = native_dns.unwrap_or(FALLBACK_DNS);
                        tokio::spawn(async move {
                            let _permit = match sem.acquire().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            match dns_via_native(&payload, ndns, if_index).await {
                                Ok(response) => {
                                    if let Some(ref dom) = domain {
                                        let ips = extract_dns_ips(&response);
                                        if !ips.is_empty() {
                                            dns_map2.insert_many(&ips, dom);
                                        }
                                    }
                                    {
                                        let mut c = cache2.lock().await;
                                        c.put(&payload, &response);
                                    }
                                    let _ = tx.send((response, dst_addr, src_addr));
                                }
                                Err(e) => {
                                    warn!("IpStackRunner: DNS via native failed: {e}");
                                }
                            }
                        });
                        continue;
                    }

                    // SOCKS5 path — only reached for Chain decisions (Bypass continues above).
                    let chain_snap: Arc<ChainMap> = chain_registry.snapshot().await;
                    let chain_entry: Option<ChainEntry> = match &decision {
                        PolicyDecision::Chain(name) => {
                            // Try the named chain first, then fall back to "default".
                            chain_snap.get(name.as_str())
                                .or_else(|| chain_snap.get("default"))
                                .or_else(|| chain_snap.values().next())
                                .cloned()
                        }
                        PolicyDecision::Bypass => unreachable!("bypass handled above"),
                    };

                    let chain_entry = match chain_entry {
                        Some(entry) => entry,
                        None => {
                            warn!("DNS query: no chain configured — dropping");
                            continue;
                        }
                    };

                    // Use per-chain DNS upstream if configured; fall back to global.
                    let chain_dns = chain_entry.dns_upstream.unwrap_or(dns_upstream);
                    let socks5_addr = chain_entry.socks5_addr;
                    let chain_id_tag = chain_entry.chain_id.clone();

                    // Log chain-tagged dispatch intent (observability).
                    DnsRoutingHint {
                        chain_id: Some(chain_id_tag.clone()),
                        name: domain.clone().unwrap_or_default(),
                    }
                    .log_intent();

                    tokio::spawn(async move {
                        let _permit = match sem.acquire().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        match dns_forward_via_socks5(&payload, socks5_addr, chain_dns).await {
                            Ok(response) => {
                                if let Some(ref dom) = domain {
                                    let ips = extract_dns_ips(&response);
                                    if !ips.is_empty() {
                                        dns_map2.insert_many(&ips, dom);
                                    }
                                }
                                {
                                    let mut c = cache2.lock().await;
                                    c.put(&payload, &response);
                                }
                                let _ = tx.send((response, dst_addr, src_addr));
                            }
                            Err(e) => {
                                warn!(chain_id = %chain_id_tag, "IpStackRunner: DNS via SOCKS5 failed: {e}");
                            }
                        }
                    });
                }
            }
        }
    }
}

// ── DNS parsing helpers ───────────────────────────────────────────────────────

fn extract_dns_domain(query: &[u8]) -> Option<String> {
    if query.len() < 13 {
        return None;
    }
    let mut pos = 12;
    let mut parts = Vec::new();
    loop {
        if pos >= query.len() {
            return None;
        }
        let len = query[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        parts.push(std::str::from_utf8(&query[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= data.len() {
            return data.len();
        }
        let b = data[pos];
        if b == 0 {
            return pos + 1;
        }
        if b & 0xC0 == 0xC0 {
            return pos + 2;
        }
        pos += 1 + b as usize;
    }
}

fn extract_dns_ips(response: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if response.len() < 12 {
        return ips;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(response, pos);
        pos += 4; // QTYPE + QCLASS
        if pos > response.len() {
            return ips;
        }
    }

    // Parse answer section
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }
        pos = skip_dns_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                let ip = std::net::Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                );
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    ips
}

// ── Native DNS (bypass path) ──────────────────────────────────────────────────

#[cfg(windows)]
async fn dns_via_native(
    query: &[u8],
    native_dns: SocketAddr,
    if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().expect("static addr is valid");
    sock.bind(&bind_addr.into())?;
    bind_to_interface(&sock, if_index, true)?;
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    let tokio_udp = tokio::net::UdpSocket::from_std(std_udp)?;
    tokio_udp.send_to(query, native_dns).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio_udp.recv(&mut buf),
    )
    .await??;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(not(windows))]
async fn dns_via_native(
    query: &[u8],
    native_dns: SocketAddr,
    _if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.send_to(query, native_dns).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        udp.recv(&mut buf),
    )
    .await??;
    buf.truncate(n);
    Ok(buf)
}

// ── TCP bypass (direct via native interface) ──────────────────────────────────

async fn handle_bypass_tcp(
    mut tcp: mirage_tcpip_stack::TcpStream,
    dst: SocketAddr,
    if_index: u32,
) -> std::result::Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let mut native = connect_via_interface(dst, if_index).await?;
    let (a_to_b, b_to_a) =
        tokio::io::copy_bidirectional_with_sizes(&mut tcp, &mut native, 64 * 1024, 64 * 1024)
            .await?;
    Ok((a_to_b, b_to_a))
}

// ── TCP → SOCKS5 ──────────────────────────────────────────────────────────────

async fn handle_tcp(
    mut tcp: mirage_tcpip_stack::TcpStream,
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    socks5_semaphore: Arc<Semaphore>,
    if_index: u32,
) -> std::result::Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let t0 = Instant::now();
    let mut proxy =
        socks5_connect_with_semaphore(socks5_addr, dst, &socks5_semaphore, if_index).await?;
    let socks5_ms = t0.elapsed().as_millis();

    // Read first bytes from smoltcp to measure handshake + first data latency
    let t1 = Instant::now();
    let mut first_buf = [0u8; 8192];
    let first_n = tcp.read(&mut first_buf).await?;
    let first_read_ms = t1.elapsed().as_millis();

    // Write those first bytes to proxy
    if first_n > 0 {
        proxy.write_all(&first_buf[..first_n]).await?;
    }

    let t2 = Instant::now();
    let (a_to_b, b_to_a) =
        tokio::io::copy_bidirectional_with_sizes(&mut tcp, &mut proxy, 64 * 1024, 64 * 1024)
            .await?;
    let relay_ms = t2.elapsed().as_millis();

    let total_ms = t0.elapsed().as_millis();
    if total_ms > 1000 {
        info!("TCP {dst}: socks5={socks5_ms}ms first_read={first_read_ms}ms({first_n}B) relay={relay_ms}ms tx={a_to_b} rx={b_to_a}");
    }
    Ok((a_to_b, b_to_a))
}

// ── SOCKS5 connect with concurrency limit ────────────────────────────────────

async fn socks5_connect_with_semaphore(
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    semaphore: &Semaphore,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let _permit = semaphore
        .acquire()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut last_err = None;
    for attempt in 0..3u8 {
        match socks5_connect(socks5_addr, dst, if_index).await {
            Ok(proxy) => return Ok(proxy),
            Err(e) => {
                warn!("IpStackRunner: SOCKS5 to {dst} attempt {attempt} failed: {e}");
                last_err = Some(e);
                if attempt < 2 {
                    // Short backoff for localhost proxy: 50ms, 100ms
                    let delay = 50u64 * (1 << attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

// ── Interface-bound TCP connect ───────────────────────────────────────────────

#[cfg(windows)]
async fn connect_via_interface(
    remote: SocketAddr,
    if_index: u32,
) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let is_ipv4 = remote.is_ipv4();
    let domain = if is_ipv4 { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_to_interface(&sock, if_index, is_ipv4)?;
    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    let tokio_sock = tokio::net::TcpSocket::from_std_stream(std_stream);
    tokio_sock.connect(remote).await
}

#[cfg(not(windows))]
async fn connect_via_interface(
    remote: SocketAddr,
    _if_index: u32,
) -> std::io::Result<TcpStream> {
    TcpStream::connect(remote).await
}

// ── SOCKS5 no-auth connect ────────────────────────────────────────────────────

async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let effective_if = if proxy.ip().is_loopback() { 0 } else { if_index };
    let mut stream = connect_via_interface(proxy, effective_if).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(format!(
            "SOCKS5 greeting rejected: {:02x} {:02x}",
            greeting_resp[0], greeting_resp[1]
        )
        .into());
    }

    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    stream.write_all(&req).await?;

    let mut resp_hdr = [0u8; 4];
    stream.read_exact(&mut resp_hdr).await?;

    if resp_hdr[0] != 0x05 {
        return Err(format!("SOCKS5 bad version in response: {}", resp_hdr[0]).into());
    }
    if resp_hdr[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected, code: {}", resp_hdr[1]).into());
    }

    match resp_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut skip = vec![0u8; len + 2];
            stream.read_exact(&mut skip).await?;
        }
        atyp => {
            return Err(format!("SOCKS5 unknown ATYP in response: {atyp}").into());
        }
    }

    Ok(stream)
}

// ── DNS warmup ────────────────────────────────────────────────────────────────

pub(crate) async fn dns_warmup(socks5_addr: SocketAddr, _if_index: u32, dns_upstream: SocketAddr) {
    // Minimal A query for example.com — just to warm up the DNS-over-TCP SOCKS5 path.
    // Uses dns_forward_via_socks5 (shared mirage-core helper) instead of the old
    // TUN-local dns_via_socks5_inner so the two paths stay consistent.
    let query: &[u8] = &[
        0x00, 0x01, // txn id
        0x01, 0x00, // standard query, recursion desired
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer/authority/additional
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,       // root label
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ];
    match dns_forward_via_socks5(query, socks5_addr, dns_upstream).await {
        Ok(_) => info!("DNS warmup: success"),
        Err(e) => tracing::warn!("DNS warmup: failed: {e}"),
    }
}
